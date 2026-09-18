"""监管链 HTTP 接口（标准库实现，零外部依赖）。

生产部署应放在 WSGI 服务器（gunicorn/uwsgi）之后，并以 mTLS 或网关
完成调用方身份认证；这里用请求头 ``X-Actor-Id`` / ``X-Actor-Role`` 与
共享签名密钥（JSON 字段 ``key``）演示角色与凭据校验。

路由
----
POST /users                         注册角色用户
POST /samples/scan                  扫描录入（同条码重复扫描幂等）
POST /samples                       登记样本
POST /samples/{bc}/temperatures     补录冷藏温度
POST /samples/{bc}/handover         逐环交接（验签/时间窗/封条/冷链）
POST /batch-handovers               批量交接
POST /samples/{bc}/anomalies        异常申报（自动隔离）
POST /samples/{bc}/release          合规主管解除隔离
POST /samples/{bc}/seal             授权更换封条（隔离流程内）
POST /samples/{bc}/split            拆分为 A/B 瓶
POST /authorizations                合规主管签发授权
POST /samples/{bc}/retest           授权复检
POST /samples/{bc}/destroy          授权销毁
GET  /samples/{bc}                  状态查询（按角色脱敏）
GET  /batches/{batch}               按批次列表
GET  /audit                         审计导出（仅合规主管，?barcode=）
GET  /healthz
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from .models import Actor, CustodyError, Role
from .service import CustodyService


def _status_for(exc: Exception) -> int:
    from .models import (
        AuthzError,
        AuthorizationRequiredError,
        DuplicateBarcodeError,
        IdempotencyConflict,
        IntegrityError,
        NotFoundError,
        QuarantineError,
        SealError,
        SignatureError,
        TimeWindowError,
        ValidationError,
        ColdChainError,
    )

    if isinstance(exc, (AuthzError, SignatureError)):
        return 403
    if isinstance(exc, PermissionError):
        return 403
    if isinstance(exc, NotFoundError):
        return 404
    if isinstance(exc, (KeyError, ValueError)):
        return 400
    if isinstance(exc, (ValidationError, DuplicateBarcodeError, IdempotencyConflict)):
        return 409
    if isinstance(exc, IntegrityError):
        return 500
    if isinstance(exc, CustodyError):
        return 422
    return 500


class CustodyHTTPHandler(BaseHTTPRequestHandler):
    service: CustodyService  # 由 make_server 注入到类上

    server_version = "CustodyChain/1.0"

    # ------------------------------------------------------------------
    # 基础收发
    # ------------------------------------------------------------------

    def _send(self, status: int, body: Any) -> None:
        data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return body

    def _actor(self, body: dict[str, Any]) -> Actor:
        actor_id = self.headers.get("X-Actor-Id")
        role = self.headers.get("X-Actor-Role")
        key = body.pop("key", None) or self.headers.get("X-Actor-Key")
        if not actor_id or not role or not key:
            raise PermissionError("缺少调用方身份头 X-Actor-Id/X-Actor-Role/密钥")
        return Actor(actor_id, Role(role), key)

    def _actor_from_headers(self) -> Actor:
        actor_id = self.headers.get("X-Actor-Id")
        role = self.headers.get("X-Actor-Role")
        key = self.headers.get("X-Actor-Key")
        if not actor_id or not role or not key:
            raise PermissionError("缺少调用方身份头 X-Actor-Id/X-Actor-Role/X-Actor-Key")
        return Actor(actor_id, Role(role), key)

    def log_message(self, fmt: str, *args: Any) -> None:  # 静音默认访问日志
        return

    # ------------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            body = self._read_json() if method == "POST" else {}
            handler, kwargs = self._route(method, path)
            handler(body, **kwargs)
        except Exception as exc:  # 顶层兜底：业务错误映射为 4xx
            self._send(
                _status_for(exc),
                {"error": type(exc).__name__, "detail": str(exc)},
            )

    def _route(self, method: str, path: str) -> tuple[Callable[..., None], dict[str, str]]:
        s = self.service
        p = path.split("/")

        if method == "GET" and path == "/healthz":
            return lambda body: self._send(200, s.health()), {}

        if method == "POST" and path == "/users":
            return self._register_user, {}
        if method == "POST" and path == "/samples/scan":
            return self._scan, {}
        if method == "POST" and path == "/samples":
            return self._register_sample, {}
        if method == "POST" and path == "/batch-handovers":
            return self._batch_handover, {}
        if method == "POST" and path == "/authorizations":
            return self._grant, {}
        if method == "GET" and path == "/audit":
            return self._audit, {}

        # /samples/{barcode}/...
        if len(p) == 4 and p[:2] == ["", "samples"]:
            bc = p[2]
            sub = p[3]
            table_post = {
                "temperatures": self._temperatures,
                "handover": self._handover,
                "anomalies": self._anomaly,
                "release": self._release,
                "seal": self._replace_seal,
                "split": self._split,
                "retest": self._retest,
                "destroy": self._destroy,
            }
            if method == "POST" and sub in table_post:
                return table_post[sub], {"barcode": bc}
        if method == "GET" and len(p) == 3 and p[:2] == ["", "samples"]:
            return self._status, {"barcode": p[2]}
        if method == "GET" and len(p) == 3 and p[:2] == ["", "batches"]:
            return self._batch_list, {"batch": p[2]}

        raise NotFoundError(f"无此路由: {method} {path}")

    # ------------------------------------------------------------------
    # 端点处理
    # ------------------------------------------------------------------

    def _register_user(self, body: dict[str, Any]) -> None:
        # 引导端点：实际部署中由身份服务提供。
        self.service.register_user(body["user_id"], body["role"], body["key"], body.get("name", ""))
        self._send(201, {"registered": body["user_id"], "role": body["role"]})

    def _scan(self, body: dict[str, Any]) -> None:
        actor = self._actor(body)
        out = self.service.scan(
            actor, body["barcode"], body["batch"], body["athlete"],
            body["seal"], body["collected_at"],
            sample_type=body.get("sample_type", "urine"),
            scan_token=body.get("scan_token"),
        )
        self._send(200 if out.get("deduped") else 201, out)

    def _register_sample(self, body: dict[str, Any]) -> None:
        actor = self._actor(body)
        out = self.service.register_sample(
            actor, body["barcode"], body["batch"], body["athlete"],
            body["seal"], body["collected_at"],
            sample_type=body.get("sample_type", "urine"),
            idem_key=body.get("idem_key"),
        )
        self._send(201, out)

    def _temperatures(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.record_temperatures(
            actor, barcode, body["readings"], idem_key=body.get("idem_key")
        )
        self._send(201, out)

    def _handover(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.handover(
            actor, barcode, body["to_id"], body["at"], body["signature"],
            body["presented_seal"], temperatures=body.get("temperatures"),
            idem_key=body.get("idem_key"),
        )
        self._send(200 if out.get("deduped") else 201, out)

    def _batch_handover(self, body: dict[str, Any]) -> None:
        actor = self._actor(body)
        out = self.service.batch_handover(
            actor, body["items"], idem_prefix=body.get("idem_prefix")
        )
        self._send(200, out)

    def _anomaly(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.report_anomaly(
            actor, barcode, body["kind"], body.get("detail", ""), body["at"],
            quarantine=body.get("quarantine", True), idem_key=body.get("idem_key"),
        )
        self._send(201, out)

    def _release(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.release_quarantine(
            actor, barcode, body["at"], body["note"],
            authorization_no=body.get("authorization_no"),
            idem_key=body.get("idem_key"),
        )
        self._send(200, out)

    def _replace_seal(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.replace_seal(
            actor, barcode, body["new_seal"], body["at"],
            body["authorization_no"], body["witness_id"],
            idem_key=body.get("idem_key"),
        )
        self._send(200, out)

    def _split(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.split_aliquots(
            actor, barcode, body["seal_a"], body["seal_b"], body["at"],
            idem_key=body.get("idem_key"),
        )
        self._send(201, out)

    def _grant(self, body: dict[str, Any]) -> None:
        actor = self._actor(body)
        out = self.service.grant_authorization(
            actor, body["auth_no"], body["barcode"], body["purpose"], body["at"],
            expires_at=body.get("expires_at"), note=body.get("note", ""),
            idem_key=body.get("idem_key"),
        )
        self._send(201, out)

    def _retest(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.retest(
            actor, barcode, body["authorization_no"], body["at"],
            idem_key=body.get("idem_key"),
        )
        self._send(200, out)

    def _destroy(self, body: dict[str, Any], barcode: str) -> None:
        actor = self._actor(body)
        out = self.service.destroy(
            actor, barcode, body["authorization_no"], body["at"],
            idem_key=body.get("idem_key"),
        )
        self._send(200, out)

    def _status(self, body: dict[str, Any], barcode: str) -> None:
        # GET 请求没有体：身份走请求头，密钥用 X-Actor-Key。
        actor = self._actor_from_headers()
        self._send(200, self.service.status(actor, barcode))

    def _batch_list(self, body: dict[str, Any], batch: str) -> None:
        actor = self._actor_from_headers()
        self._send(200, self.service.list_by_batch(actor, batch))

    def _audit(self, body: dict[str, Any]) -> None:
        actor = self._actor_from_headers()
        query = urlparse(self.path).query
        barcode = None
        if query:
            for kv in query.split("&"):
                if kv.startswith("barcode="):
                    barcode = kv.split("=", 1)[1]
        self._send(200, self.service.audit_export(actor, barcode=barcode))


def make_server(host: str, port: int, service: CustodyService) -> ThreadingHTTPServer:
    handler = type("BoundCustodyHTTPHandler", (CustodyHTTPHandler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler)


def serve(host: str = "127.0.0.1", port: int = 8080, logfile: str | None = None) -> None:
    service = CustodyService(logfile)
    httpd = make_server(host, port, service)
    print(f"监管链服务监听 http://{host}:{port}（事件日志: {logfile or '内存'}）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import sys

    serve(logfile=sys.argv[1] if len(sys.argv) > 1 else None)
