"""HTTP 接口层的集成测试：真实起服务、真实发 HTTP 请求。"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.api import make_server
from app.service import CustodyService

T0 = datetime(2026, 9, 18, 18, 0, tzinfo=timezone(timedelta(hours=8)))


def t(hours: float) -> str:
    return (T0 + timedelta(hours=hours)).isoformat()


class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "custody.jsonl"
        self.service = CustodyService(str(self.path))
        self.server = make_server("127.0.0.1", 0, self.service)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"
        for uid, role, key in [
            ("dco-1", "dco", "key-dco"),
            ("car-1", "carrier", "key-car"),
            ("lab-1", "lab", "key-lab"),
            ("comp-1", "compliance", "key-comp"),
        ]:
            self.call("POST", "/users",
                      {"user_id": uid, "role": role, "key": key, "name": uid})

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    # ------------------------------------------------------------------

    def call(self, method: str, path: str, body: dict | None = None,
             actor: tuple[str, str, str] | None = None):
        url = self.base + path
        data = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if actor:
            headers["X-Actor-Id"] = actor[0]
            headers["X-Actor-Role"] = actor[1]
            if actor[2]:
                headers["X-Actor-Key"] = actor[2]
        req = urllib.request.Request(url, data=data if method == "POST" else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def sign(self, key: str, barcode: str, at: str, to_id: str) -> str:
        import hmac
        import hashlib
        from datetime import datetime

        # 与服务端一致：先归一化为 UTC 再参与签名（跨时区安全）
        at_utc = datetime.fromisoformat(at).astimezone(timezone.utc).isoformat()
        from_id = {"key-dco": "dco-1", "key-car": "car-1"}[key]
        text = "|".join(["HANDOVER", barcode, at_utc, from_id, to_id])
        return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------

    def test_full_flow_over_http(self):
        athlete = {"name": "李四", "id_number": "310101200002023456",
                   "nationality": "CHN", "sport": "swimming"}
        dco = ("dco-1", "dco", "key-dco")
        car = ("car-1", "carrier", "key-car")
        lab = ("lab-1", "lab", "key-lab")
        comp = ("comp-1", "compliance", "key-comp")

        st, body = self.call("POST", "/samples", {
            "barcode": "S-001", "batch": "B1", "athlete": athlete,
            "seal": "SEAL-1", "collected_at": t(0), "key": "key-dco",
        }, dco)
        self.assertEqual(st, 201, body)

        # 重复扫描 -> 200 幂等
        st, body = self.call("POST", "/samples/scan", {
            "barcode": "S-001", "batch": "B1", "athlete": athlete,
            "seal": "SEAL-1", "collected_at": t(0), "key": "key-dco",
        }, dco)
        self.assertEqual(st, 200)
        self.assertTrue(body["deduped"])

        # 越权交接：运输员不是当前保管人 -> 403
        st, body = self.call("POST", "/samples/S-001/handover", {
            "to_id": "lab-1", "at": t(0.5),
            "signature": "x", "presented_seal": "SEAL-1", "key": "key-car",
        }, car)
        self.assertEqual(st, 403, body)

        # 非法封条替换式交接 -> 422
        st, body = self.call("POST", "/samples/S-001/handover", {
            "to_id": "car-1", "at": t(0.5),
            "signature": self.sign("key-dco", "S-001", t(0.5), "car-1"),
            "presented_seal": "SEAL-FORGED", "key": "key-dco",
        }, dco)
        self.assertEqual(st, 422)
        self.assertEqual(body["error"], "SealError")

        # 正常：采样官 -> 运输
        st, body = self.call("POST", "/samples/S-001/handover", {
            "to_id": "car-1", "at": t(0.5),
            "signature": self.sign("key-dco", "S-001", t(0.5), "car-1"),
            "presented_seal": "SEAL-1", "key": "key-dco",
        }, dco)
        self.assertEqual(st, 201, body)

        # 运输 -> 实验室，附温度
        temps = [{"at": t(h), "temp_c": 6.0} for h in (1, 2.5, 4, 5.5)]
        st, body = self.call("POST", "/samples/S-001/handover", {
            "to_id": "lab-1", "at": t(6),
            "signature": self.sign("key-car", "S-001", t(6), "lab-1"),
            "presented_seal": "SEAL-1", "temperatures": temps, "key": "key-car",
        }, car)
        self.assertEqual(st, 201, body)

        # 查询脱敏（实验室看不到明文证件号）
        st, body = self.call("GET", "/samples/S-001", actor=lab)
        self.assertEqual(st, 200)
        self.assertTrue(body["athlete"]["masked"])
        self.assertNotIn("310101", body["athlete"]["id_number"])

        # 合规角色看明文
        st, body = self.call("GET", "/samples/S-001", actor=comp)
        self.assertEqual(body["athlete"]["name"], "李四")

        # 审计导出仅合规主管
        st, body = self.call("GET", "/audit?barcode=S-001", actor=lab)
        self.assertEqual(st, 403)
        st, body = self.call("GET", "/audit?barcode=S-001", actor=comp)
        self.assertEqual(st, 200)
        self.assertTrue(body["verified"])
        self.assertGreaterEqual(body["event_count"], 3)

        # 缺身份头 -> 403
        st, _ = self.call("GET", "/samples/S-001")
        self.assertEqual(st, 403)

    def test_restart_with_same_logfile_keeps_chain(self):
        dco = ("dco-1", "dco", "key-dco")
        comp = ("comp-1", "compliance", "key-comp")

        # 重启前先产生事实
        st, _ = self.call("POST", "/samples", {
            "barcode": "S-900", "batch": "B9",
            "athlete": {"name": "王五", "id_number": "320101199003034567"},
            "seal": "SEAL-9", "collected_at": t(0), "key": "key-dco",
        }, dco)
        self.assertEqual(st, 201)

        # 用同一个日志文件重新构造服务（模拟进程重启）
        self.server.shutdown()
        self.server.server_close()
        revived = CustodyService(str(self.path))
        self.server = make_server("127.0.0.1", 0, revived)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        st, _ = self.call("GET", "/healthz")
        self.assertEqual(st, 200)
        # 历史事件与用户均从日志重放恢复，且哈希链校验通过
        st, body = self.call("GET", "/samples/S-900", actor=comp)
        self.assertEqual(st, 200, body)
        self.assertEqual(body["seal"], "SEAL-9")
        st, body = self.call("GET", "/audit?barcode=S-900", actor=comp)
        self.assertEqual(st, 200)
        self.assertTrue(body["verified"])
        # 仅样本自身事件计入家族过滤（用户注册等无条码事件不计）
        self.assertEqual(body["event_count"], 1)
        self.assertEqual(body["events"][0]["payload"]["type"], "sample_registered")


if __name__ == "__main__":
    unittest.main()
