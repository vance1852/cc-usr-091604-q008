"""样本监管链核心服务。

职责
----
* 用户与角色管理（采样官 / 运输 / 实验室 / 合规主管）
* 样本登记（运动员身份、批次、封条、采样时间）与扫描录入
* 逐环交接：验证前一环签名、时间窗、封条编号、冷链温度
* 异常申报 -> 自动隔离；隔离期间正常流程全部冻结，原始记录不可修改
* A/B 瓶拆分（父子关系）、授权复检、授权销毁、授权换封条
* 状态查询（非合规角色看到脱敏身份）与合规审计导出

可靠性
------
* 所有事实以事件写入仅追加哈希链日志；重启后重放恢复，状态可完整回放。
* 写操作支持 ``idem_key``：断网重试、同一条码重复扫描不会产生重复事件；
  同一幂等键若携带不同请求体则直接拒绝。
* 所有时间在入口归一化为 UTC，跨时区交接按绝对时刻比较。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .eventstore import EventStore
from .models import (
    DEFAULT_EDGE_WINDOWS,
    NEXT_ROLES,
    TEMP_MAX_C,
    TEMP_MAX_GAP_SECONDS,
    TEMP_MIN_C,
    Actor,
    AnomalyKind,
    Athlete,
    AuthzError,
    AuthorizationRequiredError,
    ColdChainError,
    CustodyError,
    DuplicateBarcodeError,
    IdempotencyConflict,
    NotFoundError,
    QuarantineError,
    Role,
    SealError,
    SignatureError,
    Status,
    TimeWindowError,
    ValidationError,
    canonical_json,
    handover_text,
    mask_athlete,
    to_utc,
    utc_iso,
    verify_signature,
)
from .state import Authorization, Projection, SampleState

# 登记后最晚送达实验室的总时长（兜底时间窗）。
MAX_COLLECTION_TO_LAB = timedelta(hours=72)


class CustodyService:
    """监管链应用服务。一个实例对应一份事件日志。"""

    def __init__(self, store: EventStore | str | Path | None = None) -> None:
        self.store = store if isinstance(store, EventStore) else EventStore(store)
        self.projection = Projection()
        self._replay()

    # ==================================================================
    # 启动 / 重放
    # ==================================================================

    def _replay(self) -> None:
        self.projection = Projection()
        for event in self.store.replay():
            self.projection.apply(event.seq, event.payload)

    def restart(self) -> None:
        """模拟服务重启：重新校验哈希链并从日志完整重放。"""

        self.store.verify_chain()
        self._replay()

    def health(self) -> dict[str, str]:
        return {"service": "custody", "status": "ok"}

    # ==================================================================
    # 内部工具
    # ==================================================================

    def _record(self, payload: dict[str, Any], idem_key: str | None = None,
                fp: str | None = None):
        """追加事件，统一处理幂等。

        返回 ``(event, replayed)``；``replayed=True`` 表示命中幂等键，
        没有写入新事件（断网重试走这条路径）。
        """

        if idem_key is not None:
            if fp is None:
                fp = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            existing = self.projection.idempotency.get(idem_key)
            if existing is not None:
                if existing["fp"] != fp:
                    raise IdempotencyConflict(
                        f"幂等键 {idem_key!r} 已用于不同的请求（拒绝重放被篡改的重试）"
                    )
                return self.store.read_all()[existing["seq"] - 1], True
            payload = dict(payload)
            payload["_idem"] = {"key": idem_key, "fp": fp}
        event = self.store.append(payload)
        self.projection.apply(event.seq, event.payload)
        return event, False

    def _idem_lookup(self, idem_key: str, fp: str):
        """命中幂等键则返回首次事件；指纹冲突则拒绝；未命中返回 None。"""

        existing = self.projection.idempotency.get(idem_key)
        if existing is None:
            return None
        if existing["fp"] != fp:
            raise IdempotencyConflict(
                f"幂等键 {idem_key!r} 已用于不同的请求（拒绝重放被篡改的重试）"
            )
        return self.store.read_all()[existing["seq"] - 1]

    def _idem_hit(self, idem_key: str, fp: str) -> dict[str, Any] | None:
        """业务校验前的幂等命中检查（用于交接等状态会前移的命令）。

        断网重试时，第一次调用可能已经成功、保管人已经变更；
        此时必须返回首次结果，而不是误判为越权。
        """

        event = self._idem_lookup(idem_key, fp)
        if event is None:
            return None
        p = event.payload
        return {
            "barcode": p.get("barcode"),
            "event_seq": event.seq,
            "custodian": p.get("to_id"),
            "status": self.projection.get(p["barcode"]).status.value
            if p.get("barcode") in self.projection.samples else None,
            "deduped": True,
        }

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def _user(self, user_id: str) -> dict[str, Any]:
        user = self.projection.users.get(user_id)
        if user is None:
            raise NotFoundError(f"未知用户: {user_id}")
        return user

    def _authenticate(self, actor: Actor) -> dict[str, Any]:
        user = self._user(actor.id)
        if user["role"] != actor.role.value:
            raise AuthzError(f"用户 {actor.id} 的注册角色与声明角色不一致")
        if user["key"] != actor.key:
            raise AuthzError("身份凭据无效")
        return user

    def _require_role(self, actor: Actor, *roles: Role) -> dict[str, Any]:
        user = self._authenticate(actor)
        if actor.role not in roles:
            raise AuthzError(
                f"角色 {actor.role.value} 无权执行该操作（允许: {', '.join(r.value for r in roles)}）"
            )
        return user

    def _require_custodian(self, actor: Actor, state: SampleState) -> None:
        if state.custodian_id != actor.id:
            raise AuthzError(
                f"样本 {state.barcode} 当前保管人是 {state.custodian_id}，"
                f"{actor.id} 无权发起交接（拒绝越权交接）"
            )

    def _require_not_quarantined(self, state: SampleState) -> None:
        if state.status == Status.QUARANTINED:
            raise QuarantineError(
                f"样本 {state.barcode} 处于隔离状态，正常流程冻结；"
                "须由合规主管申报处置后解除隔离"
            )
        if state.is_terminal():
            raise CustodyError(f"样本 {state.barcode} 已 {state.status.value}，不可再操作")

    def _check_authorization(
        self, auth_no: str, barcode: str, purpose: str, at: datetime
    ) -> Authorization:
        auth = self.projection.authorizations.get(auth_no)
        if auth is None:
            raise AuthorizationRequiredError(f"授权单 {auth_no} 不存在：{purpose} 必须事先取得书面授权")
        if auth.barcode != barcode:
            raise AuthorizationRequiredError(f"授权单 {auth_no} 针对的不是样本 {barcode}")
        if auth.purpose != purpose:
            raise AuthorizationRequiredError(f"授权单用途为 {auth.purpose}，不能用于 {purpose}")
        if auth.used:
            raise AuthorizationRequiredError(f"授权单 {auth_no} 已被事件 {auth.used_event_seq} 使用，不得重复使用")
        if auth.expires_at and at > to_utc(auth.expires_at):
            raise AuthorizationRequiredError(f"授权单 {auth_no} 已过期")
        return auth

    # ==================================================================
    # 用户注册（演示环境；生产应来自身份服务）
    # ==================================================================

    def register_user(self, user_id: str, role: Role | str, key: str, name: str = "") -> None:
        role = role if isinstance(role, Role) else Role(role)
        if not key:
            raise ValidationError("签名密钥不能为空")
        if user_id in self.projection.users:
            raise ValidationError(f"用户 {user_id} 已注册")
        payload = {
            "type": "user_registered",
            "user_id": user_id,
            "role": role.value,
            "key": key,
            "name": name,
        }
        self._record(payload)

    # ==================================================================
    # 样本登记 / 扫描录入
    # ==================================================================

    def register_sample(
        self,
        actor: Actor,
        barcode: str,
        batch: str,
        athlete: Athlete | dict[str, Any],
        seal: str,
        collected_at: datetime | str,
        sample_type: str = "urine",
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """采样官登记一个新采集的样本。"""

        self._require_role(actor, Role.DCO)
        if not barcode:
            raise ValidationError("条码不能为空")
        if not batch:
            raise ValidationError("采样批次不能为空")
        if not seal:
            raise SealError("封条编号不能为空（无封条样本不得入链）")
        at = to_utc(collected_at)
        if barcode in self.projection.samples:
            raise DuplicateBarcodeError(f"条码 {barcode} 已登记：拒绝重复扫描")

        if isinstance(athlete, Athlete):
            athlete_dict = athlete.to_dict()
        else:
            athlete_dict = dict(athlete)
        for field_name in ("name", "id_number"):
            if not athlete_dict.get(field_name):
                raise ValidationError(f"运动员 {field_name} 不能为空")

        payload = {
            "type": "sample_registered",
            "barcode": barcode,
            "batch": batch,
            "athlete": athlete_dict,
            "sample_type": sample_type,
            "seal": seal,
            "collected_at": utc_iso(at),
            "dco_id": actor.id,
        }
        event, replayed = self._record(payload, idem_key=idem_key or f"scan:{barcode}")
        return {"barcode": barcode, "event_seq": event.seq, "deduped": replayed}

    def scan(
        self,
        actor: Actor,
        barcode: str,
        batch: str,
        athlete: Athlete | dict[str, Any],
        seal: str,
        collected_at: datetime | str,
        sample_type: str = "urine",
        scan_token: str | None = None,
    ) -> dict[str, Any]:
        """扫描录入入口。

        * 新条码 -> 登记；
        * 同一条码用同一扫描令牌重复扫描（断网重试/双击）-> 返回既有记录，不产生事件；
        * 同一条码携带不同登记数据 -> 拒绝（防止用重复扫描覆盖原始登记）。
        """

        token = scan_token or f"scan:{barcode}"
        if barcode in self.projection.samples:
            state = self.projection.samples[barcode]
            # 对已存在条码做一次"扫描核对"：封条不符直接走异常语义。
            if seal and state.seal != seal:
                raise SealError(
                    f"扫描封条 {seal} 与登记封条 {state.seal} 不符，不得入链；请申报异常"
                )
            return {"barcode": barcode, "event_seq": 0, "deduped": True, "status": state.status.value}
        return self.register_sample(
            actor, barcode, batch, athlete, seal, collected_at,
            sample_type=sample_type, idem_key=token,
        )

    # ==================================================================
    # 温度
    # ==================================================================

    def _normalize_reading(self, reading: dict[str, Any]) -> dict[str, Any]:
        try:
            value = float(reading["temp_c"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("温度读数必须包含数值型 temp_c") from exc
        at = to_utc(reading["at"])
        return {"temp_c": value, "at": utc_iso(at), "by": reading.get("by", "")}

    def record_temperatures(
        self,
        actor: Actor,
        barcode: str,
        readings: Iterable[dict[str, Any]],
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """运输人员补录冷藏温度（实验室要求的冷链记录）。"""

        self._require_role(actor, Role.CARRIER, Role.LAB)
        state = self.projection.require(barcode)
        # 只有当前保管人能向该样本的证据链写入温度读数。
        self._require_custodian(actor, state)
        normalized = [self._normalize_reading(r) for r in readings]
        if not normalized:
            raise ValidationError("至少需要一条温度读数")
        payload = {
            "type": "temperature_recorded",
            "barcode": barcode,
            "readings": normalized,
            "by_id": actor.id,
        }
        event, replayed = self._record(payload, idem_key=idem_key)
        return {"barcode": barcode, "event_seq": event.seq, "count": len(normalized), "deduped": replayed}

    # ==================================================================
    # 交接
    # ==================================================================

    def handover(
        self,
        actor: Actor,
        barcode: str,
        to_id: str,
        at: datetime | str,
        signature: str,
        presented_seal: str,
        temperatures: Iterable[dict[str, Any]] | None = None,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """当前保管人把样本交给链路中的下一环。

        校验顺序（任何一项不过都拒绝，且不修改任何记录）：
        1. 身份与角色；2. 当前保管人；3. 非隔离/非终态；
        4. 交接方向合法（拒绝越级/反向 -> 越权交接）；
        5. 接收方身份存在且角色匹配；
        6. 时间窗（相对采集/发出时刻，UTC 绝对时刻，跨时区安全）；
        7. 前一环签名 HMAC；8. 封条编号一致且状态完好；
        9. 冷链温度覆盖与区间（交付实验室时强制）。
        """

        user = self._authenticate(actor)
        state = self.projection.require(barcode)
        at_dt = to_utc(at)

        # 幂等指纹只覆盖请求方提供的原始字段（时间/温度先归一化），
        # 使"断网重试"与首次请求的指纹一致。
        idem_key = idem_key or f"handover:{barcode}:{state.handover_count + 1}"
        temp_payload = [self._normalize_reading(r) for r in temperatures] if temperatures else []
        request_fp = self._fingerprint(
            {
                "barcode": barcode,
                "to_id": to_id,
                "at": utc_iso(at_dt),
                "signature": signature,
                "presented_seal": presented_seal,
                "temperatures": temp_payload,
            }
        )
        # 必须在保管人/角色校验之前：首次请求可能已成功并改变了保管人。
        hit = self._idem_hit(idem_key, request_fp)
        if hit is not None:
            return hit

        self._require_custodian(actor, state)
        self._require_not_quarantined(state)

        from_role = actor.role
        allowed = NEXT_ROLES.get(from_role, frozenset())
        to_user = self._user(to_id)
        to_role = Role(to_user["role"])
        if to_role not in allowed:
            raise AuthzError(
                f"不允许 {from_role.value} -> {to_role.value} 的交接（仅允许采样官→运输→实验室）"
            )

        # 时间窗：第一段以采集时刻为基准，其后以上一环交接时刻为基准。
        collected = to_utc(state.collected_at) if state.collected_at else None
        if state.last_handover_at is not None:
            ref = to_utc(state.last_handover_at)
        else:
            ref = collected
        if ref is not None:
            window = DEFAULT_EDGE_WINDOWS[(from_role, to_role)]
            if at_dt < ref:
                raise TimeWindowError("交接时间早于基准环节（时间戳不得倒退）")
            if (at_dt - ref).total_seconds() > window:
                raise TimeWindowError(
                    f"交接超出 {window // 3600} 小时时间窗（耗时 {at_dt - ref}）"
                )
        # 采集 -> 实验室的兜底总窗
        if collected is not None and at_dt - collected > MAX_COLLECTION_TO_LAB:
            raise TimeWindowError("距采样超过 72 小时，样本不得继续流转")

        # 前一环签名：文本绑定 条码/时刻/交出人/接收人
        text = handover_text(barcode, at_dt, actor.id, to_id)
        if not verify_signature(user["key"], text, signature):
            raise SignatureError("交接签名验证失败：前一环签名缺失、被伪造或字段不一致")

        # 封条：编号必须与登记一致（非法封条替换在此被拦截）
        if not presented_seal:
            raise SealError("交接必须当场核对并提交封条编号")
        if presented_seal != state.seal:
            raise SealError(
                f"封条编号不符：登记 {state.seal}，现场 {presented_seal}；"
                "疑似非法封条替换，拒绝交接，请申报异常"
            )

        # 冷链：送达实验室时必须具备覆盖全程的合格温度记录
        if to_role == Role.LAB:
            self._validate_cold_chain(state, temp_payload, collected)

        payload = {
            "type": "handover",
            "barcode": barcode,
            "from_id": actor.id,
            "from_role": from_role.value,
            "to_id": to_id,
            "to_role": to_role.value,
            "at": utc_iso(at_dt),
            "signature": signature,
            "seal": presented_seal,
            "temperatures": temp_payload,
        }
        event, replayed = self._record(payload, idem_key=idem_key, fp=request_fp)
        return {
            "barcode": barcode,
            "event_seq": event.seq,
            "custodian": to_id,
            "status": self.projection.get(barcode).status.value,
            "deduped": replayed,
        }

    def _validate_cold_chain(
        self,
        state: SampleState,
        inbound: list[dict[str, Any]],
        collected: datetime | None,
    ) -> None:
        readings = sorted(state.temperatures + inbound, key=lambda r: r["at"])
        if not readings:
            raise ColdChainError("实验室要求冷藏温度记录：全程无任何读数，拒绝接收")
        for r in readings:
            if not (TEMP_MIN_C <= r["temp_c"] <= TEMP_MAX_C):
                raise ColdChainError(
                    f"温度越界：{r['temp_c']}°C @ {r['at']}（要求 {TEMP_MIN_C}~{TEMP_MAX_C}°C）"
                )
        # 覆盖性：采样时刻到首读数、相邻读数、末读数到……（交付时没有终点时刻，
        # 只要求采样后及时开始记录且读数间隔不超限）。
        if collected is not None:
            first = to_utc(readings[0]["at"])
            if (first - collected).total_seconds() > TEMP_MAX_GAP_SECONDS:
                raise ColdChainError("采样后缺少及时的冷藏温度记录（开头断链）")
        for prev, nxt in zip(readings, readings[1:]):
            gap = (to_utc(nxt["at"]) - to_utc(prev["at"])).total_seconds()
            if gap > TEMP_MAX_GAP_SECONDS:
                raise ColdChainError(
                    f"冷藏记录在 {prev['at']} ~ {nxt['at']} 之间断档 {int(gap // 60)} 分钟"
                )

    def batch_handover(
        self,
        actor: Actor,
        items: Iterable[dict[str, Any]],
        idem_prefix: str | None = None,
    ) -> dict[str, Any]:
        """批量交接：逐项执行；单项失败不影响其他样本，失败项原样回报。

        每个 item 同 :meth:`handover` 的参数。断网重试可复用 idem_prefix。
        """

        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for i, item in enumerate(items):
            barcode = item.get("barcode", f"#{i}")
            try:
                result = self.handover(
                    actor,
                    barcode=item["barcode"],
                    to_id=item["to_id"],
                    at=item["at"],
                    signature=item["signature"],
                    presented_seal=item["presented_seal"],
                    temperatures=item.get("temperatures"),
                    idem_key=item.get("idem_key")
                    or (f"{idem_prefix}:{barcode}" if idem_prefix else None),
                )
                accepted.append(result)
            except CustodyError as exc:
                rejected.append({"barcode": barcode, "error": type(exc).__name__, "detail": str(exc)})
        return {"accepted": accepted, "rejected": rejected}

    # ==================================================================
    # 异常与隔离（唯一允许的"纠错"路径；原始事件永不修改）
    # ==================================================================

    def report_anomaly(
        self,
        actor: Actor,
        barcode: str,
        kind: AnomalyKind | str,
        detail: str,
        at: datetime | str,
        quarantine: bool = True,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """任何链上角色都可申报异常；默认同时把样本（及同批 A/B 瓶）隔离。"""

        self._authenticate(actor)
        kind = kind if isinstance(kind, AnomalyKind) else AnomalyKind(kind)
        state = self.projection.require(barcode)
        if state.is_terminal():
            raise CustodyError(f"样本 {barcode} 已 {state.status.value}，不可申报异常")
        at_dt = to_utc(at)

        # 单号由服务端生成，因此幂等指纹不含单号：
        # 断网重试必须回放首次申报，而不是生成第二个单号后指纹冲突。
        if idem_key:
            fp = self._fingerprint(
                {
                    "barcode": barcode,
                    "kind": kind.value,
                    "detail": detail,
                    "reporter_id": actor.id,
                    "reporter_role": actor.role.value,
                    "at": utc_iso(at_dt),
                    "quarantine": bool(quarantine),
                }
            )
            prior = self._idem_lookup(idem_key, fp)
            if prior is not None:
                rid = prior.payload["report_id"]
                quarantined = [
                    e.payload["barcode"]
                    for e in self.store.read_all()[prior.seq:]
                    if e.payload.get("type") == "quarantined"
                    and e.payload.get("report_id") == rid
                ]
                return {"report_id": rid, "quarantined": quarantined, "deduped": True}

        self.projection.anomaly_seq += 1
        report_id = f"ANM-{self.projection.anomaly_seq:06d}"
        payload = {
            "type": "anomaly_reported",
            "report_id": report_id,
            "barcode": barcode,
            "kind": kind.value,
            "detail": detail,
            "reporter_id": actor.id,
            "reporter_role": actor.role.value,
            "at": utc_iso(at_dt),
        }
        self._record(payload, idem_key=idem_key, fp=fp if idem_key else None)

        quarantined: list[str] = []
        if quarantine and state.status != Status.QUARANTINED:
            quarantined = self._quarantine_family(barcode, report_id, at_dt)
        return {"report_id": report_id, "quarantined": quarantined}

    def _quarantine_family(self, barcode: str, report_id: str, at: datetime) -> list[str]:
        targets = [s.barcode for s in self.projection.family(barcode)]
        for bc in targets:
            s = self.projection.require(bc)
            if s.status == Status.QUARANTINED or s.is_terminal():
                continue
            payload = {
                "type": "quarantined",
                "barcode": bc,
                "report_id": report_id,
                "at": utc_iso(at),
            }
            self._record(payload)
        return [bc for bc in targets if self.projection.require(bc).status == Status.QUARANTINED]

    def release_quarantine(
        self,
        actor: Actor,
        barcode: str,
        at: datetime | str,
        note: str,
        authorization_no: str | None = None,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """合规主管解除隔离。处置结论必须书面记录在 note 中。"""

        self._require_role(actor, Role.COMPLIANCE)
        state = self.projection.require(barcode)
        if state.status != Status.QUARANTINED:
            raise QuarantineError(f"样本 {barcode} 当前不在隔离中")
        at_dt = to_utc(at)
        if not note or len(note.strip()) < 4:
            raise ValidationError("解除隔离必须记录处置结论（授权依据）")
        if authorization_no:
            self._check_authorization(authorization_no, barcode, "release", at_dt)
        restored = state.prior_status or Status.AT_LAB
        payload = {
            "type": "quarantine_released",
            "barcode": barcode,
            "at": utc_iso(at_dt),
            "note": note,
            "by_id": actor.id,
            "authorization_no": authorization_no,
        }
        event, _ = self._record(payload, idem_key=idem_key)
        return {"barcode": barcode, "event_seq": event.seq, "status": restored.value}

    # ==================================================================
    # 封条更换（仅异常处置：授权 + 双人见证，留痕在 seal_history）
    # ==================================================================

    def replace_seal(
        self,
        actor: Actor,
        barcode: str,
        new_seal: str,
        at: datetime | str,
        authorization_no: str,
        witness_id: str,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """合规主管凭授权在隔离状态下更换封条；正常流转中一律禁止。"""

        self._require_role(actor, Role.COMPLIANCE)
        state = self.projection.require(barcode)
        at_dt = to_utc(at)
        if state.status != Status.QUARANTINED:
            raise QuarantineError(
                "只有隔离流程中才允许更换封条；正常流转时封条编号必须与登记一致"
            )
        if not new_seal or new_seal == state.seal:
            raise ValidationError("新封条编号不能为空且不能与旧封条相同")
        witness = self._user(witness_id)
        if witness["id"] == actor.id:
            raise AuthzError("换封条必须由另一人见证（不能自证自见）")
        self._check_authorization(authorization_no, barcode, "seal_replace", at_dt)

        old_seal = state.seal
        payload = {
            "type": "seal_replaced",
            "barcode": barcode,
            "old_seal": old_seal,
            "new_seal": new_seal,
            "at": utc_iso(at_dt),
            "authorization_no": authorization_no,
            "by_id": actor.id,
            "witness_id": witness_id,
        }
        event, _ = self._record(payload, idem_key=idem_key)
        return {"barcode": barcode, "event_seq": event.seq, "seal": new_seal, "old_seal": old_seal}

    # ==================================================================
    # A/B 瓶拆分（实验室；保持父子关系）
    # ==================================================================

    def split_aliquots(
        self,
        actor: Actor,
        barcode: str,
        seal_a: str,
        seal_b: str,
        at: datetime | str,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """实验室把样本拆为 A 瓶（检测）与 B 瓶（复检留存）。"""

        self._require_role(actor, Role.LAB)
        parent = self.projection.require(barcode)
        at_dt = to_utc(at)
        self._require_custodian(actor, parent)
        self._require_not_quarantined(parent)
        if parent.kind != "primary":
            raise ValidationError("只有原始样本可以拆分")
        if parent.children:
            raise ValidationError(f"样本 {barcode} 已拆分，父子关系不可更改")
        if not seal_a or not seal_b or seal_a == seal_b:
            raise SealError("A/B 瓶封条编号必须齐全且互不相同")

        child_a = f"{barcode}-A"
        child_b = f"{barcode}-B"
        for bc in (child_a, child_b):
            if bc in self.projection.samples:
                raise DuplicateBarcodeError(f"子瓶条码 {bc} 已存在")
        payload = {
            "type": "sample_split",
            "barcode": barcode,
            "at": utc_iso(at_dt),
            "by_id": actor.id,
            "aliquots": [
                {"barcode": child_a, "aliquot_type": "A", "seal": seal_a},
                {"barcode": child_b, "aliquot_type": "B", "seal": seal_b},
            ],
        }
        event, _ = self._record(payload, idem_key=idem_key or f"split:{barcode}")
        return {
            "parent": barcode,
            "children": {"A": child_a, "B": child_b},
            "event_seq": event.seq,
        }

    # ==================================================================
    # 授权：复检 / 销毁（合规主管签发，一次性使用）
    # ==================================================================

    def grant_authorization(
        self,
        actor: Actor,
        auth_no: str,
        barcode: str,
        purpose: str,
        at: datetime | str,
        expires_at: datetime | str | None = None,
        note: str = "",
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        self._require_role(actor, Role.COMPLIANCE)
        if purpose not in {"retest", "destroy", "seal_replace", "release"}:
            raise ValidationError("授权用途必须是 retest/destroy/seal_replace/release")
        self.projection.require(barcode)
        if auth_no in self.projection.authorizations:
            raise ValidationError(f"授权单 {auth_no} 已存在")
        at_dt = to_utc(at)
        exp_dt = to_utc(expires_at) if expires_at else None
        if exp_dt and exp_dt <= at_dt:
            raise ValidationError("授权到期时间必须晚于签发时间")
        payload = {
            "type": "authorization_granted",
            "auth_no": auth_no,
            "barcode": barcode,
            "purpose": purpose,
            "at": utc_iso(at_dt),
            "expires_at": utc_iso(exp_dt) if exp_dt else None,
            "by_id": actor.id,
            "note": note,
        }
        event, _ = self._record(payload, idem_key=idem_key)
        return {"auth_no": auth_no, "event_seq": event.seq}

    def retest(
        self,
        actor: Actor,
        barcode: str,
        authorization_no: str,
        at: datetime | str,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """实验室对 B 瓶复检；必须出示合规主管授权单。"""

        self._require_role(actor, Role.LAB)
        state = self.projection.require(barcode)
        at_dt = to_utc(at)
        self._require_custodian(actor, state)
        self._require_not_quarantined(state)
        if state.aliquot_type != "B":
            raise ValidationError(f"复检只能在 B 瓶上执行（{barcode} 不是 B 瓶）")
        self._check_authorization(authorization_no, barcode, "retest", at_dt)
        payload = {
            "type": "retested",
            "barcode": barcode,
            "authorization_no": authorization_no,
            "at": utc_iso(at_dt),
            "by_id": actor.id,
        }
        event, _ = self._record(payload, idem_key=idem_key)
        return {"barcode": barcode, "event_seq": event.seq, "status": Status.RETESTED.value}

    def destroy(
        self,
        actor: Actor,
        barcode: str,
        authorization_no: str,
        at: datetime | str,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        """销毁样本；必须出示合规主管授权单，授权单一次性核销。"""

        self._require_role(actor, Role.LAB, Role.COMPLIANCE)
        state = self.projection.require(barcode)
        at_dt = to_utc(at)
        self._require_not_quarantined(state)
        self._check_authorization(authorization_no, barcode, "destroy", at_dt)
        payload = {
            "type": "destroyed",
            "barcode": barcode,
            "authorization_no": authorization_no,
            "at": utc_iso(at_dt),
            "by_id": actor.id,
        }
        event, _ = self._record(payload, idem_key=idem_key)
        return {"barcode": barcode, "event_seq": event.seq, "status": Status.DESTROYED.value}

    # ==================================================================
    # 查询（按角色脱敏）
    # ==================================================================

    def status(self, actor: Actor, barcode: str) -> dict[str, Any]:
        self._authenticate(actor)
        state = self.projection.require(barcode)
        return self._state_view(state, actor.role)

    def list_by_batch(self, actor: Actor, batch: str) -> list[dict[str, Any]]:
        self._authenticate(actor)
        out = [
            self._state_view(s, actor.role)
            for s in self.projection.samples.values()
            if s.kind == "primary" and s.batch == batch
        ]
        out.sort(key=lambda v: v["barcode"])
        return out

    def _state_view(self, state: SampleState, role: Role) -> dict[str, Any]:
        athlete = dict(state.athlete)
        if role != Role.COMPLIANCE:
            athlete = mask_athlete(athlete)
        return {
            "barcode": state.barcode,
            "kind": state.kind,
            "batch": state.batch,
            "athlete": athlete,
            "sample_type": state.sample_type,
            "aliquot_type": state.aliquot_type,
            "parent_barcode": state.parent_barcode,
            "children": dict(state.children),
            "seal": state.seal,
            "collected_at": state.collected_at,
            "custodian": state.custodian_id,
            "custodian_role": state.custodian_role,
            "custodian_since": state.custodian_since,
            "status": state.status.value,
            "handover_count": state.handover_count,
            "open_anomalies": [a["report_id"] for a in state.anomalies if not a["resolved"]],
            "temperature_count": len(state.temperatures),
        }

    # ==================================================================
    # 审计导出（仅合规主管）
    # ==================================================================

    def audit_export(self, actor: Actor, barcode: str | None = None) -> dict[str, Any]:
        """导出一条样本（含其 A/B 子瓶）或全部样本的完整事件轨迹；先校验哈希链。"""

        self._require_role(actor, Role.COMPLIANCE)
        self.store.verify_chain()
        family: set[str] | None = None
        if barcode is not None:
            family = {s.barcode for s in self.projection.family(barcode)}
        events = []
        for e in self.store.read_all():
            if family is None or e.payload.get("barcode") in family:
                events.append(
                    {
                        "seq": e.seq,
                        "ts": e.ts,
                        "payload": e.payload,
                        "prev_hash": e.prev_hash,
                        "hash": e.hash,
                    }
                )
        return {
            "head_hash": self.store.head_hash,
            "event_count": len(events),
            "verified": True,
            "events": events,
        }

    def verify_integrity(self) -> None:
        """对外暴露的完整性校验入口（任何角色都可触发，但不返回数据）。"""

        self.store.verify_chain()
