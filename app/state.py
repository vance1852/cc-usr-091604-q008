"""事件重放投影：把仅追加日志还原成每个样本的当前监管状态。

投影在每次服务启动时从事件日志重建；状态本身从不持久化、也从不就地修改，
原始事实只存在于事件日志中。投影重建失败（哈希链断裂）会直接阻止服务启动。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Status


@dataclass
class SampleState:
    barcode: str
    kind: str = "primary"                 # primary | aliquot
    batch: str = ""
    athlete: dict[str, Any] = field(default_factory=dict)
    sample_type: str = "urine"
    aliquot_type: str | None = None       # 拆分后为 "A" / "B"
    parent_barcode: str | None = None
    children: dict[str, str] = field(default_factory=dict)  # 条码 -> A/B

    seal: str = ""
    seal_history: list[dict[str, Any]] = field(default_factory=list)

    collected_at: str | None = None
    custodian_id: str | None = None
    custodian_role: str | None = None
    custodian_since: str | None = None
    last_handover_at: str | None = None
    handover_count: int = 0
    last_signature: str | None = None

    status: Status = Status.REGISTERED
    prior_status: Status | None = None    # 隔离前状态，供解除隔离恢复

    temperatures: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)

    def is_terminal(self) -> bool:
        return self.status in (Status.DESTROYED,)


@dataclass
class Authorization:
    auth_no: str
    barcode: str
    purpose: str                          # retest | destroy | seal_replace | release
    issued_at: str
    expires_at: str | None
    issued_by: str
    note: str = ""
    used_at: str | None = None
    used_event_seq: int | None = None

    @property
    def used(self) -> bool:
        return self.used_event_seq is not None


class Projection:
    """从事件流重建的内存状态。"""

    def __init__(self) -> None:
        self.samples: dict[str, SampleState] = {}
        self.authorizations: dict[str, Authorization] = {}
        # 幂等键 -> {"seq": 事件序号, "fp": 请求指纹}
        self.idempotency: dict[str, dict[str, Any]] = {}
        self.users: dict[str, dict[str, Any]] = {}
        self.anomaly_seq = 0

    # ------------------------------------------------------------------

    def get(self, barcode: str) -> SampleState:
        return self.samples[barcode]

    def require(self, barcode: str) -> SampleState:
        from .models import NotFoundError

        state = self.samples.get(barcode)
        if state is None:
            raise NotFoundError(f"未知样本条码: {barcode}")
        return state

    def family(self, barcode: str) -> list[SampleState]:
        """返回样本本身（或父样本）及其所有 A/B 子瓶。"""

        state = self.require(barcode)
        root = self.samples[state.parent_barcode] if state.parent_barcode else state
        out = [root]
        for child_barcode in root.children:
            out.append(self.samples[child_barcode])
        return out

    def open_anomaly_exists(self, barcode: str) -> bool:
        state = self.samples.get(barcode)
        return bool(state is not None and state.status != Status.QUARANTINED
                    and any(not a.get("resolved") for a in state.anomalies))

    # ------------------------------------------------------------------
    # 事件应用（纯函数式更新；事件即事实，不再做业务校验）
    # ------------------------------------------------------------------

    def apply(self, seq: int, payload: dict[str, Any]) -> None:
        idem = payload.get("_idem")
        if idem:
            self.idempotency[idem["key"]] = {"seq": seq, "fp": idem["fp"]}
        etype = payload["type"]
        handler = getattr(self, f"_on_{etype}", None)
        if handler is None:
            raise ValueError(f"未知事件类型: {etype}")
        handler(seq, payload)

    def _on_user_registered(self, seq: int, p: dict[str, Any]) -> None:
        self.users[p["user_id"]] = {
            "id": p["user_id"],
            "role": p["role"],
            "key": p["key"],
            "name": p.get("name", ""),
        }

    def _on_sample_registered(self, seq: int, p: dict[str, Any]) -> None:
        s = SampleState(
            barcode=p["barcode"],
            batch=p["batch"],
            athlete=dict(p["athlete"]),
            sample_type=p.get("sample_type", "urine"),
            seal=p["seal"],
            collected_at=p["collected_at"],
            custodian_id=p["dco_id"],
            custodian_role="dco",
            custodian_since=p["collected_at"],
            status=Status.REGISTERED,
        )
        s.seal_history.append({"seal": p["seal"], "at": p["collected_at"], "reason": "registered"})
        self.samples[p["barcode"]] = s

    def _on_handover(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        for reading in p.get("temperatures", []):
            s.temperatures.append(dict(reading))
        s.custodian_id = p["to_id"]
        s.custodian_role = p["to_role"]
        s.custodian_since = p["at"]
        s.last_handover_at = p["at"]
        s.last_signature = p["signature"]
        s.handover_count += 1
        s.status = Status.IN_TRANSIT if p["to_role"] == "carrier" else Status.AT_LAB

    def _on_temperature_recorded(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        for reading in p["readings"]:
            s.temperatures.append(dict(reading))

    def _on_anomaly_reported(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        s.anomalies.append(
            {
                "report_id": p["report_id"],
                "kind": p["kind"],
                "detail": p.get("detail", ""),
                "reporter_id": p["reporter_id"],
                "reporter_role": p["reporter_role"],
                "at": p["at"],
                "resolved": False,
            }
        )
        # 重放时恢复异常单号计数器，保证重启后单号仍然唯一。
        try:
            report_no = int(p["report_id"].rsplit("-", 1)[-1])
        except (ValueError, IndexError):
            report_no = 0
        self.anomaly_seq = max(self.anomaly_seq, report_no)

    def _on_quarantined(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        s.prior_status = s.status
        s.status = Status.QUARANTINED

    def _on_quarantine_released(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        for anomaly in s.anomalies:
            if not anomaly["resolved"]:
                anomaly["resolved"] = True
                anomaly["resolution"] = p.get("note", "")
        s.status = s.prior_status or Status.AT_LAB
        s.prior_status = None
        if p.get("authorization_no"):
            self._consume_auth(p["authorization_no"], seq, p["at"])

    def _on_seal_replaced(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        s.seal = p["new_seal"]
        s.seal_history.append(
            {
                "seal": p["new_seal"],
                "old_seal": p["old_seal"],
                "at": p["at"],
                "reason": "authorized_replacement",
                "authorization_no": p["authorization_no"],
                "event_seq": seq,
            }
        )
        self._consume_auth(p["authorization_no"], seq, p["at"])

    def _on_sample_split(self, seq: int, p: dict[str, Any]) -> None:
        parent = self.require(p["barcode"])
        parent.status = Status.SPLIT
        for item in p["aliquots"]:
            child = SampleState(
                barcode=item["barcode"],
                kind="aliquot",
                aliquot_type=item["aliquot_type"],
                parent_barcode=parent.barcode,
                batch=parent.batch,
                athlete=dict(parent.athlete),
                sample_type=parent.sample_type,
                seal=item["seal"],
                collected_at=parent.collected_at,
                custodian_id=parent.custodian_id,
                custodian_role=parent.custodian_role,
                custodian_since=p["at"],
                last_handover_at=parent.last_handover_at,
                status=Status.AT_LAB,
            )
            child.seal_history.append(
                {"seal": item["seal"], "at": p["at"], "reason": "split", "parent": parent.barcode}
            )
            parent.children[item["barcode"]] = item["aliquot_type"]
            self.samples[item["barcode"]] = child

    def _on_authorization_granted(self, seq: int, p: dict[str, Any]) -> None:
        self.authorizations[p["auth_no"]] = Authorization(
            auth_no=p["auth_no"],
            barcode=p["barcode"],
            purpose=p["purpose"],
            issued_at=p["at"],
            expires_at=p.get("expires_at"),
            issued_by=p["by_id"],
            note=p.get("note", ""),
        )

    def _on_retested(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        s.status = Status.RETESTED
        self._consume_auth(p["authorization_no"], seq, p["at"])

    def _on_destroyed(self, seq: int, p: dict[str, Any]) -> None:
        s = self.require(p["barcode"])
        s.status = Status.DESTROYED
        self._consume_auth(p["authorization_no"], seq, p["at"])

    def _consume_auth(self, auth_no: str, seq: int, at: str) -> None:
        auth = self.authorizations.get(auth_no)
        if auth is not None:
            auth.used_event_seq = seq
            auth.used_at = at
