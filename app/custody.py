"""样本监管链服务（Chain of Custody）。

核心性质：

- **只追加**：所有业务动作都是事件，落库后不可修改；异常通过隔离
  流程处理，原始记录保持原样。
- **哈希链 + 签名**：每个事件链接前一事件哈希，并由操作人个人密钥
  签名；每次交接都会验证前一环签名。
- **幂等**：扫描录入按条码去重，其余写操作支持幂等键 —— 断网重试、
  重复扫码不会产生重复记录。所有写方法都先做幂等检查、再做状态校验，
  因此成功后的重试永远返回首次的结果。
- **跨时区**：所有时间戳强制携带时区并统一为 UTC 存储与比较。
- **脱敏**：身份敏感信息按角色脱敏，实验室只能看到假名编号。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from .crypto import (
    ZERO_HASH,
    canonical_json,
    event_hash,
    iso_utc,
    new_secret,
    pseudonym,
    sha256_hex,
    sign,
    to_utc,
    verify_signature,
)
from .errors import (
    ChainIntegrityError,
    Conflict,
    InvalidState,
    NotFound,
    PermissionDenied,
    SealMismatch,
    TimeWindowViolation,
    ValidationError,
)
from .models import (
    ALLOWED_HANDOVERS,
    AnomalyType,
    EventType,
    QuarantineResolution,
    Role,
    SampleStatus,
)
from .store import EventStore

#: 可以看到完整运动员身份的角色
_FULL_IDENTITY_ROLES = {Role.COMPLIANCE_OFFICER, Role.SAMPLING_OFFICER}

#: 允许申报异常的角色（链上所有角色）
_CHAIN_ROLES = set(Role)

#: 允许交出的状态
_DISPATCHABLE = {SampleStatus.SEALED.value, SampleStatus.IN_CUSTODY.value}


class ChainOfCustodyService:
    """赛事反兴奋剂样本监管链服务。

    参数:
        db_path: SQLite 文件路径（``":memory:"`` 仅用于测试）。
        clock: 可注入的时钟，返回带时区的 ``datetime``，便于测试。
        max_transfer_window: 发运到签收允许的最大时间窗。
        temperature_range: 冷链允许的摄氏温度区间 (min, max)。
        max_future_skew: 事件时间允许超前当前时钟的最大偏移。
        verify_on_open: 打开数据库时校验整条事件链（默认开启，防篡改）。
    """

    def __init__(
        self,
        db_path: str,
        *,
        clock=None,
        max_transfer_window: timedelta = timedelta(hours=36),
        temperature_range: tuple[float, float] = (2.0, 8.0),
        max_future_skew: timedelta = timedelta(minutes=5),
        verify_on_open: bool = True,
    ):
        self.store = EventStore(db_path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_transfer_window = max_transfer_window
        self._temp_min, self._temp_max = temperature_range
        self._max_future_skew = max_future_skew
        if verify_on_open and self.store.count_events() > 0:
            self.verify_chain()

    def close(self) -> None:
        self.store.close()

    # ==================================================================
    # 登记：人员 / 运动员 / 批次
    # ==================================================================
    def enroll_custodian(self, actor_id: str, name: str, role: Role | str) -> dict:
        """登记链上参与人并签发个人密钥（可信开通步骤，密钥只返回一次）。"""
        role = Role(role)
        if self.store.get_custodian(actor_id):
            raise Conflict(f"参与人 {actor_id!r} 已登记")
        secret = new_secret()
        now = iso_utc(self._clock())
        with self.store.transaction():
            self.store.add_custodian(actor_id, name, role.value, secret, now)
            actor = {"actor_id": actor_id, "name": name, "role": role.value, "secret": secret}
            self._append_event(
                actor=actor,
                event_type=EventType.CUSTODIAN_ENROLLED,
                sample_id=None,
                occurred_at=now,
                payload={"actor_id": actor_id, "name": name, "role": role.value},
                idempotency_key=f"enroll:{actor_id}",
                fingerprint=sha256_hex(f"enroll:{actor_id}"),
            )
        return {"actor_id": actor_id, "name": name, "role": role.value, "secret": secret}

    def register_athlete(self, actor_id: str, athlete_id: str, name: str,
                         *, team: str | None = None, id_number: str | None = None,
                         at: datetime | str | None = None) -> dict:
        """登记运动员身份（采样官或合规主管）。"""
        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.SAMPLING_OFFICER, Role.COMPLIANCE_OFFICER})
        occurred = iso_utc(at) if at is not None else iso_utc(self._clock())
        with self.store.transaction():
            self.store.upsert_athlete(athlete_id, name, team, id_number, occurred)
            self._append_event(
                actor=actor,
                event_type=EventType.ATHLETE_REGISTERED,
                sample_id=None,
                occurred_at=occurred,
                payload={
                    "athlete_id": athlete_id,
                    "athlete": {"name": name, "team": team, "id_number": id_number},
                },
                idempotency_key=f"athlete:{athlete_id}",
                fingerprint=sha256_hex(f"athlete:{athlete_id}"),
            )
        return {"athlete_id": athlete_id, "name": name, "team": team, "id_number": id_number}

    def create_batch(self, actor_id: str, batch_id: str, *, description: str | None = None,
                     at: datetime | str | None = None) -> dict:
        """创建采样批次。"""
        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.SAMPLING_OFFICER, Role.COMPLIANCE_OFFICER})
        if self.store.get_batch(batch_id):
            raise Conflict(f"批次 {batch_id!r} 已存在")
        occurred = iso_utc(at) if at is not None else iso_utc(self._clock())
        with self.store.transaction():
            self.store.add_batch(batch_id, description, actor_id, occurred)
            self._append_event(
                actor=actor,
                event_type=EventType.BATCH_CREATED,
                sample_id=None,
                occurred_at=occurred,
                payload={"batch_id": batch_id, "description": description},
                idempotency_key=f"batch:{batch_id}",
                fingerprint=sha256_hex(f"batch:{batch_id}"),
            )
        return {"batch_id": batch_id, "description": description}

    # ==================================================================
    # 扫描录入
    # ==================================================================
    def scan_intake(self, actor_id: str, barcode: str, *, batch_id: str,
                    athlete: dict, seal_number: str, collected_at: datetime | str,
                    idempotency_key: str | None = None) -> dict:
        """扫描录入：登记样本并加封。

        同一条码重复扫描是幂等的 —— 返回已存在的样本，不产生重复事件；
        若同一条码携带不同内容再次扫描，则报冲突。
        """
        if not barcode:
            raise ValidationError("条码不能为空")
        if not seal_number:
            raise ValidationError("封条编号不能为空")
        athlete_id = athlete.get("athlete_id")
        if not athlete_id or not athlete.get("name"):
            raise ValidationError("运动员信息缺少 athlete_id 或 name")
        collected = to_utc(collected_at)

        sample_id = "SMP-" + sha256_hex(barcode)[:24]
        key = idempotency_key or f"scan:{barcode}"
        fingerprint = sha256_hex(canonical_json({
            "barcode": barcode, "batch_id": batch_id,
            "athlete_id": athlete_id, "seal_number": seal_number,
        }))
        if self._check_idempotency(key, fingerprint) is not None:
            return self.get_sample(sample_id, as_role=self._require_actor(actor_id)["role"])

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.SAMPLING_OFFICER})
        if not self.store.get_batch(batch_id):
            raise NotFound(f"批次 {batch_id!r} 不存在")
        self._validate_event_time(None, collected)

        occurred = iso_utc(collected)
        with self.store.transaction():
            self.store.upsert_athlete(
                athlete_id, athlete["name"], athlete.get("team"),
                athlete.get("id_number"), occurred,
            )
            self._append_event(
                actor=actor,
                event_type=EventType.SAMPLE_REGISTERED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "barcode": barcode,
                    "batch_id": batch_id,
                    "athlete_id": athlete_id,
                    "athlete": {
                        "name": athlete["name"],
                        "team": athlete.get("team"),
                        "id_number": athlete.get("id_number"),
                    },
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            seal_ev = self._append_event(
                actor=actor,
                event_type=EventType.SAMPLE_SEALED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={"seal_number": seal_number, "collected_at": occurred},
                idempotency_key=f"{key}:seal",
                fingerprint=fingerprint,
            )
            self.store.insert_sample({
                "sample_id": sample_id,
                "barcode": barcode,
                "batch_id": batch_id,
                "athlete_id": athlete_id,
                "parent_id": None,
                "bottle": None,
                "status": SampleStatus.SEALED.value,
                "seal_number": seal_number,
                "current_custodian": actor_id,
                "last_event_id": seal_ev["event_id"],
                "last_event_at": occurred,
                "created_at": occurred,
            })
        return self.get_sample(sample_id, as_role=actor["role"])

    # ==================================================================
    # 温度记录（冷链）
    # ==================================================================
    def record_temperature(self, actor_id: str, sample_id: str, celsius: float,
                           *, recorded_at: datetime | str,
                           idempotency_key: str | None = None) -> dict:
        """记录冷链温度。越限时自动申报异常并进入隔离流程。"""
        at_utc = to_utc(recorded_at)
        key = idempotency_key or f"temp:{sample_id}:{uuid.uuid4().hex}"
        fingerprint = sha256_hex(canonical_json({
            "sample_id": sample_id, "celsius": float(celsius), "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return {"temperature_event": self._event_view(existing),
                    "quarantine_event": self._quarantine_replay(key)}

        actor = self._require_actor(actor_id)
        sample = self._require_sample(sample_id)
        if sample["status"] in (SampleStatus.SPLIT.value, SampleStatus.DESTROYED.value):
            raise InvalidState(f"样本状态 {sample['status']} 不允许记录温度")
        if not self._is_current_holder(actor_id, sample):
            raise PermissionDenied("只有当前保管人（或运输中的指定接收方）可以记录温度")
        self._validate_event_time(sample, at_utc)

        occurred = iso_utc(at_utc)
        in_range = self._temp_min <= float(celsius) <= self._temp_max
        with self.store.transaction():
            temp_ev = self._append_event(
                actor=actor,
                event_type=EventType.TEMPERATURE_RECORDED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "celsius": float(celsius),
                    "allowed_range": [self._temp_min, self._temp_max],
                    "in_range": in_range,
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            quarantine_ev = None
            if not in_range:
                quarantine_ev = self._auto_quarantine(
                    actor=actor, sample=sample, occurred_at=occurred,
                    anomaly_type=AnomalyType.TEMPERATURE_EXCURSION,
                    details=(
                        f"冷链温度 {celsius}°C 超出允许区间 "
                        f"[{self._temp_min}, {self._temp_max}]°C"
                    ),
                    idempotency_key=f"{key}:excursion",
                )
            else:
                self.store.update_sample_state(
                    sample_id, last_event_id=temp_ev["event_id"], last_event_at=occurred,
                )
        return {
            "temperature_event": self._event_view(temp_ev),
            "quarantine_event": self._event_view(quarantine_ev) if quarantine_ev else None,
        }

    # ==================================================================
    # 交接（单个 / 批量）
    # ==================================================================
    def transfer_out(self, actor_id: str, sample_id: str, to_actor_id: str,
                     *, seal_number: str, at: datetime | str,
                     idempotency_key: str | None = None) -> dict:
        """交出方发运：校验保管人身份、角色路径与封条。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "out", "sample_id": sample_id, "to": to_actor_id,
            "seal": seal_number, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        receiver = self._require_actor(to_actor_id)
        sample = self._require_sample(sample_id)
        self._check_transfer_out(actor, sample, receiver, at_utc)

        occurred = iso_utc(at_utc)
        if seal_number != sample["seal_number"]:
            quarantine_ev = self._quarantine_for_seal_mismatch(
                actor, sample, occurred, key,
                direction="交出", presented=seal_number,
            )
            raise SealMismatch(
                f"封条编号不符（登记 {sample['seal_number']}，出示 {seal_number}），"
                f"样本已进入隔离流程",
                quarantine_event_id=quarantine_ev["event_id"],
            )

        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.TRANSFER_OUT,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "to_actor_id": to_actor_id,
                    "to_role": receiver["role"],
                    "seal_number": seal_number,
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.IN_TRANSIT.value,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    def transfer_in(self, actor_id: str, sample_id: str, dispatch_event_id: str,
                    *, seal_number: str, at: datetime | str,
                    idempotency_key: str | None = None) -> dict:
        """接收方签收：验证前一环签名、时间窗与封条状态。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "in", "sample_id": sample_id, "dispatch": dispatch_event_id,
            "seal": seal_number, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        sample = self._require_sample(sample_id)
        dispatch = self._check_transfer_in(actor, sample, dispatch_event_id, at_utc)

        occurred = iso_utc(at_utc)
        if seal_number != sample["seal_number"]:
            # 封条不符：自动进入隔离流程，样本由现场接收方控制，等待合规裁决
            quarantine_ev = self._quarantine_for_seal_mismatch(
                actor, sample, occurred, key,
                direction="签收", presented=seal_number,
                take_custody=True, dispatch_event_id=dispatch_event_id,
            )
            raise SealMismatch(
                f"封条编号不符（登记 {sample['seal_number']}，出示 {seal_number}），"
                f"样本已进入隔离流程",
                quarantine_event_id=quarantine_ev["event_id"],
            )

        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.TRANSFER_IN,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "dispatch_event_id": dispatch_event_id,
                    "from_actor_id": dispatch["actor_id"],
                    "seal_number": seal_number,
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.IN_CUSTODY.value, custodian=actor_id,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    def batch_transfer_out(self, actor_id: str, items: list[dict], to_actor_id: str,
                           *, at: datetime | str, idempotency_key: str) -> list[dict]:
        """批量交出：先整体预检，再逐条追加事件。

        ``items``: ``[{"sample_id": ..., "seal_number": ...}, ...]``。
        预检发现越权 / 状态非法时整批拒绝、不产生任何事件；发现封条不符时
        仅将涉事样本隔离并抛错。每项使用派生幂等键，重试安全。
        """
        if not items:
            raise ValidationError("批量交接不能为空")
        actor = self._require_actor(actor_id)
        receiver = self._require_actor(to_actor_id)
        at_utc = to_utc(at)
        occurred = iso_utc(at_utc)

        mismatches = []
        for item in items:
            key_i = f"{idempotency_key}:{item['sample_id']}"
            fp_i = sha256_hex(canonical_json({
                "op": "out", "sample_id": item["sample_id"], "to": to_actor_id,
                "seal": item["seal_number"], "at": occurred,
            }))
            if self._check_idempotency(key_i, fp_i) is not None:
                continue  # 已完成过的项，重试时跳过预检
            sample = self._require_sample(item["sample_id"])
            self._check_transfer_out(actor, sample, receiver, at_utc)
            if item["seal_number"] != sample["seal_number"]:
                mismatches.append((sample, item, key_i))
        if mismatches:
            with self.store.transaction():
                for sample, item, key_i in mismatches:
                    self._auto_quarantine(
                        actor=actor, sample=sample, occurred_at=occurred,
                        anomaly_type=AnomalyType.SEAL_MISMATCH,
                        details=(
                            f"批量交出时封条不符：登记 {sample['seal_number']}，"
                            f"出示 {item['seal_number']}"
                        ),
                        idempotency_key=f"{key_i}:seal-mismatch",
                    )
            bad = [s["sample_id"] for s, _, _ in mismatches]
            raise SealMismatch(f"批量交出中 {len(bad)} 个样本封条不符，已隔离: {bad}")

        return [
            self.transfer_out(
                actor_id, item["sample_id"], to_actor_id,
                seal_number=item["seal_number"], at=at_utc,
                idempotency_key=f"{idempotency_key}:{item['sample_id']}",
            )
            for item in items
        ]

    def batch_transfer_in(self, actor_id: str, items: list[dict],
                          *, at: datetime | str, idempotency_key: str) -> list[dict]:
        """批量签收：``items`` 为 ``[{"sample_id", "dispatch_event_id", "seal_number"}]``。

        预检与隔离策略同 :meth:`batch_transfer_out`。
        """
        if not items:
            raise ValidationError("批量交接不能为空")
        actor = self._require_actor(actor_id)
        at_utc = to_utc(at)
        occurred = iso_utc(at_utc)

        mismatches = []
        for item in items:
            key_i = f"{idempotency_key}:{item['sample_id']}"
            fp_i = sha256_hex(canonical_json({
                "op": "in", "sample_id": item["sample_id"],
                "dispatch": item["dispatch_event_id"],
                "seal": item["seal_number"], "at": occurred,
            }))
            if self._check_idempotency(key_i, fp_i) is not None:
                continue
            sample = self._require_sample(item["sample_id"])
            self._check_transfer_in(actor, sample, item["dispatch_event_id"], at_utc)
            if item["seal_number"] != sample["seal_number"]:
                mismatches.append((sample, item, key_i))
        if mismatches:
            with self.store.transaction():
                for sample, item, key_i in mismatches:
                    self._auto_quarantine(
                        actor=actor, sample=sample, occurred_at=occurred,
                        anomaly_type=AnomalyType.SEAL_MISMATCH,
                        details=(
                            f"批量签收时封条不符：登记 {sample['seal_number']}，"
                            f"出示 {item['seal_number']}"
                        ),
                        idempotency_key=f"{key_i}:seal-mismatch",
                        take_custody=True,
                    )
            bad = [s["sample_id"] for s, _, _ in mismatches]
            raise SealMismatch(f"批量签收中 {len(bad)} 个样本封条不符，已隔离: {bad}")

        return [
            self.transfer_in(
                actor_id, item["sample_id"], item["dispatch_event_id"],
                seal_number=item["seal_number"], at=at_utc,
                idempotency_key=f"{idempotency_key}:{item['sample_id']}",
            )
            for item in items
        ]

    # ==================================================================
    # 异常申报与隔离
    # ==================================================================
    def report_anomaly(self, actor_id: str, sample_id: str,
                       anomaly_type: AnomalyType | str, details: str,
                       *, at: datetime | str,
                       idempotency_key: str | None = None) -> dict:
        """申报异常：样本进入隔离流程，原始记录不受影响。"""
        anomaly_type = AnomalyType(anomaly_type)
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "anomaly", "sample_id": sample_id,
            "type": anomaly_type.value, "details": details, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, _CHAIN_ROLES)
        sample = self._require_sample(sample_id)
        if sample["status"] == SampleStatus.DESTROYED.value:
            raise InvalidState("样本已销毁")
        self._validate_event_time(sample, at_utc)
        with self.store.transaction():
            ev = self._auto_quarantine(
                actor=actor, sample=sample, occurred_at=iso_utc(at_utc),
                anomaly_type=anomaly_type, details=details, idempotency_key=key,
                fingerprint=fingerprint,
            )
        return self._event_view(ev)

    def resolve_quarantine(self, actor_id: str, sample_id: str,
                           resolution: QuarantineResolution | str,
                           *, authorization_ref: str, at: datetime | str,
                           new_seal_number: str | None = None,
                           idempotency_key: str | None = None) -> dict:
        """合规主管裁决隔离样本。RESEAL 是唯一合法的换封途径。"""
        resolution = QuarantineResolution(resolution)
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "resolve", "sample_id": sample_id, "resolution": resolution.value,
            "auth": authorization_ref, "new_seal": new_seal_number,
            "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.COMPLIANCE_OFFICER})
        sample = self._require_sample(sample_id)
        if not authorization_ref:
            raise ValidationError("隔离裁决必须提供授权依据 authorization_ref")
        if sample["status"] != SampleStatus.QUARANTINED.value:
            raise InvalidState(f"样本状态 {sample['status']} 不在隔离中")
        if resolution is QuarantineResolution.RESEAL and not new_seal_number:
            raise ValidationError("RESEAL 裁决必须提供新封条编号")
        self._validate_event_time(sample, at_utc)

        new_status = {
            QuarantineResolution.RELEASE: SampleStatus.IN_CUSTODY,
            QuarantineResolution.RESEAL: SampleStatus.IN_CUSTODY,
            QuarantineResolution.CONDEMN: SampleStatus.CONDEMNED,
        }[resolution]
        occurred = iso_utc(at_utc)
        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.QUARANTINE_RESOLVED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "resolution": resolution.value,
                    "authorization_ref": authorization_ref,
                    "old_seal": sample["seal_number"],
                    "new_seal": new_seal_number if resolution is QuarantineResolution.RESEAL else None,
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=new_status.value,
                seal_number=new_seal_number if resolution is QuarantineResolution.RESEAL else None,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    # ==================================================================
    # 实验室：A/B 拆分、结果、复检
    # ==================================================================
    def split_ab(self, actor_id: str, sample_id: str, *,
                 barcode_a: str, barcode_b: str, seal_a: str, seal_b: str,
                 at: datetime | str, idempotency_key: str | None = None) -> dict:
        """实验室把父样本拆分为 A/B 子瓶，保持父子关系。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "split", "sample_id": sample_id,
            "a": [barcode_a, seal_a], "b": [barcode_b, seal_b], "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.LAB_TECHNICIAN})
        sample = self._require_sample(sample_id)
        if sample["current_custodian"] != actor_id:
            raise PermissionDenied("只有当前保管人可以拆分样本")
        if sample["status"] != SampleStatus.IN_CUSTODY.value:
            raise InvalidState(f"样本状态 {sample['status']} 不允许拆分")
        if barcode_a == barcode_b:
            raise ValidationError("A/B 瓶条码必须不同")
        for bc in (barcode_a, barcode_b):
            if self.store.get_sample_by_barcode(bc):
                raise Conflict(f"条码 {bc!r} 已被使用")
        self._validate_event_time(sample, at_utc)

        occurred = iso_utc(at_utc)
        child_a = "SMP-" + sha256_hex(barcode_a)[:24]
        child_b = "SMP-" + sha256_hex(barcode_b)[:24]
        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.SAMPLE_SPLIT,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={
                    "children": [
                        {"sample_id": child_a, "barcode": barcode_a,
                         "bottle": "A", "seal_number": seal_a},
                        {"sample_id": child_b, "barcode": barcode_b,
                         "bottle": "B", "seal_number": seal_b},
                    ],
                },
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.SPLIT.value,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
            for child_id, barcode, bottle, seal in (
                (child_a, barcode_a, "A", seal_a),
                (child_b, barcode_b, "B", seal_b),
            ):
                self.store.insert_sample({
                    "sample_id": child_id,
                    "barcode": barcode,
                    "batch_id": sample["batch_id"],
                    "athlete_id": sample["athlete_id"],
                    "parent_id": sample_id,
                    "bottle": bottle,
                    "status": SampleStatus.IN_CUSTODY.value,
                    "seal_number": seal,
                    "current_custodian": actor_id,
                    "last_event_id": ev["event_id"],
                    "last_event_at": occurred,
                    "created_at": occurred,
                })
        return self._event_view(ev)

    def record_result(self, actor_id: str, sample_id: str, result: str,
                      *, lab_reference: str, at: datetime | str,
                      idempotency_key: str | None = None) -> dict:
        """实验室登记检测结果。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "result", "sample_id": sample_id, "result": result,
            "ref": lab_reference, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.LAB_TECHNICIAN})
        sample = self._require_sample(sample_id)
        if sample["current_custodian"] != actor_id:
            raise PermissionDenied("只有当前保管人可以登记结果")
        if sample["status"] not in (SampleStatus.IN_CUSTODY.value,
                                    SampleStatus.RETEST_AUTHORIZED.value):
            raise InvalidState(f"样本状态 {sample['status']} 不允许登记结果")
        if not result:
            raise ValidationError("结果不能为空")
        self._validate_event_time(sample, at_utc)

        occurred = iso_utc(at_utc)
        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.RESULT_RECORDED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={"result": result, "lab_reference": lab_reference},
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.ANALYZED.value,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    def request_retest(self, actor_id: str, sample_id: str, *,
                       authorization_ref: str, reason: str,
                       at: datetime | str, idempotency_key: str | None = None) -> dict:
        """申请复检：必须留下授权依据（如结果管理机构的批复文号）。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "retest", "sample_id": sample_id,
            "auth": authorization_ref, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.LAB_TECHNICIAN})
        sample = self._require_sample(sample_id)
        if not authorization_ref:
            raise ValidationError("复检必须提供授权依据 authorization_ref")
        if sample["status"] != SampleStatus.ANALYZED.value:
            raise InvalidState(f"样本状态 {sample['status']} 不允许复检")
        self._validate_event_time(sample, at_utc)

        occurred = iso_utc(at_utc)
        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.RETEST_AUTHORIZED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={"authorization_ref": authorization_ref, "reason": reason},
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.RETEST_AUTHORIZED.value,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    # ==================================================================
    # 销毁
    # ==================================================================
    def destroy_sample(self, actor_id: str, sample_id: str, *,
                       authorization_ref: str, method: str,
                       at: datetime | str, idempotency_key: str | None = None) -> dict:
        """销毁样本：仅合规主管，且必须留下授权依据。"""
        at_utc = to_utc(at)
        key = idempotency_key_or_new(idempotency_key)
        fingerprint = sha256_hex(canonical_json({
            "op": "destroy", "sample_id": sample_id,
            "auth": authorization_ref, "method": method, "at": iso_utc(at_utc),
        }))
        existing = self._check_idempotency(key, fingerprint)
        if existing is not None:
            return self._event_view(existing)

        actor = self._require_actor(actor_id)
        self._require_role(actor, {Role.COMPLIANCE_OFFICER})
        sample = self._require_sample(sample_id)
        if not authorization_ref:
            raise ValidationError("销毁必须提供授权依据 authorization_ref")
        if not method:
            raise ValidationError("销毁必须说明方式 method")
        if sample["status"] == SampleStatus.DESTROYED.value:
            raise InvalidState("样本已销毁")
        self._validate_event_time(sample, at_utc)

        occurred = iso_utc(at_utc)
        with self.store.transaction():
            ev = self._append_event(
                actor=actor,
                event_type=EventType.SAMPLE_DESTROYED,
                sample_id=sample_id,
                occurred_at=occurred,
                payload={"authorization_ref": authorization_ref, "method": method},
                idempotency_key=key,
                fingerprint=fingerprint,
            )
            self.store.update_sample_state(
                sample_id, status=SampleStatus.DESTROYED.value,
                last_event_id=ev["event_id"], last_event_at=occurred,
            )
        return self._event_view(ev)

    # ==================================================================
    # 查询与审计导出
    # ==================================================================
    def get_sample(self, sample_id: str, *, as_role: Role | str) -> dict:
        """按角色查询样本状态（敏感身份按角色脱敏）。"""
        role = Role(as_role)
        sample = self._require_sample(sample_id)
        return self._sample_view(sample, role)

    def get_sample_history(self, sample_id: str, *, as_role: Role | str) -> list[dict]:
        """按角色查询样本的完整事件历史（回放链路）。"""
        role = Role(as_role)
        self._require_sample(sample_id)
        return [self._redact_event(self._event_view(e), role)
                for e in self.store.list_events(sample_id)]

    def get_batch_status(self, batch_id: str, *, as_role: Role | str) -> dict:
        """按角色查询批次内所有样本的状态。"""
        role = Role(as_role)
        if not self.store.get_batch(batch_id):
            raise NotFound(f"批次 {batch_id!r} 不存在")
        samples = [self._sample_view(s, role) for s in self.store.list_samples(batch_id)]
        return {"batch_id": batch_id, "samples": samples}

    def export_audit(self, *, sample_id: str | None = None, batch_id: str | None = None,
                     as_role: Role | str) -> dict:
        """导出审计包：事件序列 + 样本快照 + 校验结果。

        合规角色导出包含完整身份，且每条事件的哈希与签名都可独立复算；
        其他角色得到脱敏视图（脱敏后无法独立复算，verification 为 None）。
        """
        role = Role(as_role)
        if sample_id and batch_id:
            raise ValidationError("sample_id 与 batch_id 只能指定其一")

        if sample_id:
            sample_ids = self._collect_with_descendants(sample_id)
        elif batch_id:
            if not self.store.get_batch(batch_id):
                raise NotFound(f"批次 {batch_id!r} 不存在")
            sample_ids = {s["sample_id"] for s in self.store.list_samples(batch_id)}
        else:
            sample_ids = None  # 全量导出

        all_events = self.store.list_events()
        events = all_events if sample_ids is None else [
            e for e in all_events if e["sample_id"] in sample_ids
        ]

        verifiable = role in _FULL_IDENTITY_ROLES
        verification = None
        if verifiable:
            verification = self._verify_events(events, check_linkage=sample_ids is None)

        views = [self._event_view(e) for e in events]
        if not verifiable:
            views = [self._redact_event(v, role) for v in views]
        samples = [
            self._sample_view(s, role)
            for s in self.store.list_samples()
            if sample_ids is None or s["sample_id"] in sample_ids
        ]
        return {
            "export_id": "EXP-" + uuid.uuid4().hex,
            "generated_at": iso_utc(self._clock()),
            "scope": {"sample_id": sample_id, "batch_id": batch_id},
            "role": role.value,
            "chain_head": self.store.head_hash(ZERO_HASH),
            "events": views,
            "samples": samples,
            "verification": verification,
        }

    def verify_export(self, export: dict) -> bool:
        """独立复算审计包中每条事件的哈希与签名。"""
        verification = export.get("verification")
        if verification is None:
            raise ValidationError("脱敏导出不支持独立校验（需合规角色导出）")
        result = self._verify_events(
            [self._row_from_view(e) for e in export["events"]],
            check_linkage=verification.get("linkage") == "verified",
        )
        return bool(result["hashes_valid"] and result["signatures_valid"])

    def verify_chain(self) -> dict:
        """校验整条事件链：哈希链接、哈希复算、逐条签名。"""
        events = self.store.list_events()
        result = self._verify_events(events, check_linkage=True)
        result["events"] = len(events)
        result["head"] = self.store.head_hash(ZERO_HASH)
        return result

    # ==================================================================
    # 内部：交接校验
    # ==================================================================
    def _check_transfer_out(self, actor: dict, sample: dict, receiver: dict,
                            at_utc: datetime) -> None:
        """交出前预检（不含封条比对，封条不符走隔离流程）。"""
        if receiver["actor_id"] == actor["actor_id"]:
            raise ValidationError("不能交接给自己")
        if sample["current_custodian"] != actor["actor_id"]:
            raise PermissionDenied("只有当前保管人可以交出样本")
        if sample["status"] not in _DISPATCHABLE:
            raise InvalidState(f"样本状态 {sample['status']} 不允许交出")
        self._check_handover_path(Role(actor["role"]), Role(receiver["role"]))
        self._validate_event_time(sample, at_utc)

    def _check_transfer_in(self, actor: dict, sample: dict,
                           dispatch_event_id: str, at_utc: datetime) -> dict:
        """签收前预检：验证前一环签名、时间窗，返回发运事件（不含封条比对）。"""
        dispatch = self.store.get_event(dispatch_event_id)
        if dispatch is None or dispatch["event_type"] != EventType.TRANSFER_OUT.value:
            raise NotFound(f"发运事件 {dispatch_event_id!r} 不存在")
        if dispatch["sample_id"] != sample["sample_id"]:
            raise ValidationError("发运事件与样本不匹配")
        self._verify_event_integrity(dispatch)  # 验证前一环哈希与签名
        dispatch_payload = json.loads(dispatch["payload"])

        if actor["actor_id"] != dispatch_payload["to_actor_id"]:
            raise PermissionDenied("只有发运指定的接收方可以签收")
        if self.store.find_transfer_in_for(dispatch_event_id) is not None:
            raise InvalidState("该发运事件已被签收")
        if sample["status"] != SampleStatus.IN_TRANSIT.value:
            raise InvalidState(f"样本状态 {sample['status']} 不在运输途中")
        if sample["current_custodian"] != dispatch["actor_id"]:
            raise ChainIntegrityError("样本保管人与发运人不一致，链路断裂")

        self._validate_event_time(sample, at_utc)
        dispatched_at = to_utc(dispatch["occurred_at"])
        if at_utc < dispatched_at:
            raise TimeWindowViolation("签收时间早于发运时间")
        if at_utc - dispatched_at > self._max_transfer_window:
            raise TimeWindowViolation(
                f"交接耗时 {at_utc - dispatched_at} 超出允许窗口 {self._max_transfer_window}"
            )
        return dispatch

    def _quarantine_for_seal_mismatch(self, actor: dict, sample: dict, occurred: str,
                                      key: str, *, direction: str, presented: str,
                                      take_custody: bool = False,
                                      dispatch_event_id: str | None = None) -> dict:
        """封条不符：提交隔离事件（独立事务，异常抛出后记录依然保留）。"""
        details = (
            f"{direction}时封条不符：登记 {sample['seal_number']}，出示 {presented}"
        )
        if dispatch_event_id:
            details += f"（发运事件 {dispatch_event_id}）"
        with self.store.transaction():
            return self._auto_quarantine(
                actor=actor, sample=sample, occurred_at=occurred,
                anomaly_type=AnomalyType.SEAL_MISMATCH, details=details,
                idempotency_key=f"{key}:seal-mismatch",
                take_custody=take_custody,
            )

    # ==================================================================
    # 内部：事件追加与校验
    # ==================================================================
    def _append_event(self, *, actor: dict, event_type: EventType, sample_id: str | None,
                      occurred_at: str, payload: dict, idempotency_key: str | None,
                      fingerprint: str | None) -> dict:
        """在当前事务内追加一条签名事件（调用方必须已开启事务）。"""
        body = {
            "event_id": "EVT-" + uuid.uuid4().hex,
            "sample_id": sample_id,
            "event_type": event_type.value,
            "actor_id": actor["actor_id"],
            "role": actor["role"],
            "occurred_at": occurred_at,
            "payload": payload,
            "prev_hash": self.store.head_hash(ZERO_HASH),
        }
        digest = event_hash(body)
        record = {
            **{k: (json.dumps(v, ensure_ascii=False) if k == "payload" else v)
               for k, v in body.items()},
            "idempotency_key": idempotency_key,
            "request_fingerprint": fingerprint,
            "hash": digest,
            "signature": sign(actor["secret"], digest),
        }
        self.store.insert_event(record)
        return self.store.get_event(body["event_id"])

    def _auto_quarantine(self, *, actor: dict, sample: dict, occurred_at: str,
                         anomaly_type: AnomalyType, details: str,
                         idempotency_key: str, fingerprint: str | None = None,
                         take_custody: bool = False) -> dict:
        """在事务内追加异常事件并把样本置入隔离（不改动任何历史事件）。"""
        existing = self.store.find_event_by_idempotency(idempotency_key)
        if existing is not None:
            return existing
        ev = self._append_event(
            actor=actor,
            event_type=EventType.ANOMALY_REPORTED,
            sample_id=sample["sample_id"],
            occurred_at=occurred_at,
            payload={
                "anomaly_type": anomaly_type.value,
                "details": details,
                "previous_status": sample["status"],
            },
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
        )
        self.store.update_sample_state(
            sample["sample_id"],
            status=SampleStatus.QUARANTINED.value,
            custodian=actor["actor_id"] if take_custody else None,
            last_event_id=ev["event_id"],
            last_event_at=occurred_at,
        )
        return ev

    def _quarantine_replay(self, temp_key: str) -> dict | None:
        row = self.store.find_event_by_idempotency(f"{temp_key}:excursion")
        return self._event_view(row) if row else None

    def _verify_event_integrity(self, event_row: dict) -> None:
        """复算单条事件的哈希并验证签名（用于验证前一环）。"""
        body = {
            "event_id": event_row["event_id"],
            "sample_id": event_row["sample_id"],
            "event_type": event_row["event_type"],
            "actor_id": event_row["actor_id"],
            "role": event_row["role"],
            "occurred_at": event_row["occurred_at"],
            "payload": json.loads(event_row["payload"]),
            "prev_hash": event_row["prev_hash"],
        }
        if event_hash(body) != event_row["hash"]:
            raise ChainIntegrityError(f"事件 {event_row['event_id']} 哈希校验失败")
        actor = self.store.get_custodian(event_row["actor_id"])
        if actor is None or not verify_signature(actor["secret"], event_row["hash"],
                                                 event_row["signature"]):
            raise ChainIntegrityError(f"事件 {event_row['event_id']} 签名校验失败")

    def _verify_events(self, event_rows: list[dict], *, check_linkage: bool) -> dict:
        prev_hash = ZERO_HASH
        for row in event_rows:
            try:
                self._verify_event_integrity(row)
            except ChainIntegrityError as exc:
                raise ChainIntegrityError(
                    f"链校验失败（seq={row['seq']}）：{exc}"
                ) from exc
            if check_linkage:
                if row["prev_hash"] != prev_hash:
                    raise ChainIntegrityError(
                        f"链校验失败（seq={row['seq']}）：prev_hash 链接断裂"
                    )
                prev_hash = row["hash"]
        return {
            "hashes_valid": True,
            "signatures_valid": True,
            "linkage": "verified" if check_linkage else "partial",
        }

    # ==================================================================
    # 内部：通用校验
    # ==================================================================
    def _require_actor(self, actor_id: str) -> dict:
        actor = self.store.get_custodian(actor_id)
        if actor is None:
            raise NotFound(f"参与人 {actor_id!r} 未登记")
        return actor

    def _require_sample(self, sample_id: str) -> dict:
        sample = self.store.get_sample(sample_id)
        if sample is None:
            raise NotFound(f"样本 {sample_id!r} 不存在")
        return sample

    @staticmethod
    def _require_role(actor: dict, allowed: set[Role]) -> None:
        if Role(actor["role"]) not in allowed:
            raise PermissionDenied(
                f"角色 {actor['role']} 无权执行该操作（需要 "
                f"{'/'.join(sorted(r.value for r in allowed))}）"
            )

    @staticmethod
    def _check_handover_path(from_role: Role, to_role: Role) -> None:
        if (from_role, to_role) not in ALLOWED_HANDOVERS:
            raise PermissionDenied(f"不允许 {from_role.value} 向 {to_role.value} 交接")

    def _is_current_holder(self, actor_id: str, sample: dict) -> bool:
        if sample["current_custodian"] == actor_id:
            return True
        if sample["status"] == SampleStatus.IN_TRANSIT.value:
            dispatch = self.store.find_open_dispatch(sample["sample_id"])
            if dispatch and json.loads(dispatch["payload"]).get("to_actor_id") == actor_id:
                return True
        return False

    def _validate_event_time(self, sample: dict | None, at: datetime) -> None:
        now = self._clock()
        if at > now + self._max_future_skew:
            raise ValidationError("事件时间超出允许的未来偏移")
        if sample and sample["last_event_at"]:
            if at < to_utc(sample["last_event_at"]):
                raise ValidationError("事件时间早于该样本上一事件时间")

    def _check_idempotency(self, key: str | None, fingerprint: str) -> dict | None:
        if key is None:
            return None
        existing = self.store.find_event_by_idempotency(key)
        if existing is None:
            return None
        if existing["request_fingerprint"] != fingerprint:
            raise Conflict(f"幂等键 {key!r} 已被不同内容的请求使用")
        return existing

    def _collect_with_descendants(self, sample_id: str) -> set[str]:
        self._require_sample(sample_id)
        ids = {sample_id}
        frontier = [sample_id]
        while frontier:
            children = self.store.list_children(frontier.pop())
            for child in children:
                if child["sample_id"] not in ids:
                    ids.add(child["sample_id"])
                    frontier.append(child["sample_id"])
        return ids

    # ==================================================================
    # 内部：视图与脱敏
    # ==================================================================
    def _sample_view(self, sample: dict, role: Role) -> dict:
        custodian = self.store.get_custodian(sample["current_custodian"])
        athlete = self.store.get_athlete(sample["athlete_id"])
        children = self.store.list_children(sample["sample_id"])
        return {
            "sample_id": sample["sample_id"],
            "barcode": sample["barcode"],
            "batch_id": sample["batch_id"],
            "bottle": sample["bottle"],
            "parent_id": sample["parent_id"],
            "status": sample["status"],
            "seal_number": sample["seal_number"],
            "current_custodian": {
                "actor_id": sample["current_custodian"],
                "name": custodian["name"] if custodian else None,
                "role": custodian["role"] if custodian else None,
            },
            "athlete": self._mask_athlete(athlete, role),
            "children": [c["sample_id"] for c in children],
            "created_at": sample["created_at"],
            "last_event_at": sample["last_event_at"],
            "last_event_id": sample["last_event_id"],
        }

    def _mask_athlete(self, athlete: dict | None, role: Role) -> dict | None:
        if athlete is None:
            return None
        if role in _FULL_IDENTITY_ROLES:
            return {
                "athlete_id": athlete["athlete_id"],
                "name": athlete["name"],
                "team": athlete["team"],
                "id_number": athlete["id_number"],
            }
        if role is Role.LAB_TECHNICIAN:
            # 实验室只见到假名编号，见不到任何可识别身份
            return {"athlete_ref": pseudonym("ATH", athlete["athlete_id"])}
        return {
            "athlete_id": athlete["athlete_id"],
            "name": mask_name(athlete["name"]),
            "team": athlete["team"],
            "id_number": pseudonym("ID", athlete["id_number"] or athlete["athlete_id"]),
        }

    def _redact_event(self, event_view: dict, role: Role) -> dict:
        if role in _FULL_IDENTITY_ROLES:
            return event_view
        payload = dict(event_view.get("payload") or {})
        if "athlete" in payload and isinstance(payload["athlete"], dict):
            athlete_id = payload.get("athlete_id", "")
            payload["athlete"] = self._mask_athlete(
                {"athlete_id": athlete_id,
                 "name": payload["athlete"].get("name"),
                 "team": payload["athlete"].get("team"),
                 "id_number": payload["athlete"].get("id_number")},
                role,
            )
        if role is Role.LAB_TECHNICIAN and "athlete_id" in payload:
            payload["athlete_ref"] = pseudonym("ATH", payload.pop("athlete_id"))
        return {**event_view, "payload": payload}

    @staticmethod
    def _event_view(row: dict) -> dict:
        return {
            "seq": row["seq"],
            "event_id": row["event_id"],
            "sample_id": row["sample_id"],
            "event_type": row["event_type"],
            "actor_id": row["actor_id"],
            "role": row["role"],
            "occurred_at": row["occurred_at"],
            "payload": json.loads(row["payload"]),
            "prev_hash": row["prev_hash"],
            "hash": row["hash"],
            "signature": row["signature"],
        }

    @staticmethod
    def _row_from_view(view: dict) -> dict:
        return {
            "seq": view["seq"],
            "event_id": view["event_id"],
            "sample_id": view["sample_id"],
            "event_type": view["event_type"],
            "actor_id": view["actor_id"],
            "role": view["role"],
            "occurred_at": view["occurred_at"],
            "payload": json.dumps(view["payload"], ensure_ascii=False),
            "prev_hash": view["prev_hash"],
            "hash": view["hash"],
            "signature": view["signature"],
        }


def idempotency_key_or_new(key: str | None) -> str:
    return key if key else "op-" + uuid.uuid4().hex


def mask_name(name: str | None) -> str | None:
    if not name:
        return name
    return name[0] + "***"
