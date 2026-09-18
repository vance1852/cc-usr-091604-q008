"""监管链领域模型：角色、状态、异常、脱敏与签名工具。

设计要点
--------
* 所有时间在入口处统一转换为带时区的 UTC，跨时区交接只比较 UTC 时刻。
* 签名使用 HMAC-SHA256（演示用共享密钥，生产环境应由 HSM/KMS 托管）。
* 身份信息对非合规角色只暴露脱敏视图。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# 角色与状态
# ---------------------------------------------------------------------------

class Role(str, Enum):
    """监管链上的四类参与方。"""

    DCO = "dco"                    # 采样官
    CARRIER = "carrier"            # 运输人员
    LAB = "lab"                    # 实验室
    COMPLIANCE = "compliance"      # 合规主管


class Status(str, Enum):
    REGISTERED = "registered"      # 已采集，由采样官持有
    IN_TRANSIT = "in_transit"      # 运输中
    AT_LAB = "at_lab"              # 已送达实验室
    SPLIT = "split"                # 父样本已拆分为 A/B 瓶
    QUARANTINED = "quarantined"    # 隔离中（异常流程）
    RETESTED = "retested"          # 已完成复检
    DESTROYED = "destroyed"        # 已销毁


class AnomalyKind(str, Enum):
    SEAL_MISMATCH = "seal_mismatch"        # 封条编号/状态不符
    SEAL_BROKEN = "seal_broken"            # 封条破损
    TEMP_BREACH = "temperature_breach"     # 冷链超温
    PAPERWORK = "paperwork"                # 采样表/文书不符
    DAMAGE = "damage"                      # 容器破损
    OTHER = "other"


# 允许的交接方向：采样官 -> 运输 -> 实验室。
# 任何不在表内的交接（越级、反向、伪造双方）都属于越权交接。
NEXT_ROLES: dict[Role, frozenset[Role]] = {
    Role.DCO: frozenset({Role.CARRIER}),
    Role.CARRIER: frozenset({Role.LAB}),
    Role.LAB: frozenset(),
    Role.COMPLIANCE: frozenset(),
}

# 各段交接的最长时间窗（相对于采集时刻 / 发出时刻）。
DEFAULT_EDGE_WINDOWS: dict[tuple[Role, Role], int] = {
    (Role.DCO, Role.CARRIER): 120 * 60,    # 采集后 2 小时内交接
    (Role.CARRIER, Role.LAB): 48 * 3600,   # 运输不超过 48 小时
}

# 冷链要求（ inclusive，单位摄氏度）与读数最大允许间隔。
TEMP_MIN_C = 2.0
TEMP_MAX_C = 12.0
TEMP_MAX_GAP_SECONDS = 180 * 60  # 运输途中每 3 小时至少一个读数


# ---------------------------------------------------------------------------
# 错误类型
# ---------------------------------------------------------------------------

class CustodyError(Exception):
    """所有监管链业务错误的基类。"""


class ValidationError(CustodyError):
    """入参不合法（缺少字段、时间为 naive 等）。"""


class NotFoundError(CustodyError):
    """条码/用户/授权单不存在。"""


class AuthzError(CustodyError):
    """越权操作：角色不允许、不是当前保管人、身份密钥不符。"""


class SignatureError(CustodyError):
    """交接签名缺失或验签失败。"""


class SealError(CustodyError):
    """封条编号不一致、封条状态异常，或试图非法替换封条。"""


class TimeWindowError(CustodyError):
    """交接超出允许时间窗，或时间戳倒退。"""


class ColdChainError(CustodyError):
    """运输途中缺少冷藏温度记录或读数越界。"""


class QuarantineError(CustodyError):
    """样本处于隔离状态，正常流程必须暂停。"""


class AuthorizationRequiredError(CustodyError):
    """复检/销毁缺少合规主管授权，或授权已被使用。"""


class DuplicateBarcodeError(CustodyError):
    """同一条码重复登记。"""


class IdempotencyConflict(CustodyError):
    """同一幂等键携带了不同的请求体。"""


class IntegrityError(CustodyError):
    """事件哈希链校验失败：日志被篡改或损坏。"""


# ---------------------------------------------------------------------------
# 值对象
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Actor:
    """调用方身份。``key`` 为 HMAC 签名密钥（演示环境用）。"""

    id: str
    role: Role
    key: str

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise ValidationError("用户 id 不能为空")
        if not isinstance(self.role, Role):
            object.__setattr__(self, "role", Role(self.role))
        if not self.key:
            raise ValidationError("签名密钥不能为空")


@dataclass(frozen=True)
class Athlete:
    """运动员敏感身份信息，仅合规角色可见明文。"""

    name: str
    id_number: str                 # 证件号
    nationality: str = ""
    sport: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "id_number": self.id_number,
            "nationality": self.nationality,
            "sport": self.sport,
        }


@dataclass(frozen=True)
class Sample:
    """样本条码与采样批次（保留给起点版本的兼容对象）。"""

    barcode: str
    batch: str


# ---------------------------------------------------------------------------
# 时间与序列化
# ---------------------------------------------------------------------------

def to_utc(value: datetime | str) -> datetime:
    """把 ISO 字符串或 datetime 归一化为 UTC；拒绝 naive 时间。"""

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError(f"无法解析时间戳: {value!r}") from exc
    elif isinstance(value, datetime):
        dt = value
    else:
        raise ValidationError(f"不支持的时间类型: {type(value)!r}")
    if dt.tzinfo is None:
        raise ValidationError("时间戳必须携带时区偏移（跨时区运输一律按 UTC 比较）")
    return dt.astimezone(timezone.utc)


def utc_iso(value: datetime | str) -> str:
    return to_utc(value).isoformat()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 签名
# ---------------------------------------------------------------------------

def handover_text(barcode: str, at: datetime | str, from_id: str, to_id: str) -> str:
    """交接签名的待签名文本。

    刻意不含服务端的 prev_hash：现场设备可能断网，需要先离线签名、
    上线后重放，因此签名只依赖双方可预先确定的字段。
    """

    return "|".join(["HANDOVER", barcode, utc_iso(at), from_id, to_id])


def sign(key: str, text: str) -> str:
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_handover(actor: Actor, barcode: str, at: datetime | str, to_id: str) -> str:
    return sign(actor.key, handover_text(barcode, at, actor.id, to_id))


def verify_signature(key: str, text: str, signature: str) -> bool:
    if not isinstance(signature, str) or not signature:
        return False
    return hmac.compare_digest(sign(key, text), signature)


# ---------------------------------------------------------------------------
# PII 脱敏
# ---------------------------------------------------------------------------

def _mask_name(name: str) -> str:
    if not name:
        return ""
    return name[0] + "*" * (max(len(name), 2) - 1)


def _mask_id_number(value: str) -> str:
    if not value:
        return ""
    tail = value[-4:] if len(value) >= 4 else value
    return "*" * 4 + tail


def mask_athlete(athlete: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": _mask_name(athlete.get("name", "")),
        "id_number": _mask_id_number(athlete.get("id_number", "")),
        "nationality": athlete.get("nationality", ""),
        "sport": athlete.get("sport", ""),
        "masked": True,
    }
