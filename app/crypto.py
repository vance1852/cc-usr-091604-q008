"""哈希链与签名原语。

- 事件哈希：对事件的规范化 JSON 做 SHA-256，并链接前一事件哈希，
  任何对历史记录的篡改都会破坏链条。
- 事件签名：HMAC-SHA256，密钥为各保管人的个人密钥（真实部署中应
  放在 HSM/密钥管理服务里，这里为可运行的参考实现）。
- 时间：一律规范化为 UTC ISO-8601 字符串，跨时区运输时比较不受影响。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from .errors import ValidationError

#: 创世前驱哈希（第一个事件的 prev_hash）。
ZERO_HASH = "0" * 64


def canonical_json(obj) -> str:
    """生成确定性 JSON：键排序、无空白、UTF-8，保证哈希可复算。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_secret() -> str:
    """为保管人生成个人签名密钥。"""
    return secrets.token_hex(32)


def sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(secret: str, message: str, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, message), signature)


def event_hash(event_body: dict) -> str:
    """计算事件哈希。``event_body`` 不含 hash/signature 字段本身。"""
    return sha256_hex(canonical_json(event_body))


def to_utc(value: datetime | str) -> datetime:
    """把 datetime 或 ISO-8601 字符串规范化为 UTC 感知时间。

    朴素时间（无时区）直接拒绝 —— 监管链上的时间必须可跨时区解释。
    """
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(f"无法解析的时间戳: {value!r}") from exc
    if not isinstance(value, datetime):
        raise ValidationError(f"时间戳类型不支持: {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("时间戳必须携带时区信息（不允许朴素时间）")
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime | str) -> str:
    """规范化为 UTC ISO-8601 字符串（落库格式）。"""
    return to_utc(value).isoformat()


def pseudonym(kind: str, identifier: str) -> str:
    """为非合规角色生成不可逆的身份假名。"""
    return f"{kind}-{sha256_hex(identifier)[:12]}"
