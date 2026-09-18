"""仅追加（append-only）事件日志。

每条事件携带单调递增序号、UTC 时间戳、前一条事件的 SHA-256 以及自身哈希，
形成哈希链。任何对原始记录的事后修改都会让后续哈希全部失配，
``verify_chain`` 可以在服务启动或审计时发现篡改。

持久化格式为 JSONL（每行一个事件），以 append 方式写入并 ``fsync``：
历史行从不重写，写入中途断电/崩溃最多丢失最后一行，此前的哈希链不受影响。
重放时按行顺序读取即可。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import IntegrityError, canonical_json, utc_iso

GENESIS_HASH = "0" * 64


def event_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    body = prev_hash + canonical_json(payload)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class Event:
    """日志中的一条不可变事件。"""

    __slots__ = ("seq", "ts", "payload", "prev_hash", "hash")

    def __init__(
        self,
        seq: int,
        ts: str,
        payload: dict[str, Any],
        prev_hash: str,
        digest: str,
    ) -> None:
        self.seq = seq
        self.ts = ts
        self.payload = payload
        self.prev_hash = prev_hash
        self.hash = digest

    def to_jsonl(self) -> str:
        return canonical_json(
            {
                "seq": self.seq,
                "ts": self.ts,
                "payload": self.payload,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            }
        )

    @classmethod
    def from_jsonl(cls, line: str) -> "Event":
        obj = json.loads(line)
        return cls(
            seq=int(obj["seq"]),
            ts=obj["ts"],
            payload=obj["payload"],
            prev_hash=obj["prev_hash"],
            digest=obj["hash"],
        )


class EventStore:
    """线程安全的文件型 append-only 事件存储。"""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._lock = threading.RLock()
        self._events: list[Event] = []
        self._path = Path(path) if path else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.exists():
                self._load()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def _load(self) -> None:
        assert self._path is not None
        self._events = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    event = Event.from_jsonl(raw)
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise IntegrityError(f"事件日志第 {line_no} 行损坏") from exc
                self._events.append(event)
        # 加载即校验，启动时即可发现被篡改的历史。
        self.verify_chain()

    def _append_line(self, event: Event) -> None:
        assert self._path is not None
        # 追加写入并 fsync：已落盘的历史行从不重写，
        # 写入中途崩溃最多丢失最后一行，不会损坏此前的哈希链。
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(event.to_jsonl() + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def verify_chain(self) -> None:
        """重算全部哈希，发现断链或序号异常即抛出 IntegrityError。"""

        prev = GENESIS_HASH
        expected_seq = 1
        for event in self._events:
            if event.seq != expected_seq:
                raise IntegrityError(
                    f"事件序号不连续：期望 {expected_seq}，实际 {event.seq}"
                )
            if event.prev_hash != prev:
                raise IntegrityError(f"事件 {event.seq} 的前向哈希不匹配（日志被改写？）")
            if event.hash != event_hash(prev, event.payload):
                raise IntegrityError(f"事件 {event.seq} 内容哈希不匹配（原始记录被修改？）")
            prev = event.hash
            expected_seq += 1

    # ------------------------------------------------------------------
    # 读写
    # ------------------------------------------------------------------

    def append(self, payload: dict[str, Any], ts: datetime | str | None = None) -> Event:
        with self._lock:
            seq = len(self._events) + 1
            prev = self._events[-1].hash if self._events else GENESIS_HASH
            digest = event_hash(prev, payload)
            event = Event(
                seq=seq,
                ts=utc_iso(ts or datetime.now(timezone.utc)),
                payload=payload,
                prev_hash=prev,
                digest=digest,
            )
            if self._path is not None:
                self._append_line(event)
            self._events.append(event)
            return event

    def replay(self) -> Iterator[Event]:
        with self._lock:
            yield from list(self._events)

    def read_all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    @property
    def head_hash(self) -> str:
        with self._lock:
            return self._events[-1].hash if self._events else GENESIS_HASH

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._events)
