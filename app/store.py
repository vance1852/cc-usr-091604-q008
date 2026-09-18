"""SQLite 持久化层：追加式事件日志 + 物化状态。

设计要点：

- ``events`` 表只允许 INSERT，应用层不提供任何 UPDATE/DELETE 接口，
  保证原始记录不可修改、全量可回放。
- 每个事件携带 ``prev_hash`` 与自身 ``hash``，构成全局哈希链；
  服务重启后按 ``seq`` 重放即可校验完整性。
- ``idempotency_key`` 有唯一约束：断网重试、重复扫描都会命中
  已存在的事件而不是产生重复记录。
- ``samples`` 等表只是事件的物化视图，与事件写入在同一事务中提交。
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS custodians (
    actor_id   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL,
    secret     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS athletes (
    athlete_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    team       TEXT,
    id_number  TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id    TEXT PRIMARY KEY,
    description TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    sample_id         TEXT PRIMARY KEY,
    barcode           TEXT UNIQUE NOT NULL,
    batch_id          TEXT NOT NULL,
    athlete_id        TEXT NOT NULL,
    parent_id         TEXT,
    bottle            TEXT,
    status            TEXT NOT NULL,
    seal_number       TEXT,
    current_custodian TEXT NOT NULL,
    last_event_id     TEXT,
    last_event_at     TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            TEXT UNIQUE NOT NULL,
    idempotency_key     TEXT UNIQUE,
    request_fingerprint TEXT,
    sample_id           TEXT,
    event_type          TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    role                TEXT NOT NULL,
    occurred_at         TEXT NOT NULL,
    payload             TEXT NOT NULL,
    prev_hash           TEXT NOT NULL,
    hash                TEXT NOT NULL,
    signature           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_sample ON events(sample_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_ref ON events((json_extract(payload, '$.dispatch_event_id')));
"""


class EventStore:
    """线程安全的 SQLite 事件存储。"""

    def __init__(self, path: str):
        self._path = path
        # isolation_level=None：关闭隐式事务，由 transaction() 显式控制
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # 事务与生命周期
    # ------------------------------------------------------------------
    @contextmanager
    def transaction(self):
        """显式事务：多个写操作要么全部提交，要么全部回滚。"""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self):
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # 事件日志（只追加）
    # ------------------------------------------------------------------
    def head_hash(self, zero_hash: str) -> str:
        row = self._conn.execute(
            "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["hash"] if row else zero_hash

    def insert_event(self, record: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO events (
                event_id, idempotency_key, request_fingerprint, sample_id,
                event_type, actor_id, role, occurred_at, payload,
                prev_hash, hash, signature
            ) VALUES (
                :event_id, :idempotency_key, :request_fingerprint, :sample_id,
                :event_type, :actor_id, :role, :occurred_at, :payload,
                :prev_hash, :hash, :signature
            )
            """,
            record,
        )

    def find_event_by_idempotency(self, key: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE idempotency_key = ?", (key,)
        ).fetchone()
        return dict(row) if row else None

    def get_event(self, event_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return dict(row) if row else None

    def find_transfer_in_for(self, dispatch_event_id: str) -> dict | None:
        row = self._conn.execute(
            """
            SELECT * FROM events
            WHERE event_type = 'TRANSFER_IN'
              AND json_extract(payload, '$.dispatch_event_id') = ?
            """,
            (dispatch_event_id,),
        ).fetchone()
        return dict(row) if row else None

    def find_open_dispatch(self, sample_id: str) -> dict | None:
        """查找样本尚未被签收的发运事件（运输途中）。"""
        row = self._conn.execute(
            """
            SELECT * FROM events e
            WHERE e.event_type = 'TRANSFER_OUT' AND e.sample_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM events t
                  WHERE t.event_type = 'TRANSFER_IN'
                    AND json_extract(t.payload, '$.dispatch_event_id') = e.event_id
              )
            ORDER BY e.seq DESC LIMIT 1
            """,
            (sample_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_events(self, sample_id: str | None = None) -> list[dict]:
        if sample_id is None:
            rows = self._conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE sample_id = ? ORDER BY seq", (sample_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count_events(self, sample_id: str | None = None) -> int:
        if sample_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE sample_id = ?", (sample_id,)
            ).fetchone()
        return row["n"]

    # ------------------------------------------------------------------
    # 保管人 / 运动员 / 批次
    # ------------------------------------------------------------------
    def add_custodian(self, actor_id: str, name: str, role: str, secret: str, created_at: str) -> None:
        self._conn.execute(
            "INSERT INTO custodians (actor_id, name, role, secret, created_at) VALUES (?,?,?,?,?)",
            (actor_id, name, role, secret, created_at),
        )

    def get_custodian(self, actor_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM custodians WHERE actor_id = ?", (actor_id,)
        ).fetchone()
        return dict(row) if row else None

    def upsert_athlete(self, athlete_id: str, name: str, team: str | None,
                       id_number: str | None, created_at: str) -> None:
        self._conn.execute(
            """
            INSERT INTO athletes (athlete_id, name, team, id_number, created_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(athlete_id) DO NOTHING
            """,
            (athlete_id, name, team, id_number, created_at),
        )

    def get_athlete(self, athlete_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM athletes WHERE athlete_id = ?", (athlete_id,)
        ).fetchone()
        return dict(row) if row else None

    def add_batch(self, batch_id: str, description: str | None, created_by: str, created_at: str) -> None:
        self._conn.execute(
            "INSERT INTO batches (batch_id, description, created_by, created_at) VALUES (?,?,?,?)",
            (batch_id, description, created_by, created_at),
        )

    def get_batch(self, batch_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # 样本物化状态
    # ------------------------------------------------------------------
    def insert_sample(self, record: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO samples (
                sample_id, barcode, batch_id, athlete_id, parent_id, bottle,
                status, seal_number, current_custodian, last_event_id,
                last_event_at, created_at
            ) VALUES (
                :sample_id, :barcode, :batch_id, :athlete_id, :parent_id, :bottle,
                :status, :seal_number, :current_custodian, :last_event_id,
                :last_event_at, :created_at
            )
            """,
            record,
        )

    def get_sample(self, sample_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM samples WHERE sample_id = ?", (sample_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_sample_by_barcode(self, barcode: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM samples WHERE barcode = ?", (barcode,)
        ).fetchone()
        return dict(row) if row else None

    def update_sample_state(self, sample_id: str, *, status: str | None = None,
                            custodian: str | None = None, seal_number: str | None = None,
                            last_event_id: str, last_event_at: str) -> None:
        sample = self.get_sample(sample_id)
        self._conn.execute(
            """
            UPDATE samples
            SET status = ?, current_custodian = ?, seal_number = ?,
                last_event_id = ?, last_event_at = ?
            WHERE sample_id = ?
            """,
            (
                status if status is not None else sample["status"],
                custodian if custodian is not None else sample["current_custodian"],
                seal_number if seal_number is not None else sample["seal_number"],
                last_event_id,
                last_event_at,
                sample_id,
            ),
        )

    def list_samples(self, batch_id: str | None = None) -> list[dict]:
        if batch_id is None:
            rows = self._conn.execute("SELECT * FROM samples ORDER BY created_at, sample_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM samples WHERE batch_id = ? ORDER BY created_at, sample_id",
                (batch_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_children(self, parent_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM samples WHERE parent_id = ? ORDER BY bottle", (parent_id,)
        ).fetchall()
        return [dict(r) for r in rows]
