"""
DFU 持久化存储模块
=================
使用 aiosqlite 提供告警记录、隔离操作等持久化存储。
"""

import json
import time
from pathlib import Path

import aiosqlite

_DB_DIR = Path(__file__).parent / "data"
_DB_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = str(_DB_DIR / "dfu.db")


class PersistenceStore:
    """持久化存储，基于 SQLite，支持告警与隔离操作记录。"""

    def __init__(self, db_path: str = _DB_PATH):
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self.is_connected = False

    async def connect(self) -> None:
        """连接数据库并建表（如不存在）。"""
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip      TEXT NOT NULL,
                dst_ip      TEXT,
                event_type  TEXT NOT NULL,
                severity    TEXT DEFAULT 'medium',
                indicator   TEXT NOT NULL,
                score       REAL DEFAULT 0.0,
                details     TEXT,
                timestamp   REAL NOT NULL,
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS isolation_actions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip   TEXT NOT NULL,
                action      TEXT NOT NULL,
                rule_id     TEXT NOT NULL,
                alert_id    INTEGER,
                details     TEXT,
                timestamp   REAL NOT NULL,
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
            CREATE INDEX IF NOT EXISTS idx_isolation_target ON isolation_actions(target_ip);
        """)
        await self._conn.commit()
        self.is_connected = True

    async def close(self) -> None:
        """关闭数据库连接。"""
        if self._conn:
            await self._conn.close()
            self._conn = None
            self.is_connected = False

    async def insert_alert(self, indicator: dict) -> int:
        """插入告警记录，返回自增 ID。"""
        if not self._conn:
            await self.connect()
        cur = await self._conn.execute(
            """INSERT INTO alerts (src_ip, dst_ip, event_type, severity, indicator, score, details, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                indicator.get("src_ip", ""),
                indicator.get("dst_ip", ""),
                indicator.get("event_type", "unknown"),
                indicator.get("severity", "medium"),
                json.dumps(indicator, ensure_ascii=False),
                indicator.get("score", 0.0),
                json.dumps(indicator.get("details", {}), ensure_ascii=False),
                indicator.get("timestamp", time.time()),
            ),
        )
        await self._conn.commit()
        return cur.lastrowid or 0

    async def insert_isolation_action(self, iso_data: dict) -> int:
        """插入隔离操作记录，返回自增 ID。"""
        if not self._conn:
            await self.connect()
        cur = await self._conn.execute(
            """INSERT INTO isolation_actions (target_ip, action, rule_id, alert_id, details, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                iso_data.get("target_ip", ""),
                iso_data.get("action", "unknown"),
                iso_data.get("rule_id", ""),
                iso_data.get("alert_id"),
                json.dumps(iso_data.get("details", {}), ensure_ascii=False),
                iso_data.get("timestamp", time.time()),
            ),
        )
        await self._conn.commit()
        return cur.lastrowid or 0

    async def query_alerts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """查询告警记录。"""
        if not self._conn:
            return []
        cur = await self._conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def query_isolation_actions(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """查询隔离操作记录。"""
        if not self._conn:
            return []
        cur = await self._conn.execute(
            "SELECT * FROM isolation_actions ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


# 单例
_instance: PersistenceStore | None = None


def get_persistence() -> PersistenceStore:
    """获取持久化存储单例。"""
    global _instance
    if _instance is None:
        _instance = PersistenceStore()
    return _instance
