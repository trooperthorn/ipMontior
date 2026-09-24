"""SQLite history: one row per poll, one row per state transition.

SQLite in WAL mode is plenty for a homelab: at 200 monitors on a 60 s
interval that is about 290k rows per day, and retention pruning keeps the
file bounded. All access goes through one connection guarded by a lock and
run in a worker thread, so the event loop never blocks on disk I/O.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .checks.base import CheckResult
from .state import Transition

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    monitor TEXT NOT NULL,
    ts REAL NOT NULL,
    result TEXT NOT NULL,
    value REAL,
    latency_ms REAL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS results_monitor_ts ON results(monitor, ts);
CREATE TABLE IF NOT EXISTS events (
    monitor TEXT NOT NULL,
    ts REAL NOT NULL,
    previous TEXT NOT NULL,
    current TEXT NOT NULL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""


class Store:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    def _exec(self, sql: str, args: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            cur = self._db.execute(sql, args)
            rows = cur.fetchall()
            self._db.commit()
            return rows

    async def _run(self, sql: str, args: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        return await asyncio.to_thread(self._exec, sql, args)

    async def record(self, monitor: str, ts: float, res: CheckResult) -> None:
        await self._run(
            "INSERT INTO results VALUES (?,?,?,?,?,?)",
            (monitor, ts, res.result.value, res.value, res.latency_ms, res.message),
        )

    async def record_event(self, monitor: str, tr: Transition) -> None:
        await self._run(
            "INSERT INTO events VALUES (?,?,?,?,?)",
            (monitor, tr.at, tr.previous.value, tr.current.value, tr.message),
        )

    async def history(self, monitor: str, hours: float) -> list[dict[str, Any]]:
        since = time.time() - hours * 3600
        rows = await self._run(
            "SELECT ts, result, value, latency_ms, message FROM results "
            "WHERE monitor=? AND ts>=? ORDER BY ts LIMIT 20000",
            (monitor, since),
        )
        return [dict(zip(("ts", "result", "value", "latency_ms", "message"), r)) for r in rows]

    async def events(self, limit: int = 200, monitor: str | None = None) -> list[dict[str, Any]]:
        if monitor:
            rows = await self._run(
                "SELECT monitor, ts, previous, current, message FROM events "
                "WHERE monitor=? ORDER BY ts DESC LIMIT ?", (monitor, limit))
        else:
            rows = await self._run(
                "SELECT monitor, ts, previous, current, message FROM events "
                "ORDER BY ts DESC LIMIT ?", (limit,))
        keys = ("monitor", "ts", "previous", "current", "message")
        return [dict(zip(keys, r)) for r in rows]

    async def hourly_series(self, monitor: str, days: float) -> list[tuple[float, float]]:
        """Hourly means of non-null values: [(bucket midpoint ts, mean)]."""
        since = time.time() - days * 86400
        rows = await self._run(
            "SELECT CAST(ts / 3600 AS INTEGER) AS h, AVG(value) FROM results "
            "WHERE monitor=? AND ts>=? AND value IS NOT NULL AND result != 'fail' "
            "GROUP BY h ORDER BY h",
            (monitor, since),
        )
        return [(h * 3600 + 1800.0, float(v)) for h, v in rows]

    async def availability(self, monitor: str, hours: float) -> float | None:
        """Percent of polls in the window that were not FAIL."""
        since = time.time() - hours * 3600
        rows = await self._run(
            "SELECT COUNT(*), SUM(result != 'fail') FROM results WHERE monitor=? AND ts>=?",
            (monitor, since),
        )
        total, ok = rows[0]
        return None if not total else round(ok / total * 100, 3)

    def _delete(self, sql: str, args: tuple[Any, ...]) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.rowcount

    async def prune(self, retention_days: int) -> int:
        """Drop poll rows past retention. Transitions are kept for at least a
        year because they are small and are the record you want in a review."""
        now = time.time()
        removed = await asyncio.to_thread(
            self._delete, "DELETE FROM results WHERE ts < ?", (now - retention_days * 86400,))
        await asyncio.to_thread(
            self._delete, "DELETE FROM events WHERE ts < ?",
            (now - max(retention_days, 365) * 86400,))
        return removed

    def close(self) -> None:
        with self._lock:
            self._db.close()
