"""SQLite persistence: access logs, detection results, alerts and settings."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pandas as pd

from .config import BASELINE_LIMIT, DB_PATH, DEFAULT_SETTINGS, TIME_FORMAT, validate_settings
from .detection import evaluate_logs

SCHEMA = """
CREATE TABLE IF NOT EXISTS access_logs (
    log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          TEXT    NOT NULL,
    username         TEXT    NOT NULL,
    department       TEXT    NOT NULL,
    timestamp        TEXT    NOT NULL,
    access_type      TEXT    NOT NULL,
    records_accessed INTEGER NOT NULL CHECK (records_accessed >= 0),
    source           TEXT    NOT NULL DEFAULT 'simulated',
    query_text       TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_user_time ON access_logs (user_id, timestamp);

CREATE TABLE IF NOT EXISTS detections (
    log_id       INTEGER PRIMARY KEY REFERENCES access_logs (log_id) ON DELETE CASCADE,
    risk_score   INTEGER NOT NULL,
    risk_level   TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    evaluated_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id           INTEGER NOT NULL UNIQUE REFERENCES access_logs (log_id) ON DELETE CASCADE,
    user_id          TEXT    NOT NULL,
    username         TEXT    NOT NULL,
    timestamp        TEXT    NOT NULL,
    records_accessed INTEGER NOT NULL,
    risk_score       INTEGER NOT NULL,
    risk_level       TEXT    NOT NULL,
    reason           TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'New'
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

LOG_COLUMNS = "log_id, user_id, username, department, timestamp, records_accessed"


class SentinelDB:
    """Thin wrapper around a SQLite file. Each call opens and closes its own connection."""

    def __init__(self, path: str | Path = DB_PATH):
        self.path = Path(path)

    @contextmanager
    def _conn(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---------------------------------------------------------------- setup
    def init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            # Safe migration: add status column to existing databases.
            # SQLite raises OperationalError if the column already exists; ignore it.
            try:
                conn.execute(
                    "ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'New'"
                )
            except sqlite3.OperationalError:
                pass
            # Safe migration: databases created before the Query Console lack query_text.
            columns = [row[1] for row in conn.execute("PRAGMA table_info(access_logs)")]
            if "query_text" not in columns:
                conn.execute("ALTER TABLE access_logs ADD COLUMN query_text TEXT")

    # ------------------------------------------------------------- settings
    def get_settings(self) -> dict[str, float]:
        cfg = dict(DEFAULT_SETTINGS)
        with self._conn() as conn:
            stored = dict(conn.execute("SELECT key, value FROM settings").fetchall())
        for key in cfg:
            if key in stored:
                try:
                    # Keep each setting's own type (most are whole numbers, anomaly_z is a decimal).
                    cfg[key] = float(stored[key]) if isinstance(cfg[key], float) else int(stored[key])
                except ValueError:
                    pass
        return cfg

    def save_settings(self, cfg: dict[str, float]) -> list[str]:
        """Validate and store settings. Returns validation errors (nothing saved if any)."""
        merged = {
            **DEFAULT_SETTINGS,
            **{
                k: (float(v) if isinstance(DEFAULT_SETTINGS[k], float) else int(v))
                for k, v in cfg.items() if k in DEFAULT_SETTINGS
            },
        }
        errors = validate_settings(merged)
        if errors:
            return errors
        with self._conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                [(k, str(v)) for k, v in merged.items()],
            )
        return []

    def reset_settings(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM settings")

    # ----------------------------------------------------------------- data
    def add_events(self, events: list[dict]) -> int:
        """Insert raw access events (no detection). Call rescan() afterwards."""
        rows = [
            (
                e["user_id"], e["username"], e["department"], e["timestamp"],
                e["access_type"], int(e["records_accessed"]),
            )
            for e in events
        ]
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO access_logs "
                "(user_id, username, department, timestamp, access_type, records_accessed) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def rescan(self) -> dict[str, int]:
        """Re-run detection over every stored log with the current settings.

        Analyst review statuses are preserved: any alert that existed before the
        rescan with status 'Reviewed' keeps that status after rebuilding.
        """
        cfg = self.get_settings()
        now = datetime.now().strftime(TIME_FORMAT)
        with self._conn() as conn:
            # Snapshot existing statuses so analyst reviews survive the rebuild.
            saved_statuses: dict[int, str] = dict(
                conn.execute("SELECT log_id, status FROM alerts").fetchall()
            )
            logs = pd.read_sql_query(f"SELECT {LOG_COLUMNS} FROM access_logs", conn)
            results = evaluate_logs(logs, cfg)
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM detections")
            if results.empty:
                return {"events": 0, "alerts": 0}
            conn.executemany(
                "INSERT INTO detections (log_id, risk_score, risk_level, reason, evaluated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [(r.log_id, r.risk_score, r.risk_level, r.reason, now) for r in results.itertuples()],
            )
            merged = results[results["risk_level"] != "Low"].merge(logs, on="log_id")
            conn.executemany(
                "INSERT INTO alerts (log_id, user_id, username, timestamp, records_accessed, "
                "risk_score, risk_level, reason, created_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        int(r.log_id), r.user_id, r.username, r.timestamp, int(r.records_accessed),
                        int(r.risk_score), r.risk_level, r.reason, now,
                        saved_statuses.get(int(r.log_id), "New"),
                    )
                    for r in merged.itertuples()
                ],
            )
            return {"events": len(results), "alerts": len(merged)}

    def log_event(
        self,
        user_id: str,
        username: str,
        department: str,
        access_type: str,
        records: int,
        timestamp: datetime | None = None,
        query_text: str | None = None,
        source: str = "manual-simulated",
    ) -> dict:
        """Store one new access, run detection on it and raise an alert if suspicious."""
        cfg = self.get_settings()
        ts = (timestamp or datetime.now()).replace(microsecond=0)
        ts_text = ts.strftime(TIME_FORMAT)
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO access_logs "
                "(user_id, username, department, timestamp, access_type, records_accessed, source, query_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, username, department, ts_text, access_type, int(records), source, query_text),
            )
            log_id = cur.lastrowid
            # The user's recent history (time windows) and baseline (older accesses) both come from this.
            recent = pd.read_sql_query(
                f"SELECT {LOG_COLUMNS} FROM access_logs "
                "WHERE user_id = ? AND timestamp <= ? "
                "ORDER BY timestamp DESC, log_id DESC LIMIT ?",
                conn, params=(user_id, ts_text, 2 * BASELINE_LIMIT),
            )
            results = evaluate_logs(recent, cfg)
            row = results[results["log_id"] == log_id].iloc[0]
            score, level, reason = int(row["risk_score"]), str(row["risk_level"]), str(row["reason"])
            now = datetime.now().strftime(TIME_FORMAT)
            conn.execute(
                "INSERT INTO detections (log_id, risk_score, risk_level, reason, evaluated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (log_id, score, level, reason, now),
            )
            if level != "Low":
                conn.execute(
                    "INSERT INTO alerts (log_id, user_id, username, timestamp, records_accessed, "
                    "risk_score, risk_level, reason, created_at, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'New')",
                    (log_id, user_id, username, ts_text, int(records), score, level, reason, now),
                )
        return {"log_id": log_id, "risk_score": score, "risk_level": level, "reason": reason}

    def clear_data(self) -> None:
        """Delete all logs, detections and alerts. Settings are kept."""
        with self._conn() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM detections")
            conn.execute("DELETE FROM access_logs")
            conn.execute(
                "DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'access_logs')"
            )

    # -------------------------------------------------------------- queries
    def activity_df(self) -> pd.DataFrame:
        query = """
            SELECT l.log_id, l.user_id, l.username, l.department, l.timestamp, l.access_type,
                   l.records_accessed, d.risk_score, d.risk_level, d.reason, l.source, l.query_text
            FROM access_logs l
            LEFT JOIN detections d ON d.log_id = l.log_id
            ORDER BY l.timestamp DESC, l.log_id DESC
        """
        with self._conn() as conn:
            df = pd.read_sql_query(query, conn)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def alerts_df(self) -> pd.DataFrame:
        query = """
            SELECT alert_id, log_id, user_id, username, timestamp, records_accessed,
                   risk_score, risk_level, reason, created_at, status
            FROM alerts
            ORDER BY timestamp DESC, alert_id DESC
        """
        with self._conn() as conn:
            df = pd.read_sql_query(query, conn)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def mark_reviewed(self, alert_id: int) -> None:
        """Set the status of a single alert to 'Reviewed'."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE alerts SET status = 'Reviewed' WHERE alert_id = ?",
                (int(alert_id),),
            )

    def table_counts(self) -> dict[str, int]:
        with self._conn() as conn:
            return {
                t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("access_logs", "detections", "alerts")
            }
