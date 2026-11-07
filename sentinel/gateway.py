"""Monitored query gateway.

A simulated user runs a SELECT against the synthetic customers table. The gateway
  1. rejects anything that is not a single, read-only SELECT,
  2. runs it on a read-only connection with a time limit,
  3. counts the rows the query actually returned, and
  4. sends that measured count to the normal scoring, alert and audit-log code.

Limits worth knowing: only queries sent through this gateway are monitored, the
user identity is simulated (no real login), and monitoring is by rows returned, so
an aggregate such as COUNT(*) returns one row and scores as harmless.
"""
from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

from .config import SAMPLE_DB_PATH
from .sample_data import ensure_customers_db

MAX_SQL_LENGTH = 2000
MAX_COUNTED_ROWS = 200_000
PREVIEW_ROWS = 20
TIMEOUT_SECONDS = 5.0
LOGGED_SQL_LENGTH = 500

PREPARED_QUERIES = {
    "Look up one customer": "SELECT customer_id, full_name, email, city FROM customers WHERE customer_id = 1042",
    "One city report (60 rows)": "SELECT customer_id, full_name, segment, credit_limit FROM customers WHERE city = 'Chennai' LIMIT 60",
    "Segment export": "SELECT * FROM customers WHERE segment = 'Corporate'",
    "Full table dump": "SELECT * FROM customers",
    "Custom query": None,
}

# SQLite authorizer action codes (numeric so this works on every Python version).
_SQLITE_OK, _SQLITE_DENY = 0, 1
_ACTION_READ, _ACTION_SELECT, _ACTION_FUNCTION = 20, 21, 31
_ALLOWED_FUNCTIONS = {
    "count", "sum", "avg", "min", "max", "lower", "upper", "length", "substr", "round",
    "coalesce", "ifnull", "nullif", "abs", "date", "datetime", "strftime", "typeof",
    "instr", "replace", "trim", "ltrim", "rtrim", "like", "glob", "group_concat",
}


class QueryRejected(Exception):
    """The query was refused or failed; the message is safe to show to the user."""


def _authorizer(action, arg1, arg2, db_name, source):
    if action in (_ACTION_READ, _ACTION_SELECT):
        return _SQLITE_OK
    if action == _ACTION_FUNCTION and str(arg2 or arg1 or "").lower() in _ALLOWED_FUNCTIONS:
        return _SQLITE_OK
    return _SQLITE_DENY


def validate_select(sql: str) -> str:
    """Return the cleaned SQL or raise QueryRejected."""
    cleaned = (sql or "").strip().rstrip(";").strip()
    if not cleaned:
        raise QueryRejected("Enter a SELECT query first.")
    if len(cleaned) > MAX_SQL_LENGTH:
        raise QueryRejected(f"Query is too long (limit {MAX_SQL_LENGTH} characters).")
    if ";" in cleaned:
        raise QueryRejected("Only one statement is allowed (no semicolons inside the query).")
    if not re.match(r"select\b", cleaned, re.IGNORECASE):
        raise QueryRejected("Only read-only SELECT queries are allowed.")
    return cleaned


def classify_access(sql: str) -> str:
    return "SELECT * Query" if re.match(r"select\s+(distinct\s+)?\*", sql, re.IGNORECASE) else "SELECT Query"


def _open_readonly(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.set_authorizer(_authorizer)
    return conn


def execute_measured(
    sql: str,
    path: str | Path = SAMPLE_DB_PATH,
    preview_rows: int = PREVIEW_ROWS,
    max_counted: int = MAX_COUNTED_ROWS,
    timeout_s: float = TIMEOUT_SECONDS,
) -> dict:
    """Run a validated SELECT read-only and return columns, a preview and the measured row count."""
    sql = validate_select(sql)
    path = ensure_customers_db(path)
    conn = _open_readonly(Path(path))
    deadline = time.monotonic() + timeout_s
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
    try:
        cur = conn.execute(sql)
        if cur.description is None:
            raise QueryRejected("Only read-only SELECT queries are allowed.")
        columns = [d[0] for d in cur.description]
        preview: list[tuple] = []
        total, truncated = 0, False
        while True:
            batch = cur.fetchmany(1000)
            if not batch:
                break
            if len(preview) < preview_rows:
                preview.extend(batch[: preview_rows - len(preview)])
            total += len(batch)
            if total > max_counted:
                total, truncated = max_counted, True
                break
    except QueryRejected:
        raise
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).lower():
            raise QueryRejected(f"Query stopped: it ran longer than {timeout_s:g} seconds.") from exc
        raise QueryRejected(f"SQL error: {exc}") from exc
    except sqlite3.DatabaseError as exc:
        raise QueryRejected(f"Query rejected: {exc}") from exc
    finally:
        conn.close()
    return {"sql": sql, "columns": columns, "preview": preview, "records": total, "truncated": truncated}


def run_monitored_query(db, user: tuple, sql: str, path: str | Path = SAMPLE_DB_PATH, **limits) -> dict:
    """Run the query, then score and store the access using the measured row count.

    `user` is (user_id, username, department). Rejected queries raise QueryRejected and are not logged.
    """
    measured = execute_measured(sql, path, **limits)
    access_type = classify_access(measured["sql"])
    log = db.log_event(
        user[0], user[1], user[2], access_type, measured["records"],
        query_text=measured["sql"][:LOGGED_SQL_LENGTH], source="gateway",
    )
    alerts = db.alerts_df()
    match = alerts[alerts["log_id"] == log["log_id"]]
    return {
        **measured, "user": user, "access_type": access_type, "log": log,
        "alert_id": int(match.iloc[0]["alert_id"]) if not match.empty else None,
    }
