"""Guided live scenario: one normal access, one bulk extraction, scored and stored for real.

The record counts are entered by the simulation (they are not measured from a real query).
Scoring, alert creation and SQLite storage use the same code paths as the rest of the app.
"""
from __future__ import annotations

from .simulator import USERS

NORMAL_USER = USERS["U1001"]   # (user_id, username, department)
BULK_USER = USERS["U1011"]
NORMAL_ACCESS = "SELECT Query"
BULK_ACCESS = "Full Table Export"


def _first_row(df, log_id):
    rows = df[df["log_id"] == log_id]
    return rows.iloc[0] if not rows.empty else None


def run_guided_scenario(db, normal_records: int = 8, bulk_records: int = 3200) -> dict:
    """Log the two accesses, then collect everything the UI needs to narrate the story."""
    before = db.table_counts()
    normal = db.log_event(*NORMAL_USER, NORMAL_ACCESS, int(normal_records))
    bulk = db.log_event(*BULK_USER, BULK_ACCESS, int(bulk_records))
    after = db.table_counts()

    alerts = db.alerts_df()
    activity = db.activity_df()
    ids = [normal["log_id"], bulk["log_id"]]
    return {
        "normal": {**normal, "user": NORMAL_USER, "access_type": NORMAL_ACCESS, "records": int(normal_records)},
        "bulk": {**bulk, "user": BULK_USER, "access_type": BULK_ACCESS, "records": int(bulk_records)},
        "normal_alert": _first_row(alerts, normal["log_id"]),
        "bulk_alert": _first_row(alerts, bulk["log_id"]),
        "audit_rows": activity[activity["log_id"].isin(ids)].sort_values("log_id"),
        "counts_before": before,
        "counts_after": after,
        "unreviewed": int((alerts["status"] == "New").sum()),
        "thresholds": db.get_settings(),
        "db_name": db.path.name,
    }
