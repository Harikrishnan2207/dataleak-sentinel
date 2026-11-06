"""Rule-based detection engine.

Every access event gets a risk score (0-100) built from:
  1. Volume    - records accessed, mapped into a band using the configurable thresholds.
  2. Behaviour - bonus points for repeated high-volume access, unusual access
                 frequency and high cumulative volume inside a time window.

The score maps to a risk level: <=25 Low, 26-60 Medium, >60 High. Any triggered
behaviour rule guarantees at least Medium, so an access that looks harmless on
its own (for example a tiny query that is the 10th in a few minutes) still alerts.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

import pandas as pd

from .config import (
    BONUS_CUMULATIVE,
    BONUS_FREQUENCY,
    BONUS_REPEATED,
    SCORE_LOW_MAX,
    SCORE_MEDIUM_MAX,
)

RESULT_COLUMNS = ["log_id", "risk_score", "risk_level", "reason"]


def level_from_score(score: int) -> str:
    if score <= SCORE_LOW_MAX:
        return "Low"
    if score <= SCORE_MEDIUM_MAX:
        return "Medium"
    return "High"


def volume_score(records: int, cfg: dict[str, int]) -> int:
    """Map a record count to a base score inside its volume band."""
    low, med = cfg["low_max"], cfg["medium_max"]
    if records <= low:
        return max(1, round(SCORE_LOW_MAX * records / low))
    if records <= med:
        span = SCORE_MEDIUM_MAX - SCORE_LOW_MAX - 1
        return SCORE_LOW_MAX + 1 + round(span * (records - low) / (med - low))
    # High band: 61..85, saturating at 6x the medium limit.
    extra = min(1.0, (records - med) / (5 * med))
    return SCORE_MEDIUM_MAX + 1 + round(24 * extra)


def score_event(records, ts, prior, cfg):
    """Score one access.

    `prior` holds (timestamp, records) of the same user's earlier accesses.
    Returns (score, list_of_reasons).
    """
    low, med = cfg["low_max"], cfg["medium_max"]
    reasons: list[str] = []

    if records > med:
        reasons.append(
            f"Bulk extraction: {records:,} records exceeds the high-risk threshold of {med:,}"
        )
    elif records > low:
        reasons.append(
            f"Elevated volume: {records:,} records exceeds the low-risk limit of {low:,}"
        )

    bonus = 0
    repeat_cut = ts - timedelta(minutes=cfg["repeat_window_min"])
    freq_cut = ts - timedelta(minutes=cfg["freq_window_min"])
    in_repeat_window = [(t, r) for t, r in prior if t >= repeat_cut]

    # Rule 1: repeated high-volume access.
    if records >= cfg["repeat_min_records"]:
        big = sum(1 for _, r in in_repeat_window if r >= cfg["repeat_min_records"]) + 1
        if big >= cfg["repeat_count"]:
            bonus += BONUS_REPEATED
            reasons.append(
                f"Repeated high-volume access: {big} accesses of at least "
                f"{cfg['repeat_min_records']:,} records within {cfg['repeat_window_min']} min"
            )

    # Rule 2: unusual access frequency.
    recent = sum(1 for t, _ in prior if t >= freq_cut) + 1
    if recent >= cfg["freq_count"]:
        bonus += BONUS_FREQUENCY
        reasons.append(
            f"Unusual access frequency: {recent} accesses within {cfg['freq_window_min']} min"
        )

    # Rule 3: cumulative volume inside the window.
    total = records + sum(r for _, r in in_repeat_window)
    if in_repeat_window and total >= cfg["cumulative_limit"]:
        bonus += BONUS_CUMULATIVE
        reasons.append(
            f"Cumulative volume: {total:,} records within {cfg['repeat_window_min']} min"
        )

    base = volume_score(records, cfg)
    if bonus:
        # A triggered behaviour rule always lifts the access to at least Medium,
        # even when every individual query is small.
        base = max(base, SCORE_LOW_MAX + 1)
    score = min(100, base + bonus)
    if not reasons:
        reasons.append("Within normal volume and frequency")
    return score, reasons


def evaluate_logs(logs: pd.DataFrame, cfg: dict[str, int]) -> pd.DataFrame:
    """Evaluate every log row in chronological order.

    `logs` needs the columns: log_id, user_id, timestamp, records_accessed.
    Returns a DataFrame with RESULT_COLUMNS.
    """
    if logs.empty:
        return pd.DataFrame(columns=RESULT_COLUMNS)

    df = logs[["log_id", "user_id", "timestamp", "records_accessed"]].copy()
    df["_ts"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(["_ts", "log_id"], kind="stable")

    window = timedelta(minutes=max(cfg["repeat_window_min"], cfg["freq_window_min"]))
    history: dict[str, deque] = {}
    rows = []
    for log_id, user_id, ts, n in zip(df["log_id"], df["user_id"], df["_ts"], df["records_accessed"]):
        ts = ts.to_pydatetime()
        n = int(n)
        prior = history.setdefault(str(user_id), deque())
        while prior and prior[0][0] < ts - window:
            prior.popleft()
        score, reasons = score_event(n, ts, prior, cfg)
        rows.append((int(log_id), score, level_from_score(score), "; ".join(reasons)))
        prior.append((ts, n))

    return pd.DataFrame(rows, columns=RESULT_COLUMNS)
