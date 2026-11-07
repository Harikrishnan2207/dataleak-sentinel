"""Rule-based detection engine.

Every access event gets a risk score (0-100) built from:
  1. Volume    - records accessed, mapped into a band using the configurable thresholds.
  2. Behaviour - bonus points for repeated high-volume access, unusual access
                 frequency, high cumulative volume inside a time window, and an
                 access that is unusual for that particular user (statistical baseline).

The score maps to a risk level: <=25 Low, 26-60 Medium, >60 High. Any triggered
behaviour rule guarantees at least Medium, so an access that looks harmless on
its own (for example a tiny query that is the 10th in a few minutes) still alerts.
"""
from __future__ import annotations

import math
import statistics
from collections import deque
from datetime import datetime, timedelta

import pandas as pd

from .config import (
    ANOMALY_SCALE_FLOOR,
    BASELINE_LIMIT,
    BONUS_ANOMALY,
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


def baseline_stats(history) -> tuple[float, float]:
    """Robust centre and spread of a user's record counts, on a log scale.

    Record counts are heavily skewed, so they are log-transformed. The centre is the
    median and the spread is the median absolute deviation (scaled to match a standard
    deviation), which a few large outliers cannot drag around the way a mean would.
    """
    logs = [math.log1p(max(0, int(r))) for r in history]
    centre = statistics.median(logs)
    mad = statistics.median(abs(v - centre) for v in logs)
    return centre, max(1.4826 * mad, ANOMALY_SCALE_FLOOR)


def anomaly_zscore(records: int, history) -> float:
    """Robust z-score of `records` against the user's own history (positive = larger than usual)."""
    centre, scale = baseline_stats(history)
    return (math.log1p(max(0, int(records))) - centre) / scale


def unusual_above(history, cfg) -> int:
    """Smallest record count that would be flagged as unusual for this baseline."""
    centre, scale = baseline_stats(history)
    return max(int(cfg["anomaly_min_records"]), math.ceil(math.expm1(centre + cfg["anomaly_z"] * scale)))


def score_event(records, ts, prior, cfg, baseline=None):
    """Score one access.

    `prior` holds (timestamp, records) of the same user's earlier accesses inside the
    time windows; `baseline` holds the record counts of the user's earlier accesses
    (any age, most recent BASELINE_LIMIT). Returns (score, list_of_reasons).
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

    # Rule 4: unusual for this user compared with their own history.
    if (
        baseline is not None
        and cfg.get("anomaly_enabled", 1)
        and len(baseline) >= cfg.get("anomaly_min_history", 8)
        and records >= cfg.get("anomaly_min_records", 10)
    ):
        z = anomaly_zscore(records, baseline)
        if z >= cfg.get("anomaly_z", 3.5):
            bonus += BONUS_ANOMALY
            typical = round(math.expm1(baseline_stats(baseline)[0]))
            reasons.append(
                f"Unusual for this user: {records:,} records vs typical {typical:,} "
                f"(robust z-score {z:.1f}, based on {len(baseline)} earlier accesses)"
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
    baselines: dict[str, deque] = {}
    rows = []
    for log_id, user_id, ts, n in zip(df["log_id"], df["user_id"], df["_ts"], df["records_accessed"]):
        ts = ts.to_pydatetime()
        n = int(n)
        prior = history.setdefault(str(user_id), deque())
        while prior and prior[0][0] < ts - window:
            prior.popleft()
        seen = baselines.setdefault(str(user_id), deque(maxlen=BASELINE_LIMIT))
        score, reasons = score_event(n, ts, prior, cfg, list(seen))
        rows.append((int(log_id), score, level_from_score(score), "; ".join(reasons)))
        prior.append((ts, n))
        seen.append(n)

    return pd.DataFrame(rows, columns=RESULT_COLUMNS)


def user_baselines(logs: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Per-user summary of what the detector currently treats as normal."""
    rows = []
    for (user_id, username), grp in logs.groupby(["user_id", "username"]):
        history = list(grp.sort_values("timestamp")["records_accessed"].tail(BASELINE_LIMIT))
        ready = len(history) >= cfg["anomaly_min_history"]
        centre, _ = baseline_stats(history)
        rows.append({
            "user_id": user_id, "username": username, "accesses": len(grp),
            "typical_records": round(math.expm1(centre)),
            "unusual_above": unusual_above(history, cfg) if ready else None,
            "status": "Baseline ready" if ready else f"Learning ({len(history)} of {cfg['anomaly_min_history']})",
        })
    return pd.DataFrame(rows).sort_values("accesses", ascending=False).reset_index(drop=True) if rows else pd.DataFrame(
        columns=["user_id", "username", "accesses", "typical_records", "unusual_above", "status"])
