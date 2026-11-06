"""Central configuration: paths, default thresholds, colours and validation."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
# Override with the DATALEAK_DB_PATH environment variable (used by the tests).
DB_PATH = Path(os.environ.get("DATALEAK_DB_PATH", DATA_DIR / "dataleak_sentinel.db"))

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# User-configurable detection settings (stored in the SQLite `settings` table).
DEFAULT_SETTINGS: dict[str, int] = {
    "low_max": 20,              # 1..low_max records            -> Low volume
    "medium_max": 100,          # low_max+1..medium_max records -> Medium volume; above -> High
    "repeat_min_records": 50,   # an access counts as "high-volume" at or above this size
    "repeat_count": 3,          # this many high-volume accesses ...
    "repeat_window_min": 60,    # ... inside this window = repeated high-volume access
    "freq_count": 10,           # this many accesses ...
    "freq_window_min": 15,      # ... inside this window = unusual frequency
    "cumulative_limit": 500,    # records pulled by one user inside repeat_window_min
}

# Risk score bands (0-100). Volume alone maps a record count into a band;
# behavioural rules add points and can push an access into a higher band.
SCORE_LOW_MAX = 25
SCORE_MEDIUM_MAX = 60
BONUS_REPEATED = 15
BONUS_FREQUENCY = 10
BONUS_CUMULATIVE = 10

RISK_LEVELS = ["Low", "Medium", "High"]
RISK_COLORS = {"Low": "#34D399", "Medium": "#FBBF24", "High": "#F87171"}
ACCENT = "#38BDF8"


def validate_settings(cfg: dict[str, int]) -> list[str]:
    """Return a list of human-readable problems (empty list = valid)."""
    errors: list[str] = []
    if cfg["low_max"] < 1:
        errors.append("The low-risk limit must be at least 1 record.")
    if cfg["medium_max"] <= cfg["low_max"]:
        errors.append("The medium-risk limit must be greater than the low-risk limit.")
    if cfg["repeat_min_records"] < 1:
        errors.append("High-volume access must start at 1 record or more.")
    if cfg["repeat_count"] < 2:
        errors.append("Repeated access needs at least 2 accesses.")
    if cfg["freq_count"] < 2:
        errors.append("Unusual frequency needs at least 2 accesses.")
    if cfg["repeat_window_min"] < 1 or cfg["freq_window_min"] < 1:
        errors.append("Time windows must be at least 1 minute.")
    if cfg["cumulative_limit"] < 1:
        errors.append("The cumulative volume limit must be at least 1 record.")
    return errors
