"""Synthetic demo data. Every user, department and event here is invented."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .config import TIME_FORMAT

# (user_id, username, department)
EMPLOYEES = [
    ("U1001", "aarav.nair", "Finance"),
    ("U1002", "meera.iyer", "Finance"),
    ("U1003", "rohan.das", "HR"),
    ("U1004", "sana.khan", "HR"),
    ("U1005", "vikram.rao", "Sales"),
    ("U1006", "isha.menon", "Sales"),
    ("U1007", "arjun.pillai", "Engineering"),
    ("U1008", "diya.sharma", "Engineering"),
    ("U1009", "karan.mehta", "Support"),
    ("U1010", "nisha.joseph", "Support"),
    ("U1011", "farhan.ali", "Operations"),
    ("U1012", "lakshmi.nair", "Operations"),
    ("U1013", "temp.contractor", "Contractor"),
]
USERS = {uid: (uid, name, dept) for uid, name, dept in EMPLOYEES}

ACCESS_TYPES = [
    "SELECT Query", "Report View", "API Read", "CSV Export",
    "Report Export", "SELECT * Query", "Full Table Export", "Database Dump",
]

NORMAL_USERS = ["U1001", "U1002", "U1003", "U1004", "U1005", "U1006", "U1007", "U1008"]
MEDIUM_USERS = ["U1009", "U1010"]
BULK_USER = "U1011"
REPEAT_USER = "U1012"
BURST_USER = "U1013"


def _work_hours_minutes_ago(rng: random.Random, now: datetime) -> int:
    """Random point in the last 48 h, mostly during working hours (08:00-19:00)."""
    minutes = rng.randint(30, 48 * 60)
    for _ in range(25):
        minutes = rng.randint(30, 48 * 60)
        hour = (now - timedelta(minutes=minutes)).hour
        if 8 <= hour < 19 or rng.random() < 0.05:
            break
    return minutes


def generate_demo_events(seed: int = 42, now: datetime | None = None) -> list[dict]:
    """Build a mixed batch: normal, medium-risk, bulk extraction, repeated access, burst."""
    rng = random.Random(seed)
    now = (now or datetime.now()).replace(microsecond=0)
    events: list[dict] = []

    def add(uid: str, minutes_ago: float, access_type: str, records: int) -> None:
        user_id, username, dept = USERS[uid]
        ts = now - timedelta(minutes=minutes_ago)
        events.append({
            "user_id": user_id, "username": username, "department": dept,
            "timestamp": ts.strftime(TIME_FORMAT), "access_type": access_type,
            "records_accessed": int(records),
        })

    def baseline(uid: str, count: int) -> None:
        for _ in range(count):
            records = min(20, max(1, int(rng.lognormvariate(1.8, 0.7))))
            add(uid, _work_hours_minutes_ago(rng, now) + 240,
                rng.choice(["SELECT Query", "Report View", "API Read"]), records)

    # 1. Normal employee activity (1-20 records)
    for uid in NORMAL_USERS:
        for _ in range(rng.randint(12, 18)):
            records = min(20, max(1, int(rng.lognormvariate(1.8, 0.7))))
            add(uid, _work_hours_minutes_ago(rng, now),
                rng.choice(["SELECT Query", "Report View", "API Read"]), records)

    # 2. Medium-risk activity (21-100 records), spread out over the day
    for uid in MEDIUM_USERS:
        baseline(uid, 6)
        for _ in range(rng.randint(4, 6)):
            add(uid, _work_hours_minutes_ago(rng, now),
                rng.choice(["SELECT Query", "CSV Export", "Report Export"]), rng.randint(25, 95))

    # 3. High-risk bulk extraction
    baseline(BULK_USER, 8)
    add(BULK_USER, 190, "Full Table Export", rng.randint(2500, 4800))
    add(BULK_USER, 70, "SELECT * Query", rng.randint(900, 2400))

    # 4. Repeated suspicious access: several large pulls in under an hour
    baseline(REPEAT_USER, 8)
    for offset, records in zip([95, 86, 77, 68, 57], [85, 140, 210, 180, 320]):
        add(REPEAT_USER, offset, "CSV Export", records + rng.randint(-10, 10))

    # 5. Unusual frequency: many tiny queries in a few minutes
    baseline(BURST_USER, 4)
    for i in range(12):
        add(BURST_USER, 38 - i * 0.95 + rng.uniform(-0.2, 0.2), "API Read", rng.randint(3, 14))

    events.sort(key=lambda e: e["timestamp"])
    return events
