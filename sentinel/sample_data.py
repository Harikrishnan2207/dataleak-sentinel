"""Synthetic customer table used by the Query Console.

Every name, e-mail address and number here is invented. E-mails use the reserved
example.com domain, so nothing can belong to a real person.
"""
from __future__ import annotations

import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

from .config import SAMPLE_DB_PATH

DEFAULT_ROWS = 20_000
COLUMNS = ["customer_id", "full_name", "email", "city", "segment", "credit_limit", "member_since"]

FIRST_NAMES = [
    "Aarav", "Meera", "Rohan", "Sana", "Vikram", "Isha", "Arjun", "Diya", "Karan", "Nisha",
    "Farhan", "Lakshmi", "Ravi", "Anita", "Suresh", "Priya", "Imran", "Kavya", "Manoj", "Divya",
    "Harish", "Pooja", "Sanjay", "Neha", "Akash", "Swati", "Rahul", "Ananya", "Vijay", "Tara",
]
LAST_NAMES = [
    "Nair", "Iyer", "Das", "Khan", "Rao", "Menon", "Pillai", "Sharma", "Mehta", "Joseph",
    "Ali", "Kumar", "Reddy", "Singh", "Patel", "Gupta", "Bose", "Shetty", "Varma", "Naidu",
    "Chopra", "Banerjee", "Kapoor", "Mishra", "Pandey", "Thomas", "George", "Verma", "Jain", "Roy",
]
CITIES = ["Chennai", "Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Pune", "Kolkata", "Kochi"]
SEGMENTS = ["Retail"] * 6 + ["SME"] * 2 + ["Corporate"] * 2


def ensure_customers_db(path: str | Path = SAMPLE_DB_PATH, rows: int = DEFAULT_ROWS, seed: int = 7) -> Path:
    """Create and fill the customers table if it is missing or empty. Safe to call repeatedly."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS customers ("
            "customer_id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL, "
            "city TEXT NOT NULL, segment TEXT NOT NULL, credit_limit INTEGER NOT NULL, "
            "member_since TEXT NOT NULL)"
        )
        if conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
            rng = random.Random(seed)
            start = date(2015, 1, 1)
            data = []
            for cid in range(1, rows + 1):
                first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
                data.append((
                    cid, f"{first} {last}", f"{first}.{last}{cid}@example.com".lower(),
                    rng.choice(CITIES), rng.choice(SEGMENTS), rng.randint(10, 500) * 1000,
                    (start + timedelta(days=rng.randint(0, 3600))).isoformat(),
                ))
            conn.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)", data)
        conn.commit()
    finally:
        conn.close()
    return path


def customer_count(path: str | Path = SAMPLE_DB_PATH) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    finally:
        conn.close()
