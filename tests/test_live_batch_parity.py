"""Scoring one access live (log_event) must give the same answer as re-scanning everything (rescan)."""
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from sentinel.config import TIME_FORMAT
from sentinel.database import SentinelDB
from sentinel.detection import evaluate_logs
from sentinel.evaluation import generate_labelled_dataset


def _event(user, ts, records):
    return {"user_id": user, "username": f"name-{user}", "department": "Finance",
            "timestamp": ts.strftime(TIME_FORMAT), "access_type": "SELECT Query", "records_accessed": records}


class ParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = SentinelDB(Path(self.tmp.name) / "parity.db")
        self.db.init_schema()

    def tearDown(self):
        self.tmp.cleanup()

    def _stored(self, log_id):
        row = self.db.activity_df().set_index("log_id").loc[log_id]
        return int(row["risk_score"]), row["risk_level"], row["reason"]

    def test_user_with_more_rows_in_the_window_than_the_old_lookup_limit(self):
        """450 accesses inside the 12-hour window: live scoring must still see all of them."""
        now = datetime.now().replace(microsecond=0)
        self.db.add_events([_event("U1", now - timedelta(hours=5, seconds=-40 * i), 2) for i in range(450)])
        self.db.rescan()
        live = self.db.log_event("U1", "name-U1", "Finance", "SELECT Query", 2)
        self.db.rescan()
        self.assertEqual((live["risk_score"], live["risk_level"], live["reason"]), self._stored(live["log_id"]))
        self.assertIn("902 records", live["reason"])   # 450 earlier accesses x 2 rows + this one

    def test_old_baseline_and_recent_window_are_both_used(self):
        now = datetime.now().replace(microsecond=0)
        old = [_event("U2", now - timedelta(days=3, hours=i), 3 + i % 2) for i in range(30)]
        recent = [_event("U2", now - timedelta(minutes=5 * i), 4) for i in range(1, 11)]
        self.db.add_events(old + recent)
        self.db.rescan()
        live = self.db.log_event("U2", "name-U2", "Finance", "SELECT Query", 19)
        self.db.rescan()
        self.assertEqual((live["risk_score"], live["risk_level"], live["reason"]), self._stored(live["log_id"]))
        self.assertIn("Unusual for this user", live["reason"])

    def test_realistic_organisation_matches_a_full_rescan(self):
        """Hold back each of ten users' latest access, score them live, compare with scoring everything at once."""
        data = generate_labelled_dataset(1000)
        data = data[data["kind"] == "ordinary"].reset_index(drop=True)
        data["log_id"] = range(1, len(data) + 1)
        batch = evaluate_logs(data, dict(self.db.get_settings())).set_index("log_id")
        last = data.sort_values(["timestamp", "log_id"]).groupby("user_id").tail(1).head(10)
        held = set(last["log_id"])
        rest = data[~data["log_id"].isin(held)]
        self.db.add_events([{
            "user_id": r.user_id, "username": r.username, "department": "Finance", "timestamp": r.timestamp,
            "access_type": "SELECT Query", "records_accessed": int(r.records_accessed)} for r in rest.itertuples()])
        self.db.rescan()
        for r in last.sort_values("timestamp").itertuples():
            live = self.db.log_event(r.user_id, r.username, "Finance", "SELECT Query", int(r.records_accessed),
                                     timestamp=datetime.strptime(r.timestamp, TIME_FORMAT))
            expected = batch.loc[r.log_id]
            self.assertEqual((live["risk_score"], live["risk_level"], live["reason"]),
                             (int(expected["risk_score"]), expected["risk_level"], expected["reason"]), r.user_id)


if __name__ == "__main__":
    unittest.main()
