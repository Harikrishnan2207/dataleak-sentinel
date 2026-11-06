import tempfile
import unittest
from pathlib import Path

from sentinel.database import SentinelDB
from sentinel.simulator import generate_demo_events


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "test.db"
        self.db = SentinelDB(self.path)
        self.db.init_schema()

    def tearDown(self):
        self.tmp.cleanup()

    def _load_demo(self):
        self.db.add_events(generate_demo_events(seed=1))
        return self.db.rescan()

    def test_demo_generates_all_scenarios(self):
        summary = self._load_demo()
        df = self.db.activity_df()
        self.assertEqual(summary["events"], len(df))
        self.assertEqual(set(df["risk_level"]), {"Low", "Medium", "High"})
        flagged = set(self.db.alerts_df()["username"])
        self.assertIn("farhan.ali", flagged)       # bulk extraction
        self.assertIn("lakshmi.nair", flagged)     # repeated high-volume
        self.assertIn("temp.contractor", flagged)  # unusual frequency
        self.assertNotIn("aarav.nair", flagged)    # normal user
        reasons = " ".join(self.db.alerts_df()["reason"])
        self.assertIn("Repeated high-volume", reasons)
        self.assertIn("Unusual access frequency", reasons)
        self.assertIn("Bulk extraction", reasons)

    def test_alert_default_status_is_new(self):
        self._load_demo()
        self.assertTrue((self.db.alerts_df()["status"] == "New").all())

    def test_mark_reviewed_persists_through_rescan(self):
        self._load_demo()
        alert = self.db.alerts_df().iloc[0]
        alert_id, log_id = int(alert["alert_id"]), int(alert["log_id"])

        self.db.mark_reviewed(alert_id)
        self.db.rescan()

        reviewed = self.db.alerts_df().set_index("log_id").loc[log_id, "status"]
        self.assertEqual(reviewed, "Reviewed")

    def test_persists_after_reopen(self):
        self._load_demo()
        n = len(self.db.activity_df())
        reopened = SentinelDB(self.path)
        reopened.init_schema()
        self.assertEqual(len(reopened.activity_df()), n)
        self.assertEqual(reopened.table_counts()["detections"], n)

    def test_clear_keeps_settings(self):
        self._load_demo()
        self.assertEqual(self.db.save_settings({"low_max": 30}), [])
        self.db.clear_data()
        self.assertEqual(self.db.table_counts(), {"access_logs": 0, "detections": 0, "alerts": 0})
        self.assertEqual(self.db.get_settings()["low_max"], 30)

    def test_threshold_change_and_rescan(self):
        self._load_demo()
        before = len(self.db.alerts_df())
        self.assertEqual(self.db.save_settings({"low_max": 200, "medium_max": 500}), [])
        self.db.rescan()
        self.assertLess(len(self.db.alerts_df()), before + 1)
        self.assertEqual(self.db.get_settings()["medium_max"], 500)

    def test_invalid_settings_rejected(self):
        errors = self.db.save_settings({"low_max": 50, "medium_max": 40})
        self.assertTrue(errors)
        self.assertEqual(self.db.get_settings()["low_max"], 20)

    def test_manual_event_creates_alert(self):
        res = self.db.log_event("U1001", "aarav.nair", "Finance", "SELECT * Query", 500)
        self.assertEqual(res["risk_level"], "High")
        alerts = self.db.alerts_df()
        self.assertEqual(len(alerts), 1)
        low = self.db.log_event("U1002", "meera.iyer", "Finance", "SELECT Query", 5)
        self.assertEqual(low["risk_level"], "Low")
        self.assertEqual(len(self.db.alerts_df()), 1)
        # Same user right after a 500-record pull: cumulative-volume rule fires.
        follow_up = self.db.log_event("U1001", "aarav.nair", "Finance", "SELECT Query", 5)
        self.assertEqual(follow_up["risk_level"], "Medium")
        self.assertIn("Cumulative volume", follow_up["reason"])

    def test_demo_is_reproducible_per_seed(self):
        from datetime import datetime
        now = datetime(2026, 1, 1, 12, 0, 0)
        self.assertEqual(generate_demo_events(5, now), generate_demo_events(5, now))
        self.assertNotEqual(generate_demo_events(5, now), generate_demo_events(6, now))


if __name__ == "__main__":
    unittest.main()
