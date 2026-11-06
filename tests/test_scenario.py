import tempfile
import unittest
from pathlib import Path

from sentinel.database import SentinelDB
from sentinel.scenario import run_guided_scenario


class GuidedScenarioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scenario.db"
        self.db = SentinelDB(self.path)
        self.db.init_schema()

    def tearDown(self):
        self.tmp.cleanup()

    def test_story_normal_then_bulk(self):
        r = run_guided_scenario(self.db, 8, 3200)
        self.assertEqual(r["normal"]["risk_level"], "Low")
        self.assertEqual(r["bulk"]["risk_level"], "High")
        self.assertIsNone(r["normal_alert"])
        self.assertIsNotNone(r["bulk_alert"])
        self.assertEqual(r["bulk_alert"]["status"], "New")
        self.assertEqual(r["unreviewed"], 1)
        self.assertEqual(r["counts_before"]["access_logs"], 0)
        self.assertEqual(r["counts_after"], {"access_logs": 2, "detections": 2, "alerts": 1})
        self.assertEqual(len(r["audit_rows"]), 2)

    def test_scores_follow_configured_thresholds(self):
        self.db.save_settings({"low_max": 5000, "medium_max": 9000})
        r = run_guided_scenario(self.db, 8, 3200)
        self.assertEqual(r["bulk"]["risk_level"], "Low")
        self.assertIsNone(r["bulk_alert"])

    def test_scenario_is_persisted(self):
        run_guided_scenario(self.db, 8, 3200)
        reopened = SentinelDB(self.path)
        reopened.init_schema()
        self.assertEqual(reopened.table_counts()["access_logs"], 2)
        self.assertEqual(len(reopened.alerts_df()), 1)

    def test_repeating_the_scenario_accumulates_history(self):
        run_guided_scenario(self.db, 8, 3200)
        r = run_guided_scenario(self.db, 8, 3200)
        self.assertEqual(r["counts_after"]["access_logs"], 4)
        self.assertEqual(r["bulk"]["risk_level"], "High")


if __name__ == "__main__":
    unittest.main()
