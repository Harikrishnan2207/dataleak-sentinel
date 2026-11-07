import tempfile
import unittest
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from sentinel.config import DEFAULT_SETTINGS
from sentinel.database import SentinelDB
from sentinel.detection import (
    anomaly_zscore, baseline_stats, evaluate_logs, level_from_score, score_event, unusual_above, user_baselines,
)
from sentinel.simulator import NORMAL_USERS, SPIKE_USER, generate_demo_events

CFG = dict(DEFAULT_SETTINGS)
T0 = datetime(2026, 1, 1, 12, 0, 0)
STEADY = [3, 4] * 10   # 20 earlier accesses of 3-4 rows


def score(records, baseline, cfg=CFG):
    s, reasons = score_event(records, T0, deque(), cfg, baseline)
    return s, level_from_score(s), reasons


class AnomalyRule(unittest.TestCase):
    def test_low_volume_spike_is_flagged_for_a_steady_user(self):
        s, level, reasons = score(19, STEADY)   # 19 is inside the Low volume band (1-20)
        self.assertEqual(level, "Medium")
        self.assertTrue(any("Unusual for this user" in r for r in reasons))

    def test_same_access_is_normal_without_a_baseline(self):
        self.assertEqual(score(19, None)[1], "Low")
        self.assertEqual(score(19, [])[1], "Low")

    def test_needs_enough_history(self):
        self.assertEqual(score(19, STEADY[:14])[1], "Low")
        self.assertEqual(score(19, STEADY[:15])[1], "Medium")

    def test_small_accesses_are_never_flagged(self):
        self.assertEqual(score(8, STEADY)[1], "Low")

    def test_busy_user_is_not_flagged_for_normal_variation(self):
        noisy = [2, 40, 3, 60, 5, 25, 8, 90, 4, 35, 6, 55, 3, 70, 9, 45]
        self.assertEqual(score(60, noisy)[2][0].startswith("Elevated"), True)
        self.assertFalse(any("Unusual for this user" in r for r in score(60, noisy)[2]))

    def test_can_be_switched_off(self):
        self.assertEqual(score(19, STEADY, {**CFG, "anomaly_enabled": 0})[1], "Low")

    def test_threshold_is_configurable(self):
        self.assertEqual(score(12, STEADY)[1], "Medium")
        self.assertEqual(score(12, STEADY, {**CFG, "anomaly_z": 12.0})[1], "Low")

    def test_median_is_robust_to_a_few_huge_pulls(self):
        clean = baseline_stats(STEADY)[0]
        poisoned = baseline_stats(STEADY + [5000, 5000, 5000])[0]
        self.assertLess(abs(poisoned - clean), 0.3)

    def test_zscore_and_unusual_above_agree(self):
        limit = unusual_above(STEADY, CFG)
        self.assertGreaterEqual(anomaly_zscore(limit, STEADY), CFG["anomaly_z"])
        self.assertLess(anomaly_zscore(limit - 1, STEADY), CFG["anomaly_z"] + 1e-9) if limit - 1 >= CFG["anomaly_min_records"] else None

    def test_evaluate_logs_uses_per_user_history_in_time_order(self):
        rows = [(i + 1, "A", (T0 + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S"), STEADY[i % 20]) for i in range(20)]
        rows.append((100, "A", (T0 + timedelta(hours=30)).strftime("%Y-%m-%d %H:%M:%S"), 19))
        rows.append((101, "B", (T0 + timedelta(hours=31)).strftime("%Y-%m-%d %H:%M:%S"), 19))   # B has no history
        res = evaluate_logs(pd.DataFrame(rows, columns=["log_id", "user_id", "timestamp", "records_accessed"]), CFG)
        by_id = res.set_index("log_id")
        self.assertEqual(by_id.loc[100, "risk_level"], "Medium")
        self.assertIn("Unusual for this user", by_id.loc[100, "reason"])
        self.assertEqual(by_id.loc[101, "risk_level"], "Low")
        self.assertTrue((by_id.loc[1:20, "risk_level"] == "Low").all())

    def test_user_baselines_table(self):
        rows = [(i + 1, "U1", "ann", (T0 + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S"), 3 + i % 2) for i in range(20)]
        rows += [(100 + i, "U2", "bob", (T0 + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S"), 5) for i in range(4)]
        table = user_baselines(
            pd.DataFrame(rows, columns=["log_id", "user_id", "username", "timestamp", "records_accessed"]), CFG
        ).set_index("user_id")
        self.assertEqual(table.loc["U1", "status"], "Baseline ready")
        self.assertGreaterEqual(table.loc["U1", "unusual_above"], CFG["anomaly_min_records"])
        self.assertTrue(table.loc["U2", "status"].startswith("Learning"))
        self.assertTrue(pd.isna(table.loc["U2", "unusual_above"]))
        self.assertTrue(user_baselines(pd.DataFrame(columns=["user_id", "username", "timestamp", "records_accessed"]), CFG).empty)


class AnomalyWithDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SentinelDB(Path(self.tmp.name) / "a.db")
        self.db.init_schema()

    def tearDown(self):
        self.tmp.cleanup()

    def test_settings_keep_their_types_and_validate(self):
        self.assertEqual(self.db.save_settings({"anomaly_z": 5.5, "anomaly_min_history": 20, "anomaly_enabled": 0}), [])
        cfg = self.db.get_settings()
        self.assertEqual(cfg["anomaly_z"], 5.5)
        self.assertIsInstance(cfg["anomaly_z"], float)
        self.assertEqual(cfg["anomaly_min_history"], 20)
        self.assertIsInstance(cfg["anomaly_min_history"], int)
        self.assertEqual(cfg["anomaly_enabled"], 0)
        for bad in ({"anomaly_z": 0}, {"anomaly_min_history": 2}, {"anomaly_enabled": 2}, {"anomaly_min_records": 0}):
            self.assertTrue(self.db.save_settings(bad), bad)
        self.assertEqual(self.db.get_settings()["anomaly_z"], 5.5)   # invalid saves changed nothing

    def test_log_event_uses_the_full_history_not_just_the_recent_window(self):
        old = [{
            "user_id": "U1001", "username": "aarav.nair", "department": "Finance",
            "timestamp": (datetime.now() - timedelta(days=3, hours=i)).strftime("%Y-%m-%d %H:%M:%S"),
            "access_type": "SELECT Query", "records_accessed": 3 + i % 2,
        } for i in range(20)]
        self.db.add_events(old)
        self.assertEqual(self.db.rescan()["alerts"], 0)
        res = self.db.log_event("U1001", "aarav.nair", "Finance", "SELECT Query", 19)
        self.assertEqual(res["risk_level"], "Medium")
        self.assertIn("Unusual for this user", res["reason"])
        self.assertEqual(len(self.db.alerts_df()), 1)
        # A user with no history making the same access is not flagged.
        other = self.db.log_event("U1002", "meera.iyer", "Finance", "SELECT Query", 19)
        self.assertEqual(other["risk_level"], "Low")

    def test_rescan_and_log_event_agree(self):
        old = [{
            "user_id": "U1001", "username": "aarav.nair", "department": "Finance",
            "timestamp": (datetime.now() - timedelta(days=3, hours=i)).strftime("%Y-%m-%d %H:%M:%S"),
            "access_type": "SELECT Query", "records_accessed": 3 + i % 2,
        } for i in range(20)]
        self.db.add_events(old)
        self.db.rescan()
        live = self.db.log_event("U1001", "aarav.nair", "Finance", "SELECT Query", 19)
        self.db.rescan()
        again = self.db.activity_df().iloc[0]
        self.assertEqual((int(again["risk_score"]), again["risk_level"]), (live["risk_score"], live["risk_level"]))


class DemoData(unittest.TestCase):
    NOW = datetime(2026, 1, 1, 12, 0, 0)

    def _evaluate(self, seed):
        df = pd.DataFrame(generate_demo_events(seed, self.NOW))
        df["log_id"] = range(1, len(df) + 1)
        return evaluate_logs(df, CFG).merge(df, on="log_id")

    def test_demo_spike_user_is_flagged_only_by_the_baseline(self):
        for seed in (1, 2, 3, 42):
            res = self._evaluate(seed)
            spike = res[(res["user_id"] == "U1014") & (res["records_accessed"] == 19)]
            self.assertEqual(len(spike), 1, seed)
            self.assertIn("Unusual for this user", spike.iloc[0]["reason"])
            self.assertEqual(spike.iloc[0]["risk_level"], "Medium")
            self.assertNotIn("Elevated volume", spike.iloc[0]["reason"])   # volume alone says Low

    def test_calibration_guard_on_normal_users(self):
        """Deterministic guard: ordinary synthetic users stay well under 1% false anomaly alerts."""
        flagged = total = 0
        for seed in range(40):
            res = self._evaluate(seed)
            normal = res[res["user_id"].isin(NORMAL_USERS)]
            flagged += int(normal["reason"].str.contains("Unusual for this user").sum())
            total += len(normal)
        self.assertGreater(total, 4000)
        self.assertLess(flagged / total, 0.01)

    def test_spike_user_exists_in_roster(self):
        from sentinel.simulator import USERS
        self.assertEqual(USERS[SPIKE_USER][1], "tara.george")


if __name__ == "__main__":
    unittest.main()
