import unittest
from collections import deque
from datetime import datetime, timedelta

import pandas as pd

from sentinel.config import DEFAULT_SETTINGS
from sentinel.detection import evaluate_logs, level_from_score, score_event, volume_score

CFG = dict(DEFAULT_SETTINGS)
T0 = datetime(2026, 1, 1, 12, 0, 0)


def level(records):
    return level_from_score(score_event(records, T0, deque(), CFG)[0])


class VolumeTiers(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(level(1), "Low")
        self.assertEqual(level(20), "Low")
        self.assertEqual(level(21), "Medium")
        self.assertEqual(level(100), "Medium")
        self.assertEqual(level(101), "High")
        self.assertEqual(level(5000), "High")

    def test_scores_increase_with_volume(self):
        scores = [volume_score(n, CFG) for n in (1, 20, 21, 100, 101, 1000, 100000)]
        self.assertEqual(scores, sorted(scores))
        self.assertLessEqual(max(scores), 85)

    def test_custom_thresholds(self):
        cfg = {**CFG, "low_max": 50, "medium_max": 200}
        self.assertEqual(level_from_score(score_event(50, T0, deque(), cfg)[0]), "Low")
        self.assertEqual(level_from_score(score_event(51, T0, deque(), cfg)[0]), "Medium")
        self.assertEqual(level_from_score(score_event(201, T0, deque(), cfg)[0]), "High")


class BehaviourRules(unittest.TestCase):
    def test_repeated_high_volume_escalates(self):
        prior = deque([(T0 - timedelta(minutes=20), 60), (T0 - timedelta(minutes=10), 70)])
        score, reasons = score_event(80, T0, prior, CFG)
        self.assertTrue(any("Repeated high-volume" in r for r in reasons))
        self.assertEqual(level_from_score(score), "High")

    def test_old_accesses_are_ignored(self):
        prior = deque([(T0 - timedelta(hours=5), 60), (T0 - timedelta(hours=4), 70)])
        _, reasons = score_event(80, T0, prior, CFG)
        self.assertFalse(any("Repeated" in r for r in reasons))

    def test_frequency_flags_small_accesses(self):
        prior = deque((T0 - timedelta(minutes=m), 5) for m in range(1, 10))
        score, reasons = score_event(5, T0, prior, CFG)
        self.assertTrue(any("frequency" in r for r in reasons))
        self.assertEqual(level_from_score(score), "Medium")

    def test_normal_event_has_clean_reason(self):
        score, reasons = score_event(8, T0, deque(), CFG)
        self.assertEqual(level_from_score(score), "Low")
        self.assertEqual(reasons, ["Within normal volume and frequency"])


class EvaluateLogs(unittest.TestCase):
    def test_per_user_isolation_and_order(self):
        rows = []
        for i in range(10):  # user A bursts
            rows.append((i + 1, "A", (T0 + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S"), 4))
        rows.append((99, "B", T0.strftime("%Y-%m-%d %H:%M:%S"), 4))
        res = evaluate_logs(pd.DataFrame(rows, columns=["log_id", "user_id", "timestamp", "records_accessed"]), CFG)
        by_id = res.set_index("log_id")
        self.assertEqual(by_id.loc[10, "risk_level"], "Medium")  # 10th access in window
        self.assertEqual(by_id.loc[9, "risk_level"], "Low")
        self.assertEqual(by_id.loc[99, "risk_level"], "Low")

    def test_empty(self):
        self.assertTrue(evaluate_logs(pd.DataFrame(columns=["log_id", "user_id", "timestamp", "records_accessed"]), CFG).empty)


if __name__ == "__main__":
    unittest.main()
