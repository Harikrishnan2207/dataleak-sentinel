import unittest

import pandas as pd

from sentinel.config import DEFAULT_SETTINGS
from sentinel.evaluation import (
    ATTACKS, CONFIGS, EPISODES_PER_ATTACK, confusion, episode_outcomes, generate_labelled_dataset,
    ratio, render_report, run_evaluation, score_dataset,
)

SEED = 1000


class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate_labelled_dataset(SEED)

    def test_deterministic(self):
        pd.testing.assert_frame_equal(self.df, generate_labelled_dataset(SEED))
        self.assertFalse(self.df.equals(generate_labelled_dataset(SEED + 1)))

    def test_labels_match_episodes(self):
        attack = self.df[self.df["label"] == 1]
        self.assertTrue(attack["episode"].notna().all())
        self.assertTrue(self.df[self.df["label"] == 0]["episode"].isna().all())
        self.assertEqual(attack["episode"].nunique(), len(ATTACKS) * EPISODES_PER_ATTACK)
        self.assertEqual(set(attack["kind"]), set(ATTACKS))
        # every episode belongs to exactly one user
        self.assertTrue((attack.groupby("episode")["user_id"].nunique() == 1).all())

    def test_basic_shape(self):
        self.assertEqual(self.df["user_id"].nunique(), 40)
        self.assertEqual(list(self.df["log_id"]), list(range(1, len(self.df) + 1)))
        self.assertTrue(self.df["timestamp"].is_monotonic_increasing)
        self.assertTrue((self.df["records_accessed"] >= 0).all())
        self.assertLessEqual(pd.to_datetime(self.df["timestamp"]).max(), pd.Timestamp("2026-03-01 12:00:00"))
        self.assertEqual(set(self.df["kind"]) - set(ATTACKS), {"ordinary", "legit_export", "legit_burst"})

    def test_low_volume_spikes_hit_light_users_only(self):
        spikes = self.df[self.df["kind"] == "low_volume_spike"]
        self.assertTrue((spikes["profile"] == "light").all())
        self.assertTrue(spikes["records_accessed"].between(12, 19).all())


class ScoringAgreesWithAnIndependentCalculation(unittest.TestCase):
    def test_thresholds_only_equals_the_plain_volume_rule(self):
        """With every behaviour rule off, an event is flagged exactly when it exceeds the Low limit."""
        df = generate_labelled_dataset(SEED)
        scored = score_dataset(df, CONFIGS["thresholds_only"][1])
        expected = scored["records_accessed"] > DEFAULT_SETTINGS["low_max"]
        self.assertTrue((scored["flagged"] == expected).all())

    def test_each_layer_can_only_add_alerts(self):
        df = generate_labelled_dataset(SEED)
        flags = [score_dataset(df, CONFIGS[n][1])["flagged"] for n in ("thresholds_only", "rules_no_anomaly", "full_default")]
        self.assertTrue((flags[1] | ~flags[0]).all())   # whatever layer 1 flags, layer 2 flags too
        self.assertTrue((flags[2] | ~flags[1]).all())

    def test_default_engine_detects_spike_and_drip_episodes(self):
        scored = score_dataset(generate_labelled_dataset(SEED), {})
        outcomes = episode_outcomes(scored)
        for attack in ("low_volume_spike", "sub_threshold_drip"):
            with self.subTest(attack=attack):
                episodes = [e for e in outcomes if e["kind"] == attack]
                self.assertEqual(len(episodes), EPISODES_PER_ATTACK)
                self.assertTrue(all(e["detected"] for e in episodes))


class MetricTests(unittest.TestCase):
    def test_confusion_and_ratio(self):
        scored = pd.DataFrame({"label": [1, 1, 0, 0, 0], "flagged": [True, False, True, False, False]})
        self.assertEqual(confusion(scored), {"tp": 1, "fp": 1, "fn": 1, "tn": 2})
        self.assertEqual(ratio(1, 4), 0.25)
        self.assertIsNone(ratio(1, 0))

    def test_episode_outcomes(self):
        scored = pd.DataFrame({
            "episode": [1, 1, 1, 2, 2], "kind": ["a"] * 3 + ["b"] * 2, "timestamp": ["2026-01-01 10:00:0%d" % i for i in range(5)],
            "log_id": range(5), "flagged": [False, False, True, False, False]})
        out = {o["kind"]: o for o in episode_outcomes(scored)}
        self.assertEqual((out["a"]["detected"], out["a"]["events_before_first_alert"]), (True, 2))
        self.assertEqual((out["b"]["detected"], out["b"]["events_before_first_alert"]), (False, None))

    def test_report_is_deterministic_and_complete(self):
        data = run_evaluation([SEED, SEED + 1])
        report = render_report(data)
        self.assertEqual(report, render_report(run_evaluation([SEED, SEED + 1])))
        for heading in ("## How the test works", "## Event-level results", "## Attack episodes detected",
                        "## False alerts on benign activity", "Where the false alerts", "## Limits of this evaluation"):
            self.assertIn(heading, report)
        for attack in ATTACKS:
            self.assertIn(f"`{attack}`", report)


if __name__ == "__main__":
    unittest.main()
