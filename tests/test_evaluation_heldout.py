import unittest

import pandas as pd

from sentinel.config import DEFAULT_SETTINGS
from sentinel.evaluation import generate_labelled_dataset
from sentinel.evaluation_heldout import (
    ATTACKS, HELDOUT_SEEDS, IN_SAMPLE_SEEDS, PREVIOUS_DEFAULTS, build_results, detection, episode_stats,
    follow_on_example, generate_heldout_dataset, render_report, run_family, score, sweep_drip, sweep_spike,
)


class PreviousSettings(unittest.TestCase):
    def test_previous_defaults_cover_every_setting(self):
        """A setting added later must be added to PREVIOUS_DEFAULTS too, or the comparison would silently drift."""
        self.assertEqual(set(PREVIOUS_DEFAULTS), set(DEFAULT_SETTINGS))

    def test_previous_defaults_reproduce_the_originally_published_untuned_result(self):
        """Regression anchor: the untuned engine caught 383 of 540 attack episodes on the original data."""
        result = run_family(generate_labelled_dataset, IN_SAMPLE_SEEDS, PREVIOUS_DEFAULTS)
        self.assertEqual(detection(result["episodes"]), (383, 540))


class HeldOutData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate_heldout_dataset(HELDOUT_SEEDS[0])

    def test_deterministic_and_different_from_the_original_data(self):
        pd.testing.assert_frame_equal(self.df, generate_heldout_dataset(HELDOUT_SEEDS[0]))
        self.assertFalse(self.df["records_accessed"].equals(generate_labelled_dataset(1000)["records_accessed"]))

    def test_labels_and_episodes(self):
        attack = self.df[self.df["label"] == 1]
        self.assertEqual(attack["episode"].nunique(), 18)
        self.assertEqual(set(attack["kind"]), set(ATTACKS))
        self.assertTrue((attack.groupby("episode")["user_id"].nunique() == 1).all())
        self.assertTrue(self.df[self.df["label"] == 0]["episode"].isna().all())
        busy = self.df[self.df["kind"] == "busy_day"]
        self.assertEqual(len(busy), 75)
        self.assertTrue((busy["label"] == 0).all())
        self.assertTrue(busy["records_accessed"].between(10, 25).all())

    def test_seeds_do_not_overlap_with_the_tuning_data(self):
        self.assertTrue(set(HELDOUT_SEEDS).isdisjoint(IN_SAMPLE_SEEDS))


class Metrics(unittest.TestCase):
    def test_share_of_rows_read_before_the_first_alert(self):
        scored = pd.DataFrame({
            "episode": [1, 1, 1, 1], "kind": ["sub_threshold_drip"] * 4, "timestamp": ["2026-01-01 10:00:0%d" % i for i in range(4)],
            "log_id": range(4), "records_accessed": [10, 10, 10, 10], "flagged": [False, False, True, False]})
        stats = episode_stats(scored)[0]
        self.assertEqual((stats["detected"], stats["events_before_first_alert"], stats["share_read"]), (True, 2, 0.75))
        scored["flagged"] = False
        stats = episode_stats(scored)[0]
        self.assertEqual((stats["detected"], stats["share_read"]), (False, 1.0))

    def test_follow_on_example_shows_the_cumulative_rule(self):
        rows = follow_on_example(dict(DEFAULT_SETTINGS))
        self.assertEqual(rows[0]["level"], "High")
        self.assertTrue(all(r["level"] != "Low" for r in rows[1:]))
        self.assertEqual(follow_on_example(dict(PREVIOUS_DEFAULTS))[1]["level"], "Low")   # old 60-minute window forgot the export

    def test_sweeps_are_bounded_and_deterministic(self):
        a = sweep_spike([10, 19], 5, dict(DEFAULT_SETTINGS))
        self.assertEqual(a, sweep_spike([10, 19], 5, dict(DEFAULT_SETTINGS)))
        self.assertTrue(all(0 <= v <= 1 for v in a.values()))
        d = sweep_drip([8, 16], 4, dict(DEFAULT_SETTINGS))
        self.assertEqual(d, sweep_drip([8, 16], 4, dict(DEFAULT_SETTINGS)))
        for v in d.values():
            self.assertTrue(0 <= v["detected"] <= 1 and 0 < v["share_read"] <= 1)
        self.assertEqual(d[16]["total"], 30 * 16)


class Report(unittest.TestCase):
    def test_report_is_deterministic_and_complete(self):
        args = dict(in_seeds=[1000, 1001], held_seeds=[2000, 2001], spike_trials=3, drip_trials=3)
        report = render_report(build_results(**args))
        self.assertEqual(report, render_report(build_results(**args)))
        for heading in ("## Settings compared", "## A. Original scenarios", "## B. Reshaped scenarios",
                        "## C. Sweeps", "## D. A side effect", "## What this shows", "## Limits of this report"):
            self.assertIn(heading, report)
        for kind in ATTACKS + ["busy_day"]:
            self.assertIn(f"`{kind}`", report)
        self.assertIn("`anomaly_z` | 4 | 2.5", report)


if __name__ == "__main__":
    unittest.main()
