import unittest

from sentinel.api import EventIn

from demo_traffic import build_event_plan, score_plan


class DemoTrafficTests(unittest.TestCase):
    def test_event_plan_is_deterministic_for_a_run_id(self):
        self.assertEqual(build_event_plan("a1b2c3d4"), build_event_plan("a1b2c3d4"))

    def test_each_run_uses_distinct_user_ids(self):
        first = build_event_plan("a1b2c3d4")
        second = build_event_plan("e5f6a7b8")
        first_ids = {event["payload"]["user_id"] for event in first}
        second_ids = {event["payload"]["user_id"] for event in second}
        self.assertTrue(first_ids.isdisjoint(second_ids))

    def test_all_planned_events_pass_event_input_validation(self):
        for event in build_event_plan("a1b2c3d4"):
            validated = EventIn.model_validate(event["payload"])
            self.assertEqual(validated.user_id, event["payload"]["user_id"])

    def test_offline_scores_match_the_three_act_story(self):
        events = build_event_plan("a1b2c3d4")
        scores = score_plan(events)
        normal = [(i, event) for i, event in enumerate(events, start=1) if event["act"] == "Normal day"]
        repeated = [
            (i, event) for i, event in enumerate(events, start=1)
            if event["act"] == "Repeated small accesses"
        ]
        bulk = [(i, event) for i, event in enumerate(events, start=1) if event["act"] == "Bulk dump"]

        self.assertEqual(len({event["payload"]["user_id"] for _, event in normal}), 6)
        self.assertTrue(all(1 <= sum(e["payload"]["user_id"] == event["payload"]["user_id"]
                                     for _, e in normal) <= 2 for _, event in normal))
        self.assertTrue(all(scores[index]["risk_level"] == "Low" for index, _ in normal))
        self.assertEqual(len(repeated), 10)
        self.assertTrue(all(
            scores[index]["risk_level"] == "Low" and scores[index]["risk_score"] < 26
            for index, _ in repeated[:-1]
        ))
        self.assertTrue(all(
            6 <= event["payload"]["records_accessed"] <= 12 for _, event in repeated
        ))
        self.assertEqual(scores[repeated[-1][0]]["risk_level"], "Medium")
        self.assertEqual(scores[repeated[-1][0]]["risk_score"], 36)
        self.assertIn("Unusual access frequency", scores[repeated[-1][0]]["reason"])
        self.assertIn("10 accesses within 15 min", scores[repeated[-1][0]]["reason"])
        self.assertEqual(scores[bulk[0][0]]["risk_level"], "High")
        self.assertIn("Bulk extraction", scores[bulk[0][0]]["reason"])


if __name__ == "__main__":
    unittest.main()
