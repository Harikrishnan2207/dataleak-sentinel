import re
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    from sentinel.api import create_app
    HAVE_API = True
except ImportError:  # fastapi/httpx not installed: these tests are skipped
    HAVE_API = False

from sentinel.database import SentinelDB

KEY = "test-key-0123456789abcdef"
GOOD = {"user_id": "U1011", "username": "farhan.ali", "department": "Operations",
        "access_type": "Full Table Export", "records_accessed": 3200}
NORMAL = {"user_id": "U1001", "username": "aarav.nair", "department": "Finance",
          "access_type": "SELECT Query", "records_accessed": 8}


def _dashboard_script(path):
    from sentinel.database import SentinelDB as DB
    from sentinel.ui import pages, styles
    styles.inject()
    pages.dashboard(DB(path))


@unittest.skipUnless(HAVE_API, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self.tmp.name) / "api.db"
        self.db = SentinelDB(self.path)
        self.db.init_schema()
        self.app = create_app(db=self.db, api_key=KEY)
        self.client = TestClient(self.app)
        self.auth = {"X-API-Key": KEY}

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------ startup / auth
    def test_refuses_to_start_without_a_strong_key(self):
        for bad in ("", "short", "x" * 15):
            with self.assertRaises(RuntimeError):
                create_app(db=self.db, api_key=bad)

    def test_health_is_open_and_minimal(self):
        r = self.client.get("/health")
        self.assertEqual((r.status_code, r.json()), (200, {"status": "ok"}))

    def test_events_and_alerts_require_the_key(self):
        for headers in ({}, {"X-API-Key": "wrong"}, {"X-API-Key": ""}, {"X-API-Key": KEY[:-1]}, {"X-API-Key": KEY + "x"}):
            self.assertEqual(self.client.post("/events", json=GOOD, headers=headers).status_code, 401, headers)
            self.assertEqual(self.client.get("/alerts", headers=headers).status_code, 401, headers)
        self.assertEqual(self.db.table_counts()["access_logs"], 0)   # nothing stored without a valid key

    def test_valid_key_is_accepted(self):
        self.assertEqual(self.client.post("/events", json=NORMAL, headers=self.auth).status_code, 201)

    # ------------------------------------------------------------ scoring + storage
    def test_normal_event_is_low_and_stored(self):
        r = self.client.post("/events", json=NORMAL, headers=self.auth)
        body = r.json()
        self.assertEqual((body["risk_level"], body["alert_id"]), ("Low", None))
        row = self.db.activity_df().iloc[0]
        self.assertEqual((row["username"], row["records_accessed"], row["source"]), ("aarav.nair", 8, "api"))
        self.assertEqual(self.db.table_counts(), {"access_logs": 1, "detections": 1, "alerts": 0})

    def test_bulk_event_raises_an_alert_visible_through_the_alerts_endpoint(self):
        body = self.client.post("/events", json=GOOD, headers=self.auth).json()
        self.assertEqual(body["risk_level"], "High")
        self.assertIsNotNone(body["alert_id"])
        alerts = self.client.get("/alerts", headers=self.auth).json()
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]["alert_id"], alerts[0]["status"], alerts[0]["records_accessed"]),
                         (body["alert_id"], "New", 3200))

    def test_result_matches_direct_use_of_the_scoring_code(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            direct = SentinelDB(Path(tmp) / "direct.db")
            direct.init_schema()
            expected = direct.log_event(*[GOOD[k] for k in ("user_id", "username", "department", "access_type")],
                                        GOOD["records_accessed"])
        got = self.client.post("/events", json=GOOD, headers=self.auth).json()
        for field in ("risk_score", "risk_level", "reason"):
            self.assertEqual(got[field], expected[field])

    def test_frequency_rule_works_through_the_api(self):
        levels = [self.client.post("/events", json={**NORMAL, "records_accessed": 4}, headers=self.auth).json()
                  for _ in range(12)]
        self.assertEqual(levels[0]["risk_level"], "Low")
        self.assertEqual(levels[-1]["risk_level"], "Medium")
        self.assertIn("Unusual access frequency", levels[-1]["reason"])

    def test_server_stamps_the_time(self):
        self.client.post("/events", json=NORMAL, headers=self.auth)
        stamped = self.db.activity_df().iloc[0]["timestamp"]
        self.assertLess(abs(datetime.now() - stamped.to_pydatetime()), timedelta(seconds=10))

    def test_client_supplied_timestamp_is_rejected(self):
        r = self.client.post("/events", json={**NORMAL, "timestamp": "2020-01-01 00:00:00"}, headers=self.auth)
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.db.table_counts()["access_logs"], 0)

    # ------------------------------------------------------------ invalid input
    def test_invalid_input_is_rejected_and_nothing_is_stored(self):
        bad_events = [
            {**NORMAL, "records_accessed": -1},
            {**NORMAL, "records_accessed": 10**9},
            {**NORMAL, "records_accessed": "8"},
            {**NORMAL, "records_accessed": 8.5},
            {**NORMAL, "records_accessed": True},
            {**NORMAL, "records_accessed": None},
            {**NORMAL, "user_id": ""},
            {**NORMAL, "user_id": "U 1001"},
            {**NORMAL, "username": "x'); DROP TABLE alerts;--"},
            {**NORMAL, "username": "<script>alert(1)</script>"},
            {**NORMAL, "department": "a" * 65},
            {**NORMAL, "access_type": "SELECT; DROP"},
            {**NORMAL, "query_text": "x" * 501},
            {**NORMAL, "surprise": 1},
            {k: v for k, v in NORMAL.items() if k != "department"},
            {},
        ]
        for event in bad_events:
            r = self.client.post("/events", json=event, headers=self.auth)
            self.assertEqual(r.status_code, 422, event)
        self.assertEqual(self.db.table_counts()["access_logs"], 0)

    def test_malformed_body_is_rejected(self):
        r = self.client.post("/events", content="not json", headers={**self.auth, "Content-Type": "application/json"})
        self.assertEqual(r.status_code, 422)
        r = self.client.post("/events", json=[NORMAL], headers=self.auth)
        self.assertEqual(r.status_code, 422)

    def test_query_text_is_stored_literally_not_executed(self):
        evil = "SELECT 1'); DROP TABLE access_logs; --"
        r = self.client.post("/events", json={**NORMAL, "query_text": evil}, headers=self.auth)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.db.activity_df().iloc[0]["query_text"], evil)
        self.assertEqual(self.db.table_counts()["access_logs"], 1)   # tables intact

    def test_zero_records_is_accepted(self):
        self.assertEqual(self.client.post("/events", json={**NORMAL, "records_accessed": 0}, headers=self.auth).status_code, 201)

    def test_alerts_query_parameters_are_validated(self):
        for params in ({"limit": 0}, {"limit": 201}, {"limit": "x"}, {"status": "Closed"}):
            self.assertEqual(self.client.get("/alerts", params=params, headers=self.auth).status_code, 422, params)
        self.client.post("/events", json=GOOD, headers=self.auth)
        self.assertEqual(len(self.client.get("/alerts", params={"status": "New"}, headers=self.auth).json()), 1)
        self.assertEqual(self.client.get("/alerts", params={"status": "Reviewed"}, headers=self.auth).json(), [])
        alert_id = self.db.alerts_df().iloc[0]["alert_id"]
        self.db.mark_reviewed(int(alert_id))
        self.assertEqual(len(self.client.get("/alerts", params={"status": "Reviewed"}, headers=self.auth).json()), 1)

    # ------------------------------------------------------------ concurrency + dashboard
    def test_concurrent_posts_do_not_lock_or_lose_events(self):
        def post(i):
            client = TestClient(self.app)
            event = {**NORMAL, "user_id": f"U{2000 + i}", "username": f"user{i}", "records_accessed": 5}
            return client.post("/events", json=event, headers=self.auth).status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(post, range(80)))
        self.assertEqual(set(codes), {201})
        self.assertEqual(self.db.table_counts()["access_logs"], 80)

    def test_dashboard_reads_events_sent_through_the_api(self):
        from streamlit.testing.v1 import AppTest
        self.client.post("/events", json=NORMAL, headers=self.auth)
        self.client.post("/events", json=GOOD, headers=self.auth)
        at = AppTest.from_function(_dashboard_script, args=(str(self.path),), default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)
        cards = {}
        for m in at.markdown:
            if m.value.startswith('<div class="kpi"'):
                label = re.search(r'kpi-label">([^<]+)<', m.value).group(1)
                cards[label] = re.search(r'kpi-value">([^<]+)<', m.value).group(1)
        self.assertEqual(cards["Total access attempts"], "2")
        self.assertEqual(cards["Flagged users"], "1")
        self.assertEqual(cards["Unreviewed alerts"], "1")


if __name__ == "__main__":
    unittest.main()
