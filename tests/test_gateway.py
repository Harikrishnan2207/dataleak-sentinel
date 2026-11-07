import sqlite3
import tempfile
import unittest
from pathlib import Path

from sentinel.database import SentinelDB
from sentinel.gateway import QueryRejected, execute_measured, run_monitored_query, validate_select
from sentinel.sample_data import customer_count, ensure_customers_db

USER = ("U1011", "farhan.ali", "Operations")


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.customers = ensure_customers_db(Path(cls.tmp.name) / "customers.db", rows=3000)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.audit_tmp = tempfile.TemporaryDirectory()
        self.db = SentinelDB(Path(self.audit_tmp.name) / "audit.db")
        self.db.init_schema()

    def tearDown(self):
        self.audit_tmp.cleanup()

    def test_sample_data_is_synthetic_and_deterministic(self):
        self.assertEqual(customer_count(self.customers), 3000)
        again = ensure_customers_db(self.customers, rows=3000)
        self.assertEqual(customer_count(again), 3000)  # not duplicated
        conn = sqlite3.connect(self.customers)
        bad = conn.execute("SELECT COUNT(*) FROM customers WHERE email NOT LIKE '%@example.com'").fetchone()[0]
        conn.close()
        self.assertEqual(bad, 0)

    def test_measured_count_matches_real_row_count(self):
        conn = sqlite3.connect(self.customers)
        expected = conn.execute("SELECT COUNT(*) FROM customers WHERE segment = 'Corporate'").fetchone()[0]
        conn.close()
        res = execute_measured("SELECT * FROM customers WHERE segment = 'Corporate'", self.customers)
        self.assertEqual(res["records"], expected)
        self.assertEqual(len(res["preview"]), 20)
        self.assertFalse(res["truncated"])

    def test_small_query_is_low_and_large_dump_alerts(self):
        small = run_monitored_query(self.db, USER, "SELECT * FROM customers WHERE customer_id = 5", self.customers)
        self.assertEqual(small["records"], 1)
        self.assertEqual(small["log"]["risk_level"], "Low")
        self.assertIsNone(small["alert_id"])
        big = run_monitored_query(self.db, USER, "SELECT * FROM customers", self.customers)
        self.assertEqual(big["records"], 3000)
        self.assertEqual(big["log"]["risk_level"], "High")
        self.assertIsNotNone(big["alert_id"])

    def test_query_is_stored_in_audit_log(self):
        run_monitored_query(self.db, USER, "SELECT city FROM customers LIMIT 30;", self.customers)
        row = self.db.activity_df().iloc[0]
        self.assertEqual(row["source"], "gateway")
        self.assertEqual(row["query_text"], "SELECT city FROM customers LIMIT 30")
        self.assertEqual(row["records_accessed"], 30)
        self.assertEqual(row["risk_level"], "Medium")

    def test_non_select_statements_are_rejected_and_data_untouched(self):
        attempts = [
            "DELETE FROM customers", "UPDATE customers SET city = 'X'", "DROP TABLE customers",
            "INSERT INTO customers VALUES (1,'a','b','c','d',1,'e')", "PRAGMA table_info(customers)",
            "ATTACH DATABASE 'x.db' AS x", "SELECT 1; DROP TABLE customers", "", "   ",
            "SELECT randomblob(100000000)", "WITH x AS (SELECT 1) SELECT * FROM x",
        ]
        for sql in attempts:
            with self.assertRaises(QueryRejected, msg=sql):
                execute_measured(sql, self.customers)
        self.assertEqual(customer_count(self.customers), 3000)
        self.assertEqual(self.db.table_counts()["access_logs"], 0)  # rejected queries are not logged

    def test_sql_errors_are_reported_not_crashed(self):
        for sql in ("SELECT * FROM nope", "SELECT nope FROM customers", "SELEC * FROM customers"):
            with self.assertRaises(QueryRejected):
                execute_measured(sql, self.customers)

    def test_row_count_safety_cap(self):
        res = execute_measured("SELECT * FROM customers", self.customers, max_counted=500)
        self.assertEqual(res["records"], 500)
        self.assertTrue(res["truncated"])

    def test_runaway_query_is_stopped(self):
        with self.assertRaises(QueryRejected) as ctx:
            execute_measured("SELECT COUNT(*) FROM customers a, customers b, customers c, customers d",
                             self.customers, timeout_s=0.3)
        self.assertIn("ran longer", str(ctx.exception))

    def test_validate_select(self):
        self.assertEqual(validate_select("  select 1 ; "), "select 1")


class MigrationTests(unittest.TestCase):
    def test_old_database_gains_new_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            conn = sqlite3.connect(path)
            conn.executescript(
                "CREATE TABLE access_logs (log_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,"
                " username TEXT NOT NULL, department TEXT NOT NULL, timestamp TEXT NOT NULL,"
                " access_type TEXT NOT NULL, records_accessed INTEGER NOT NULL, source TEXT NOT NULL DEFAULT 'simulated');"
                "INSERT INTO access_logs (user_id, username, department, timestamp, access_type, records_accessed)"
                " VALUES ('U1001','aarav.nair','Finance','2026-01-01 10:00:00','SELECT Query',5);"
            )
            conn.commit()
            conn.close()
            db = SentinelDB(path)
            db.init_schema()
            db.init_schema()  # idempotent
            self.assertEqual(db.rescan()["events"], 1)
            df = db.activity_df()
            self.assertIn("query_text", df.columns)
            self.assertTrue(df["query_text"].isna().all())
            cols = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(alerts)")]
            self.assertIn("status", cols)


if __name__ == "__main__":
    unittest.main()
