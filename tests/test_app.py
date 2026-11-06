"""Headless UI smoke test using Streamlit's AppTest (no browser needed)."""
import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.TemporaryDirectory()
os.environ["DATALEAK_DB_PATH"] = str(Path(_TMP.name) / "app_test.db")

from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parent.parent / "app.py")
PAGES = ["Dashboard", "User Activity", "Security Alerts", "Audit Logs", "Detection Rules", "Demo Simulation"]


def button(at, label):
    return next(b for b in at.button if b.label == label)


class AppSmokeTest(unittest.TestCase):
    def test_full_flow(self):
        at = AppTest.from_file(APP, default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)

        # Every page renders on an empty database.
        for page in PAGES:
            at.sidebar.radio[0].set_value(page).run()
            self.assertFalse(at.exception, f"{page} (empty): {at.exception}")

        # Generate demo data from the Demo Simulation page.
        at.sidebar.radio[0].set_value("Demo Simulation").run()
        button(at, "Generate demo data").click().run()
        self.assertFalse(at.exception, at.exception)

        # Every page renders with data, and key content is present.
        for page in PAGES:
            at.sidebar.radio[0].set_value(page).run()
            self.assertFalse(at.exception, f"{page}: {at.exception}")
        at.sidebar.radio[0].set_value("Dashboard").run()
        self.assertGreater(len(at.markdown), 5)
        at.sidebar.radio[0].set_value("User Activity").run()
        self.assertTrue(len(at.dataframe) >= 1)

        # Guided scenario: runs, renders all seven steps and stores two new events.
        at.sidebar.radio[0].set_value("Demo Simulation").run()
        button(at, "Run guided scenario").click().run()
        self.assertFalse(at.exception, at.exception)
        self.assertTrue(any("Step 7" in m.value for m in at.markdown))

        # Manual event on the demo page.
        at.sidebar.radio[0].set_value("Demo Simulation").run()
        next(b for b in at.button if b.label == "Log access event").click().run()
        self.assertFalse(at.exception, at.exception)

        # Clear everything (needs the confirmation checkbox).
        at.checkbox[0].check().run()
        button(at, "Clear all data").click().run()
        self.assertFalse(at.exception, at.exception)
        at.sidebar.radio[0].set_value("Dashboard").run()
        self.assertFalse(at.exception, at.exception)


if __name__ == "__main__":
    unittest.main()
