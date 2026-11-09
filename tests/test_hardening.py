import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class StreamlitBindingTests(unittest.TestCase):
    def test_dashboard_listens_on_this_computer_only(self):
        text = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
        server = re.search(r"\[server\](.*?)(?=\n\[|\Z)", text, re.S)
        self.assertIsNotNone(server, "config.toml needs a [server] section")
        self.assertRegex(server.group(1), r'(?m)^\s*address\s*=\s*"127\.0\.0\.1"\s*$')


if __name__ == "__main__":
    unittest.main()
