import json
import tempfile
import unittest
from pathlib import Path

from aegis_soc.engine import extract_indicators, normalize_alert
from aegis_soc.workflow import process_alert


ROOT = Path(__file__).resolve().parents[1]


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.alert = json.loads((ROOT / "data" / "sample_alert.json").read_text(encoding="utf-8"))
        self.intel = json.loads((ROOT / "data" / "threat_intel.json").read_text(encoding="utf-8"))

    def test_extracts_expected_indicators(self):
        event = normalize_alert(self.alert)
        indicators = {(i.kind, i.value) for i in extract_indicators(event)}
        self.assertIn(("ipv4", "203.0.113.66"), indicators)
        self.assertIn(("domain", "update-check.example.net"), indicators)
        self.assertIn(("sha256", "a" * 64), indicators)
        self.assertNotIn(("domain", "powershell.exe"), indicators)
        self.assertNotIn(("domain", "analyst.demo"), indicators)

    def test_high_risk_alert_escalates(self):
        result = process_alert(self.alert, self.intel)
        self.assertEqual(result["decision"]["risk"], "critical")
        self.assertEqual(result["decision"]["action"], "escalate")
        self.assertGreaterEqual(result["decision"]["score"], 80)

    def test_output_files_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            process_alert(self.alert, self.intel, tmp)
            for name in ("decision.json", "ticket.json", "notification.json", "audit.jsonl"):
                self.assertTrue((Path(tmp) / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
