"""Run:  python -m unittest discover -s tests -v
Checks parser, every detection rule, and the overall accuracy on generated data."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.parser import parse_web_line, parse_lines
from core.generator import generate
from core.analyze import analyze


def build(seed):
    d = tempfile.mkdtemp()
    generate(d, seed=seed)
    ev = []
    for n in ("access.log", "auth.log"):
        ev += parse_lines(open(os.path.join(d, n)).readlines())[0]
    ev.sort(key=lambda e: e["epoch"])
    return analyze(ev, json.load(open(os.path.join(d, "ground_truth.json"))))


class ParserTests(unittest.TestCase):
    def test_apache_line(self):
        e = parse_web_line('1.2.3.4 - - [13/Oct/2026:10:00:00 +0530] "GET /a?b=1 HTTP/1.1" 404 196 "-" "curl/7"')
        self.assertEqual((e["ip"], e["status"], e["bytes"]), ("1.2.3.4", 404, 196))
        self.assertEqual(e["ts"], "2026-10-13T04:30:00Z")  # timezone converted to UTC

    def test_garbage_is_skipped(self):
        ev, skipped = parse_lines(["hello world", ""])
        self.assertEqual((len(ev), skipped), (0, 1))


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = build(7)

    def rules_for(self, ip):
        return {a["rule"] for a in self.r["alerts"] if a["ip"] == ip}

    def test_full_chain(self):
        self.assertTrue({"WEB_SCANNER", "SSH_BRUTE_FORCE", "SSH_COMPROMISE", "EXFIL_LARGE"} <= self.rules_for("185.220.101.45"))

    def test_web_attacks(self):
        self.assertIn("WEB_SQLI", self.rules_for("45.155.205.12"))
        self.assertIn("WEB_XSS", self.rules_for("103.75.190.7"))
        self.assertIn("WEB_TRAVERSAL", self.rules_for("103.75.190.7"))
        self.assertIn("WEB_FLOOD", self.rules_for("198.51.100.77"))

    def test_ml_catches_low_and_slow(self):
        self.assertEqual(self.rules_for("203.0.113.50"), {"ML_IP_ANOMALY"})

    def test_no_false_alarms_on_normal_users(self):
        self.assertEqual(self.r["evaluation"]["false_alarms"], [])

    def test_storyline_verdict(self):
        top = self.r["incidents"][0]
        self.assertEqual((top["ip"], top["verdict"]), ("185.220.101.45", "Likely compromised"))
        self.assertEqual(top["stages"], [0, 1, 3, 4])

    def test_accuracy_over_seeds(self):
        for seed in (1, 42, 99):
            ev = build(seed)["evaluation"]
            self.assertEqual(ev["recall"], 1.0, f"seed {seed}")
            self.assertEqual(ev["precision"], 1.0, f"seed {seed}")


if __name__ == "__main__":
    unittest.main()
