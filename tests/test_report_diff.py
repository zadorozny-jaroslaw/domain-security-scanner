from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from domain_security_scanner.reporting.diff import (
    ReportDiffError,
    compare_report_files,
    compare_reports,
)


def _report(**updates):
    report = {
        "domain": "example.com",
        "target_domain": "example.com",
        "generated_at": "2026-09-28T12:00:00+00:00",
        "scanner_version": "1.2.0",
        "scan_groups": ["domain", "mail"],
        "score": {"score": 100, "label": "Strong"},
        "checks": [
            {"category": "Domain", "name": "DNSSEC", "status": "pass"},
            {"category": "Mail", "name": "SPF", "status": "unknown"},
        ],
        "dns_records": {"example.com": {"A": ["192.0.2.2", "192.0.2.1"]}},
        "subdomains": ["www.example.com", "example.com"],
    }
    report.update(updates)
    return report


class ReportDiffTest(unittest.TestCase):
    def test_identical_reports_are_unchanged(self):
        result = compare_reports(_report(), _report())
        self.assertFalse(result.has_changes)
        self.assertGreater(result.unchanged_count, 0)

    def test_generated_at_is_ignored(self):
        old = _report()
        new = _report(generated_at="2026-09-28T13:00:00+00:00")
        self.assertFalse(compare_reports(old, new).has_changes)

    def test_dictionary_key_order_is_ignored(self):
        old = _report(score={"score": 100, "label": "Strong"})
        new = _report(score={"label": "Strong", "score": 100})
        self.assertFalse(compare_reports(old, new).has_changes)

    def test_known_semantic_sets_ignore_order(self):
        old = _report()
        new = _report(
            scan_groups=["mail", "domain"],
            subdomains=["example.com", "www.example.com"],
            dns_records={"example.com": {"A": ["192.0.2.1", "192.0.2.2"]}},
            checks=list(reversed(old["checks"])),
        )
        self.assertFalse(compare_reports(old, new).has_changes)

    def test_unknown_status_is_compared_literally(self):
        old = _report()
        new_checks = [dict(item) for item in old["checks"]]
        new_checks[1]["status"] = "warn"
        result = compare_reports(old, _report(checks=new_checks))
        self.assertTrue(result.has_changes)
        self.assertEqual(len(result.changed), 1)

    def test_added_removed_and_changed_are_distinguished(self):
        old = _report(extra_old=True)
        new = _report(extra_new=True, scanner_version="1.3.0")
        result = compare_reports(old, new)
        self.assertEqual(result.added[0]["path"], "$.extra_new")
        self.assertEqual(result.removed[0]["path"], "$.extra_old")
        self.assertEqual(result.changed[0]["path"], "$.scanner_version")
        self.assertEqual(result.changed[0]["old"], "1.2.0")
        self.assertEqual(result.changed[0]["new"], "1.3.0")

    def test_unknown_lists_remain_order_sensitive(self):
        old = _report(custom_order=["first", "second"])
        new = _report(custom_order=["second", "first"])
        self.assertTrue(compare_reports(old, new).has_changes)

    def test_invalid_json_and_incompatible_input_raise(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_path = Path(tmpdir) / "old.json"
            new_path = Path(tmpdir) / "new.json"
            old_path.write_text("{broken", encoding="utf-8")
            new_path.write_text(json.dumps(_report()), encoding="utf-8")
            with self.assertRaises(ReportDiffError):
                compare_report_files(old_path, new_path)

            old_path.write_text(json.dumps(["not", "a", "report"]), encoding="utf-8")
            with self.assertRaises(ReportDiffError):
                compare_report_files(old_path, new_path)


if __name__ == "__main__":
    unittest.main()
