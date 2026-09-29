from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from domain_security_scanner.reporting.dns_pdf import dns_posture_rows
from domain_security_scanner.reporting.pdf import generate_pdf


def _dns(status: str = "secure") -> dict:
    return {
        "dns": {
            "dnssec": {"status": status},
            "delegation": {
                "available": True,
                "consistent": True,
                "complete": True,
            },
            "soa": {"ns_rrset_consistent": True},
            "open_recursion": {"status": "closed", "open_servers": []},
            "caa": {
                "effective_name": "policy.example.com",
                "analysis": {
                    "state": "effective",
                    "syntax_error_records": [],
                    "malformed_value_records": [],
                },
            },
        }
    }


class DnsPdfSummaryTest(unittest.TestCase):
    def test_dnssec_states_are_explicit(self):
        expected = {
            "secure": ("pass", "SECURE"),
            "unsigned": ("warn", "UNSIGNED"),
            "broken": ("fail", "BROKEN"),
            "unknown": ("unknown", "VERIFY"),
        }
        for state, (status, label) in expected.items():
            with self.subTest(state=state):
                rows = dns_posture_rows(_dns(state))
                self.assertEqual(rows[0]["status"], status)
                self.assertIn(label, rows[0]["value"])

    def test_confirmed_delegation_failure_is_visible(self):
        report = _dns()
        report["dns"]["delegation"].update(consistent=False, complete=True)
        rows = {row["item"]: row for row in dns_posture_rows(report)}
        self.assertEqual(rows["Delegation"]["status"], "fail")
        self.assertIn("Confirmed parent/child", rows["Delegation"]["value"])

    def test_unknown_recursion_is_not_forced_to_failure(self):
        report = _dns()
        report["dns"]["open_recursion"] = {"status": "unknown"}
        rows = {row["item"]: row for row in dns_posture_rows(report)}
        self.assertEqual(rows["Open recursion"]["status"], "unknown")

    def test_effective_caa_source_is_shown(self):
        rows = {row["item"]: row for row in dns_posture_rows(_dns())}
        self.assertIn("policy.example.com", rows["CAA"]["value"])


class DnsPdfRenderTest(unittest.TestCase):
    def test_domain_only_report_builds_with_dns_posture_data(self):
        report = {
            "target_domain": "example.com",
            "root_domain": "example.com",
            "generated_at": "2026-09-29T17:00:00+00:00",
            "score": {"score": 90, "label": "Strong"},
            "checks": [],
            "scan_groups": ["domain"],
            "scan_selection": {"requested": ["domain"], "skipped": [], "warnings": []},
            "rdap": {
                "url": "https://rdap.example/",
                "registrar": "Example Registrar",
                "nameservers": ["ns1.example.net", "ns2.example.net"],
                "status": [],
                "transfer_lock": "detected",
            },
            "subdomains": [],
            "host_inventory": {
                "live": [],
                "historical": [],
                "unresolved": [],
                "dns_unknown": [],
                "not_assessed": [],
            },
            "dns_records": {},
            "emails": [],
            "limitations": ["Controlled fixture report."],
            **_dns(),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.pdf"
            generate_pdf(report, output)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 4000)
            self.assertEqual(output.read_bytes()[:4], b"%PDF")


if __name__ == "__main__":
    unittest.main()
