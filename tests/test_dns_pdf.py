from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_summary_is_kept_to_two_customer_facing_rows(self):
        rows = dns_posture_rows(_dns())
        self.assertEqual(
            [row["item"] for row in rows],
            ["DNSSEC", "Delegation / authority"],
        )

    def test_confirmed_delegation_failure_is_visible(self):
        report = _dns()
        report["dns"]["delegation"].update(consistent=False, complete=True)
        row = dns_posture_rows(report)[1]
        self.assertEqual(row["status"], "fail")
        self.assertIn("Delegation: ACTION", row["value"])

    def test_unknown_recursion_is_not_forced_to_failure(self):
        report = _dns()
        report["dns"]["open_recursion"] = {"status": "unknown"}
        row = dns_posture_rows(report)[1]
        self.assertEqual(row["status"], "unknown")
        self.assertIn("Open recursion: VERIFY", row["value"])

    def test_confirmed_open_recursion_is_obvious(self):
        report = _dns()
        report["dns"]["open_recursion"] = {
            "status": "open",
            "open_servers": ["ns1.example.net"],
        }
        row = dns_posture_rows(report)[1]
        self.assertEqual(row["status"], "fail")
        self.assertIn("Open recursion: ACTION on ns1.example.net", row["value"])

    def test_non_pass_authoritative_rrset_remains_visible(self):
        report = _dns()
        report["dns"]["soa"]["ns_rrset_consistent"] = False
        row = dns_posture_rows(report)[1]
        self.assertEqual(row["status"], "warn")
        self.assertIn("Apex NS RRset: REVIEW", row["value"])

    def test_effective_caa_source_is_shown_when_inherited(self):
        report = _dns()
        report["target_domain"] = "www.example.com"
        report["dns"]["caa"]["effective_name"] = "example.com"
        row = dns_posture_rows(report)[1]
        self.assertIn("CAA: OK at example.com", row["value"])

    def test_same_owner_pass_caa_is_not_repeated_in_summary(self):
        report = _dns()
        report["target_domain"] = "policy.example.com"
        row = dns_posture_rows(report)[1]
        self.assertNotIn("CAA:", row["value"])


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
            # A domain-only report must not force a new page between the compact
            # DNS posture summary and the DNS appendix. ReportLab may still
            # paginate naturally when content requires it.
            with patch(
                "domain_security_scanner.reporting.pdf.PageBreak",
                side_effect=AssertionError("domain-only DNS flow forced a PageBreak"),
            ):
                generate_pdf(report, output)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 4000)
            self.assertEqual(output.read_bytes()[:4], b"%PDF")


if __name__ == "__main__":
    unittest.main()
