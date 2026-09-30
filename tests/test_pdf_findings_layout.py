from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reportlab.platypus import Paragraph, Table as ReportLabTable

from domain_security_scanner.reporting.pdf import generate_pdf


class PdfFindingsLayoutTest(unittest.TestCase):
    def test_long_check_name_uses_wrappable_paragraph_cell(self):
        report = {
            "target_domain": "example.com",
            "root_domain": "example.com",
            "generated_at": "2026-09-30T13:20:26+00:00",
            "score": {"score": 100, "label": "Strong"},
            "checks": [
                {
                    "category": "Domain",
                    "name": "Authoritative NS RRset consistency",
                    "status": "info",
                    "message": "Controlled layout regression fixture.",
                    "weight": 0,
                    "earned": 0,
                    "applicable": False,
                }
            ],
            "scan_groups": ["domain"],
            "scan_selection": {
                "requested": ["domain"],
                "skipped": [],
                "warnings": [],
            },
            "rdap": {
                "url": "https://rdap.example/",
                "registrar": "Example Registrar",
                "nameservers": ["ns1.example.net", "ns2.example.net"],
                "status": [],
                "transfer_lock": "detected",
            },
            "dns": {},
            "dns_records": {},
            "subdomains": [],
            "host_inventory": {
                "live": [],
                "historical": [],
                "unresolved": [],
                "dns_unknown": [],
                "not_assessed": [],
            },
            "emails": [],
            "limitations": ["Controlled layout regression fixture."],
        }
        captured_findings = []

        def capture_table(data, *args, **kwargs):
            if data and data[0] == ["Status", "Area", "Check", "Result"]:
                captured_findings.append(data)
            return ReportLabTable(data, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.pdf"
            with patch(
                "domain_security_scanner.reporting.pdf.Table",
                side_effect=capture_table,
            ):
                generate_pdf(report, output)

        self.assertEqual(len(captured_findings), 1)
        self.assertIsInstance(captured_findings[0][1][2], Paragraph)


if __name__ == "__main__":
    unittest.main()
