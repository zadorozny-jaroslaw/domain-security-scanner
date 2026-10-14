"""Deterministic CLI runtime-failure contract for issue #29 (no network scans)."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import domain_security_scanner.cli as cli


class _ScannerStub:
    def __init__(self, domain, *, max_pages=20, max_hosts=25, scan_groups=None):
        self.target_domain = domain
        self.root_domain = "example.com"
        self.scan_groups = tuple(scan_groups or ())

    def set_scan_selection_context(self, **kwargs):
        pass

    def run(self):
        pass

    def to_dict(self):
        return {
            "target_domain": self.target_domain,
            "checks": [],
            "score": {"score": 92, "label": "Strong"},
        }


class CliRuntimeFailureTest(unittest.TestCase):
    def run_cli(self, scanner=_ScannerStub, *, extra=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "Scanner", scanner),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(
                ["scan", "example.com", "--authorized", "--json-stdout", *extra]
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_invalid_target_is_usage_error(self):
        with patch.object(cli, "Scanner", side_effect=ValueError("invalid domain")):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = cli.main(["scan", "not-a-domain", "--authorized", "--json-stdout"])
        self.assertEqual(code, 2)
        self.assertIn("invalid domain", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_scanner_initialization_failure_returns_three(self):
        with patch.object(cli, "Scanner", side_effect=OSError("resolver unavailable")):
            err = io.StringIO()
            with redirect_stderr(err):
                code = cli.main(["scan", "example.com", "--authorized", "--json-stdout"])
        self.assertEqual(code, 3)
        self.assertIn("Cannot initialize scan", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_scan_context_failure_returns_three(self):
        class FailingContext(_ScannerStub):
            def set_scan_selection_context(self, **kwargs):
                raise RuntimeError("context unavailable")

        code, out, err = self.run_cli(FailingContext)
        self.assertEqual((code, out), (3, ""))
        self.assertIn("Scan could not complete: context unavailable", err)

    def test_scan_execution_failure_returns_three(self):
        class FailingScan(_ScannerStub):
            def run(self):
                raise RuntimeError("scan stopped")

        code, out, err = self.run_cli(FailingScan)
        self.assertEqual((code, out), (3, ""))
        self.assertIn("Scan could not complete: scan stopped", err)
        self.assertNotIn("Traceback", err)

    def test_report_assembly_failure_returns_three(self):
        class FailingReport(_ScannerStub):
            def to_dict(self):
                raise OSError("report assembly failed")

        code, out, err = self.run_cli(FailingReport)
        self.assertEqual((code, out), (3, ""))
        self.assertIn("report assembly failed", err)

    def test_missing_report_score_returns_three_before_writing(self):
        class BadReport(_ScannerStub):
            def to_dict(self):
                return {"checks": []}

        code, out, err = self.run_cli(BadReport)
        self.assertEqual((code, out), (3, ""))
        self.assertIn("Scan could not complete", err)

    def test_keyboard_interrupt_returns_130(self):
        class InterruptedScan(_ScannerStub):
            def run(self):
                raise KeyboardInterrupt

        code, out, err = self.run_cli(InterruptedScan)
        self.assertEqual((code, out), (130, ""))
        self.assertIn("Interrupted by user.", err)
        self.assertNotIn("Traceback", err)

    def test_successful_scan_with_action_findings_is_still_zero(self):
        class FindingsScan(_ScannerStub):
            def to_dict(self):
                report = super().to_dict()
                report["checks"] = [{"status": "ACTION"}, {"status": "VERIFY"}]
                return report

        code, out, err = self.run_cli(FindingsScan)
        self.assertEqual(code, 0)
        self.assertIn('"ACTION"', out)
        self.assertIn('"VERIFY"', out)
        self.assertIn("Score: 92/100", err)


if __name__ == "__main__":
    unittest.main()
