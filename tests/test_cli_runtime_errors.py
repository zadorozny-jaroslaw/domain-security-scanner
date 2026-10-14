"""Deterministic CLI runtime-failure contract for issue #29 (no network scans)."""
from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
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


class CliOutputFailureTest(unittest.TestCase):
    def _run_file_mode(self, prefix, *, scanner=_ScannerStub, pdf_error=None, json_only=False):
        stderr, stdout = io.StringIO(), io.StringIO()
        args = ["scan", "example.com", "--authorized", "--out", str(prefix)]
        if json_only:
            args.append("--json-only")
        with (
            patch.object(cli, "Scanner", scanner),
            patch.object(cli, "generate_pdf", side_effect=pdf_error),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = cli.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_json_serialization_failure_returns_four(self):
        class NonSerializableScan(_ScannerStub):
            def to_dict(self):
                report = super().to_dict()
                report["unserializable"] = object()
                return report

        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "report"
            code, out, err = self._run_file_mode(
                prefix, scanner=NonSerializableScan, json_only=True
            )
            self.assertFalse(prefix.with_suffix(".json").exists())
        self.assertEqual((code, out), (4, ""))
        self.assertIn("Could not serialize JSON report", err)
        self.assertNotIn("Traceback", err)

    def test_json_write_permission_failure_returns_four_even_when_quiet(self):
        err = io.StringIO()
        with (
            patch.object(cli, "Scanner", _ScannerStub),
            patch.object(cli.Path, "write_text", side_effect=PermissionError("denied")),
            redirect_stderr(err),
        ):
            code = cli.main(
                ["scan", "example.com", "--authorized", "--json-only", "-q"]
            )
        self.assertEqual(code, 4)
        self.assertIn("Could not write JSON report", err.getvalue())
        self.assertIn("denied", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_pdf_failure_returns_four_and_json_is_still_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "pdf-failure"
            code, out, err = self._run_file_mode(
                prefix, pdf_error=OSError("pdf denied")
            )
            saved = json.loads(prefix.with_suffix(".json").read_text())
        self.assertEqual((code, out), (4, ""))
        self.assertEqual(saved["score"]["score"], 92)
        self.assertIn("Could not generate PDF report", err)
        self.assertIn("pdf denied", err)

    def test_pdf_keyboard_interrupt_returns_130(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self._run_file_mode(
                Path(tmp) / "report", pdf_error=KeyboardInterrupt
            )
        self.assertEqual((code, out), (130, ""))
        self.assertIn("Interrupted by user", err)

    def test_stdout_write_failure_returns_four(self):
        class FailingStdout:
            def write(self, chunk):
                raise OSError("stdout unavailable")

            def flush(self):
                pass

        err = io.StringIO()
        with (
            patch.object(cli, "Scanner", _ScannerStub),
            patch.object(cli.sys, "stdout", FailingStdout()),
            redirect_stderr(err),
        ):
            code = cli.main(
                ["scan", "example.com", "--authorized", "--json-stdout"]
            )
        self.assertEqual(code, 4)
        self.assertIn("Could not write JSON to stdout", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


class CliDiffRuntimeContractTest(unittest.TestCase):
    def _run_diff(self, old_path, new_path):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(["diff", str(old_path), str(new_path)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_invalid_utf8_report_returns_two_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "invalid-utf8.json"
            new = Path(tmp) / "valid.json"
            old.write_bytes(b"\xff\xfe")
            new.write_text(
                json.dumps({"target_domain": "example.com", "score": {}, "checks": []}),
                encoding="utf-8",
            )
            code, out, err = self._run_diff(old, new)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("cannot decode", err)
        self.assertNotIn("Traceback", err)

    def test_missing_diff_file_returns_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self._run_diff(
                Path(tmp) / "missing.json", Path(tmp) / "also-missing.json"
            )
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Diff error", err)

    def test_diff_unchanged_and_changed_exit_codes_remain_zero_and_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            template = {"target_domain": "example.com", "checks": [], "score": {"score": 100}}
            a.write_text(json.dumps(template), encoding="utf-8")
            b.write_text(json.dumps(template), encoding="utf-8")
            equal_code, equal_out, equal_err = self._run_diff(a, b)
            template["score"]["score"] = 50
            b.write_text(json.dumps(template), encoding="utf-8")
            changed_code, changed_out, changed_err = self._run_diff(a, b)
        self.assertEqual((equal_code, changed_code), (0, 1))
        self.assertIn("No meaningful differences", equal_out)
        self.assertIn("CHANGED", changed_out)
        self.assertEqual((equal_err, changed_err), ("", ""))


if __name__ == "__main__":
    unittest.main()
