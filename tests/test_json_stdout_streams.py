from __future__ import annotations

import io
import json
import logging
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import domain_security_scanner.cli as cli
from domain_security_scanner.runtime_logging import TRACE_LEVEL


_probe_logger = logging.getLogger("domain_security_scanner.scanner")


class _StreamProbeScanner:
    def __init__(
        self,
        domain,
        *,
        max_pages=20,
        max_hosts=25,
        scan_groups=None,
    ):
        self.target_domain = domain
        self.root_domain = "example.com"
        self.scan_groups = tuple(scan_groups or ())

    def set_scan_selection_context(self, **kwargs):
        pass

    def run(self):
        _probe_logger.debug("slice2-debug-probe")
        _probe_logger.log(TRACE_LEVEL, "slice2-trace-probe")

    def to_dict(self):
        return {
            "target_domain": self.target_domain,
            "root_domain": self.root_domain,
            "scan_groups": list(self.scan_groups),
            "score": {
                "score": 93,
                "label": "Strong",
                "earned_points": 9.3,
                "possible_points": 10,
            },
            "checks": [
                {
                    "category": "Mail",
                    "name": "Stream contract probe",
                    "status": "unknown",
                    "message": "stable evidence",
                    "weight": 0,
                    "earned": 0,
                    "applicable": False,
                }
            ],
        }


class JsonStdoutStreamContractTest(unittest.TestCase):
    def _run_cli(self, extra_args=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        args = [
            "scan",
            "example.com",
            "--authorized",
            "--json-stdout",
        ]
        args.extend(extra_args or ())

        with (
            patch.object(cli, "Scanner", _StreamProbeScanner),
            patch.object(cli, "generate_pdf") as generate_pdf,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(args)

        return result, stdout.getvalue(), stderr.getvalue(), generate_pdf

    def _assert_pure_json_stdout(self, stdout):
        report = json.loads(stdout)
        self.assertNotIn("[+]", stdout)
        self.assertNotIn("[!]", stdout)
        self.assertNotIn("slice2-debug-probe", stdout)
        self.assertNotIn("slice2-trace-probe", stdout)
        return report

    def test_default_mode_keeps_human_status_on_stderr(self):
        result, stdout, stderr, generate_pdf = self._run_cli()

        self.assertEqual(result, 0)
        report = self._assert_pure_json_stdout(stdout)
        self.assertEqual(report["target_domain"], "example.com")
        self.assertIn("[+] Web target: example.com", stderr)
        self.assertIn("[+] JSON: stdout", stderr)
        self.assertNotIn("slice2-debug-probe", stderr)
        self.assertNotIn("slice2-trace-probe", stderr)
        generate_pdf.assert_not_called()

    def test_verbose_mode_keeps_debug_progress_on_stderr(self):
        result, stdout, stderr, generate_pdf = self._run_cli(["-v"])

        self.assertEqual(result, 0)
        self._assert_pure_json_stdout(stdout)
        self.assertIn("slice2-debug-probe", stderr)
        self.assertNotIn("slice2-trace-probe", stderr)
        generate_pdf.assert_not_called()

    def test_double_verbose_mode_keeps_trace_diagnostics_on_stderr(self):
        result, stdout, stderr, generate_pdf = self._run_cli(["-vv"])

        self.assertEqual(result, 0)
        self._assert_pure_json_stdout(stdout)
        self.assertIn("slice2-debug-probe", stderr)
        self.assertIn("slice2-trace-probe", stderr)
        generate_pdf.assert_not_called()

    def test_selection_warning_does_not_corrupt_json_stdout(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            [
                "--scan",
                "mail,web",
                "--skip",
                "mail",
            ]
        )

        self.assertEqual(result, 0)
        report = self._assert_pure_json_stdout(stdout)
        self.assertEqual(report["scan_groups"], ["web"])
        self.assertIn("[!] Warning:", stderr)
        self.assertIn("--skip has higher priority", stderr)
        generate_pdf.assert_not_called()

    def test_quiet_mode_preserves_requested_json_and_suppresses_human_output(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            [
                "--quiet",
                "--scan",
                "mail,web",
                "--skip",
                "mail",
            ]
        )

        self.assertEqual(result, 0)
        report = self._assert_pure_json_stdout(stdout)
        self.assertEqual(report["scan_groups"], ["web"])
        self.assertEqual(stderr, "")
        generate_pdf.assert_not_called()

    def test_report_content_is_identical_across_verbosity_modes(self):
        reports = []

        for mode_args in ([], ["-v"], ["-vv"], ["--quiet"]):
            with self.subTest(mode=mode_args or ["default"]):
                result, stdout, _, generate_pdf = self._run_cli(mode_args)
                self.assertEqual(result, 0)
                reports.append(self._assert_pure_json_stdout(stdout))
                generate_pdf.assert_not_called()

        for report in reports[1:]:
            self.assertEqual(report, reports[0])


if __name__ == "__main__":
    unittest.main()
