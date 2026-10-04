from __future__ import annotations

import io
import logging
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import domain_security_scanner.cli as cli
from domain_security_scanner.runtime_logging import (
    LOGGER_NAME,
    TRACE_LEVEL,
    configure_cli_logging,
    verbosity_to_level,
)


class _FakeScanner:
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
        pass

    def to_dict(self):
        return {
            "target_domain": self.target_domain,
            "scan_groups": list(self.scan_groups),
            "score": {
                "score": 100,
                "label": "Strong",
                "earned_points": 1,
                "possible_points": 1,
            },
            "checks": [],
        }


class RuntimeLoggingTest(unittest.TestCase):
    def test_verbosity_maps_to_expected_levels(self):
        self.assertEqual(verbosity_to_level(), logging.INFO)
        self.assertEqual(verbosity_to_level(verbose=1), logging.DEBUG)
        self.assertEqual(verbosity_to_level(verbose=2), TRACE_LEVEL)
        self.assertEqual(verbosity_to_level(verbose=3), TRACE_LEVEL)
        self.assertEqual(verbosity_to_level(verbose=2, quiet=True), logging.ERROR)

    def test_package_logger_only_emits_messages_allowed_by_level(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            configure_cli_logging(verbose=1)
            project_logger = logging.getLogger(f"{LOGGER_NAME}.test")
            project_logger.debug("debug-visible")
            project_logger.info("info-visible")

        output = stderr.getvalue()
        self.assertIn("debug-visible", output)
        self.assertIn("info-visible", output)

    def test_quiet_suppresses_info_and_warning_but_keeps_errors(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            configure_cli_logging(quiet=True)
            project_logger = logging.getLogger(f"{LOGGER_NAME}.test")
            project_logger.info("info-hidden")
            project_logger.warning("warning-hidden")
            project_logger.error("error-visible")

        output = stderr.getvalue()
        self.assertNotIn("info-hidden", output)
        self.assertNotIn("warning-hidden", output)
        self.assertIn("error-visible", output)

    def test_reconfiguration_does_not_duplicate_cli_handlers(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            configure_cli_logging()
            configure_cli_logging()
            logging.getLogger(f"{LOGGER_NAME}.test").info("once")

        self.assertEqual(stderr.getvalue().count("once"), 1)


class CliLoggingContractTest(unittest.TestCase):
    def _run_cli(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(cli, "Scanner", _FakeScanner),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(args)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_default_scan_writes_human_status_to_stderr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "default"
            result, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--out",
                    str(prefix),
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "")
        self.assertIn("[+] Web target: example.com", stderr)
        self.assertIn("[+] Score: 100/100 (Strong)", stderr)

    def test_quiet_scan_suppresses_normal_status_and_warnings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "quiet"
            result, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--quiet",
                    "--scan",
                    "mail,web",
                    "--skip",
                    "mail",
                    "--out",
                    str(prefix),
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    def test_repeated_cli_calls_do_not_duplicate_status_lines(self):
        stderr = io.StringIO()
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch.object(cli, "Scanner", _FakeScanner),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                for index in range(2):
                    prefix = Path(tmpdir) / f"run-{index}"
                    result = cli.main(
                        [
                            "scan",
                            "example.com",
                            "--authorized",
                            "--json-only",
                            "--out",
                            str(prefix),
                        ]
                    )
                    self.assertEqual(result, 0)

        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue().count("[+] Score: 100/100 (Strong)"), 2)


if __name__ == "__main__":
    unittest.main()
