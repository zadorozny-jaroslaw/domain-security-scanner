from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import domain_security_scanner.cli as cli


class CliCommandStructureTest(unittest.TestCase):
    def _run(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(cli, "Scanner") as scanner,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                code = cli.main(args)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue(), scanner

    def test_top_level_help_lists_explicit_commands_and_examples(self):
        code, stdout, stderr, scanner = self._run(["--help"])

        self.assertEqual(code, 0)
        self.assertIn("{scan,diff}", stdout)
        self.assertIn("scan", stdout)
        self.assertIn("diff", stdout)
        self.assertIn(
            "python domain_security_scan.py scan example.com --authorized",
            stdout,
        )
        self.assertIn(
            "python domain_security_scan.py diff previous.json current.json",
            stdout,
        )
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_scan_help_contains_scan_options_and_readable_limits(self):
        code, stdout, stderr, scanner = self._run(["scan", "--help"])

        self.assertEqual(code, 0)
        self.assertIn("Run a security hygiene scan", stdout)
        self.assertIn("--authorized", stdout)
        self.assertIn("Confirm authorization non-interactively", stdout)
        self.assertIn("authorization prompt.", stdout)
        self.assertIn("--max-pages N", stdout)
        self.assertIn("--max-hosts N", stdout)
        self.assertIn("1-100; default: 20", stdout)
        self.assertIn("1-100; default: 25", stdout)
        self.assertIn("--scan", stdout)
        self.assertIn("--skip", stdout)
        self.assertNotIn("{1,2,3,4,5", stdout)
        self.assertNotIn("OLD_JSON", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_diff_help_describes_report_arguments_without_scan_options(self):
        code, stdout, stderr, scanner = self._run(["diff", "--help"])

        self.assertEqual(code, 0)
        self.assertIn("OLD_JSON", stdout)
        self.assertIn("NEW_JSON", stdout)
        self.assertIn("older scanner JSON report", stdout)
        self.assertIn("newer scanner JSON report", stdout)
        self.assertNotIn("--authorized", stdout)
        self.assertNotIn("--max-pages", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_legacy_flat_scan_invocation_is_rejected(self):
        code, stdout, stderr, scanner = self._run(
            ["example.com", "--authorized"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("invalid choice", stderr)
        scanner.assert_not_called()

    def test_legacy_top_level_diff_flag_is_rejected(self):
        code, stdout, stderr, scanner = self._run(
            ["--diff", "old.json", "new.json"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("invalid choice", stderr)
        scanner.assert_not_called()

    def test_max_pages_below_range_is_rejected_before_scanner(self):
        code, stdout, stderr, scanner = self._run(
            ["scan", "example.com", "--authorized", "--max-pages", "0"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("must be between 1 and 100", stderr)
        scanner.assert_not_called()

    def test_max_hosts_above_range_is_rejected_before_scanner(self):
        code, stdout, stderr, scanner = self._run(
            ["scan", "example.com", "--authorized", "--max-hosts", "101"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("must be between 1 and 100", stderr)
        scanner.assert_not_called()

    def test_non_integer_scan_limit_is_rejected_before_scanner(self):
        code, stdout, stderr, scanner = self._run(
            ["scan", "example.com", "--authorized", "--max-pages", "many"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("must be an integer between 1 and 100", stderr)
        scanner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
