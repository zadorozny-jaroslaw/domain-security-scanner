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
            "domeval scan example.com --authorized",
            stdout,
        )
        self.assertIn(
            "domeval diff previous.json current.json",
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
        self.assertIn("-v, --verbose", stdout)
        self.assertIn("-q, --quiet", stdout)
        self.assertNotIn("{1,2,3,4,5", stdout)
        self.assertNotIn("OLD_JSON", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_scan_help_groups_options_by_purpose(self):
        code, stdout, stderr, scanner = self._run(["scan", "--help"])

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

        groups = (
            ("Scan target", ("domain",)),
            ("Authorization", ("--authorized",)),
            ("Scan selection", ("--scan GROUPS", "--skip GROUPS")),
            ("Scan limits", ("--max-pages N", "--max-hosts N")),
            ("Output", ("--out PREFIX", "--json-only", "--json-stdout")),
            ("Logging", ("-v, --verbose", "-q, --quiet")),
        )
        positions = []
        for heading, options in groups:
            marker = f"\n{heading}:\n"
            self.assertIn(marker, stdout)
            positions.append(stdout.index(marker))
            section = stdout.split(marker, 1)[1].split("\n\n", 1)[0]
            for option in options:
                with self.subTest(heading=heading, option=option):
                    self.assertIn(option, section)

        self.assertEqual(positions, sorted(positions))

    def test_grouping_preserves_scan_argument_defaults_and_values(self):
        parser = cli.build_parser()
        defaults = parser.parse_args(["scan", "example.com"])

        self.assertEqual(defaults.domain, "example.com")
        self.assertFalse(defaults.authorized)
        self.assertEqual((defaults.max_pages, defaults.max_hosts), (20, 25))
        self.assertIsNone(defaults.scan)
        self.assertIsNone(defaults.skip)
        self.assertIsNone(defaults.out)
        self.assertFalse(defaults.json_only)
        self.assertFalse(defaults.json_stdout)
        self.assertEqual(defaults.verbose, 0)
        self.assertFalse(defaults.quiet)

        selected = parser.parse_args([
            "scan", "example.com", "--authorized",
            "--scan", "mail,web", "--skip", "mail",
            "--max-pages", "15", "--max-hosts", "30",
            "--json-stdout", "-vv",
        ])
        self.assertTrue(selected.authorized)
        self.assertEqual(selected.scan, ("mail", "web"))
        self.assertEqual(selected.skip, ("mail",))
        self.assertEqual((selected.max_pages, selected.max_hosts), (15, 30))
        self.assertTrue(selected.json_stdout)
        self.assertFalse(selected.json_only)
        self.assertEqual(selected.verbose, 2)

    def test_grouping_preserves_json_output_mutual_exclusion(self):
        code, stdout, stderr, scanner = self._run([
            "scan", "example.com", "--authorized", "--json-only", "--json-stdout",
        ])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("not allowed with argument", stderr)
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
        self.assertNotIn("--verbose", stdout)
        self.assertNotIn("--quiet", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_help_short_flag_matches_long_flag_for_every_command(self):
        for prefix in ([], ["scan"], ["diff"]):
            with self.subTest(command=prefix or ["top-level"]):
                short_code, short_out, short_err, short_scanner = self._run(
                    [*prefix, "-h"]
                )
                long_code, long_out, long_err, long_scanner = self._run(
                    [*prefix, "--help"]
                )
                self.assertEqual((short_code, long_code), (0, 0))
                self.assertEqual(short_out, long_out)
                self.assertEqual((short_err, long_err), ("", ""))
                short_scanner.assert_not_called()
                long_scanner.assert_not_called()

    def test_top_level_help_explains_commands_and_further_help(self):
        code, stdout, stderr, scanner = self._run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("Commands:", stdout)
        self.assertIn("scan  Assess a domain", stdout)
        self.assertIn("diff  Compare saved JSON reports", stdout)
        self.assertIn("domeval scan example.com", stdout)
        self.assertIn("domeval diff previous.json current.json", stdout)
        self.assertIn("domeval COMMAND --help", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_scan_help_has_task_examples_defaults_and_authorization(self):
        code, stdout, stderr, scanner = self._run(["scan", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("domeval scan example.com\n", stdout)
        self.assertIn("--authorized --scan mail,web", stdout)
        self.assertIn("--authorized --json-only", stdout)
        self.assertIn("--json-stdout | jq '.score.score'", stdout)
        self.assertIn("all six scan groups run", stdout)
        self.assertIn("--skip overrides --scan", stdout)
        self.assertIn("non-interactive scans require --authorized", stdout)
        self.assertIn("explicit permission to assess", stdout)
        self.assertIn("security-report-<domain>.json and .pdf", stdout)
        self.assertIn("Progress and diagnostics use stderr", stdout)
        self.assertIn("--json-only or --out", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_diff_help_has_local_example_and_exit_statuses(self):
        code, stdout, stderr, scanner = self._run(["diff", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("domeval diff previous.json current.json", stdout)
        self.assertIn("Reads local JSON files only", stdout)
        self.assertIn("no network scan or authorization", stdout)
        self.assertIn("Exit codes: 0 = equivalent, 1 = changed, 2 = invalid input", stdout)
        self.assertEqual(stderr, "")
        scanner.assert_not_called()

    def test_verbose_and_quiet_are_mutually_exclusive(self):
        code, stdout, stderr, scanner = self._run(
            ["scan", "example.com", "--authorized", "-v", "--quiet"]
        )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("not allowed with argument", stderr)
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
