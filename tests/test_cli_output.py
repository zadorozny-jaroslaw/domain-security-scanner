from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import domain_security_scanner.cli as cli


class _InteractiveInput(io.StringIO):
    def isatty(self):
        return True


class _FailIfReadInput(io.StringIO):
    def isatty(self):
        return True

    def readline(self, *args, **kwargs):
        raise AssertionError("--authorized should skip the authorization prompt")


class _FakeScanner:
    last_instance = None

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
        self.max_pages = max_pages
        self.max_hosts = max_hosts
        self.selection_context = None
        self.ran = False
        type(self).last_instance = self

    def set_scan_selection_context(
        self,
        *,
        requested=None,
        skipped=None,
        warnings_list=None,
    ):
        self.selection_context = {
            "requested": requested,
            "skipped": skipped,
            "warnings": list(warnings_list or ()),
        }

    def run(self):
        self.ran = True

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


class CliOutputModeTest(unittest.TestCase):
    def setUp(self):
        _FakeScanner.last_instance = None

    def _run_cli(self, args, *, pdf_side_effect=None, stdin=None):
        stdout = io.StringIO()
        stderr = io.StringIO()

        if stdin is None:
            stdin = io.StringIO()

        with (
            patch.object(sys, "stdin", stdin),
            patch.object(cli, "Scanner", _FakeScanner),
            patch.object(
                cli,
                "generate_pdf",
                side_effect=pdf_side_effect,
            ) as generate_pdf,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(args)

        return result, stdout.getvalue(), stderr.getvalue(), generate_pdf

    def test_default_output_writes_json_and_generates_pdf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "default-report"

            def write_pdf(report, path):
                Path(path).write_bytes(b"%PDF-test")

            result, stdout, stderr, generate_pdf = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--out",
                    str(prefix),
                ],
                pdf_side_effect=write_pdf,
            )

            self.assertEqual(result, 0)
            self.assertEqual(stdout, "")
            self.assertTrue(prefix.with_suffix(".json").is_file())
            self.assertTrue(prefix.with_suffix(".pdf").is_file())
            generate_pdf.assert_called_once()
            self.assertIn("[+] JSON:", stderr)
            self.assertIn("[+] PDF:", stderr)

    def test_json_only_writes_json_without_generating_pdf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "json-report"

            result, stdout, stderr, generate_pdf = self._run_cli(
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
            self.assertTrue(prefix.with_suffix(".json").is_file())
            self.assertFalse(prefix.with_suffix(".pdf").exists())
            generate_pdf.assert_not_called()
            self.assertIn("[+] JSON:", stderr)
            self.assertNotIn("[+] PDF:", stderr)

    def test_json_only_preserves_json_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            default_prefix = Path(tmpdir) / "default"
            json_only_prefix = Path(tmpdir) / "json-only"

            def write_pdf(report, path):
                Path(path).write_bytes(b"%PDF-test")

            default_result, _, _, _ = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--out",
                    str(default_prefix),
                ],
                pdf_side_effect=write_pdf,
            )
            json_only_result, _, _, _ = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--out",
                    str(json_only_prefix),
                ]
            )

            self.assertEqual(default_result, 0)
            self.assertEqual(json_only_result, 0)

            default_report = json.loads(
                default_prefix.with_suffix(".json").read_text(encoding="utf-8")
            )
            json_only_report = json.loads(
                json_only_prefix.with_suffix(".json").read_text(encoding="utf-8")
            )
            self.assertEqual(default_report, json_only_report)

    def test_json_only_remains_compatible_with_scan_skip_and_out(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "scoped-report"

            result, _, stderr, generate_pdf = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--scan",
                    "mail,web",
                    "--skip",
                    "mail",
                    "--out",
                    str(prefix),
                ]
            )

            self.assertEqual(result, 0)
            self.assertTrue(prefix.with_suffix(".json").is_file())
            self.assertFalse(prefix.with_suffix(".pdf").exists())
            generate_pdf.assert_not_called()

            instance = _FakeScanner.last_instance
            self.assertIsNotNone(instance)
            self.assertEqual(instance.scan_groups, ("web",))
            self.assertEqual(
                instance.selection_context["requested"],
                ("mail", "web"),
            )
            self.assertEqual(
                instance.selection_context["skipped"],
                ("mail",),
            )
            self.assertIn("--skip has higher priority", stderr)

    def test_missing_authorized_prompts_and_yes_allows_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "interactive-report"

            result, stdout, stderr, generate_pdf = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--json-only",
                    "--out",
                    str(prefix),
                ],
                stdin=_InteractiveInput("yes\n"),
            )

            self.assertEqual(result, 0)
            self.assertEqual(stdout, "")
            self.assertIn("external requests against example.com", stderr)
            self.assertIn("Continue with scan? [y/N]:", stderr)
            self.assertIsNotNone(_FakeScanner.last_instance)
            self.assertTrue(_FakeScanner.last_instance.ran)
            self.assertTrue(prefix.with_suffix(".json").is_file())
            generate_pdf.assert_not_called()
            self.assertIn("[+] JSON:", stderr)

    def test_missing_authorized_prompts_and_default_no_cancels(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            ["scan", "example.com", "--json-only"],
            stdin=_InteractiveInput("\n"),
        )

        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Continue with scan? [y/N]:", stderr)
        self.assertIn("Scan cancelled.", stderr)
        self.assertIsNone(_FakeScanner.last_instance)
        generate_pdf.assert_not_called()

    def test_missing_authorized_in_non_interactive_mode_fails_with_advice(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            ["scan", "example.com", "--json-only"],
            stdin=io.StringIO("yes\n"),
        )

        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("non-interactive use", stderr)
        self.assertIn("--authorized", stderr)
        self.assertIsNone(_FakeScanner.last_instance)
        generate_pdf.assert_not_called()

    def test_authorized_flag_skips_interactive_prompt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "authorized-report"

            result, stdout, stderr, generate_pdf = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--out",
                    str(prefix),
                ],
                stdin=_FailIfReadInput(),
            )

            self.assertEqual(result, 0)
            self.assertEqual(stdout, "")
            self.assertNotIn("Continue with scan?", stderr)
            self.assertIn("[+] JSON:", stderr)
            self.assertTrue(prefix.with_suffix(".json").is_file())
            generate_pdf.assert_not_called()


if __name__ == "__main__":
    unittest.main()
