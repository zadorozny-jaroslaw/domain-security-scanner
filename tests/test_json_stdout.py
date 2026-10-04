from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import domain_security_scanner.cli as cli


@contextmanager
def _working_directory(path: str):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


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
            "root_domain": self.root_domain,
            "scan_groups": list(self.scan_groups),
            "score": {
                "score": 91,
                "label": "Strong",
                "earned_points": 9.1,
                "possible_points": 10,
            },
            "checks": [
                {
                    "category": "Mail",
                    "name": "Synthetic JSON stdout finding",
                    "status": "unknown",
                    "message": "stable evidence",
                    "weight": 0,
                    "earned": 0,
                    "applicable": False,
                }
            ],
        }


class JsonStdoutContractTest(unittest.TestCase):
    def _run_cli(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(cli, "Scanner", _FakeScanner),
            patch.object(cli, "generate_pdf") as generate_pdf,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                result = cli.main(args)
            except SystemExit as exc:
                result = exc.code

        return result, stdout.getvalue(), stderr.getvalue(), generate_pdf

    def test_scan_help_describes_json_stdout_as_stdout_only_mode(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            ["scan", "--help"]
        )

        self.assertEqual(result, 0)
        self.assertIn("--json-stdout", stdout)
        self.assertIn("stdout only", stdout)
        self.assertIn("do not create JSON or PDF files", stdout)
        self.assertEqual(stderr, "")
        generate_pdf.assert_not_called()

    def test_json_stdout_emits_valid_report_without_creating_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with _working_directory(tmpdir):
                result, stdout, stderr, generate_pdf = self._run_cli(
                    [
                        "scan",
                        "example.com",
                        "--authorized",
                        "--json-stdout",
                    ]
                )
                created = list(Path(".").iterdir())

        self.assertEqual(result, 0)
        report = json.loads(stdout)
        self.assertEqual(report["target_domain"], "example.com")
        self.assertEqual(report["score"]["score"], 91)
        self.assertEqual(created, [])
        generate_pdf.assert_not_called()
        self.assertIn("[+] Web target: example.com", stderr)
        self.assertIn("[+] JSON: stdout", stderr)

    def test_json_stdout_content_matches_file_json_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "file-report"

            file_result, file_stdout, _, file_pdf = self._run_cli(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--json-only",
                    "--out",
                    str(prefix),
                ]
            )
            with _working_directory(tmpdir):
                stdout_result, json_stdout, _, stdout_pdf = self._run_cli(
                    [
                        "scan",
                        "example.com",
                        "--authorized",
                        "--json-stdout",
                    ]
                )

            file_report = json.loads(
                prefix.with_suffix(".json").read_text(encoding="utf-8")
            )

        self.assertEqual(file_result, 0)
        self.assertEqual(stdout_result, 0)
        self.assertEqual(file_stdout, "")
        self.assertEqual(json.loads(json_stdout), file_report)
        file_pdf.assert_not_called()
        stdout_pdf.assert_not_called()

    def test_json_stdout_uses_utf8_bytes_when_text_wrapper_cannot_encode_report(self):
        binary_stdout = io.BytesIO()
        cp1252_stdout = io.TextIOWrapper(
            binary_stdout,
            encoding="cp1252",
            errors="strict",
        )
        stderr = io.StringIO()

        class _UnicodeScanner(_FakeScanner):
            def to_dict(self):
                report = super().to_dict()
                report["unicode_marker"] = "zażółć gęślą jaźń"
                return report

        try:
            with (
                patch.object(cli, "Scanner", _UnicodeScanner),
                patch.object(cli, "generate_pdf") as generate_pdf,
                patch.object(cli.sys, "stdout", cp1252_stdout),
                redirect_stderr(stderr),
            ):
                result = cli.main(
                    [
                        "scan",
                        "example.com",
                        "--authorized",
                        "--json-stdout",
                    ]
                )

            cp1252_stdout.flush()
            payload = binary_stdout.getvalue().decode("utf-8")
        finally:
            cp1252_stdout.detach()

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(payload)["unicode_marker"],
            "zażółć gęślą jaźń",
        )
        generate_pdf.assert_not_called()
        self.assertIn("[+] JSON: stdout", stderr.getvalue())


    def test_json_stdout_and_json_only_are_mutually_exclusive(self):
        result, stdout, stderr, generate_pdf = self._run_cli(
            [
                "scan",
                "example.com",
                "--authorized",
                "--json-only",
                "--json-stdout",
            ]
        )

        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("not allowed with argument", stderr)
        generate_pdf.assert_not_called()

    def test_json_stdout_rejects_out_before_scanner_activity(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(cli, "Scanner") as scanner,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                result = cli.main(
                    [
                        "scan",
                        "example.com",
                        "--authorized",
                        "--json-stdout",
                        "--out",
                        "should-not-exist",
                    ]
                )
            except SystemExit as exc:
                result = exc.code

        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "--json-stdout is stdout-only and cannot be used with --out",
            stderr.getvalue(),
        )
        scanner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
