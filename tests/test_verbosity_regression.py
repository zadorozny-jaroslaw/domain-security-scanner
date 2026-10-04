from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import domain_security_scanner.cli as cli
from domain_security_scanner.reporting import pdf as pdf_reporting
from domain_security_scanner.runtime_logging import configure_cli_logging


class _DeterministicScanner:
    init_calls = []

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
        self.selection_context = None
        type(self).init_calls.append(
            {
                "domain": domain,
                "max_pages": max_pages,
                "max_hosts": max_hosts,
                "scan_groups": self.scan_groups,
            }
        )

    def set_scan_selection_context(
        self,
        *,
        requested=None,
        skipped=None,
        warnings_list=None,
    ):
        self.selection_context = {
            "requested": list(requested) if requested is not None else None,
            "skipped": list(skipped or ()),
            "warnings": list(warnings_list or ()),
        }

    def run(self):
        pass

    def to_dict(self):
        return {
            "target_domain": self.target_domain,
            "root_domain": self.root_domain,
            "scan_groups": list(self.scan_groups),
            "scan_selection": copy.deepcopy(self.selection_context),
            "score": {
                "score": 87,
                "label": "Good",
                "earned_points": 8.7,
                "possible_points": 10,
            },
            "checks": [
                {
                    "category": "Mail",
                    "name": "Synthetic regression finding",
                    "status": "warn",
                    "message": "stable evidence",
                    "weight": 1,
                    "earned": 0.5,
                    "applicable": True,
                }
            ],
            "evidence_marker": "verbosity-must-not-change-report-data",
        }


class _InvalidScanner:
    def __init__(self, *args, **kwargs):
        raise ValueError("invalid-target-for-quiet-regression")


class VerbosityReportRegressionTest(unittest.TestCase):
    def setUp(self):
        _DeterministicScanner.init_calls = []

    def _run_mode(self, tmpdir: str, name: str, extra_args: list[str]):
        prefix = Path(tmpdir) / name
        stdout = io.StringIO()
        stderr = io.StringIO()
        pdf_reports = []

        def write_pdf(report, path):
            pdf_reports.append(copy.deepcopy(report))
            Path(path).write_bytes(b"%PDF-regression")

        with (
            patch.object(cli, "Scanner", _DeterministicScanner),
            patch.object(cli, "generate_pdf", side_effect=write_pdf) as generate_pdf,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(
                [
                    "scan",
                    "example.com",
                    "--authorized",
                    "--scan",
                    "mail,web",
                    "--out",
                    str(prefix),
                    *extra_args,
                ]
            )

        json_path = prefix.with_suffix(".json")
        pdf_path = prefix.with_suffix(".pdf")
        report = json.loads(json_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(json_path.is_file())
        self.assertTrue(pdf_path.is_file())
        generate_pdf.assert_called_once()
        self.assertEqual(len(pdf_reports), 1)

        return report, pdf_reports[0], stderr.getvalue()

    def test_verbosity_modes_preserve_json_pdf_input_scoring_and_scan_configuration(self):
        modes = [
            ("default", []),
            ("verbose", ["-v"]),
            ("trace", ["-vv"]),
            ("quiet", ["--quiet"]),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            results = {
                name: self._run_mode(tmpdir, name, args)
                for name, args in modes
            }

        baseline_report, baseline_pdf_report, _ = results["default"]

        for name, (report, pdf_report, stderr) in results.items():
            with self.subTest(mode=name):
                self.assertEqual(report, baseline_report)
                self.assertEqual(pdf_report, baseline_pdf_report)
                self.assertEqual(report["score"], baseline_report["score"])
                self.assertEqual(
                    report["evidence_marker"],
                    "verbosity-must-not-change-report-data",
                )
                if name == "quiet":
                    self.assertEqual(stderr, "")

        self.assertEqual(len(_DeterministicScanner.init_calls), len(modes))
        first_call = _DeterministicScanner.init_calls[0]
        for call in _DeterministicScanner.init_calls[1:]:
            self.assertEqual(call, first_call)

    def test_quiet_keeps_real_cli_errors_visible(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(cli, "Scanner", _InvalidScanner),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = cli.main(
                [
                    "scan",
                    "invalid.example",
                    "--authorized",
                    "--quiet",
                    "--json-only",
                ]
            )

        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("invalid-target-for-quiet-regression", stderr.getvalue())


class PdfWarningLoggingRegressionTest(unittest.TestCase):
    def _run_font_fallback(self, *, quiet: bool):
        stderr = io.StringIO()

        with (
            patch.object(pdf_reporting.Path, "exists", return_value=False),
            redirect_stderr(stderr),
        ):
            configure_cli_logging(quiet=quiet)
            fonts = pdf_reporting.register_pdf_fonts()

        return fonts, stderr.getvalue()

    def test_pdf_font_fallback_warning_uses_central_logging(self):
        fonts, output = self._run_font_fallback(quiet=False)

        self.assertEqual(fonts, ("Helvetica", "Helvetica-Bold"))
        self.assertIn("Unicode TTF font not found", output)

    def test_quiet_suppresses_pdf_font_fallback_warning(self):
        fonts, output = self._run_font_fallback(quiet=True)

        self.assertEqual(fonts, ("Helvetica", "Helvetica-Bold"))
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
