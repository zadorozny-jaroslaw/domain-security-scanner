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


def _report(**updates):
    report = {
        "domain": "example.com",
        "target_domain": "example.com",
        "generated_at": "2026-09-28T12:00:00+00:00",
        "score": {"score": 100, "label": "Strong"},
        "checks": [],
        "subdomains": ["www.example.com", "example.com"],
    }
    report.update(updates)
    return report


class CliDiffModeTest(unittest.TestCase):
    def _run(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", ["domain_security_scan.py", *args]),
            patch.object(cli, "Scanner") as scanner,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                code = cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue(), scanner

    def test_diff_does_not_require_domain_or_authorization_or_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = Path(tmpdir) / "old.json"
            new = Path(tmpdir) / "new.json"
            old.write_text(json.dumps(_report()), encoding="utf-8")
            new.write_text(
                json.dumps(_report(generated_at="2026-09-28T13:00:00+00:00")),
                encoding="utf-8",
            )

            code, stdout, stderr, scanner = self._run(["--diff", str(old), str(new)])

            self.assertEqual(code, 0)
            self.assertIn("No meaningful differences.", stdout)
            self.assertEqual(stderr, "")
            scanner.assert_not_called()

    def test_meaningful_difference_returns_one(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = Path(tmpdir) / "old.json"
            new = Path(tmpdir) / "new.json"
            old.write_text(json.dumps(_report()), encoding="utf-8")
            new.write_text(json.dumps(_report(score={"score": 90})), encoding="utf-8")

            code, stdout, _, scanner = self._run(["--diff", str(old), str(new)])

            self.assertEqual(code, 1)
            self.assertIn("CHANGED", stdout)
            scanner.assert_not_called()

    def test_invalid_json_returns_two(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = Path(tmpdir) / "old.json"
            new = Path(tmpdir) / "new.json"
            old.write_text("{broken", encoding="utf-8")
            new.write_text(json.dumps(_report()), encoding="utf-8")

            code, _, stderr, scanner = self._run(["--diff", str(old), str(new)])

            self.assertEqual(code, 2)
            self.assertIn("Diff error:", stderr)
            scanner.assert_not_called()

    def test_scan_and_diff_modes_are_mutually_exclusive(self):
        code, _, stderr, scanner = self._run(
            ["example.com", "--authorized", "--diff", "old.json", "new.json"]
        )
        self.assertEqual(code, 2)
        self.assertIn("cannot be combined", stderr)
        scanner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
