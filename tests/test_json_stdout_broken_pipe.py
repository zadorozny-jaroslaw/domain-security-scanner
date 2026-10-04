from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import domain_security_scanner.cli as cli


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
                "score": 100,
                "label": "Strong",
                "earned_points": 1,
                "possible_points": 1,
            },
            "checks": [],
        }


class _BrokenPipeBuffer:
    def write(self, data):
        raise BrokenPipeError("downstream consumer closed the pipe")

    def flush(self):
        raise AssertionError("flush should not run after write fails")


class _BrokenBinaryStdout:
    def __init__(self):
        self.buffer = _BrokenPipeBuffer()
        self.close_called = False

    def close(self):
        self.close_called = True


class _BrokenTextStdout:
    def __init__(self):
        self.close_called = False

    def write(self, data):
        raise BrokenPipeError("downstream consumer closed the pipe")

    def flush(self):
        raise AssertionError("flush should not run after write fails")

    def close(self):
        self.close_called = True


class JsonStdoutBrokenPipeTest(unittest.TestCase):
    def _run_with_stdout(self, stdout):
        stderr = io.StringIO()

        with (
            patch.object(cli, "Scanner", _FakeScanner),
            patch.object(cli, "generate_pdf") as generate_pdf,
            patch.object(cli.sys, "stdout", stdout),
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
            stdout_after = cli.sys.stdout

        return result, stderr.getvalue(), generate_pdf, stdout_after

    def test_binary_stdout_broken_pipe_terminates_cleanly(self):
        stdout = _BrokenBinaryStdout()

        result, stderr, generate_pdf, stdout_after = self._run_with_stdout(stdout)

        self.assertEqual(result, 0)
        self.assertTrue(stdout.close_called)
        self.assertIsNone(stdout_after)
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("BrokenPipeError", stderr)
        self.assertNotIn("[+] JSON: stdout", stderr)
        generate_pdf.assert_not_called()

    def test_text_stdout_broken_pipe_terminates_cleanly(self):
        stdout = _BrokenTextStdout()

        result, stderr, generate_pdf, stdout_after = self._run_with_stdout(stdout)

        self.assertEqual(result, 0)
        self.assertTrue(stdout.close_called)
        self.assertIsNone(stdout_after)
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("BrokenPipeError", stderr)
        self.assertNotIn("[+] JSON: stdout", stderr)
        generate_pdf.assert_not_called()


if __name__ == "__main__":
    unittest.main()
