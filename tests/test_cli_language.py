"""CLI-facing English text and domain validation contract for issue #26."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import domain_security_scanner.cli as cli
from domain_security_scanner.utils import normalize_domain


class CliLanguageTest(unittest.TestCase):
    def test_invalid_domain_raises_english_message_without_changing_rejection(self):
        for value in ("not a domain", "example..com", "invalid"):
            with self.subTest(domain=value):
                with self.assertRaisesRegex(ValueError, r"^Invalid domain: ") as raised:
                    normalize_domain(value)
                self.assertEqual(str(raised.exception), f"Invalid domain: {value}")

    def test_existing_domain_normalization_is_unchanged(self):
        self.assertEqual(
            normalize_domain("https://WWW.Example.com/path"),
            "www.example.com",
        )
        self.assertEqual(normalize_domain("EXAMPLE.PL."), "example.pl")

    def test_invalid_domain_cli_error_is_english_and_keeps_exit_two(self):
        # Use real domain validation without initializing a network scanner.
        def validate_target(domain, **kwargs):
            normalize_domain(domain)
            self.fail("Invalid domain was accepted by the validator")

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "Scanner", side_effect=validate_target) as scanner,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = cli.main(["scan", "not a domain", "--authorized", "--json-stdout"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Invalid scan target: Invalid domain: not a domain", stderr.getvalue())
        self.assertNotIn("Nieprawidłowa domena", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        scanner.assert_called_once()

    def test_argument_validation_stays_english_and_returns_two(self):
        for arguments, expected in (
            (["scan", "example.com", "--scan", "not-a-group"], "unknown scan group"),
            (["scan", "example.com", "--max-pages", "0"], "must be between 1 and 100"),
        ):
            with self.subTest(arguments=arguments):
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch.object(cli, "Scanner") as scanner,
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as caught,
                ):
                    cli.main(arguments)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(expected, stderr.getvalue())
                scanner.assert_not_called()

    def test_interactive_authorization_notice_preserves_safety_wording(self):
        class TerminalInput(io.StringIO):
            def isatty(self):
                return True

        stderr = io.StringIO()
        with (
            patch.object(cli.sys, "stdin", TerminalInput("no\n")),
            redirect_stderr(stderr),
        ):
            authorized = cli._confirm_scan_authorization("example.com")

        self.assertFalse(authorized)
        self.assertIn("This scan will make external requests against example.com", stderr.getvalue())
        self.assertIn("explicit permission to assess it", stderr.getvalue())
        self.assertIn("Continue with scan? [y/N]", stderr.getvalue())
        self.assertIn("Scan cancelled", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
