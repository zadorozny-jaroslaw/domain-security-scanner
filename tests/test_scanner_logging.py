from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr

from domain_security_scanner.runtime_logging import configure_cli_logging
from domain_security_scanner.scanner import Scanner


class ScannerProgressLoggingTest(unittest.TestCase):
    @staticmethod
    def _replace_steps(instance, *, fail_step=None):
        calls = []

        def step(name):
            def fake(*args, **kwargs):
                calls.append((name, kwargs))
                if name == fail_step:
                    raise RuntimeError("secret-token-must-not-be-logged")
            return fake

        instance.rdap_lookup = step("rdap_lookup")
        instance.collect_domain_dns = step("collect_domain_dns")
        instance.collect_mail_dns = step("collect_mail_dns")
        instance.discover_ct_subdomains = step("discover_ct_subdomains")
        instance.crawl = step("crawl")
        instance.collect_subdomain_dns = step("collect_subdomain_dns")
        instance.check_tls = step("check_tls")
        instance.check_http = step("check_http")
        instance.check_cms_currency = step("check_cms_currency")
        return calls

    def test_default_logging_does_not_emit_scanner_progress(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        calls = self._replace_steps(instance)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging()
            instance.run()

        self.assertEqual(
            [name for name, _ in calls],
            ["rdap_lookup", "collect_mail_dns"],
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_verbose_logs_selected_group_without_claiming_prerequisite_group(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        self._replace_steps(instance)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=1)
            instance.run()

        output = stderr.getvalue()
        self.assertIn("Starting scan group: mail", output)
        self.assertIn("Completed scan group: mail", output)
        self.assertNotIn("Starting scan group: domain", output)
        self.assertNotIn("Completed scan group: domain", output)
        self.assertNotIn("Running step:", output)
        self.assertNotIn("Completed step:", output)

    def test_trace_logs_prerequisite_and_selected_execution_steps(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        self._replace_steps(instance)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            instance.run()

        output = stderr.getvalue()
        self.assertIn(
            "Running step: rdap_lookup [owner=domain, prerequisite]",
            output,
        )
        self.assertIn(
            "Completed step: rdap_lookup [owner=domain, prerequisite]",
            output,
        )
        self.assertIn(
            "Running step: collect_mail_dns [group=mail]",
            output,
        )
        self.assertIn(
            "Completed step: collect_mail_dns [group=mail]",
            output,
        )
        self.assertIn("Starting scan group: mail", output)
        self.assertIn("Completed scan group: mail", output)

    def test_cms_verbose_does_not_report_web_prerequisite_as_selected_group(self):
        instance = Scanner("example.com", scan_groups=("cms",))
        self._replace_steps(instance)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=1)
            instance.run()

        output = stderr.getvalue()
        self.assertIn("Starting scan group: cms", output)
        self.assertIn("Completed scan group: cms", output)
        self.assertNotIn("Starting scan group: web", output)
        self.assertNotIn("Completed scan group: web", output)

    def test_trace_failure_logs_exception_type_but_not_exception_message(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        self._replace_steps(instance, fail_step="collect_mail_dns")
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            with self.assertRaises(RuntimeError):
                instance.run()

        output = stderr.getvalue()
        self.assertIn("Step failed: collect_mail_dns [group=mail]", output)
        self.assertIn("RuntimeError", output)
        self.assertIn("Scan group failed: mail", output)
        self.assertNotIn("secret-token-must-not-be-logged", output)
        self.assertNotIn("Completed scan group: mail", output)

    def test_quiet_suppresses_scanner_progress(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        self._replace_steps(instance)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(quiet=True)
            instance.run()

        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
