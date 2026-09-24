from __future__ import annotations

import argparse
import unittest

from domain_security_scanner.cli import _parse_group_list, _resolve_scan_groups
from domain_security_scanner.orchestration import build_scan_plan, normalize_scan_groups
from domain_security_scanner.reporting.pdf import REPORT_SCAN_GROUPS, _report_scan_scope
from domain_security_scanner.scanner import SCAN_GROUPS, Scanner


class ScanGroupCliTest(unittest.TestCase):
    def test_default_selects_all_groups(self):
        selected, warnings_list = _resolve_scan_groups(None, None)
        self.assertEqual(selected, SCAN_GROUPS)
        self.assertEqual(warnings_list, [])

    def test_scan_selects_only_requested_groups_in_canonical_order(self):
        selected, warnings_list = _resolve_scan_groups(("web", "mail"), None)
        self.assertEqual(selected, ("mail", "web"))
        self.assertEqual(warnings_list, [])

    def test_skip_removes_groups_from_default_full_scan(self):
        selected, warnings_list = _resolve_scan_groups(None, ("cms", "discovery"))
        self.assertEqual(
            selected,
            ("domain", "mail", "tls", "web"),
        )
        self.assertEqual(warnings_list, [])

    def test_skip_wins_when_scan_and_skip_are_both_present(self):
        selected, warnings_list = _resolve_scan_groups(
            ("domain", "mail", "web"),
            ("mail", "cms"),
        )
        self.assertEqual(selected, ("domain", "web"))
        self.assertEqual(len(warnings_list), 2)
        self.assertIn("--skip has higher priority", warnings_list[0])
        self.assertIn("mail", warnings_list[1])
        self.assertIn("will NOT be scanned", warnings_list[1])

    def test_scan_and_skip_without_overlap_only_warns_about_redundancy(self):
        selected, warnings_list = _resolve_scan_groups(
            ("mail", "web"),
            ("cms",),
        )
        self.assertEqual(selected, ("mail", "web"))
        self.assertEqual(len(warnings_list), 1)
        self.assertIn("--skip has higher priority", warnings_list[0])

    def test_skip_all_groups_warns_when_no_scope_remains(self):
        selected, warnings_list = _resolve_scan_groups(None, SCAN_GROUPS)
        self.assertEqual(selected, ())
        self.assertEqual(len(warnings_list), 1)
        self.assertIn("No scan groups remain selected", warnings_list[0])

    def test_overlap_can_remove_entire_requested_scope(self):
        selected, warnings_list = _resolve_scan_groups(("mail",), ("mail",))
        self.assertEqual(selected, ())
        self.assertEqual(len(warnings_list), 3)
        self.assertIn("--skip has higher priority", warnings_list[0])
        self.assertIn("mail", warnings_list[1])
        self.assertIn("No scan groups remain selected", warnings_list[2])

    def test_group_list_is_case_insensitive_and_deduplicated(self):
        self.assertEqual(
            _parse_group_list(" MAIL,web,mail "),
            ("mail", "web"),
        )

    def test_group_list_rejects_empty_value(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_group_list(" , ")

    def test_group_aliases_are_not_accepted(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_group_list("all")

    def test_unknown_group_is_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_group_list("web,unknown")


class ScanOrchestrationPlanTest(unittest.TestCase):
    def test_default_plan_preserves_existing_execution_order_and_ownership(self):
        plan = build_scan_plan(SCAN_GROUPS)

        self.assertEqual(
            [(step.active_group, step.method_name) for step in plan],
            [
                ("domain", "rdap_lookup"),
                ("domain", "collect_domain_dns"),
                ("mail", "collect_mail_dns"),
                ("discovery", "discover_ct_subdomains"),
                ("discovery", "crawl"),
                ("discovery", "collect_subdomain_dns"),
                ("tls", "check_tls"),
                ("web", "check_http"),
                ("cms", "check_cms_currency"),
            ],
        )
        self.assertEqual(plan[-2].call_kwargs(), {"run_web_checks": True})

    def test_each_individual_group_has_expected_plan(self):
        expected = {
            "domain": [
                ("domain", "rdap_lookup"),
                ("domain", "collect_domain_dns"),
            ],
            "discovery": [
                ("domain", "rdap_lookup"),
                ("discovery", "discover_ct_subdomains"),
                ("discovery", "crawl"),
                ("discovery", "collect_subdomain_dns"),
            ],
            "mail": [
                ("domain", "rdap_lookup"),
                ("mail", "collect_mail_dns"),
            ],
            "tls": [
                ("tls", "check_tls"),
            ],
            "web": [
                ("web", "check_http"),
            ],
            "cms": [
                ("web", "check_http"),
                ("cms", "check_cms_currency"),
            ],
        }

        for group, expected_steps in expected.items():
            with self.subTest(group=group):
                plan = build_scan_plan((group,))
                self.assertEqual(
                    [(step.active_group, step.method_name) for step in plan],
                    expected_steps,
                )

    def test_web_and_cms_share_one_http_context_step(self):
        plan = build_scan_plan(("web", "cms"))

        self.assertEqual(
            [step.method_name for step in plan],
            ["check_http", "check_cms_currency"],
        )
        self.assertEqual(plan[0].call_kwargs(), {"run_web_checks": True})

    def test_cms_only_uses_http_context_without_web_findings(self):
        plan = build_scan_plan(("cms",))

        self.assertEqual(
            [(step.active_group, step.method_name) for step in plan],
            [("web", "check_http"), ("cms", "check_cms_currency")],
        )
        self.assertEqual(plan[0].call_kwargs(), {"run_web_checks": False})

    def test_empty_selection_produces_no_execution_steps(self):
        self.assertEqual(build_scan_plan(()), ())

    def test_normalize_scan_groups_keeps_canonical_order(self):
        self.assertEqual(
            normalize_scan_groups(("web", "domain", "web", "mail")),
            ("domain", "mail", "web"),
        )

    def test_normalize_scan_groups_rejects_unknown_group(self):
        with self.assertRaises(ValueError):
            normalize_scan_groups(("web", "unknown"))


class ScannerGroupGatingTest(unittest.TestCase):
    @staticmethod
    def _replace_steps(instance):
        calls = []

        def step(name):
            def fake(*args, **kwargs):
                calls.append((name, kwargs))
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

    def test_default_run_keeps_existing_execution_order(self):
        instance = Scanner("example.com")
        calls = self._replace_steps(instance)

        instance.run()

        self.assertEqual(
            [name for name, _ in calls],
            [
                "rdap_lookup",
                "collect_domain_dns",
                "collect_mail_dns",
                "discover_ct_subdomains",
                "crawl",
                "collect_subdomain_dns",
                "check_tls",
                "check_http",
                "check_cms_currency",
            ],
        )
        self.assertTrue(calls[-2][1]["run_web_checks"])

    def test_mail_only_uses_domain_lookup_as_silent_prerequisite(self):
        instance = Scanner("example.com", scan_groups=("mail",))
        calls = self._replace_steps(instance)

        instance.run()

        self.assertEqual(
            [name for name, _ in calls],
            ["rdap_lookup", "collect_mail_dns"],
        )

    def test_web_only_does_not_run_cms_group(self):
        instance = Scanner("example.com", scan_groups=("web",))
        calls = self._replace_steps(instance)

        instance.run()

        self.assertEqual([name for name, _ in calls], ["check_http"])
        self.assertTrue(calls[0][1]["run_web_checks"])

    def test_cms_only_reuses_https_context_without_web_checks(self):
        instance = Scanner("example.com", scan_groups=("cms",))
        calls = self._replace_steps(instance)

        instance.run()

        self.assertEqual(
            [name for name, _ in calls],
            ["check_http", "check_cms_currency"],
        )
        self.assertFalse(calls[0][1]["run_web_checks"])

    def test_skipped_prerequisite_findings_are_suppressed(self):
        instance = Scanner("example.com", scan_groups=("mail",))

        instance._run_group_step(
            "domain",
            instance.add_check,
            "Domain",
            "prerequisite",
            "warn",
            "should be hidden",
            1,
            0,
        )
        instance._run_group_step(
            "mail",
            instance.add_check,
            "Mail",
            "selected",
            "pass",
            "should be visible",
            1,
            1,
        )

        self.assertEqual([check.name for check in instance.checks], ["selected"])

    def test_skipped_prerequisite_findings_do_not_affect_score(self):
        instance = Scanner("example.com", scan_groups=("mail",))

        instance._run_group_step(
            "domain",
            instance.add_check,
            "Domain",
            "hidden prerequisite",
            "fail",
            "must not affect score",
            10,
            0,
        )
        instance._run_group_step(
            "mail",
            instance.add_check,
            "Mail",
            "selected check",
            "pass",
            "counts toward score",
            2,
            2,
        )

        self.assertEqual(
            instance.score(),
            {
                "score": 100,
                "label": "Strong",
                "earned_points": 2,
                "possible_points": 2,
            },
        )

    def test_scan_selection_metadata_preserves_cli_intent(self):
        instance = Scanner("example.com", scan_groups=("web",))
        warnings_list = [
            "Both --scan and --skip were provided. --skip has higher priority; using both options may be redundant.",
            "The following scan groups are listed in both --scan and --skip and will NOT be scanned: mail.",
        ]

        instance.set_scan_selection_context(
            requested=("mail", "web"),
            skipped=("mail",),
            warnings_list=warnings_list,
        )
        report = instance.to_dict()

        self.assertEqual(report["scan_groups"], ["web"])
        self.assertEqual(report["scan_selection"]["requested"], ["mail", "web"])
        self.assertEqual(report["scan_selection"]["skipped"], ["mail"])
        self.assertEqual(report["scan_selection"]["overlap"], ["mail"])
        self.assertEqual(report["scan_selection"]["effective"], ["web"])
        self.assertEqual(report["scan_selection"]["warnings"], warnings_list)


class ReportScanScopeTest(unittest.TestCase):
    def test_legacy_report_without_scan_groups_renders_as_full_scope(self):
        selected, skipped, warnings_list = _report_scan_scope({})
        self.assertEqual(selected, REPORT_SCAN_GROUPS)
        self.assertEqual(skipped, ())
        self.assertEqual(warnings_list, ())

    def test_report_scope_uses_effective_groups_and_selection_warnings(self):
        report = {
            "scan_groups": ["web"],
            "scan_selection": {
                "warnings": [
                    "Both --scan and --skip were provided.",
                    "mail will NOT be scanned.",
                ]
            },
        }

        selected, skipped, warnings_list = _report_scan_scope(report)

        self.assertEqual(selected, ("web",))
        self.assertEqual(
            skipped,
            ("domain", "discovery", "mail", "tls", "cms"),
        )
        self.assertEqual(
            warnings_list,
            (
                "Both --scan and --skip were provided.",
                "mail will NOT be scanned.",
            ),
        )

    def test_explicit_empty_scope_is_not_treated_as_legacy_full_scan(self):
        selected, skipped, warnings_list = _report_scan_scope({"scan_groups": []})
        self.assertEqual(selected, ())
        self.assertEqual(skipped, REPORT_SCAN_GROUPS)
        self.assertEqual(warnings_list, ())



class CmsPrerequisiteHttpTest(unittest.TestCase):
    def test_cms_only_http_context_fetches_only_https_homepage(self):
        instance = Scanner("example.com", scan_groups=("cms",))
        urls = []

        class Response:
            status_code = 200
            url = "https://example.com/"
            headers = {}
            text = "<html></html>"

        def fake_get(url, **kwargs):
            urls.append(url)
            return Response()

        instance.session.get = fake_get

        active_groups = []

        def fake_detect(response, html):
            active_groups.append(instance._active_scan_group)
            instance.add_check(
                "Web",
                "CMS / platform",
                "info",
                "cms context",
                0,
                0,
                False,
            )
            return {
                "detected": False,
                "name": None,
                "version": None,
                "confidence": "none",
                "signals": [],
                "technology_headers": {},
            }

        instance.detect_cms = fake_detect
        instance._run_group_step(
            "web",
            instance.check_http,
            run_web_checks=False,
        )

        self.assertEqual(urls, ["https://example.com"])
        self.assertEqual(active_groups, ["cms"])
        self.assertEqual([check.name for check in instance.checks], ["CMS / platform"])


if __name__ == "__main__":
    unittest.main()
