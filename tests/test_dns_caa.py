from __future__ import annotations

import unittest
from dataclasses import dataclass
from enum import StrEnum

from domain_security_scanner.domains.domain.caa import (
    analyze_caa_records,
    caa_lookup_names,
    collect_caa_policy,
    parse_caa_record,
)


class _State(StrEnum):
    ANSWER = "answer"
    NO_ANSWER = "no_answer"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class _Result:
    state: _State
    records: tuple[str, ...] = ()
    failed: bool = False
    error: str | None = None


class _Query:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, name, rtype):
        key = (name, rtype)
        self.calls.append(key)
        return self.responses.get(
            key,
            _Result(_State.NO_ANSWER),
        )


class CaaTreeWalkTest(unittest.TestCase):
    def test_lookup_names_climb_to_tld_but_not_dns_root(self):
        self.assertEqual(
            caa_lookup_names("Shop.EU.Example.COM."),
            (
                "shop.eu.example.com",
                "eu.example.com",
                "example.com",
                "com",
            ),
        )

    def test_exact_host_caa_stops_immediately(self):
        query = _Query({
            ("shop.eu.example.com", "CAA"): _Result(
                _State.ANSWER,
                ('0 issue "ca.example"',),
            ),
        })

        evidence = collect_caa_policy("shop.eu.example.com", query)

        self.assertEqual(evidence["effective_name"], "shop.eu.example.com")
        self.assertEqual(evidence["analysis"]["state"], "effective")
        self.assertEqual(
            query.calls,
            [("shop.eu.example.com", "CAA")],
        )

    def test_intermediate_ancestor_caa_is_not_skipped(self):
        query = _Query({
            ("shop.eu.example.com", "CAA"): _Result(_State.NO_ANSWER),
            ("eu.example.com", "CAA"): _Result(
                _State.ANSWER,
                ('0 issue "intermediate-ca.example"',),
            ),
            ("example.com", "CAA"): _Result(
                _State.ANSWER,
                ('0 issue "root-ca.example"',),
            ),
        })

        evidence = collect_caa_policy("shop.eu.example.com", query)

        self.assertEqual(evidence["effective_name"], "eu.example.com")
        self.assertEqual(
            [step["name"] for step in evidence["lookup_chain"]],
            ["shop.eu.example.com", "eu.example.com"],
        )
        self.assertEqual(
            evidence["records"][0]["issuer_domain"],
            "intermediate-ca.example",
        )
        self.assertNotIn(("example.com", "CAA"), query.calls)

    def test_registered_root_caa_is_found_after_empty_children(self):
        query = _Query({
            ("shop.eu.example.com", "CAA"): _Result(_State.NO_ANSWER),
            ("eu.example.com", "CAA"): _Result(_State.NO_ANSWER),
            ("example.com", "CAA"): _Result(
                _State.ANSWER,
                ('0 issue "root-ca.example"',),
            ),
        })

        evidence = collect_caa_policy("shop.eu.example.com", query)

        self.assertEqual(evidence["effective_name"], "example.com")
        self.assertEqual(
            query.calls,
            [
                ("shop.eu.example.com", "CAA"),
                ("eu.example.com", "CAA"),
                ("example.com", "CAA"),
            ],
        )

    def test_no_caa_walks_through_tld_and_reports_absent(self):
        query = _Query()

        evidence = collect_caa_policy("shop.eu.example.com", query)

        self.assertIsNone(evidence["effective_name"])
        self.assertEqual(evidence["analysis"]["state"], "absent")
        self.assertEqual(
            [step["name"] for step in evidence["lookup_chain"]],
            [
                "shop.eu.example.com",
                "eu.example.com",
                "example.com",
                "com",
            ],
        )

    def test_resolver_failure_stops_walk_and_remains_unknown(self):
        query = _Query({
            ("shop.eu.example.com", "CAA"): _Result(_State.NO_ANSWER),
            ("eu.example.com", "CAA"): _Result(
                _State.TIMEOUT,
                failed=True,
                error="timed out",
            ),
            ("example.com", "CAA"): _Result(
                _State.ANSWER,
                ('0 issue "must-not-be-used.example"',),
            ),
        })

        evidence = collect_caa_policy("shop.eu.example.com", query)

        self.assertEqual(evidence["analysis"]["state"], "unknown")
        self.assertIsNone(evidence["effective_name"])
        self.assertEqual(evidence["lookup_failure"]["name"], "eu.example.com")
        self.assertNotIn(("example.com", "CAA"), query.calls)


class CaaParsingTest(unittest.TestCase):
    def test_issue_issuewild_and_iodef_are_parsed_structurally(self):
        analysis = analyze_caa_records(
            [
                '0 issue "ca.example; accounturi=https://ca.example/acct/123; validationmethods=dns-01"',
                '0 issuewild "wild-ca.example"',
                '0 iodef "mailto:security@example.com"',
            ]
        )

        self.assertEqual(
            analysis["recognized_tags"],
            ["iodef", "issue", "issuewild"],
        )
        self.assertEqual(analysis["fqdn_issuers"], ["ca.example"])
        self.assertEqual(analysis["wildcard_issuers"], ["wild-ca.example"])
        self.assertEqual(analysis["iodef_urls"], ["mailto:security@example.com"])
        issue = next(record for record in analysis["parsed_records"] if record["tag"] == "issue")
        self.assertEqual(
            issue["parameters"],
            [
                {"tag": "accounturi", "value": "https://ca.example/acct/123"},
                {"tag": "validationmethods", "value": "dns-01"},
            ],
        )

    def test_iodef_only_does_not_restrict_certificate_issuance(self):
        analysis = analyze_caa_records(
            ['0 iodef "mailto:security@example.com"']
        )

        self.assertTrue(analysis["has_iodef"])
        self.assertFalse(analysis["fqdn_issuance_restricted"])
        self.assertFalse(analysis["wildcard_issuance_restricted"])

    def test_issuewild_only_does_not_restrict_non_wildcard_fqdn(self):
        analysis = analyze_caa_records(
            ['0 issuewild "wild-ca.example"']
        )

        self.assertFalse(analysis["fqdn_issuance_restricted"])
        self.assertTrue(analysis["wildcard_issuance_restricted"])
        self.assertEqual(analysis["wildcard_issuers"], ["wild-ca.example"])

    def test_unknown_critical_tag_uses_most_significant_flag_bit(self):
        analysis = analyze_caa_records(
            [
                '128 tbs "Unknown"',
                '1 future "reserved-bit-only"',
            ]
        )

        self.assertEqual(analysis["unknown_tags"], ["future", "tbs"])
        self.assertEqual(analysis["critical_unknown_tags"], ["tbs"])
        self.assertTrue(analysis["unknown_critical_blocks_unsupported_issuers"])
        tbs = next(record for record in analysis["parsed_records"] if record["tag"] == "tbs")
        future = next(record for record in analysis["parsed_records"] if record["tag"] == "future")
        self.assertTrue(tbs["critical"])
        self.assertFalse(future["critical"])
        self.assertEqual(future["reserved_flags"], 1)

    def test_malformed_issue_value_is_treated_as_empty_issuer(self):
        parsed = parse_caa_record('0 issue "%%%%%"')
        analysis = analyze_caa_records(['0 issue "%%%%%"'])

        self.assertTrue(parsed["syntax_valid"])
        self.assertFalse(parsed["value_valid"])
        self.assertIsNone(parsed["issuer_domain"])
        self.assertTrue(parsed["forbids_issuance"])
        self.assertEqual(
            analysis["malformed_value_records"],
            ['0 issue "%%%%%"'],
        )
        self.assertTrue(analysis["fqdn_issuance_forbidden"])

    def test_unparseable_presentation_is_retained_as_error_evidence(self):
        analysis = analyze_caa_records(["not-a-caa-record"])

        self.assertEqual(analysis["syntax_error_records"], ["not-a-caa-record"])
        self.assertFalse(analysis["parsed_records"][0]["syntax_valid"])


if __name__ == "__main__":
    unittest.main()
