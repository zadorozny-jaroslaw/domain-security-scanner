from __future__ import annotations

import unittest

from domain_security_scanner.scanner import Scanner
from domain_security_scanner.standards import (
    RFC_7838,
    analyze_alt_svc_headers,
    get_standard,
)


class AltSvcRegistryTest(unittest.TestCase):
    def test_rfc7838_is_registered(self):
        self.assertEqual(get_standard("rfc7838"), RFC_7838)
        self.assertEqual(RFC_7838.title, "HTTP Alternative Services")
        self.assertEqual(RFC_7838.url, "https://www.rfc-editor.org/info/rfc7838")


class AltSvcRfc7838Test(unittest.TestCase):
    ORIGIN = "https://example.com/"

    def test_missing_alt_svc_is_valid_and_informational(self):
        analysis = analyze_alt_svc_headers(origin_url=self.ORIGIN)
        self.assertFalse(analysis["present"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["alternative_count"], 0)
        self.assertFalse(analysis["alternatives_contacted"])

    def test_clear_is_valid_without_alternatives(self):
        analysis = analyze_alt_svc_headers(
            ["clear"],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["clear"])
        self.assertEqual(analysis["alternative_count"], 0)

    def test_clear_mixed_with_alternative_is_invalid(self):
        analysis = analyze_alt_svc_headers(
            ['clear, h3=":443"'],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("must not be combined" in item for item in analysis["errors"]))

    def test_clear_must_be_the_sole_field_value(self):
        analysis = analyze_alt_svc_headers(
            ["clear, clear"],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("sole field value" in item for item in analysis["errors"]))

    def test_parses_multiple_alternatives_in_preference_order(self):
        analysis = analyze_alt_svc_headers(
            ['h2="alt.example.com:8443", h3=":443"'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["protocol_ids"], ["h2", "h3"])
        self.assertEqual(analysis["alternative_count"], 2)
        self.assertEqual(
            analysis["alternatives"][0]["authority"]["resolved_host"],
            "alt.example.com",
        )
        self.assertEqual(
            analysis["alternatives"][1]["authority"]["resolved_host"],
            "example.com",
        )
        self.assertTrue(analysis["alternatives"][1]["authority"]["uses_origin_host"])

    def test_default_ma_is_24_hours(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"'],
            origin_url=self.ORIGIN,
        )
        alternative = analysis["alternatives"][0]
        self.assertEqual(alternative["ma"], 86400)
        self.assertTrue(alternative["ma_defaulted"])

    def test_ma_and_response_age_produce_remaining_freshness(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"; ma=3600'],
            origin_url=self.ORIGIN,
            response_age=30,
        )
        alternative = analysis["alternatives"][0]
        self.assertEqual(alternative["ma"], 3600)
        self.assertFalse(alternative["ma_defaulted"])
        self.assertEqual(alternative["remaining_freshness"], 3570)

    def test_persist_one_is_accepted(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"; persist=1'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertTrue(analysis["alternatives"][0]["persist"])

    def test_persist_other_value_is_ignored_and_reviewed(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"; persist=0'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertFalse(analysis["alternatives"][0]["persist"])
        self.assertTrue(any("ignored" in item for item in analysis["warnings"]))

    def test_unknown_parameter_is_retained_and_accepted(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"; future=enabled'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(
            analysis["alternatives"][0]["unknown_parameters"],
            ["future"],
        )

    def test_quoted_ma_is_invalid(self):
        analysis = analyze_alt_svc_headers(
            ['h3=":443"; ma="60"'],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("unquoted" in item for item in analysis["errors"]))

    def test_alt_authority_requires_quoted_string(self):
        analysis = analyze_alt_svc_headers(
            ["h3=:443"],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("quoted-string" in item for item in analysis["errors"]))

    def test_ipv6_alt_authority_is_accepted(self):
        analysis = analyze_alt_svc_headers(
            ['h3="[2001:db8::1]:443"'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(
            analysis["alternatives"][0]["authority"]["host"],
            "[2001:db8::1]",
        )

    def test_ipvfuture_alt_authority_is_accepted(self):
        analysis = analyze_alt_svc_headers(
            ['h3="[v1.example]:443"'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])

    def test_internationalized_host_must_use_a_label(self):
        analysis = analyze_alt_svc_headers(
            ['h3="münich.example:443"'],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("A-label" in item for item in analysis["errors"]))

    def test_uppercase_percent_encoding_for_protocol_id_is_accepted(self):
        analysis = analyze_alt_svc_headers(
            ['w%3Dx%3Ay#z=":443"'],
            origin_url=self.ORIGIN,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["protocol_ids"], ["w%3Dx%3Ay#z"])

    def test_lowercase_percent_encoding_for_protocol_id_is_invalid(self):
        analysis = analyze_alt_svc_headers(
            ['w%3dx=":443"'],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("uppercase" in item for item in analysis["errors"]))

    def test_token_character_must_not_be_unnecessarily_percent_encoded(self):
        analysis = analyze_alt_svc_headers(
            ['%68%32=":443"'],
            origin_url=self.ORIGIN,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("unnecessarily" in item for item in analysis["errors"]))


class AltSvcIntegrationTest(unittest.TestCase):
    def test_web_scan_records_alt_svc_without_contacting_alternative(self):
        instance = Scanner("example.com", scan_groups=("web",))

        class Response:
            def __init__(self, status_code, url, headers=None, text=""):
                self.status_code = status_code
                self.url = url
                self.headers = headers or {}
                self.text = text
                self.history = []
                self.raw = None

        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            if url == "http://example.com":
                return Response(301, url, {"Location": "https://example.com"})
            if url.endswith("/.well-known/security.txt"):
                return Response(
                    404,
                    url,
                    {"Content-Type": "text/plain; charset=utf-8"},
                )
            return Response(
                200,
                "https://example.com/",
                {
                    "Alt-Svc": 'h3="alt.example.net:443"; ma=3600; persist=1',
                    "Link": '</policy>; rel="privacy-policy"',
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                },
                "<html></html>",
            )

        instance.session.get = fake_get
        instance.check_http()

        self.assertTrue(instance.http["alt_svc"]["present"])
        self.assertTrue(instance.http["alt_svc"]["valid"])
        self.assertFalse(instance.http["alt_svc"]["alternatives_contacted"])
        self.assertEqual(instance.http["alt_svc"]["protocol_ids"], ["h3"])
        self.assertIn("links", instance.http)
        self.assertNotIn("https://alt.example.net:443", calls)

        finding = next(check for check in instance.checks if check.name == "HTTP Alt-Svc")
        self.assertEqual(finding.status, "info")
        self.assertFalse(finding.applicable)
        self.assertEqual(finding.weight, 0)


if __name__ == "__main__":
    unittest.main()
