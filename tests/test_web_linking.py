from __future__ import annotations

import unittest

from domain_security_scanner.scanner import Scanner
from domain_security_scanner.standards import RFC_8288, analyze_link_headers, get_standard


class WebLinkingRegistryTest(unittest.TestCase):
    def test_rfc8288_is_registered(self):
        self.assertEqual(get_standard("rfc8288"), RFC_8288)
        self.assertEqual(RFC_8288.title, "Web Linking")
        self.assertEqual(RFC_8288.url, "https://www.rfc-editor.org/info/rfc8288")


class LinkHeaderRfc8288Test(unittest.TestCase):
    CONTEXT = "https://example.com/docs/page"

    def test_missing_link_header_is_valid_and_informational(self):
        analysis = analyze_link_headers(context_url=self.CONTEXT)
        self.assertFalse(analysis["present"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["link_count"], 0)

    def test_parses_multiple_links_and_resolves_relative_targets(self):
        analysis = analyze_link_headers(
            [
                '</docs/prev>; rel="prev", '
                '<https://cdn.example.com/app.css>; rel="preload stylesheet"; type="text/css"'
            ],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["link_count"], 2)
        self.assertEqual(
            analysis["links"][0]["resolved_target"],
            "https://example.com/docs/prev",
        )
        self.assertEqual(
            analysis["relation_types"],
            ["preload", "prev", "stylesheet"],
        )
        self.assertFalse(analysis["targets_dereferenced"])

    def test_comma_inside_link_target_does_not_split_link_value(self):
        analysis = analyze_link_headers(
            ['<https://example.com/a,b>; rel="alternate"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["link_count"], 1)
        self.assertEqual(
            analysis["links"][0]["target"],
            "https://example.com/a,b",
        )

    def test_comma_inside_quoted_parameter_does_not_split_link_value(self):
        analysis = analyze_link_headers(
            ['</chapter>; rel="next"; title="Chapter 2, continued"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["link_count"], 1)
        self.assertEqual(
            analysis["links"][0]["parameters"]["title"],
            ["Chapter 2, continued"],
        )

    def test_empty_uri_reference_resolves_to_context(self):
        analysis = analyze_link_headers(
            ['<>; rel="self"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["links"][0]["resolved_target"], self.CONTEXT)

    def test_rel_parameter_is_required(self):
        analysis = analyze_link_headers(
            ["</next>; title=Next"],
            context_url=self.CONTEXT,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("missing required rel" in error for error in analysis["errors"]))

    def test_duplicate_rel_is_reviewed_and_first_value_is_used(self):
        analysis = analyze_link_headers(
            ['</next>; rel="next"; rel="alternate"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertEqual(analysis["links"][0]["relations"], ["next"])
        self.assertTrue(any("rel parameter appears more than once" in warning for warning in analysis["warnings"]))

    def test_extension_relation_absolute_uri_is_accepted(self):
        analysis = analyze_link_headers(
            ['</api>; rel="https://example.net/rels/service"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(
            analysis["links"][0]["relations"],
            ["https://example.net/rels/service"],
        )

    def test_invalid_relation_type_is_rejected(self):
        analysis = analyze_link_headers(
            ['</api>; rel="not/a/relation"'],
            context_url=self.CONTEXT,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("invalid link relation type" in error for error in analysis["errors"]))

    def test_rev_parameter_is_deprecated_but_link_remains_parseable(self):
        analysis = analyze_link_headers(
            ['</previous>; rel="next"; rev="prev"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("rev parameter is deprecated" in warning for warning in analysis["warnings"]))

    def test_anchor_changes_context_without_dereferencing(self):
        analysis = analyze_link_headers(
            ['</terms>; rel="copyright"; anchor="#section"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(
            analysis["links"][0]["resolved_context"],
            "https://example.com/docs/page#section",
        )
        self.assertFalse(analysis["targets_dereferenced"])

    def test_invalid_target_uri_reference_is_rejected(self):
        analysis = analyze_link_headers(
            ['<https://exa mple.com/>; rel="canonical"'],
            context_url=self.CONTEXT,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("target" in error for error in analysis["errors"]))

    def test_repeated_hreflang_is_allowed(self):
        analysis = analyze_link_headers(
            ['</translated>; rel="alternate"; hreflang=en; hreflang=pl'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(
            analysis["links"][0]["parameters"]["hreflang"],
            ["en", "pl"],
        )

    def test_duplicate_type_parameter_is_reviewed(self):
        analysis = analyze_link_headers(
            ['</feed>; rel="alternate"; type="application/json"; type="application/xml"'],
            context_url=self.CONTEXT,
        )
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("type parameter appears more than once" in warning for warning in analysis["warnings"]))


class WebLinkingIntegrationTest(unittest.TestCase):
    def test_web_scan_records_link_analysis_and_finding(self):
        instance = Scanner("example.com", scan_groups=("web",))

        class Response:
            def __init__(self, status_code, url, headers=None, text=""):
                self.status_code = status_code
                self.url = url
                self.headers = headers or {}
                self.text = text
                self.history = []
                self.raw = None

        def fake_get(url, **kwargs):
            if url == "http://example.com":
                return Response(301, url, {"Location": "https://example.com"})
            if url.endswith("/.well-known/security.txt"):
                return Response(404, url, {"Content-Type": "text/plain; charset=utf-8"})
            return Response(
                200,
                "https://example.com/",
                {
                    "Link": '</policy>; rel="privacy-policy"',
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                },
                "<html></html>",
            )

        instance.session.get = fake_get
        instance.check_http()

        self.assertTrue(instance.http["links"]["present"])
        self.assertTrue(instance.http["links"]["valid"])
        self.assertEqual(instance.http["links"]["relation_types"], ["privacy-policy"])
        finding = next(check for check in instance.checks if check.name == "HTTP Link header")
        self.assertEqual(finding.status, "info")
        self.assertFalse(finding.applicable)
        self.assertEqual(finding.weight, 0)


if __name__ == "__main__":
    unittest.main()
