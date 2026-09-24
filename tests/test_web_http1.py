from __future__ import annotations

import unittest

from domain_security_scanner.scanner import Scanner
from domain_security_scanner.standards import (
    RFC_9112,
    analyze_http1_response_framing,
    get_standard,
    normalize_http_version,
)


class Http11RegistryTest(unittest.TestCase):
    def test_rfc9112_is_registered(self):
        self.assertEqual(get_standard("rfc9112"), RFC_9112)
        self.assertEqual(RFC_9112.title, "HTTP/1.1")
        self.assertEqual(RFC_9112.url, "https://www.rfc-editor.org/info/rfc9112")


class Http11FramingRfc9112Test(unittest.TestCase):
    def test_normalizes_urllib3_http_version_integer(self):
        self.assertEqual(normalize_http_version(11), "1.1")
        self.assertEqual(normalize_http_version(10), "1.0")
        self.assertEqual(normalize_http_version("HTTP/2"), "2")

    def test_valid_content_length_response(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["123"],
        )
        self.assertTrue(analysis["applicable"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["framing"], "content-length")
        self.assertEqual(analysis["content_length"], 123)

    def test_identical_duplicate_content_length_is_accepted(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["42", "42"],
            raw_header_fidelity=True,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertTrue(analysis["duplicate_identical_content_length"])
        self.assertEqual(analysis["content_length"], 42)

    def test_comma_joined_identical_content_length_is_accepted(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["42, 42"],
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertTrue(analysis["duplicate_identical_content_length"])

    def test_conflicting_content_length_requires_review(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["42", "43"],
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(analysis["conflicting_content_length"])

    def test_invalid_content_length_requires_review(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["12x"],
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("invalid Content-Length" in item for item in analysis["errors"]))

    def test_transfer_encoding_and_content_length_requires_review(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            content_length_values=["100"],
            transfer_encoding_values=["chunked"],
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(
            any("Transfer-Encoding and Content-Length" in item for item in analysis["errors"])
        )

    def test_final_chunked_transfer_encoding_is_valid(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            transfer_encoding_values=["gzip, chunked"],
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["framing"], "chunked")
        self.assertTrue(analysis["chunked_final"])

    def test_duplicate_chunked_requires_review(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            transfer_encoding_values=["chunked, chunked"],
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("more than once" in item for item in analysis["errors"]))

    def test_nonfinal_transfer_coding_is_close_delimited_not_automatic_failure(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            transfer_encoding_values=["chunked, gzip"],
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(
            analysis["framing"],
            "close-delimited-transfer-encoding",
        )
        self.assertTrue(any("connection close" in item for item in analysis["notes"]))

    def test_no_explicit_length_is_close_delimited_and_informational(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
        )
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["framing"], "close-delimited")

    def test_bodyless_status_is_classified_without_body(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=204,
            content_length_values=["0"],
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["framing"], "no-body")
        self.assertTrue(analysis["body_forbidden_by_status_or_method"])

    def test_http2_is_not_applicable(self):
        analysis = analyze_http1_response_framing(
            http_version=20,
            status_code=200,
            content_length_values=["20"],
        )
        self.assertFalse(analysis["applicable"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["http_version"], "2")

    def test_http10_transfer_encoding_is_faulty(self):
        analysis = analyze_http1_response_framing(
            http_version=10,
            status_code=200,
            transfer_encoding_values=["chunked"],
        )
        self.assertFalse(analysis["applicable"])
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("HTTP/1.0" in item for item in analysis["errors"]))

    def test_wire_level_claims_remain_explicitly_unverified(self):
        analysis = analyze_http1_response_framing(
            http_version=11,
            status_code=200,
            transfer_encoding_values=["chunked"],
        )
        self.assertFalse(analysis["raw_wire_checked"])
        self.assertFalse(analysis["body_length_verified"])
        self.assertFalse(analysis["chunk_boundaries_verified"])
        self.assertFalse(analysis["trailers_verified"])


class Http11FramingIntegrationTest(unittest.TestCase):
    def test_web_scan_reuses_primary_response_without_extra_probe(self):
        instance = Scanner("example.com", scan_groups=("web",))

        class RawHeaders:
            def __init__(self, values):
                self.values = values

            def getlist(self, name):
                return list(self.values.get(name.lower(), []))

        class Raw:
            def __init__(self, values):
                self.version = 11
                self.headers = RawHeaders(values)

        class Response:
            def __init__(self, status_code, url, headers=None, text="", raw_values=None):
                self.status_code = status_code
                self.url = url
                self.headers = headers or {}
                self.text = text
                self.history = []
                self.raw = Raw(raw_values or {})

        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            if url == "http://example.com":
                return Response(
                    301,
                    url,
                    {"Location": "https://example.com"},
                )
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
                    "Content-Length": "20",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                },
                "<html></html>",
                raw_values={"content-length": ["20"]},
            )

        instance.session.get = fake_get
        instance.check_http()

        # The final Web mixin composition should retain all additive passive
        # standards analyses on the same primary HTTPS response.
        self.assertIn("cache", instance.http)
        self.assertIn("links", instance.http)
        self.assertIn("alt_svc", instance.http)
        self.assertIn("http1_framing", instance.http)

        analysis = instance.http["http1_framing"]
        self.assertTrue(analysis["applicable"])
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["framing"], "content-length")
        self.assertTrue(analysis["raw_header_fidelity"])

        # Only the existing HTTP, HTTPS and security.txt requests are made.
        self.assertEqual(
            calls,
            [
                "http://example.com",
                "https://example.com",
                "https://example.com/.well-known/security.txt",
            ],
        )

        finding = next(
            check for check in instance.checks
            if check.name == "HTTP/1.1 framing metadata"
        )
        self.assertEqual(finding.status, "info")
        self.assertFalse(finding.applicable)
        self.assertEqual(finding.weight, 0)

    def test_te_and_content_length_conflict_becomes_review(self):
        instance = Scanner("example.com", scan_groups=("web",))

        class RawHeaders:
            def getlist(self, name):
                values = {
                    "content-length": ["20"],
                    "transfer-encoding": ["chunked"],
                }
                return values.get(name.lower(), [])

        class Raw:
            version = 11
            headers = RawHeaders()

        class Response:
            status_code = 200
            url = "https://example.com/"
            headers = {
                "Content-Length": "20",
                "Transfer-Encoding": "chunked",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            }
            text = "<html></html>"
            history = []
            raw = Raw()

        def fake_get(url, **kwargs):
            if url == "http://example.com":
                redirect = type("Redirect", (), {})()
                redirect.status_code = 301
                redirect.url = url
                redirect.headers = {"Location": "https://example.com"}
                redirect.text = ""
                redirect.history = []
                redirect.raw = None
                return redirect
            if url.endswith("/.well-known/security.txt"):
                missing = type("Missing", (), {})()
                missing.status_code = 404
                missing.url = url
                missing.headers = {"Content-Type": "text/plain; charset=utf-8"}
                missing.text = ""
                missing.history = []
                missing.raw = None
                return missing
            return Response()

        instance.session.get = fake_get
        instance.check_http()

        finding = next(
            check for check in instance.checks
            if check.name == "HTTP/1.1 framing metadata"
        )
        self.assertEqual(finding.status, "warn")
        self.assertTrue(instance.http["http1_framing"]["review"])


if __name__ == "__main__":
    unittest.main()
