from __future__ import annotations

import unittest
from datetime import datetime, timezone

from domain_security_scanner.standards import (
    RFC_3986,
    RFC_6797,
    RFC_8615,
    RFC_9110,
    RFC_9111,
    RFC_9116,
    RFC_10025,
    analyze_hsts,
    analyze_http_cache_policy,
    analyze_redirect,
    analyze_security_txt,
    analyze_set_cookie_header,
    get_standard,
    is_well_formed_uri_reference,
)


class WebStandardRegistryTest(unittest.TestCase):
    def test_existing_web_checks_are_registered(self):
        for standard in (
            RFC_3986,
            RFC_6797,
            RFC_8615,
            RFC_9110,
            RFC_9111,
            RFC_9116,
            RFC_10025,
        ):
            with self.subTest(standard=standard.key):
                self.assertEqual(get_standard(standard.key.lower()), standard)
                self.assertEqual(
                    standard.url,
                    f"https://www.rfc-editor.org/info/rfc{standard.number}",
                )


class UriAndRedirectRfcTest(unittest.TestCase):
    def test_uri_reference_accepts_absolute_and_relative_references(self):
        self.assertTrue(is_well_formed_uri_reference("https://example.com/a?b=1"))
        self.assertTrue(is_well_formed_uri_reference("/next"))
        self.assertFalse(is_well_formed_uri_reference("https://example.com/%ZZ"))
        self.assertFalse(is_well_formed_uri_reference("https://exa mple.com/"))

    def test_http_redirect_accepts_rfc9110_303_to_https(self):
        analysis = analyze_redirect(
            303,
            "https://example.com/login",
            "http://example.com",
        )
        self.assertTrue(analysis["redirect_status"])
        self.assertTrue(analysis["secure_target"])

    def test_relative_redirect_from_http_does_not_count_as_https_upgrade(self):
        analysis = analyze_redirect(301, "/home", "http://example.com")
        self.assertEqual(analysis["resolved_location"], "http://example.com/home")
        self.assertFalse(analysis["secure_target"])

    def test_invalid_location_is_not_accepted(self):
        analysis = analyze_redirect(302, "https://example.com/%ZZ", "http://example.com")
        self.assertFalse(analysis["valid_location"])
        self.assertFalse(analysis["secure_target"])


class HstsRfc6797Test(unittest.TestCase):
    def test_valid_active_hsts_policy(self):
        analysis = analyze_hsts(["max-age=31536000; includeSubDomains"])
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["active"])
        self.assertEqual(analysis["max_age"], 31536000)
        self.assertTrue(analysis["include_subdomains"])

    def test_hsts_requires_max_age(self):
        analysis = analyze_hsts(["includeSubDomains"])
        self.assertFalse(analysis["valid"])
        self.assertIn("missing required max-age directive", analysis["errors"])

    def test_hsts_rejects_duplicate_directives(self):
        analysis = analyze_hsts(["max-age=100; MAX-AGE=200"])
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("duplicate" in error for error in analysis["errors"]))

    def test_hsts_allows_unknown_well_formed_directive(self):
        analysis = analyze_hsts(["max-age=100; future-extension=1"])
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["unknown_directives"], ["future-extension"])

    def test_hsts_max_age_zero_is_valid_but_inactive(self):
        analysis = analyze_hsts(["max-age=0; includeSubDomains"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["active"])
        self.assertTrue(analysis["warnings"])

    def test_multiple_hsts_field_lines_are_server_error(self):
        analysis = analyze_hsts(["max-age=100", "max-age=200"])
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("more than one" in error for error in analysis["errors"]))


class HttpCacheRfc9111Test(unittest.TestCase):
    def test_missing_cache_policy_is_informational_not_invalid(self):
        analysis = analyze_http_cache_policy()
        self.assertFalse(analysis["present"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["freshness_source"], "heuristic/unspecified")

    def test_valid_max_age_policy(self):
        analysis = analyze_http_cache_policy(["public, max-age=300"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertTrue(analysis["public"])
        self.assertEqual(analysis["max_age"], 300)
        self.assertEqual(analysis["freshness_source"], "max-age")

    def test_unknown_extension_directive_is_accepted(self):
        analysis = analyze_http_cache_policy(["max-age=60, immutable"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["unknown_directives"], ["immutable"])

    def test_quoted_max_age_is_invalid_server_output(self):
        analysis = analyze_http_cache_policy(['max-age="60"'])
        self.assertFalse(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("unquoted" in error for error in analysis["errors"]))

    def test_duplicate_freshness_directive_is_reviewed(self):
        analysis = analyze_http_cache_policy(["max-age=60, max-age=120"])
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertEqual(analysis["duplicate_directives"], ["max-age"])

    def test_conflicting_no_cache_and_max_age_uses_restrictive_semantics(self):
        analysis = analyze_http_cache_policy(["max-age=60, no-cache"])
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["no_cache"])
        self.assertTrue(any("more restrictive" in warning for warning in analysis["warnings"]))

    def test_qualified_private_preserves_quoted_field_list(self):
        analysis = analyze_http_cache_policy(['private="Set-Cookie, X-Private", max-age=0'])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["review"])
        self.assertEqual(analysis["directives"]["private"], ["Set-Cookie, X-Private"])

    def test_invalid_age_is_reviewed(self):
        analysis = analyze_http_cache_policy(age_values=["not-a-number"])
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("Age" in error for error in analysis["errors"]))

    def test_multiple_age_values_use_first_member_and_warn(self):
        analysis = analyze_http_cache_policy(age_values=["12, 20"])
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["age"], 12)
        self.assertTrue(any("multiple Age" in warning for warning in analysis["warnings"]))

    def test_invalid_expires_is_treated_as_expired_and_reviewed(self):
        analysis = analyze_http_cache_policy(expires_values=["0"])
        self.assertTrue(analysis["valid"])
        self.assertFalse(analysis["expires_valid"])
        self.assertEqual(analysis["freshness_source"], "expires-invalid")
        self.assertTrue(any("already expired" in warning for warning in analysis["warnings"]))

    def test_response_pragma_is_deprecated(self):
        analysis = analyze_http_cache_policy(pragma_values=["no-cache"])
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("deprecated" in warning for warning in analysis["warnings"]))

    def test_warning_response_header_is_obsoleted(self):
        analysis = analyze_http_cache_policy(warning_values=['110 - "Response is stale"'])
        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["review"])
        self.assertTrue(any("obsoleted" in warning for warning in analysis["warnings"]))


class SecurityTxtRfc9116Test(unittest.TestCase):
    NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
    URL = "https://example.com/.well-known/security.txt"

    def test_valid_security_txt_core_fields(self):
        analysis = analyze_security_txt(
            status_code=200,
            text=(
                "Contact: mailto:security@example.com\n"
                "Canonical: https://example.com/.well-known/security.txt\n"
                "Expires: 2026-12-31T23:59:59Z\n"
            ),
            content_type="text/plain; charset=utf-8",
            requested_url=self.URL,
            final_url=self.URL,
            now=self.NOW,
        )
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["contacts"], ["mailto:security@example.com"])

    def test_security_txt_requires_expires(self):
        analysis = analyze_security_txt(
            status_code=200,
            text="Contact: mailto:security@example.com\n",
            content_type="text/plain; charset=utf-8",
            requested_url=self.URL,
            final_url=self.URL,
            now=self.NOW,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("Expires" in error for error in analysis["errors"]))

    def test_security_txt_rejects_expired_policy(self):
        analysis = analyze_security_txt(
            status_code=200,
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: 2026-01-01T00:00:00Z\n"
            ),
            content_type="text/plain; charset=utf-8",
            requested_url=self.URL,
            final_url=self.URL,
            now=self.NOW,
        )
        self.assertFalse(analysis["valid"])
        self.assertIn("security.txt is expired", analysis["errors"])

    def test_security_txt_requires_plain_text_utf8(self):
        analysis = analyze_security_txt(
            status_code=200,
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: 2026-12-31T23:59:59Z\n"
            ),
            content_type="text/html; charset=iso-8859-1",
            requested_url=self.URL,
            final_url=self.URL,
            now=self.NOW,
        )
        self.assertFalse(analysis["valid"])
        self.assertIn("Content-Type must be text/plain", analysis["errors"])
        self.assertIn("Content-Type charset must be utf-8", analysis["errors"])

    def test_security_txt_contact_web_uri_must_use_https(self):
        analysis = analyze_security_txt(
            status_code=200,
            text=(
                "Contact: http://example.com/security\n"
                "Expires: 2026-12-31T23:59:59Z\n"
            ),
            content_type="text/plain; charset=utf-8",
            requested_url=self.URL,
            final_url=self.URL,
            now=self.NOW,
        )
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("Contact" in error for error in analysis["errors"]))


class CookieRfc10025Test(unittest.TestCase):
    def test_samesite_none_requires_secure(self):
        analysis = analyze_set_cookie_header("session=abc; HttpOnly; SameSite=None")
        self.assertIn("SameSite=None requires Secure", analysis["rfc_errors"])

    def test_secure_cookie_prefix_requires_secure(self):
        analysis = analyze_set_cookie_header("__Secure-session=abc; Path=/")
        self.assertTrue(any("__Secure-" in error for error in analysis["rfc_errors"]))

    def test_host_cookie_prefix_requires_secure_path_and_no_domain(self):
        analysis = analyze_set_cookie_header(
            "__Host-session=abc; Secure; Domain=example.com; Path=/app"
        )
        self.assertIn("__Host- cookie prefix forbids Domain", analysis["rfc_errors"])
        self.assertIn("__Host- cookie prefix requires Path=/", analysis["rfc_errors"])

    def test_host_cookie_prefix_valid_form(self):
        analysis = analyze_set_cookie_header("__Host-session=abc; Secure; Path=/; HttpOnly")
        self.assertEqual(analysis["rfc_errors"], [])

    def test_duplicate_cookie_attribute_is_invalid_server_output(self):
        analysis = analyze_set_cookie_header("session=abc; Secure; secure")
        self.assertTrue(any("duplicate" in error for error in analysis["rfc_errors"]))


if __name__ == "__main__":
    unittest.main()
