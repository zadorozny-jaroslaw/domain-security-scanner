import unittest

import domain_security_scan as scanner
from domain_security_scanner.standards import RFC_7505, analyze_mx_records, get_standard


class _FakeRecord:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class _FakeAnswer(list):
    def __init__(self, records=()):
        super().__init__(_FakeRecord(x) for x in records)
        self.rrset = object() if records else None


class _FakeResolver:
    def __init__(self, responses=None):
        self.responses = responses or {}

    def resolve(self, host, rtype, raise_on_no_answer=False):
        key = (host.lower().rstrip("."), rtype.upper())
        response = self.responses.get(key, _FakeAnswer())
        if isinstance(response, BaseException):
            raise response
        return response


class NullMxRfc7505Test(unittest.TestCase):
    def test_rfc_registry_contains_null_mx_standard(self):
        self.assertEqual(get_standard("rfc7505"), RFC_7505)
        self.assertEqual(RFC_7505.url, "https://www.rfc-editor.org/info/rfc7505")

    def test_valid_null_mx_requires_single_zero_root_exchange(self):
        analysis = analyze_mx_records(["0 ."])

        self.assertTrue(analysis["valid"])
        self.assertTrue(analysis["null_mx"])
        self.assertEqual(analysis["record_count"], 1)

    def test_null_mx_must_not_coexist_with_other_mx(self):
        analysis = analyze_mx_records(["0 .", "10 mail.example.com."])

        self.assertFalse(analysis["valid"])
        self.assertFalse(analysis["null_mx"])
        self.assertTrue(any("only MX" in error for error in analysis["errors"]))

    def test_root_exchange_with_nonzero_preference_is_invalid(self):
        analysis = analyze_mx_records(["10 ."])

        self.assertFalse(analysis["valid"])
        self.assertFalse(analysis["null_mx"])
        self.assertTrue(any("preference 0" in error for error in analysis["errors"]))

    def test_valid_null_mx_is_scored_as_intentional_no_inbound_mail(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["0 ."]),
        })
        instance.session.get = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))

        instance.collect_dns()

        mx = next(check for check in instance.checks if check.name == "MX")
        mta_sts = next(check for check in instance.checks if check.name == "MTA-STS")
        tls_rpt = next(check for check in instance.checks if check.name == "TLS-RPT")
        self.assertEqual(mx.status, "pass")
        self.assertEqual(mx.earned, 2)
        self.assertTrue(instance.mail["null_mx"])
        self.assertFalse(instance.mail["accepts_inbound_mail"])
        self.assertFalse(mta_sts.applicable)
        self.assertFalse(tls_rpt.applicable)

    def test_mixed_null_and_regular_mx_fails_rfc7505_check(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["0 .", "10 mail.example.com."]),
        })
        instance.session.get = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))

        instance.collect_dns()

        mx = next(check for check in instance.checks if check.name == "MX")
        self.assertEqual(mx.status, "fail")
        self.assertEqual(mx.earned, 0)
        self.assertFalse(instance.mail["null_mx"])


if __name__ == "__main__":
    unittest.main()


class _FakeHttpResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class MtaStsRfc8461Test(unittest.TestCase):
    def test_mta_sts_txt_requires_id(self):
        from domain_security_scanner.standards import analyze_mta_sts_txt

        analysis = analyze_mta_sts_txt(["v=STSv1; foo=bar"])
        self.assertTrue(analysis["configured"])
        self.assertFalse(analysis["valid"])
        self.assertTrue(any("id" in error for error in analysis["errors"]))

    def test_mta_sts_txt_accepts_rfc_whitespace_before_semicolon(self):
        from domain_security_scanner.standards import analyze_mta_sts_txt

        analysis = analyze_mta_sts_txt(["v=STSv1 ; id=abc123"])
        self.assertTrue(analysis["valid"])
        self.assertEqual(analysis["id"], "abc123")

    def test_mta_sts_txt_rejects_multiple_usable_records(self):
        from domain_security_scanner.standards import analyze_mta_sts_txt

        analysis = analyze_mta_sts_txt([
            "v=STSv1; id=one",
            "v=STSv1; id=two",
        ])
        self.assertFalse(analysis["valid"])
        self.assertEqual(analysis["candidate_count"], 2)

    def test_mta_sts_policy_validates_required_fields(self):
        from domain_security_scanner.standards import parse_mta_sts_policy

        policy = parse_mta_sts_policy(
            "version: STSv1\n"
            "mode: enforce\n"
            "mx: mail.example.com\n"
            "mx: *.backup.example.com\n"
            "max_age: 604800\n"
        )
        self.assertTrue(policy["valid"])
        self.assertEqual(policy["mode"], "enforce")
        self.assertEqual(policy["max_age"], 604800)

    def test_mta_sts_policy_rejects_excessive_max_age(self):
        from domain_security_scanner.standards import parse_mta_sts_policy

        policy = parse_mta_sts_policy(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557601\n"
        )
        self.assertFalse(policy["valid"])
        self.assertTrue(any("31557600" in error for error in policy["errors"]))

    def test_mta_sts_wildcard_matches_only_one_leftmost_label(self):
        from domain_security_scanner.standards import mta_sts_mx_matches

        self.assertTrue(mta_sts_mx_matches("mx1.example.com", "*.example.com"))
        self.assertFalse(mta_sts_mx_matches("example.com", "*.example.com"))
        self.assertFalse(mta_sts_mx_matches("a.b.example.com", "*.example.com"))

    def test_scanner_validates_enforce_policy_and_does_not_follow_redirects(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["10 mail.example.com."]),
            ("_mta-sts.example.com", "TXT"): _FakeAnswer(['"v=STSv1; id=20260918"']),
        })
        calls = []

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            return _FakeHttpResponse(
                200,
                "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
                {"content-type": "text/plain; charset=utf-8"},
            )

        instance.session.get = fake_get
        instance.collect_dns()

        check = next(check for check in instance.checks if check.name == "MTA-STS")
        self.assertEqual(check.status, "pass")
        self.assertEqual(check.earned, 3)
        policy_call = next(call for call in calls if "mta-sts.example.com" in call[0])
        self.assertIs(policy_call[1]["allow_redirects"], False)

    def test_scanner_rejects_mta_sts_redirect(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["10 mail.example.com."]),
            ("_mta-sts.example.com", "TXT"): _FakeAnswer(['"v=STSv1; id=20260918"']),
        })
        instance.session.get = lambda *args, **kwargs: _FakeHttpResponse(
            301, "", {"location": "https://other.example/mta-sts.txt"}
        )

        instance.collect_dns()

        check = next(check for check in instance.checks if check.name == "MTA-STS")
        self.assertEqual(check.status, "fail")
        self.assertIn("przekierowaniami", check.message)
