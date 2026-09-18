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
