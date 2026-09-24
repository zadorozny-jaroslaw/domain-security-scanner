import unittest

import dns.exception
import dns.resolver

import domain_security_scan as scanner
from domain_security_scanner.models import DnsQueryResult, DnsQueryState
from domain_security_scanner.version import __version__ as package_version

class CoreHelpersTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(scanner.__version__, package_version)
        self.assertRegex(package_version, r"^\d+\.\d+\.\d+$")

    def test_normalize_domain_preserves_web_host(self):
        self.assertEqual(
            scanner.normalize_domain("https://WWW.Example.com/path"),
            "www.example.com",
        )

    def test_fallback_root_domain(self):
        self.assertEqual(
            scanner.fallback_root_domain("new.home.example.com"),
            "example.com",
        )

    def test_fallback_multilabel_suffix(self):
        self.assertEqual(
            scanner.fallback_root_domain("app.example.co.uk"),
            "example.co.uk",
        )

    def test_rejects_invalid_domain(self):
        with self.assertRaises(ValueError):
            scanner.normalize_domain("not a domain")


class ResultModelsTest(unittest.TestCase):
    def test_check_accepts_existing_string_values_and_serializes_identically(self):
        check = scanner.Check(
            "Mail",
            "SPF",
            "fail",
            "Missing SPF.",
            8,
            0,
            True,
        )

        self.assertEqual(check.category, "Mail")
        self.assertEqual(check.status, "fail")
        self.assertEqual(
            check.to_dict(),
            {
                "category": "Mail",
                "name": "SPF",
                "status": "fail",
                "message": "Missing SPF.",
                "weight": 8,
                "earned": 0,
                "applicable": True,
            },
        )

    def test_check_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            scanner.Check("Mail", "SPF", "invalid", "Bad status")

    def test_check_rejects_unknown_category(self):
        with self.assertRaises(ValueError):
            scanner.Check("Unknown", "Example", "info", "Bad category")

    def test_score_public_shape_is_unchanged(self):
        instance = scanner.Scanner("example.com")
        instance.add_check("Web", "One", "pass", "ok", 2, 2)
        instance.add_check("Web", "Two", "warn", "review", 2, 1)
        instance.add_check("Web", "Ignored", "unknown", "verify", 5, 0, False)

        self.assertEqual(
            instance.score(),
            {
                "score": 75,
                "label": "Good",
                "earned_points": 3,
                "possible_points": 4,
            },
        )

    def test_report_serializes_status_and_category_as_plain_strings(self):
        instance = scanner.Scanner("example.com")
        instance.add_check("Domain", "CAA", "pass", "ok", 3, 3)
        report = instance.to_dict()

        self.assertIs(type(report["checks"][0]["category"]), str)
        self.assertIs(type(report["checks"][0]["status"]), str)
        self.assertEqual(report["checks"][0]["category"], "Domain")
        self.assertEqual(report["checks"][0]["status"], "pass")


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
        self.calls = []

    def resolve(self, host, rtype, raise_on_no_answer=False):
        key = (host.lower().rstrip("."), rtype.upper())
        self.calls.append(key)
        response = self.responses.get(key, _FakeAnswer())
        if isinstance(response, BaseException):
            raise response
        return response


class DnsEvidenceTest(unittest.TestCase):
    def test_dns_query_result_caches_successful_answer(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["10 mail.example.com."])
        })

        first = instance.dns_query_result("Example.COM.", "mx")
        second = instance.dns_query("example.com", "MX")

        self.assertEqual(first.state, DnsQueryState.ANSWER)
        self.assertEqual(first.records, ("10 mail.example.com.",))
        self.assertEqual(second, ["10 mail.example.com."])
        self.assertEqual(instance.resolver.calls, [("example.com", "MX")])

    def test_dns_timeout_is_not_treated_as_absent(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "TXT"): dns.exception.Timeout(timeout=1)
        })

        result = instance.dns_query_result("example.com", "TXT")

        self.assertEqual(result.state, DnsQueryState.TIMEOUT)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(instance.dns_query("example.com", "TXT"), [])
        self.assertEqual(len(instance.resolver.calls), 1)

    def test_dns_no_answer_is_conclusive_absence(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver()

        result = instance.dns_query_result("example.com", "CAA")

        self.assertEqual(result.state, DnsQueryState.NO_ANSWER)
        self.assertTrue(result.absent)
        self.assertFalse(result.failed)

    def test_nxdomain_is_conclusive_absence(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("missing.example.com", "TXT"): dns.resolver.NXDOMAIN()
        })

        result = instance.dns_query_result("missing.example.com", "TXT")

        self.assertEqual(result.state, DnsQueryState.NXDOMAIN)
        self.assertTrue(result.absent)
        self.assertFalse(result.failed)

    def test_spf_becomes_unknown_when_root_txt_lookup_times_out(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("example.com", "TXT"): dns.exception.Timeout(timeout=1)
        })
        instance.session.get = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))

        instance.collect_dns()
        spf = next(check for check in instance.checks if check.name == "SPF")

        self.assertEqual(spf.status, "unknown")
        self.assertFalse(spf.applicable)
        self.assertNotIn(8, [check.weight for check in instance.checks if check.name == "SPF" and check.applicable])

    def test_spf_missing_still_fails_on_conclusive_no_answer(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver()
        instance.session.get = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))

        instance.collect_dns()
        spf = next(check for check in instance.checks if check.name == "SPF")

        self.assertEqual(spf.status, "fail")
        self.assertTrue(spf.applicable)
        self.assertEqual(spf.weight, 8)

    def test_spf_budget_marks_incomplete_nested_dns_evidence(self):
        instance = scanner.Scanner("example.com")
        instance.resolver = _FakeResolver({
            ("_spf.example.net", "TXT"): dns.exception.Timeout(timeout=1)
        })

        result = instance._estimate_spf_dns_lookups(
            "example.com",
            "v=spf1 include:_spf.example.net -all",
        )

        self.assertEqual(result["count"], 1)
        self.assertFalse(result["complete"])
        self.assertTrue(any("could not be resolved" in note for note in result["notes"]))


class HostInventoryTest(unittest.TestCase):
    def test_host_inventory_separates_live_historical_unknown_and_unassessed(self):
        instance = scanner.Scanner("example.com")
        instance.subdomains = {
            "example.com",
            "live.example.com",
            "old.example.com",
            "empty.example.com",
            "unknown.example.com",
            "skipped.example.com",
        }
        instance.ct_subdomains = {"old.example.com", "empty.example.com"}
        instance.dns_records = {
            "example.com": {"A": ["192.0.2.10"]},
            "live.example.com": {"CNAME": ["example.com."]},
            "old.example.com": {rtype: [] for rtype in scanner.COMMON_DNS_TYPES},
            "empty.example.com": {rtype: [] for rtype in scanner.COMMON_DNS_TYPES},
            "unknown.example.com": {rtype: [] for rtype in scanner.COMMON_DNS_TYPES},
        }
        instance.dns_query_cache[("old.example.com", "A")] = DnsQueryResult(
            "old.example.com", "A", DnsQueryState.NXDOMAIN
        )
        instance.dns_query_cache[("empty.example.com", "A")] = DnsQueryResult(
            "empty.example.com", "A", DnsQueryState.NO_ANSWER
        )
        instance.dns_query_cache[("unknown.example.com", "A")] = DnsQueryResult(
            "unknown.example.com", "A", DnsQueryState.TIMEOUT, error="timeout"
        )

        inventory = instance.host_inventory()

        self.assertEqual(inventory["live"], ["example.com", "live.example.com"])
        self.assertEqual(inventory["historical"], ["old.example.com"])
        self.assertEqual(inventory["unresolved"], ["empty.example.com"])
        self.assertEqual(inventory["dns_unknown"], ["unknown.example.com"])
        self.assertEqual(inventory["not_assessed"], ["skipped.example.com"])
        self.assertEqual(instance.to_dict()["host_inventory"], inventory)

    def test_ct_discovery_tracks_historical_source(self):
        instance = scanner.Scanner("example.com")

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return [{"name_value": "old.example.com\n*.wild.example.com"}]

        instance.session.get = lambda *args, **kwargs: Response()
        instance.discover_ct_subdomains()

        self.assertIn("old.example.com", instance.subdomains)
        self.assertIn("wild.example.com", instance.subdomains)
        self.assertIn("old.example.com", instance.ct_subdomains)
        self.assertIn("wild.example.com", instance.ct_subdomains)


if __name__ == "__main__":
    unittest.main()
