from __future__ import annotations

import copy
import unittest

from domain_security_scanner.domains.domain.dns_customer_reporting import (
    enrich_dns_records_for_report,
    recover_customer_dns_checks,
)


def _dns_fixture():
    return {
        "path_integrity": {"status": "suspected_interception"},
        "encrypted_recursive": {
            "attempted": True,
            "status": "usable",
            "rrsets": {
                "SOA": {
                    "status": "consensus",
                    "rdata": [
                        "kristina.ns.cloudflare.com. dns.cloudflare.com. "
                        "2416130857 10000 2400 604800 1800"
                    ],
                },
                "NS": {
                    "status": "consensus",
                    "rdata": [
                        "kristina.ns.cloudflare.com.",
                        "wesley.ns.cloudflare.com.",
                    ],
                },
            },
        },
        "dnssec": {
            "status": "secure",
            "validation_source": "encrypted_recursive",
        },
    }


def _check(name, *, weight=0):
    return {
        "category": "Domain",
        "name": name,
        "status": "unknown",
        "message": "old",
        "weight": weight,
        "earned": 0,
        "applicable": False,
    }


class DnsCustomerReportingTest(unittest.TestCase):
    def test_zone_level_soa_service_is_promoted_but_per_server_checks_are_info(self):
        checks = [
            _check("Authoritative SOA service"),
            _check("Authoritative SOA consistency"),
            _check("Authoritative SOA serial"),
            _check("Authoritative NS RRset consistency", weight=3),
            _check("Authoritative EDNS(0)"),
            _check("Authoritative negative DNS"),
            _check("DNSSEC denial of existence"),
            _check("Authoritative DNS transport", weight=2),
            _check("Authoritative open recursion", weight=8),
            _check("Delegated nameserver authority", weight=7),
            _check("Transfer lock", weight=4),
        ]

        recovered = recover_customer_dns_checks(checks, _dns_fixture())
        by_name = {item["name"]: item for item in recovered}

        self.assertEqual(by_name["Authoritative SOA service"]["status"], "pass")
        self.assertTrue(by_name["Authoritative SOA service"]["applicable"])
        self.assertEqual(by_name["Authoritative SOA consistency"]["status"], "info")
        self.assertEqual(by_name["Authoritative SOA serial"]["status"], "info")
        self.assertIn("2416130857", by_name["Authoritative SOA serial"]["message"])
        self.assertEqual(by_name["Authoritative NS RRset consistency"]["status"], "info")
        self.assertFalse(by_name["Authoritative NS RRset consistency"]["applicable"])
        self.assertEqual(by_name["Authoritative EDNS(0)"]["status"], "info")
        self.assertEqual(by_name["Authoritative negative DNS"]["status"], "info")
        self.assertEqual(by_name["DNSSEC denial of existence"]["status"], "info")

        # High-impact checks that truly require per-server attribution remain VERIFY.
        self.assertEqual(by_name["Authoritative DNS transport"]["status"], "unknown")
        self.assertEqual(by_name["Authoritative open recursion"]["status"], "unknown")
        self.assertEqual(by_name["Delegated nameserver authority"]["status"], "unknown")
        self.assertEqual(by_name["Transfer lock"]["status"], "unknown")

    def test_no_reporting_promotion_without_suspect_direct_path(self):
        dns = _dns_fixture()
        dns["path_integrity"] = {"status": "usable"}
        checks = [_check("Authoritative SOA service")]

        self.assertEqual(recover_customer_dns_checks(checks, dns), checks)

    def test_soa_service_is_not_promoted_without_secure_local_validation(self):
        dns = _dns_fixture()
        dns["dnssec"] = {"status": "unknown", "validation_source": None}
        checks = [_check("Authoritative SOA service")]

        recovered = recover_customer_dns_checks(checks, dns)
        self.assertEqual(recovered[0]["status"], "unknown")

    def test_report_inventory_adds_consensus_ns_and_soa_without_mutating_source(self):
        source = {
            "zadorozny.pl": {
                "A": ["51.38.156.191"],
                "NS": [],
                "DS": ["2371 13 2 deadbeef"],
            }
        }
        original = copy.deepcopy(source)

        recovered = enrich_dns_records_for_report(
            source,
            "zadorozny.pl",
            _dns_fixture(),
        )

        self.assertEqual(source, original)
        self.assertEqual(
            recovered["zadorozny.pl"]["NS"],
            ["kristina.ns.cloudflare.com.", "wesley.ns.cloudflare.com."],
        )
        self.assertEqual(
            recovered["zadorozny.pl"]["SOA"],
            [
                "kristina.ns.cloudflare.com. dns.cloudflare.com. "
                "2416130857 10000 2400 604800 1800"
            ],
        )
        self.assertEqual(recovered["zadorozny.pl"]["DS"], ["2371 13 2 deadbeef"])

    def test_existing_inventory_values_are_not_replaced(self):
        source = {
            "example.com": {
                "NS": ["ns.original.example."],
                "SOA": ["ns.original.example. hostmaster.example. 1 2 3 4 5"],
            }
        }

        recovered = enrich_dns_records_for_report(
            source,
            "example.com",
            _dns_fixture(),
        )

        self.assertEqual(recovered, source)


if __name__ == "__main__":
    unittest.main()
