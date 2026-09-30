from __future__ import annotations

import unittest
from types import SimpleNamespace

from domain_security_scanner.domains.domain.delegation_findings import DelegationFinding
from domain_security_scanner.domains.domain.dns_zone_recovery import (
    build_dns_zone_recovery,
    dns_zone_recovery_report_data,
    recover_delegation_findings,
)
from domain_security_scanner.domains.domain.encrypted_dns import (
    ENCRYPTED_DNS_USABLE,
    RRSET_CONSENSUS,
    EncryptedDnsEvidence,
    EncryptedDnsNameserverEvidence,
    EncryptedDnsRrsetEvidence,
)
from domain_security_scanner.reporting.dns_pdf import dns_posture_rows


def _encrypted(*, ns=("ns1.provider.net", "ns2.provider.net"), zone="example.com"):
    rrset = EncryptedDnsRrsetEvidence(
        qtype="NS",
        status=RRSET_CONSENSUS,
        rdata=tuple(ns),
        observations=(),
    )
    hosts = tuple(
        EncryptedDnsNameserverEvidence(
            name=name,
            ipv4=(f"192.0.2.{index}",),
            addressable_resolvers=("cloudflare", "google"),
            confirmed_addressable=True,
            alias_status="direct",
        )
        for index, name in enumerate(ns, start=11)
    )
    return EncryptedDnsEvidence(
        zone=zone,
        status=ENCRYPTED_DNS_USABLE,
        trigger="suspected_interception",
        attempted=True,
        rrsets=(rrset,),
        nameservers=hosts,
    )


class DnsZoneRecoveryTest(unittest.TestCase):
    def test_registry_and_encrypted_zone_consensus_recovers_safe_zone_level_posture(self):
        recovery = build_dns_zone_recovery(
            {
                "root_domain": "example.com",
                "nameservers": ["NS1.PROVIDER.NET.", "ns2.provider.net"],
            },
            _encrypted(),
            SimpleNamespace(status="secure"),
        )

        self.assertTrue(recovery.available)
        self.assertTrue(recovery.registry_zone_consistent)
        self.assertTrue(recovery.redundancy_confirmed)
        self.assertTrue(recovery.all_nameservers_addressable)
        self.assertTrue(recovery.alias_free)
        self.assertFalse(recovery.glue_required)
        self.assertEqual(recovery.dnssec_validation_status, "secure")

    def test_unknown_delegation_findings_are_promoted_only_by_positive_recovery(self):
        recovery = build_dns_zone_recovery(
            {
                "root_domain": "example.com",
                "nameservers": ["ns1.provider.net", "ns2.provider.net"],
            },
            _encrypted(),
        )
        findings = (
            DelegationFinding("Name server redundancy", "unknown", "old", 3, 0, False),
            DelegationFinding("DNS delegation consistency", "unknown", "old", 6, 0, False),
            DelegationFinding("Nameserver addressability", "unknown", "old", 7, 0, False),
            DelegationFinding("Delegation glue", "unknown", "old", 0, 0, False),
            DelegationFinding("Nameserver target aliasing", "unknown", "old", 0, 0, False),
            DelegationFinding("Delegated nameserver authority", "unknown", "old", 7, 0, False),
        )

        recovered = {item.name: item for item in recover_delegation_findings(findings, recovery)}

        self.assertEqual(recovered["Name server redundancy"].status, "pass")
        self.assertEqual(recovered["Name server redundancy"].earned, 3)
        self.assertEqual(recovered["DNS delegation consistency"].status, "pass")
        self.assertEqual(recovered["DNS delegation consistency"].earned, 6)
        self.assertEqual(recovered["Nameserver addressability"].status, "pass")
        self.assertEqual(recovered["Nameserver addressability"].earned, 7)
        self.assertEqual(recovered["Delegation glue"].status, "info")
        self.assertFalse(recovered["Delegation glue"].applicable)
        self.assertEqual(recovered["Nameserver target aliasing"].status, "pass")
        self.assertEqual(recovered["Delegated nameserver authority"].status, "unknown")

    def test_registry_zone_mismatch_is_not_converted_into_failure(self):
        recovery = build_dns_zone_recovery(
            {
                "root_domain": "example.com",
                "nameservers": ["ns1.provider.net", "ns3.provider.net"],
            },
            _encrypted(),
        )
        finding = DelegationFinding(
            "DNS delegation consistency", "unknown", "old", 6, 0, False
        )

        recovered = recover_delegation_findings((finding,), recovery)[0]

        self.assertFalse(recovery.registry_zone_consistent)
        self.assertEqual(recovered.status, "unknown")
        self.assertFalse(recovered.applicable)

    def test_in_bailiwick_nameserver_does_not_claim_glue_is_not_required(self):
        recovery = build_dns_zone_recovery(
            {
                "root_domain": "example.com",
                "nameservers": ["ns1.example.com", "ns2.provider.net"],
            },
            _encrypted(ns=("ns1.example.com", "ns2.provider.net")),
        )
        finding = DelegationFinding("Delegation glue", "unknown", "old", 0, 0, False)

        recovered = recover_delegation_findings((finding,), recovery)[0]

        self.assertTrue(recovery.glue_required)
        self.assertEqual(recovered.status, "unknown")

    def test_recovery_report_preserves_zone_level_scope(self):
        recovery = build_dns_zone_recovery(
            {
                "root_domain": "example.com",
                "nameservers": ["ns1.provider.net", "ns2.provider.net"],
            },
            _encrypted(),
        )

        report = dns_zone_recovery_report_data(recovery)

        self.assertTrue(report["available"])
        self.assertEqual(report["source"], "rdap_registry_plus_encrypted_dns")
        self.assertTrue(report["registry_zone_consistent"])
        self.assertTrue(report["all_nameservers_addressable"])
        self.assertTrue(report["scope"]["zone_level_only"])
        self.assertFalse(report["scope"]["per_authoritative_server_attribution"])

    def test_pdf_summary_distinguishes_recovered_zone_from_intercepted_per_server_path(self):
        report = {
            "root_domain": "example.com",
            "target_domain": "example.com",
            "rdap": {},
            "dns_records": {},
            "dns": {
                "path_integrity": {"status": "suspected_interception"},
                "dnssec": {"status": "secure", "validation_source": "encrypted_recursive"},
                "delegation": {"available": False, "consistent": None, "complete": False},
                "zone_recovery": {
                    "available": True,
                    "registry_zone_consistent": True,
                    "all_nameservers_addressable": True,
                    "glue_required": False,
                },
                "soa": {"ns_rrset_consistent": None},
                "open_recursion": {"status": "unknown", "open_servers": []},
                "caa": {"analysis": {"state": "effective"}, "effective_name": "example.com"},
                "encrypted_recursive": {"status": "usable", "attempted": True},
            },
        }

        rows = dns_posture_rows(report)

        self.assertEqual(rows[0]["status"], "pass")
        self.assertEqual(rows[1]["status"], "unknown")
        self.assertIn("Delegation: OK", rows[1]["value"])
        self.assertIn("Direct per-server DNS: VERIFY", rows[1]["value"])
        self.assertIn("NS addresses: OK", rows[1]["value"])
        self.assertIn("Glue: N/A", rows[1]["value"])


if __name__ == "__main__":
    unittest.main()
