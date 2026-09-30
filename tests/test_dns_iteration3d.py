from __future__ import annotations

import unittest
from types import SimpleNamespace

from domain_security_scanner.domains.domain.authoritative_findings import (
    _soa_authority_finding,
)
from domain_security_scanner.domains.domain.delegation_findings import (
    build_delegation_findings,
)
from domain_security_scanner.domains.domain.dns_reconciliation import (
    reconcile_delegation,
)
from domain_security_scanner.domains.domain.dnssec_findings import (
    build_dnssec_findings,
)
from domain_security_scanner.domains.domain.reporting import delegation_report_data
from domain_security_scanner.reporting.dns_pdf import dns_posture_rows


def _delegation_ns(name: str):
    return SimpleNamespace(
        name=name,
        in_bailiwick=False,
        address_status="available",
        alias_status="direct",
        alias_targets=(),
        authority_status="unknown",
        authoritative_child_views=(),
        glue_status="not_required",
        glue_consistent=None,
        glue_only_addresses=(),
        resolved_only_addresses=(),
    )


def _delegation_analysis():
    return SimpleNamespace(
        zone="example.com",
        parent_nameservers=("ns1.example.net", "ns2.example.net"),
        child_views=(),
        observed_child_nameservers=(),
        parent_child_consistent=None,
        parent_child_complete=False,
        missing_from_child=(),
        extra_in_child=(),
        nameservers=(
            _delegation_ns("ns1.example.net"),
            _delegation_ns("ns2.example.net"),
        ),
    )


def _authoritative_analysis(rrset=("ns1.example.net", "ns2.example.net")):
    return SimpleNamespace(
        ns_rrset_consistent=True,
        servers=(
            SimpleNamespace(name="ns1.example.net", apex_nameservers=rrset),
            SimpleNamespace(name="ns2.example.net", apex_nameservers=rrset),
        ),
    )


def _delegation_evidence():
    return SimpleNamespace(
        zone="example.com",
        parent_zone="com",
        available=True,
        delegated_nameservers=("ns1.example.net", "ns2.example.net"),
        delegated_servers=(),
        glue=(),
        source_server_name="a.gtld-servers.net",
        source_server_ip="192.0.2.1",
        parent_ns_result=None,
        delegation_queries=(),
        error=None,
    )


class DnsIntegrationReconciliationTest(unittest.TestCase):
    def test_later_authoritative_apex_ns_reconciles_incomplete_delegation(self):
        analysis = _delegation_analysis()
        authoritative = _authoritative_analysis()

        reconciled = reconcile_delegation(analysis, authoritative)

        self.assertTrue(reconciled.consistent)
        self.assertTrue(reconciled.complete)
        self.assertEqual(reconciled.consistency_source, "authoritative_apex_ns")
        self.assertEqual(
            reconciled.child_nameservers,
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertEqual(
            reconciled.authority_confirmed_servers,
            ("ns1.example.net", "ns2.example.net"),
        )

        findings = {
            item.name: item
            for item in build_delegation_findings(
                _delegation_evidence(), analysis, authoritative
            )
        }
        self.assertEqual(findings["DNS delegation consistency"].status, "pass")
        self.assertEqual(findings["Delegated nameserver authority"].status, "pass")

    def test_complete_authoritative_fallback_can_confirm_real_parent_child_mismatch(self):
        analysis = _delegation_analysis()
        authoritative = _authoritative_analysis(
            ("ns1.example.net", "ns3.example.net")
        )

        reconciled = reconcile_delegation(analysis, authoritative)

        self.assertFalse(reconciled.consistent)
        self.assertTrue(reconciled.complete)
        self.assertEqual(reconciled.missing_from_child, ("ns2.example.net",))
        self.assertEqual(reconciled.extra_in_child, ("ns3.example.net",))

        findings = {
            item.name: item
            for item in build_delegation_findings(
                _delegation_evidence(), analysis, authoritative
            )
        }
        self.assertEqual(findings["DNS delegation consistency"].status, "fail")

    def test_reconciliation_is_not_used_when_authoritative_views_are_incomplete(self):
        analysis = _delegation_analysis()
        authoritative = SimpleNamespace(
            ns_rrset_consistent=None,
            servers=(
                SimpleNamespace(
                    name="ns1.example.net",
                    apex_nameservers=("ns1.example.net", "ns2.example.net"),
                ),
                SimpleNamespace(name="ns2.example.net", apex_nameservers=()),
            ),
        )

        reconciled = reconcile_delegation(analysis, authoritative)

        self.assertIsNone(reconciled.consistent)
        self.assertFalse(reconciled.complete)

    def test_public_json_exposes_reconciliation_source(self):
        report = delegation_report_data(
            _delegation_evidence(),
            _delegation_analysis(),
            _authoritative_analysis(),
        )

        self.assertTrue(report["consistent"])
        self.assertTrue(report["complete"])
        self.assertEqual(report["consistency_source"], "authoritative_apex_ns")
        self.assertEqual(
            report["child_ns"],
            ["ns1.example.net", "ns2.example.net"],
        )


class DnsInconclusivePresentationTest(unittest.TestCase):
    def test_no_usable_soa_is_verify_not_warning(self):
        analysis = SimpleNamespace(
            servers=(
                SimpleNamespace(name="ns1.example.net", soa_authority_status="no_soa"),
                SimpleNamespace(name="ns2.example.net", soa_authority_status="no_soa"),
            )
        )

        finding = _soa_authority_finding(analysis)

        self.assertEqual(finding.status, "unknown")
        self.assertFalse(finding.applicable)
        self.assertIn("nie jest traktowany jako potwierdzona awaria", finding.message)

    def test_dnssec_verify_message_uses_independent_signing_context_without_claiming_secure(self):
        evidence = SimpleNamespace(
            zone="example.com",
            selected_dnskey=SimpleNamespace(
                result=SimpleNamespace(
                    state=SimpleNamespace(value="answer"),
                    aa=True,
                )
            ),
        )
        analysis = SimpleNamespace(state=SimpleNamespace(value="unknown"))

        # Match the enum comparison used by the production function without
        # requiring network/crypto fixtures in this integration-focused test.
        from domain_security_scanner.domains.domain.dnssec_analysis import DnssecState
        analysis.state = DnssecState.UNKNOWN

        finding = build_dnssec_findings(
            evidence,
            analysis,
            rdap={"secureDNS": {"delegationSigned": True}},
            dns_records={"example.com": {"DS": ["12345 13 2 AABB"]}},
        )[0]

        self.assertEqual(finding.status, "unknown")
        self.assertFalse(finding.applicable)
        self.assertIn("RDAP wskazuje podpisaną delegację", finding.message)
        self.assertIn("autorytatywny DNSKEY", finding.message)
        self.assertIn("nie wpływa na scoring", finding.message)

    def test_pdf_dnssec_verify_explains_context_and_score_semantics(self):
        report = {
            "target_domain": "example.com",
            "root_domain": "example.com",
            "rdap": {"secureDNS": {"delegationSigned": True}},
            "dns_records": {"example.com": {"DS": ["12345 13 2 AABB"]}},
            "dns": {
                "dnssec": {"status": "unknown", "dnskeys": ["257 3 13 KEY"]},
                "delegation": {
                    "available": True,
                    "consistent": True,
                    "complete": True,
                },
                "soa": {"ns_rrset_consistent": True},
                "open_recursion": {"status": "unknown"},
                "caa": {
                    "effective_name": "example.com",
                    "analysis": {"state": "effective"},
                },
            },
        }

        rows = dns_posture_rows(report)

        self.assertEqual(rows[0]["status"], "unknown")
        self.assertIn("RDAP/recursive DS context", rows[0]["value"])
        self.assertIn("child DNSKEY", rows[0]["value"])
        self.assertIn("VERIFY items are excluded", rows[1]["value"])


if __name__ == "__main__":
    unittest.main()
