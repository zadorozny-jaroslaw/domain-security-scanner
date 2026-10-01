from __future__ import annotations

import json
import unittest

from domain_security_scanner.domains.domain.authoritative import (
    AuthoritativeDnsEvidence,
    AuthoritativeEndpointEvidence,
    AuthoritativeServerEvidence,
    SoaObservation,
    SoaRecord,
)
from domain_security_scanner.domains.domain.authoritative_analysis import (
    analyze_authoritative_dns,
)
from domain_security_scanner.domains.domain.delegation import (
    DelegatedNameserverEvidence,
    DelegationGlueEvidence,
    NameserverAddressEvidence,
    ParentDelegationEvidence,
)
from domain_security_scanner.domains.domain.delegation_analysis import (
    ChildNameserverView,
    DelegationAnalysis,
    NameserverDelegationAnalysis,
)
from domain_security_scanner.domains.domain.reporting import (
    dns_infrastructure_report_data,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)
from domain_security_scanner.scanner import Scanner


def _query(
    qname: str,
    qtype: str,
    state: DnsQueryState,
    *,
    records=(),
    mode=DnsQueryMode.RECURSIVE,
    transport=None,
    server_name=None,
    server_ip=None,
    aa=None,
    rcode="NOERROR",
):
    return DnsQueryResult(
        qname,
        qtype,
        state,
        records=tuple(records),
        query_mode=mode,
        transport=transport,
        server_name=server_name,
        server_ip=server_ip,
        aa=aa,
        rcode=rcode,
    )


class DnsInfrastructureReportTest(unittest.TestCase):
    def _fixture(self):
        parent_ns_lookup = _query(
            "com",
            "NS",
            DnsQueryState.ANSWER,
            records=("a.gtld-servers.net.",),
        )
        referral_query = _query(
            "example.com",
            "NS",
            DnsQueryState.ANSWER,
            records=("ns1.example.com.",),
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="a.gtld-servers.net",
            server_ip="192.0.2.1",
            aa=False,
        )
        a_result = _query(
            "ns1.example.com",
            "A",
            DnsQueryState.ANSWER,
            records=("192.0.2.53",),
        )
        aaaa_result = _query(
            "ns1.example.com",
            "AAAA",
            DnsQueryState.NO_ANSWER,
        )
        cname_result = _query(
            "ns1.example.com",
            "CNAME",
            DnsQueryState.NO_ANSWER,
        )
        child_ns_query = _query(
            "example.com",
            "NS",
            DnsQueryState.ANSWER,
            records=("ns1.example.com.",),
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            aa=True,
        )
        addresses = NameserverAddressEvidence(
            name="ns1.example.com",
            ipv4=("192.0.2.53",),
            a_result=a_result,
            aaaa_result=aaaa_result,
            cname_result=cname_result,
        )
        glue = DelegationGlueEvidence(
            name="ns1.example.com",
            ipv4=("192.0.2.53",),
        )
        delegated_server = DelegatedNameserverEvidence(
            name="ns1.example.com",
            addresses=addresses,
            glue=glue,
            candidate_addresses=("192.0.2.53",),
            probe_addresses=("192.0.2.53",),
            authority_queries=(child_ns_query,),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            parent_ns_result=parent_ns_lookup,
            parent_nameservers=("a.gtld-servers.net",),
            delegation_queries=(referral_query,),
            delegated_nameservers=("ns1.example.com",),
            glue=(glue,),
            source_server_name="a.gtld-servers.net",
            source_server_ip="192.0.2.1",
            delegated_servers=(delegated_server,),
        )
        child_view = ChildNameserverView(
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            nameservers=("ns1.example.com",),
        )
        ns_analysis = NameserverDelegationAnalysis(
            name="ns1.example.com",
            in_bailiwick=True,
            address_status="available",
            alias_status="direct",
            alias_targets=(),
            authority_status="authoritative",
            authoritative_child_views=(child_view,),
            glue_status="present",
            glue_consistent=True,
            glue_only_addresses=(),
            resolved_only_addresses=(),
        )
        delegation_analysis = DelegationAnalysis(
            zone="example.com",
            parent_nameservers=("ns1.example.com",),
            child_views=(child_view,),
            observed_child_nameservers=("ns1.example.com",),
            parent_child_consistent=True,
            parent_child_complete=True,
            missing_from_child=(),
            extra_in_child=(),
            nameservers=(ns_analysis,),
        )

        soa = SoaRecord(
            mname="ns1.example.com",
            rname="hostmaster.example.com",
            serial=2026092901,
            refresh=3600,
            retry=600,
            expire=1209600,
            minimum=300,
        )
        udp_soa_query = _query(
            "example.com",
            "SOA",
            DnsQueryState.ANSWER,
            records=(
                "ns1.example.com. hostmaster.example.com. 2026092901 3600 600 1209600 300",
            ),
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            aa=True,
        )
        tcp_soa_query = _query(
            "example.com",
            "SOA",
            DnsQueryState.ANSWER,
            records=udp_soa_query.records,
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.TCP,
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            aa=True,
        )
        edns_soa_query = _query(
            "example.com",
            "SOA",
            DnsQueryState.ANSWER,
            records=udp_soa_query.records,
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            aa=True,
        )
        endpoint = AuthoritativeEndpointEvidence(
            server_name="ns1.example.com",
            server_ip="192.0.2.53",
            udp_soa=SoaObservation(udp_soa_query, soa=soa),
            tcp_soa=SoaObservation(tcp_soa_query, soa=soa),
            edns_soa=SoaObservation(edns_soa_query, soa=soa),
        )
        authoritative_dns = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                AuthoritativeServerEvidence(
                    name="ns1.example.com",
                    candidate_addresses=("192.0.2.53",),
                    probe_addresses=("192.0.2.53",),
                    unprobed_addresses=(),
                    apex_ns_result=child_ns_query,
                    apex_nameservers=("ns1.example.com",),
                    endpoints=(endpoint,),
                ),
            ),
        )
        authoritative_analysis = analyze_authoritative_dns(authoritative_dns)
        caa = {
            "lookup_chain": [
                {
                    "name": "www.example.com",
                    "state": "no_answer",
                    "records": [],
                },
                {
                    "name": "example.com",
                    "state": "answer",
                    "records": ['0 issue "letsencrypt.org"'],
                },
            ],
            "effective_name": "example.com",
            "records": [
                {
                    "raw": '0 issue "letsencrypt.org"',
                    "syntax_valid": True,
                    "flags": 0,
                    "critical": False,
                    "tag": "issue",
                    "value": "letsencrypt.org",
                }
            ],
            "analysis": {
                "state": "effective",
                "record_count": 1,
                "fqdn_issuers": ["letsencrypt.org"],
            },
            "lookup_failure": None,
        }
        return (
            delegation,
            delegation_analysis,
            authoritative_dns,
            authoritative_analysis,
            caa,
        )

    def test_report_distinguishes_recursive_from_authoritative_evidence(self):
        report = dns_infrastructure_report_data(*self._fixture())

        self.assertEqual(report["delegation"]["parent_ns"], ["ns1.example.com"])
        self.assertEqual(report["delegation"]["child_ns"], ["ns1.example.com"])
        self.assertTrue(report["delegation"]["consistent"])
        self.assertEqual(
            report["delegation"]["parent_ns_lookup"]["query_mode"],
            "recursive",
        )
        self.assertEqual(
            report["delegation"]["referral_queries"][0]["query_mode"],
            "authoritative",
        )
        server = report["delegation"]["nameservers"][0]
        self.assertEqual(server["recursive_addresses"]["query_mode"], "recursive")
        self.assertEqual(
            server["recursive_addresses"]["queries"]["A"]["query_mode"],
            "recursive",
        )
        self.assertEqual(
            server["authoritative_queries"][0]["query_mode"],
            "authoritative",
        )

    def test_report_serializes_authoritative_server_and_soa_summary(self):
        report = dns_infrastructure_report_data(*self._fixture())

        self.assertEqual(len(report["authoritative_servers"]), 1)
        server = report["authoritative_servers"][0]
        self.assertEqual(server["name"], "ns1.example.com")
        self.assertEqual(server["soa_authority_status"], "authoritative")
        self.assertEqual(server["edns_status"], "ok")
        self.assertEqual(server["endpoints"][0]["transport_status"], "both_respond")
        self.assertEqual(
            server["endpoints"][0]["tcp_soa"]["query"]["query_mode"],
            "authoritative",
        )
        self.assertEqual(report["soa"]["serials"]["ns1.example.com"], [2026092901])
        self.assertIsNone(report["soa"]["configuration_consistent"])
        self.assertIsNone(report["soa"]["serial_consistent"])

    def test_caa_is_mirrored_under_dns_with_recursive_context(self):
        *_, caa = self._fixture()
        report = dns_infrastructure_report_data(*self._fixture())

        self.assertEqual(report["caa"]["query_mode"], "recursive")
        self.assertEqual(report["caa"]["effective_name"], "example.com")
        self.assertEqual(report["caa"]["analysis"]["state"], "effective")
        self.assertTrue(
            all(
                step["query_mode"] == "recursive"
                for step in report["caa"]["lookup_chain"]
            )
        )
        self.assertNotIn("query_mode", caa["lookup_chain"][0])

    def test_empty_report_shape_is_explicit_and_json_serializable(self):
        report = dns_infrastructure_report_data(None, None, None, None, {})

        self.assertEqual(report["delegation"]["parent_ns"], [])
        self.assertEqual(report["authoritative_servers"], [])
        self.assertIsNone(report["soa"]["configuration_consistent"])
        self.assertEqual(report["caa"]["query_mode"], "recursive")
        self.assertEqual(report["caa"]["analysis"]["state"], "unknown")
        json.dumps(report)


class ScannerDnsCompatibilityTest(unittest.TestCase):
    def test_legacy_dns_records_and_top_level_caa_remain_unchanged(self):
        instance = Scanner("example.com", scan_groups=("domain",))
        legacy_dns_records = {
            "example.com": {
                "A": ["192.0.2.10"],
                "AAAA": [],
                "NS": ["ns1.example.com."],
            }
        }
        legacy_caa = {
            "lookup_chain": [
                {
                    "name": "example.com",
                    "state": "answer",
                    "records": ['0 issue "letsencrypt.org"'],
                }
            ],
            "effective_name": "example.com",
            "records": [{"raw": '0 issue "letsencrypt.org"'}],
            "analysis": {"state": "effective"},
            "lookup_failure": None,
        }
        instance.dns_records = legacy_dns_records
        instance.caa = legacy_caa

        report = instance.to_dict()

        self.assertEqual(report["dns_records"], legacy_dns_records)
        self.assertEqual(report["caa"], legacy_caa)
        self.assertEqual(report["dns"]["caa"]["effective_name"], "example.com")
        self.assertEqual(report["dns"]["caa"]["query_mode"], "recursive")
        self.assertIn("delegation", report["dns"])
        self.assertIn("authoritative_servers", report["dns"])
        self.assertIn("soa", report["dns"])
        self.assertIn("dnssec", report["dns"])
        self.assertIn("negative_response", report["dns"])
        self.assertIn("wildcard", report["dns"])
        self.assertIn("open_recursion", report["dns"])
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
