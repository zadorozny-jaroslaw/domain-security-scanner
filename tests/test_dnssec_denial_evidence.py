from __future__ import annotations

import unittest
from types import SimpleNamespace

from domain_security_scanner.domains.domain.dnssec import DnssecEvidenceCollectorMixin
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


NEGATIVE_NAME = "dssnx0-deadbeef.example.com"


def _direct_result(host, qtype, state, *, server_name, server_ip, want_dnssec=True):
    return DnsQueryResult(
        host,
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name=server_name,
        server_ip=server_ip,
        rcode="NXDOMAIN" if state == DnsQueryState.NXDOMAIN else "NOERROR",
        aa=True,
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=want_dnssec,
    )


def _delegation():
    authority = _direct_result(
        "example.com",
        "NS",
        DnsQueryState.ANSWER,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        want_dnssec=False,
    )
    server = SimpleNamespace(
        name="ns1.example.net",
        authority_queries=(authority,),
        candidate_addresses=("192.0.2.53",),
    )
    return SimpleNamespace(
        zone="example.com",
        source_server_name="a.gtld-servers.net",
        source_server_ip="192.0.2.1",
        delegated_servers=(server,),
    )


class _Collector(DnssecEvidenceCollectorMixin):
    def __init__(self, *, parent_state=DnsQueryState.ANSWER, negative_names=(NEGATIVE_NAME,)):
        self.root_domain = "example.com"
        self.parent_state = parent_state
        self.negative_dns = SimpleNamespace(negative_names=negative_names)
        self.calls = []

    def authoritative_dns_query_result(self, host, qtype, **kwargs):
        self.calls.append((host, qtype, dict(kwargs)))
        if qtype == "DS":
            state = self.parent_state
        elif qtype == "A" and host == NEGATIVE_NAME:
            state = DnsQueryState.NXDOMAIN
        else:
            state = DnsQueryState.ANSWER
        return _direct_result(
            host,
            qtype,
            state,
            server_name=kwargs.get("server_name"),
            server_ip=kwargs["server_ip"],
            want_dnssec=kwargs.get("want_dnssec", False),
        )


class DnssecDenialEvidenceTest(unittest.TestCase):
    def test_reuses_one_issue19_negative_name_with_dnssec_do_bit(self):
        collector = _Collector()
        evidence = collector.collect_dnssec_evidence(_delegation())

        self.assertIsNotNone(evidence.denial_probe)
        self.assertEqual(evidence.denial_probe.result.qname, NEGATIVE_NAME)
        self.assertEqual(evidence.denial_probe.result.state, DnsQueryState.NXDOMAIN)
        self.assertTrue(evidence.denial_probe.result.request_want_dnssec)

        self.assertEqual(len(collector.calls), 5)
        self.assertEqual(
            [(host, qtype) for host, qtype, _ in collector.calls],
            [
                ("example.com", "DS"),
                ("example.com", "DNSKEY"),
                ("example.com", "SOA"),
                ("example.com", "NS"),
                (NEGATIVE_NAME, "A"),
            ],
        )
        denial_call = collector.calls[-1][2]
        self.assertEqual(denial_call["server_ip"], "192.0.2.53")
        self.assertEqual(denial_call["server_name"], "ns1.example.net")
        self.assertTrue(denial_call["want_dnssec"])
        self.assertEqual(denial_call["edns_payload"], 1232)

    def test_unsigned_zone_still_stops_after_parent_ds(self):
        collector = _Collector(parent_state=DnsQueryState.NO_ANSWER)
        evidence = collector.collect_dnssec_evidence(_delegation())

        self.assertIsNone(evidence.denial_probe)
        self.assertEqual(len(collector.calls), 1)
        self.assertEqual(collector.calls[0][1], "DS")

    def test_missing_issue19_probe_does_not_create_another_random_name(self):
        collector = _Collector(negative_names=())
        evidence = collector.collect_dnssec_evidence(_delegation())

        self.assertIsNone(evidence.denial_probe)
        self.assertEqual(len(collector.calls), 4)
        self.assertFalse(any(qtype == "A" for _, qtype, _ in collector.calls))


if __name__ == "__main__":
    unittest.main()
