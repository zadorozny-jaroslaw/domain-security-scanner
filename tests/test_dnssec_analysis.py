from __future__ import annotations

import unittest
from unittest.mock import patch

import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ed25519

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
)
from domain_security_scanner.domains.domain.dnssec_analysis import (
    DNSSEC_POLICY_VERSION,
    DNSSEC_VALIDATION_POLICY,
    DnssecState,
    DnssecStepOutcome,
    analyze_dnssec_evidence,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


NOW = 1_800_000_000
VALID_INCEPTION = NOW - 3600
VALID_EXPIRATION = NOW + 3600


def _rrsig_rrset(owner: str, signature) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(
        dns.name.from_text(owner),
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
    )
    rrset.ttl = 300
    rrset.add(signature, 300)
    return rrset


def _answer_result(qtype: str, *rrsets, server_ip="192.0.2.53"):
    return DnsQueryResult(
        "example.com",
        qtype,
        DnsQueryState.ANSWER,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip=server_ip,
        rcode="NOERROR",
        aa=True,
        answer_section=tuple(rrset.to_text() for rrset in rrsets),
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=True,
    )


def _state_result(qtype: str, state: DnsQueryState):
    return DnsQueryResult(
        "example.com",
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        rcode="NOERROR",
        aa=True,
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=True,
    )


def _query(qtype: str, result: DnsQueryResult) -> DnssecQueryEvidence:
    return DnssecQueryEvidence(
        qtype=qtype,
        server_name=result.server_name,
        server_ip=result.server_ip,
        udp_result=result,
    )


def _signed_fixture(
    *,
    ds_matches: bool = True,
    dnskey_inception: int = VALID_INCEPTION,
    dnskey_expiration: int = VALID_EXPIRATION,
    soa_inception: int = VALID_INCEPTION,
    soa_expiration: int = VALID_EXPIRATION,
    ns_inception: int = VALID_INCEPTION,
    ns_expiration: int = VALID_EXPIRATION,
) -> DnssecEvidence:
    zone = dns.name.from_text("example.com.")
    private_key = ed25519.Ed25519PrivateKey.generate()
    dnskey = dns.dnssec.make_dnskey(private_key.public_key(), "ED25519", flags=257)

    dnskey_rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    dnskey_rrset.ttl = 300
    dnskey_rrset.add(dnskey, 300)
    dnskey_sig = dns.dnssec.sign(
        dnskey_rrset,
        private_key,
        zone,
        dnskey,
        inception=dnskey_inception,
        expiration=dnskey_expiration,
        policy=DNSSEC_VALIDATION_POLICY,
    )
    dnskey_rrsig = _rrsig_rrset("example.com.", dnskey_sig)

    if ds_matches:
        ds = dns.dnssec.make_ds(
            zone,
            dnskey,
            "SHA256",
            policy=DNSSEC_VALIDATION_POLICY,
            validating=True,
        )
    else:
        other_private = ed25519.Ed25519PrivateKey.generate()
        other_key = dns.dnssec.make_dnskey(
            other_private.public_key(), "ED25519", flags=257
        )
        ds = dns.dnssec.make_ds(
            zone,
            other_key,
            "SHA256",
            policy=DNSSEC_VALIDATION_POLICY,
            validating=True,
        )

    ds_rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DS)
    ds_rrset.ttl = 300
    ds_rrset.add(ds, 300)

    soa_rrset = dns.rrset.from_text(
        "example.com.",
        300,
        "IN",
        "SOA",
        "ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300",
    )
    soa_sig = dns.dnssec.sign(
        soa_rrset,
        private_key,
        zone,
        dnskey,
        inception=soa_inception,
        expiration=soa_expiration,
        policy=DNSSEC_VALIDATION_POLICY,
    )
    soa_rrsig = _rrsig_rrset("example.com.", soa_sig)

    ns_rrset = dns.rrset.from_text(
        "example.com.",
        300,
        "IN",
        "NS",
        "ns1.example.net.",
        "ns2.example.net.",
    )
    ns_sig = dns.dnssec.sign(
        ns_rrset,
        private_key,
        zone,
        dnskey,
        inception=ns_inception,
        expiration=ns_expiration,
        policy=DNSSEC_VALIDATION_POLICY,
    )
    ns_rrsig = _rrsig_rrset("example.com.", ns_sig)

    return DnssecEvidence(
        zone="example.com",
        parent_ds=_query("DS", _answer_result("DS", ds_rrset, server_ip="192.0.2.1")),
        dnskey_attempts=(
            _query("DNSKEY", _answer_result("DNSKEY", dnskey_rrset, dnskey_rrsig)),
        ),
        selected_dnskey=_query(
            "DNSKEY", _answer_result("DNSKEY", dnskey_rrset, dnskey_rrsig)
        ),
        apex_rrsets=(
            _query("SOA", _answer_result("SOA", soa_rrset, soa_rrsig)),
            _query("NS", _answer_result("NS", ns_rrset, ns_rrsig)),
        ),
    )


class DnssecAnalysisTest(unittest.TestCase):
    def test_policy_snapshot_is_explicit_and_current_for_issue_16(self):
        self.assertEqual(DNSSEC_POLICY_VERSION, "2025-11-rfc9904-rfc9905-rfc9906")

    def test_no_parent_ds_is_unsigned(self):
        evidence = DnssecEvidence(
            zone="example.com",
            parent_ds=_query("DS", _state_result("DS", DnsQueryState.NO_ANSWER)),
        )
        result = analyze_dnssec_evidence(evidence, now=NOW)
        self.assertEqual(result.state, DnssecState.UNSIGNED)
        self.assertEqual(result.steps[-1].outcome, DnssecStepOutcome.NOT_APPLICABLE)

    def test_complete_signed_fixture_is_secure(self):
        result = analyze_dnssec_evidence(_signed_fixture(), now=NOW)
        self.assertEqual(result.state, DnssecState.SECURE)
        self.assertEqual(result.ds_count, 1)
        self.assertEqual(result.dnskey_count, 1)
        self.assertEqual(len(result.matched_key_tags), 1)
        self.assertTrue(all(step.outcome == DnssecStepOutcome.PASS for step in result.steps))

    def test_complete_ds_mismatch_is_broken(self):
        result = analyze_dnssec_evidence(
            _signed_fixture(ds_matches=False),
            now=NOW,
        )
        self.assertEqual(result.state, DnssecState.BROKEN)
        self.assertEqual(result.steps[-1].name, "DS to DNSKEY")
        self.assertEqual(result.steps[-1].outcome, DnssecStepOutcome.FAIL)

    def test_expired_dnskey_signature_is_broken_and_detected(self):
        result = analyze_dnssec_evidence(
            _signed_fixture(
                dnskey_inception=NOW - 7200,
                dnskey_expiration=NOW - 1,
            ),
            now=NOW,
        )
        self.assertEqual(result.state, DnssecState.BROKEN)
        step = result.steps[-1]
        self.assertEqual(step.name, "DNSKEY RRset")
        self.assertEqual(step.signatures.expired, 1)
        self.assertEqual(step.signatures.current, 0)

    def test_not_yet_valid_apex_signature_is_broken_and_detected(self):
        result = analyze_dnssec_evidence(
            _signed_fixture(
                soa_inception=NOW + 1,
                soa_expiration=NOW + 7200,
            ),
            now=NOW,
        )
        self.assertEqual(result.state, DnssecState.BROKEN)
        step = result.steps[-1]
        self.assertEqual(step.name, "Apex SOA")
        self.assertEqual(step.signatures.not_yet_valid, 1)
        self.assertEqual(step.signatures.current, 0)

    def test_invalid_apex_signature_is_broken(self):
        evidence = _signed_fixture()
        ns_query = evidence.apex_rrsets[1]
        ns_result = ns_query.result
        # Mutate the signed NS RRset text while retaining its original RRSIG.
        answer = list(ns_result.answer_section)
        self.assertEqual(len(answer), 2)
        answer[0] = answer[0].replace("ns2.example.net.", "ns3.example.net.")
        tampered = DnsQueryResult(
            ns_result.host,
            ns_result.rtype,
            ns_result.state,
            ns_result.records,
            query_mode=ns_result.query_mode,
            transport=ns_result.transport,
            server_name=ns_result.server_name,
            server_ip=ns_result.server_ip,
            rcode=ns_result.rcode,
            aa=ns_result.aa,
            answer_section=tuple(answer),
            request_edns_version=ns_result.request_edns_version,
            request_edns_payload=ns_result.request_edns_payload,
            request_want_dnssec=ns_result.request_want_dnssec,
        )
        evidence = DnssecEvidence(
            zone=evidence.zone,
            parent_ds=evidence.parent_ds,
            dnskey_attempts=evidence.dnskey_attempts,
            selected_dnskey=evidence.selected_dnskey,
            apex_rrsets=(evidence.apex_rrsets[0], _query("NS", tampered)),
        )

        result = analyze_dnssec_evidence(evidence, now=NOW)
        self.assertEqual(result.state, DnssecState.BROKEN)
        step = result.steps[-1]
        self.assertEqual(step.name, "Apex NS")
        self.assertEqual(step.signatures.invalid, 1)

    def test_unavailable_dnskey_evidence_is_unknown_not_broken(self):
        evidence = _signed_fixture()
        timeout = _query("DNSKEY", _state_result("DNSKEY", DnsQueryState.TIMEOUT))
        evidence = DnssecEvidence(
            zone=evidence.zone,
            parent_ds=evidence.parent_ds,
            dnskey_attempts=(timeout,),
            selected_dnskey=timeout,
            apex_rrsets=(),
        )
        result = analyze_dnssec_evidence(evidence, now=NOW)
        self.assertEqual(result.state, DnssecState.UNKNOWN)
        self.assertEqual(result.steps[-1].outcome, DnssecStepOutcome.UNKNOWN)

    def test_unsupported_local_crypto_is_unknown(self):
        evidence = _signed_fixture()
        with patch(
            "domain_security_scanner.domains.domain.dnssec_analysis.dns.dnssec.validate_rrsig",
            side_effect=dns.exception.UnsupportedAlgorithm("unsupported locally"),
        ):
            result = analyze_dnssec_evidence(evidence, now=NOW)
        self.assertEqual(result.state, DnssecState.UNKNOWN)
        self.assertEqual(result.steps[-1].name, "DNSKEY RRset")
        self.assertEqual(result.steps[-1].signatures.unsupported, 1)


if __name__ == "__main__":
    unittest.main()
