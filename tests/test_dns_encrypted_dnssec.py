from __future__ import annotations

import unittest
from dataclasses import replace

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ed25519

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
    DnssecScanMixin,
    dnssec_report_data,
)
from domain_security_scanner.domains.domain.dnssec_analysis import (
    DNSSEC_VALIDATION_POLICY,
    DnssecState,
)
from domain_security_scanner.domains.domain.dnssec_findings import build_dnssec_findings
from domain_security_scanner.domains.domain.encrypted_dns import (
    DOH_RESOLVERS,
    ENCRYPTED_DNS_USABLE,
    RRSET_CONSENSUS,
    RRSET_DISAGREEMENT,
    EncryptedDnsEvidence,
    EncryptedDnsObservation,
    EncryptedDnsRrsetEvidence,
    encrypted_dns_report_data,
)
from domain_security_scanner.domains.domain.encrypted_dnssec import (
    ENCRYPTED_DNSSEC_SECURE,
    ENCRYPTED_DNSSEC_UNKNOWN,
    validate_dnssec_from_encrypted,
)
from domain_security_scanner.models import DnsQueryMode, DnsQueryResult, DnsQueryState
from domain_security_scanner.reporting.dns_pdf import dns_posture_rows


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


def _recursive_result(qtype: str, *rrsets) -> DnsQueryResult:
    records = tuple(
        rdata.to_text()
        for rrset in rrsets
        if dns.rdatatype.to_text(rrset.rdtype) == qtype
        for rdata in rrset
    )
    return DnsQueryResult(
        "example.com",
        qtype,
        DnsQueryState.ANSWER,
        records,
        query_mode=DnsQueryMode.RECURSIVE,
        server_name="validating-doh",
        rcode="NOERROR",
        aa=False,
        answer_section=tuple(rrset.to_text() for rrset in rrsets),
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=True,
        request_recursion_desired=True,
        rd=True,
        ra=True,
    )


def _direct_timeout_evidence() -> DnssecEvidence:
    result = DnsQueryResult(
        "example.com",
        "DS",
        DnsQueryState.TIMEOUT,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        server_name="a.gtld-servers.net",
        server_ip="192.0.2.1",
        error="timeout",
        request_want_dnssec=True,
    )
    query = DnssecQueryEvidence(
        qtype="DS",
        server_name="a.gtld-servers.net",
        server_ip="192.0.2.1",
        udp_result=result,
    )
    return DnssecEvidence(zone="example.com", parent_ds=query, parent_ds_attempts=(query,))


def _signed_encrypted_evidence() -> EncryptedDnsEvidence:
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
        inception=VALID_INCEPTION,
        expiration=VALID_EXPIRATION,
        policy=DNSSEC_VALIDATION_POLICY,
    )
    dnskey_rrsig = _rrsig_rrset("example.com.", dnskey_sig)

    ds = dns.dnssec.make_ds(
        zone,
        dnskey,
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
        "ns1.example.net. hostmaster.example.com. 42 3600 600 86400 300",
    )
    soa_sig = dns.dnssec.sign(
        soa_rrset,
        private_key,
        zone,
        dnskey,
        inception=VALID_INCEPTION,
        expiration=VALID_EXPIRATION,
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
        inception=VALID_INCEPTION,
        expiration=VALID_EXPIRATION,
        policy=DNSSEC_VALIDATION_POLICY,
    )
    ns_rrsig = _rrsig_rrset("example.com.", ns_sig)

    material = {
        "DS": (ds_rrset,),
        "DNSKEY": (dnskey_rrset, dnskey_rrsig),
        "SOA": (soa_rrset, soa_rrsig),
        "NS": (ns_rrset, ns_rrsig),
    }

    rrsets = []
    for qtype in ("SOA", "NS", "DS", "DNSKEY"):
        response_rrsets = material[qtype]
        observations = tuple(
            EncryptedDnsObservation(
                resolver_name=name,
                resolver_url=url,
                qtype=qtype,
                result=_recursive_result(qtype, *response_rrsets),
                authenticated_data=True,
            )
            for name, url in DOH_RESOLVERS
        )
        requested = response_rrsets[0]
        rrsets.append(
            EncryptedDnsRrsetEvidence(
                qtype=qtype,
                status=RRSET_CONSENSUS,
                rdata=tuple(sorted(rdata.to_text() for rdata in requested)),
                observations=observations,
            )
        )

    return EncryptedDnsEvidence(
        zone="example.com",
        status=ENCRYPTED_DNS_USABLE,
        trigger="suspected_interception",
        attempted=True,
        rrsets=tuple(rrsets),
    )


class EncryptedDnssecValidationTest(unittest.TestCase):
    def test_two_authenticated_doh_paths_promote_unknown_to_secure(self):
        validation = validate_dnssec_from_encrypted(
            _signed_encrypted_evidence(),
            now=NOW,
        )

        self.assertEqual(validation.status, ENCRYPTED_DNSSEC_SECURE)
        self.assertEqual(len(validation.resolver_results), 2)
        self.assertTrue(
            all(item.status == DnssecState.SECURE.value for item in validation.resolver_results)
        )
        self.assertIsNotNone(validation.selected_evidence)
        self.assertEqual(validation.selected_evidence.source, "encrypted_recursive")
        self.assertEqual(validation.selected_analysis.state, DnssecState.SECURE)

    def test_missing_ad_on_one_resolver_stays_unknown(self):
        evidence = _signed_encrypted_evidence()
        rrsets = list(evidence.rrsets)
        dnskey_index = next(i for i, item in enumerate(rrsets) if item.qtype == "DNSKEY")
        dnskey = rrsets[dnskey_index]
        observations = list(dnskey.observations)
        observations[1] = replace(observations[1], authenticated_data=False)
        rrsets[dnskey_index] = replace(dnskey, observations=tuple(observations))
        evidence = replace(evidence, rrsets=tuple(rrsets))

        validation = validate_dnssec_from_encrypted(evidence, now=NOW)

        self.assertEqual(validation.status, ENCRYPTED_DNSSEC_UNKNOWN)
        self.assertIsNone(validation.selected_evidence)

    def test_rrset_disagreement_stays_unknown(self):
        evidence = _signed_encrypted_evidence()
        rrsets = tuple(
            replace(item, status=RRSET_DISAGREEMENT, rdata=())
            if item.qtype == "DS"
            else item
            for item in evidence.rrsets
        )

        validation = validate_dnssec_from_encrypted(
            replace(evidence, rrsets=rrsets),
            now=NOW,
        )

        self.assertEqual(validation.status, ENCRYPTED_DNSSEC_UNKNOWN)
        self.assertIn("DS", validation.reason)

    def test_report_exposes_encrypted_validation_source_and_recursive_queries(self):
        validation = validate_dnssec_from_encrypted(
            _signed_encrypted_evidence(),
            now=NOW,
        )
        report = dnssec_report_data(
            validation.selected_evidence,
            validation.selected_analysis,
        )

        self.assertEqual(report["status"], "secure")
        self.assertEqual(report["validation_source"], "encrypted_recursive")
        self.assertEqual(report["queries"]["parent_ds"]["query_mode"], "recursive")

    def test_encrypted_report_exposes_dnssec_validation_provenance(self):
        evidence = _signed_encrypted_evidence()
        validation = validate_dnssec_from_encrypted(evidence, now=NOW)
        report = encrypted_dns_report_data(evidence, validation)

        self.assertEqual(report["dnssec_validation"]["status"], "secure")
        self.assertTrue(report["dnssec_validation"]["local_cryptographic_validation"])
        self.assertTrue(report["dnssec_validation"]["authenticated_data_required"])
        self.assertEqual(len(report["dnssec_validation"]["resolvers"]), 2)

    def test_customer_finding_and_pdf_identify_encrypted_secure_source(self):
        validation = validate_dnssec_from_encrypted(
            _signed_encrypted_evidence(),
            now=NOW,
        )
        finding = build_dnssec_findings(
            validation.selected_evidence,
            validation.selected_analysis,
        )[0]
        self.assertEqual(finding.status, "pass")
        self.assertIn("DNS-over-HTTPS", finding.message)

        report = {
            "root_domain": "example.com",
            "target_domain": "example.com",
            "rdap": {},
            "dns_records": {},
            "dns": {
                "dnssec": {
                    "status": "secure",
                    "validation_source": "encrypted_recursive",
                },
                "delegation": {"available": False},
                "soa": {"ns_rrset_consistent": None},
                "open_recursion": {"status": "unknown", "open_servers": []},
                "caa": {"analysis": {"state": "unknown"}},
                "encrypted_recursive": {"status": "usable", "attempted": True},
            },
        }
        rows = dns_posture_rows(report)
        self.assertEqual(rows[0]["status"], "pass")
        self.assertIn("DNS-over-HTTPS", rows[0]["value"])


class _TerminalDnsMixin:
    def collect_domain_dns(self):
        return None


class _DnssecHarness(DnssecScanMixin, _TerminalDnsMixin):
    def __init__(self, encrypted_dns):
        self.root_domain = "example.com"
        self.delegation = None
        self.encrypted_dns = encrypted_dns
        self.rdap = {}
        self.dns_records = {}
        self.checks = []

    def collect_dnssec_evidence(self, delegation):
        return _direct_timeout_evidence()

    def add_check(self, category, name, status, message, weight, earned, applicable):
        self.checks.append((category, name, status, message, weight, earned, applicable))


class EncryptedDnssecWiringTest(unittest.TestCase):
    def test_dnssec_mixin_promotes_only_unknown_direct_result(self):
        scanner = _DnssecHarness(_signed_encrypted_evidence())

        # Use the fixture's deterministic signature window.
        import domain_security_scanner.domains.domain.encrypted_dnssec as encrypted_dnssec
        original = encrypted_dnssec.validate_dnssec_from_encrypted

        def validate_with_fixed_time(evidence):
            return original(evidence, now=NOW)

        encrypted_dnssec.validate_dnssec_from_encrypted = validate_with_fixed_time
        try:
            scanner.collect_domain_dns()
        finally:
            encrypted_dnssec.validate_dnssec_from_encrypted = original

        self.assertEqual(scanner.dnssec_direct_analysis.state, DnssecState.UNKNOWN)
        self.assertEqual(scanner.dnssec_analysis.state, DnssecState.SECURE)
        self.assertEqual(scanner.dnssec.source, "encrypted_recursive")
        dnssec_checks = [item for item in scanner.checks if item[1] == "DNSSEC"]
        self.assertEqual(len(dnssec_checks), 1)
        self.assertEqual(dnssec_checks[0][2], "pass")


if __name__ == "__main__":
    unittest.main()
