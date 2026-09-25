import unittest

from domain_security_scanner.domains.domain.delegation import (
    DelegatedNameserverEvidence,
    DelegationGlueEvidence,
    NameserverAddressEvidence,
    ParentDelegationEvidence,
)
from domain_security_scanner.domains.domain.delegation_analysis import (
    ADDRESS_AVAILABLE,
    ADDRESS_NO_ADDRESS,
    ADDRESS_UNKNOWN,
    ALIAS_ALIAS,
    ALIAS_DIRECT,
    ALIAS_UNKNOWN,
    AUTHORITY_AUTHORITATIVE,
    AUTHORITY_LAME,
    AUTHORITY_UNKNOWN,
    GLUE_MISSING,
    GLUE_NOT_REQUIRED,
    GLUE_PRESENT,
    ChildNameserverView,
    DelegationAnalysis,
    NameserverDelegationAnalysis,
)
from domain_security_scanner.domains.domain.delegation_findings import (
    build_delegation_findings,
)


def _evidence(nameservers=("ns1.example.net", "ns2.example.net"), *, available=True):
    return ParentDelegationEvidence(
        zone="example.com",
        parent_zone="com",
        delegated_nameservers=tuple(nameservers) if available else (),
        source_server_name="a.gtld-servers.net" if available else None,
        source_server_ip="192.0.2.53" if available else None,
        error=None if available else "parent unavailable",
    )


def _ns(
    name,
    *,
    authority=AUTHORITY_AUTHORITATIVE,
    address=ADDRESS_AVAILABLE,
    alias=ALIAS_DIRECT,
    in_bailiwick=False,
    glue=GLUE_NOT_REQUIRED,
    glue_consistent=None,
):
    views = ()
    if authority == AUTHORITY_AUTHORITATIVE:
        views = (
            ChildNameserverView(
                server_name=name,
                server_ip="192.0.2.10",
                nameservers=("ns1.example.net", "ns2.example.net"),
            ),
        )
    return NameserverDelegationAnalysis(
        name=name,
        in_bailiwick=in_bailiwick,
        address_status=address,
        alias_status=alias,
        alias_targets=("alias.example.net",) if alias == ALIAS_ALIAS else (),
        authority_status=authority,
        authoritative_child_views=views,
        glue_status=glue,
        glue_consistent=glue_consistent,
        glue_only_addresses=(),
        resolved_only_addresses=(),
    )


def _analysis(
    nameservers=None,
    *,
    parent_ns=("ns1.example.net", "ns2.example.net"),
    consistent=True,
    complete=True,
    missing=(),
    extra=(),
):
    nameservers = nameservers or (
        _ns("ns1.example.net"),
        _ns("ns2.example.net"),
    )
    child_views = tuple(
        view
        for item in nameservers
        for view in item.authoritative_child_views
    )
    return DelegationAnalysis(
        zone="example.com",
        parent_nameservers=tuple(parent_ns),
        child_views=child_views,
        observed_child_nameservers=tuple(parent_ns) if consistent is True else (),
        parent_child_consistent=consistent,
        parent_child_complete=complete,
        missing_from_child=tuple(missing),
        extra_in_child=tuple(extra),
        nameservers=tuple(nameservers),
    )


def _finding_map(evidence, analysis):
    return {
        finding.name: finding
        for finding in build_delegation_findings(evidence, analysis)
    }


class DelegationFindingsTest(unittest.TestCase):
    def test_healthy_delegation_reuses_existing_redundancy_weight_only(self):
        findings = _finding_map(_evidence(), _analysis())

        redundancy = findings["Name server redundancy"]
        self.assertEqual(redundancy.status, "pass")
        self.assertEqual(redundancy.weight, 3)
        self.assertEqual(redundancy.earned, 3)

        self.assertEqual(findings["DNS delegation consistency"].status, "pass")
        self.assertEqual(findings["Delegated nameserver authority"].status, "pass")
        self.assertEqual(findings["Nameserver addressability"].status, "pass")
        self.assertEqual(findings["Delegation glue"].status, "info")
        self.assertEqual(findings["Nameserver target aliasing"].status, "pass")

        for name, finding in findings.items():
            if name != "Name server redundancy":
                self.assertEqual(finding.weight, 0)

    def test_single_parent_nameserver_warns_without_rdap_dependency(self):
        evidence = _evidence(("ns1.example.net",))
        analysis = _analysis(
            nameservers=(_ns("ns1.example.net"),),
            parent_ns=("ns1.example.net",),
            consistent=True,
            complete=True,
        )

        finding = _finding_map(evidence, analysis)["Name server redundancy"]

        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, 3)
        self.assertEqual(finding.earned, 0)

    def test_unavailable_parent_evidence_does_not_create_false_failures(self):
        evidence = _evidence(available=False)
        analysis = _analysis(
            nameservers=(),
            parent_ns=(),
            consistent=None,
            complete=False,
        )

        findings = _finding_map(evidence, analysis)

        self.assertEqual(findings["Name server redundancy"].status, "unknown")
        self.assertFalse(findings["Name server redundancy"].applicable)
        self.assertEqual(findings["DNS delegation consistency"].status, "unknown")
        self.assertEqual(findings["Delegated nameserver authority"].status, "unknown")
        self.assertEqual(findings["Nameserver addressability"].status, "unknown")
        self.assertEqual(findings["Delegation glue"].status, "unknown")
        self.assertEqual(findings["Nameserver target aliasing"].status, "unknown")
        self.assertTrue(
            all(
                finding.status != "fail"
                for finding in findings.values()
            )
        )

    def test_parent_child_mismatch_is_warn_not_critical_failure(self):
        analysis = _analysis(
            consistent=False,
            missing=("old.example.net",),
            extra=("new.example.net",),
        )

        finding = _finding_map(_evidence(), analysis)[
            "DNS delegation consistency"
        ]

        self.assertEqual(finding.status, "warn")
        self.assertIn("old.example.net", finding.message)
        self.assertIn("new.example.net", finding.message)
        self.assertIn("stan przejściowy", finding.message)

    def test_positive_lame_evidence_is_fail_but_timeout_is_unknown(self):
        lame_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", authority=AUTHORITY_LAME),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )
        timeout_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", authority=AUTHORITY_UNKNOWN),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )

        lame = _finding_map(_evidence(), lame_analysis)[
            "Delegated nameserver authority"
        ]
        timeout = _finding_map(_evidence(), timeout_analysis)[
            "Delegated nameserver authority"
        ]

        self.assertEqual(lame.status, "fail")
        self.assertIn("ns1.example.net", lame.message)
        self.assertEqual(lame.weight, 0)

        self.assertEqual(timeout.status, "unknown")
        self.assertFalse(timeout.applicable)

    def test_missing_address_is_distinct_from_unavailable_lookup(self):
        missing_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", address=ADDRESS_NO_ADDRESS),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )
        unknown_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", address=ADDRESS_UNKNOWN),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )

        missing = _finding_map(_evidence(), missing_analysis)[
            "Nameserver addressability"
        ]
        unknown = _finding_map(_evidence(), unknown_analysis)[
            "Nameserver addressability"
        ]

        self.assertEqual(missing.status, "fail")
        self.assertEqual(unknown.status, "unknown")

    def test_in_bailiwick_missing_or_stale_glue_is_advisory(self):
        missing_analysis = _analysis(
            nameservers=(
                _ns(
                    "ns1.example.com",
                    in_bailiwick=True,
                    glue=GLUE_MISSING,
                ),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )
        stale_analysis = _analysis(
            nameservers=(
                _ns(
                    "ns1.example.com",
                    in_bailiwick=True,
                    glue=GLUE_PRESENT,
                    glue_consistent=False,
                ),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )

        missing = _finding_map(_evidence(), missing_analysis)["Delegation glue"]
        stale = _finding_map(_evidence(), stale_analysis)["Delegation glue"]

        self.assertEqual(missing.status, "warn")
        self.assertEqual(stale.status, "warn")
        self.assertEqual(missing.weight, 0)
        self.assertEqual(stale.weight, 0)

    def test_nameserver_cname_alias_is_warn_and_lookup_failure_is_unknown(self):
        alias_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", alias=ALIAS_ALIAS),
                _ns("ns2.example.net"),
            ),
        )
        unknown_analysis = _analysis(
            nameservers=(
                _ns("ns1.example.net", alias=ALIAS_UNKNOWN),
                _ns("ns2.example.net"),
            ),
        )

        alias = _finding_map(_evidence(), alias_analysis)[
            "Nameserver target aliasing"
        ]
        unknown = _finding_map(_evidence(), unknown_analysis)[
            "Nameserver target aliasing"
        ]

        self.assertEqual(alias.status, "warn")
        self.assertEqual(unknown.status, "unknown")


if __name__ == "__main__":
    unittest.main()
