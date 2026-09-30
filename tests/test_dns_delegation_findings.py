import unittest
from types import SimpleNamespace

from domain_security_scanner.domains.domain.delegation import ParentDelegationEvidence
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
from domain_security_scanner.domains.domain.dns_reconciliation import (
    reconcile_delegation,
)
from domain_security_scanner.domains.domain.dns_scoring import (
    DELEGATED_AUTHORITY_WEIGHT,
    DELEGATION_CONSISTENCY_WEIGHT,
    NAME_SERVER_REDUNDANCY_WEIGHT,
    NAMESERVER_ADDRESSABILITY_WEIGHT,
)
from domain_security_scanner.domains.domain.reporting import delegation_report_data


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


def _finding_map(evidence, analysis, authoritative_analysis=None):
    return {
        finding.name: finding
        for finding in build_delegation_findings(
            evidence,
            analysis,
            authoritative_analysis,
        )
    }


def _incomplete_analysis():
    return _analysis(
        nameservers=(
            _ns("ns1.example.net", authority=AUTHORITY_UNKNOWN),
            _ns("ns2.example.net", authority=AUTHORITY_UNKNOWN),
        ),
        consistent=None,
        complete=False,
    )


def _authoritative_analysis(rrset=("ns1.example.net", "ns2.example.net")):
    return SimpleNamespace(
        ns_rrset_consistent=True,
        servers=(
            SimpleNamespace(name="ns1.example.net", apex_nameservers=rrset),
            SimpleNamespace(name="ns2.example.net", apex_nameservers=rrset),
        ),
    )


class DelegationFindingsTest(unittest.TestCase):
    def test_healthy_delegation_uses_impact_calibrated_weights(self):
        findings = _finding_map(_evidence(), _analysis())

        self.assertEqual(findings["Name server redundancy"].weight, NAME_SERVER_REDUNDANCY_WEIGHT)
        self.assertEqual(findings["Name server redundancy"].earned, NAME_SERVER_REDUNDANCY_WEIGHT)
        self.assertEqual(findings["DNS delegation consistency"].weight, DELEGATION_CONSISTENCY_WEIGHT)
        self.assertEqual(findings["DNS delegation consistency"].earned, DELEGATION_CONSISTENCY_WEIGHT)
        self.assertEqual(findings["Delegated nameserver authority"].weight, DELEGATED_AUTHORITY_WEIGHT)
        self.assertEqual(findings["Delegated nameserver authority"].earned, DELEGATED_AUTHORITY_WEIGHT)
        self.assertEqual(findings["Nameserver addressability"].weight, NAMESERVER_ADDRESSABILITY_WEIGHT)
        self.assertEqual(findings["Nameserver addressability"].earned, NAMESERVER_ADDRESSABILITY_WEIGHT)
        self.assertEqual(findings["Delegation glue"].weight, 0)
        self.assertEqual(findings["Nameserver target aliasing"].weight, 0)

    def test_single_parent_nameserver_warns_with_low_weight(self):
        evidence = _evidence(("ns1.example.net",))
        analysis = _analysis(
            nameservers=(_ns("ns1.example.net"),),
            parent_ns=("ns1.example.net",),
            consistent=True,
            complete=True,
        )
        finding = _finding_map(evidence, analysis)["Name server redundancy"]
        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, NAME_SERVER_REDUNDANCY_WEIGHT)
        self.assertEqual(finding.earned, 0)

    def test_unavailable_parent_evidence_does_not_create_false_failures_or_score(self):
        findings = _finding_map(
            _evidence(available=False),
            _analysis(nameservers=(), parent_ns=(), consistent=None, complete=False),
        )
        self.assertTrue(
            all(finding.status != "fail" for finding in findings.values())
        )
        for name in (
            "Name server redundancy",
            "DNS delegation consistency",
            "Delegated nameserver authority",
            "Nameserver addressability",
        ):
            self.assertEqual(findings[name].status, "unknown")
            self.assertFalse(findings[name].applicable)

    def test_complete_parent_child_mismatch_is_high_impact_failure(self):
        finding = _finding_map(
            _evidence(),
            _analysis(
                consistent=False,
                complete=True,
                missing=("old.example.net",),
                extra=("new.example.net",),
            ),
        )["DNS delegation consistency"]
        self.assertEqual(finding.status, "fail")
        self.assertEqual(finding.weight, DELEGATION_CONSISTENCY_WEIGHT)
        self.assertEqual(finding.earned, 0)
        self.assertIn("old.example.net", finding.message)
        self.assertIn("new.example.net", finding.message)

    def test_partial_parent_child_mismatch_is_warn_with_partial_credit(self):
        finding = _finding_map(
            _evidence(),
            _analysis(
                consistent=False,
                complete=False,
                missing=("old.example.net",),
            ),
        )["DNS delegation consistency"]
        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, DELEGATION_CONSISTENCY_WEIGHT)
        self.assertEqual(finding.earned, DELEGATION_CONSISTENCY_WEIGHT / 2)
        self.assertIn("stan przejściowy", finding.message)

    def test_positive_lame_evidence_scores_but_timeout_is_unknown(self):
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
        lame = _finding_map(_evidence(), lame_analysis)["Delegated nameserver authority"]
        timeout = _finding_map(_evidence(), timeout_analysis)["Delegated nameserver authority"]
        self.assertEqual(lame.status, "fail")
        self.assertEqual(lame.weight, DELEGATED_AUTHORITY_WEIGHT)
        self.assertEqual(lame.earned, 0)
        self.assertEqual(timeout.status, "unknown")
        self.assertFalse(timeout.applicable)

    def test_missing_address_scores_but_unavailable_lookup_is_unknown(self):
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
        missing = _finding_map(_evidence(), missing_analysis)["Nameserver addressability"]
        unknown = _finding_map(_evidence(), unknown_analysis)["Nameserver addressability"]
        self.assertEqual(missing.status, "fail")
        self.assertEqual(missing.weight, NAMESERVER_ADDRESSABILITY_WEIGHT)
        self.assertEqual(missing.earned, 0)
        self.assertEqual(unknown.status, "unknown")
        self.assertFalse(unknown.applicable)

    def test_glue_and_nameserver_aliasing_remain_non_scoring(self):
        analysis = _analysis(
            nameservers=(
                _ns(
                    "ns1.example.com",
                    in_bailiwick=True,
                    glue=GLUE_MISSING,
                    alias=ALIAS_ALIAS,
                ),
                _ns("ns2.example.net"),
            ),
            consistent=None,
            complete=False,
        )
        findings = _finding_map(_evidence(), analysis)
        self.assertEqual(findings["Delegation glue"].status, "warn")
        self.assertEqual(findings["Delegation glue"].weight, 0)
        self.assertEqual(findings["Nameserver target aliasing"].status, "warn")
        self.assertEqual(findings["Nameserver target aliasing"].weight, 0)

    def test_stale_glue_and_alias_lookup_unknown_remain_non_scoring(self):
        analysis = _analysis(
            nameservers=(
                _ns(
                    "ns1.example.com",
                    in_bailiwick=True,
                    glue=GLUE_PRESENT,
                    glue_consistent=False,
                    alias=ALIAS_UNKNOWN,
                ),
                _ns("ns2.example.net"),
            ),
        )
        findings = _finding_map(_evidence(), analysis)
        self.assertEqual(findings["Delegation glue"].weight, 0)
        self.assertEqual(findings["Nameserver target aliasing"].status, "unknown")
        self.assertFalse(findings["Nameserver target aliasing"].applicable)

    def test_later_authoritative_rrset_reconciles_incomplete_delegation(self):
        analysis = _incomplete_analysis()
        authoritative = _authoritative_analysis()

        reconciled = reconcile_delegation(analysis, authoritative)
        findings = _finding_map(_evidence(), analysis, authoritative)

        self.assertTrue(reconciled.consistent)
        self.assertTrue(reconciled.complete)
        self.assertEqual(reconciled.consistency_source, "authoritative_apex_ns")
        self.assertEqual(
            reconciled.authority_confirmed_servers,
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertEqual(findings["DNS delegation consistency"].status, "pass")
        self.assertEqual(findings["Delegated nameserver authority"].status, "pass")

    def test_complete_authoritative_reconciliation_can_confirm_real_mismatch(self):
        analysis = _incomplete_analysis()
        authoritative = _authoritative_analysis(
            ("ns1.example.net", "ns3.example.net")
        )

        reconciled = reconcile_delegation(analysis, authoritative)
        findings = _finding_map(_evidence(), analysis, authoritative)

        self.assertFalse(reconciled.consistent)
        self.assertTrue(reconciled.complete)
        self.assertEqual(reconciled.missing_from_child, ("ns2.example.net",))
        self.assertEqual(reconciled.extra_in_child, ("ns3.example.net",))
        self.assertEqual(findings["DNS delegation consistency"].status, "fail")

    def test_incomplete_authoritative_views_do_not_force_reconciliation(self):
        analysis = _incomplete_analysis()
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

    def test_public_delegation_report_exposes_reconciliation_source(self):
        report = delegation_report_data(
            _evidence(),
            _incomplete_analysis(),
            _authoritative_analysis(),
        )

        self.assertTrue(report["consistent"])
        self.assertTrue(report["complete"])
        self.assertEqual(report["consistency_source"], "authoritative_apex_ns")
        self.assertEqual(
            report["child_ns"],
            ["ns1.example.net", "ns2.example.net"],
        )


if __name__ == "__main__":
    unittest.main()
