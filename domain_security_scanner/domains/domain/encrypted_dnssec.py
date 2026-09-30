from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .dnssec import DnssecEvidence, DnssecQueryEvidence
from .dnssec_analysis import DnssecAnalysis, DnssecState, analyze_dnssec_evidence
from .encrypted_dns import (
    RRSET_CONSENSUS,
    EncryptedDnsEvidence,
    EncryptedDnsObservation,
)

ENCRYPTED_DNSSEC_REQUIRED_RRTYPES = ("DS", "DNSKEY", "SOA", "NS")
ENCRYPTED_DNSSEC_SECURE = "secure"
ENCRYPTED_DNSSEC_UNKNOWN = "unknown"


@dataclass(frozen=True)
class EncryptedDnssecResolverValidation:
    """Local cryptographic DNSSEC result for one HTTPS resolver path."""

    resolver_name: str
    status: str
    reason: str
    analysis: DnssecAnalysis | None = None
    evidence: DnssecEvidence | None = None


@dataclass(frozen=True)
class EncryptedDnssecValidation:
    """Consensus-gated DNSSEC validation recovered through encrypted DNS."""

    status: str
    reason: str
    resolver_results: tuple[EncryptedDnssecResolverValidation, ...] = ()
    selected_evidence: DnssecEvidence | None = None
    selected_analysis: DnssecAnalysis | None = None


def _rrsets_by_type(evidence: EncryptedDnsEvidence) -> dict[str, Any]:
    return {str(item.qtype).upper(): item for item in evidence.rrsets}


def _observation_for_resolver(rrset: Any, resolver_name: str) -> EncryptedDnsObservation | None:
    return next(
        (
            observation
            for observation in tuple(getattr(rrset, "observations", ()) or ())
            if observation.resolver_name == resolver_name
        ),
        None,
    )


def _query_evidence(
    observation: EncryptedDnsObservation,
    qtype: str,
) -> DnssecQueryEvidence:
    return DnssecQueryEvidence(
        qtype=qtype,
        server_name=f"{observation.resolver_name} DoH",
        server_ip=None,
        udp_result=observation.result,
    )


def _build_resolver_evidence(
    evidence: EncryptedDnsEvidence,
    resolver_name: str,
) -> tuple[DnssecEvidence | None, str | None]:
    rrsets = _rrsets_by_type(evidence)
    observations: dict[str, EncryptedDnsObservation] = {}

    for qtype in ENCRYPTED_DNSSEC_REQUIRED_RRTYPES:
        rrset = rrsets.get(qtype)
        if rrset is None or rrset.status != RRSET_CONSENSUS:
            return None, f"{qtype} does not have two-resolver consensus."
        observation = _observation_for_resolver(rrset, resolver_name)
        if observation is None:
            return None, f"{qtype} is missing the {resolver_name} observation."
        if observation.authenticated_data is not True:
            return None, (
                f"{qtype} from {resolver_name} did not carry authenticated-data (AD) validation."
            )
        if getattr(observation.result.state, "value", observation.result.state) != "answer":
            return None, f"{qtype} from {resolver_name} is not an answer."
        observations[qtype] = observation

    parent_ds = _query_evidence(observations["DS"], "DS")
    dnskey = _query_evidence(observations["DNSKEY"], "DNSKEY")
    soa = _query_evidence(observations["SOA"], "SOA")
    ns = _query_evidence(observations["NS"], "NS")

    return (
        DnssecEvidence(
            zone=evidence.zone,
            parent_ds=parent_ds,
            dnskey_attempts=(dnskey,),
            selected_dnskey=dnskey,
            apex_rrsets=(soa, ns),
            parent_ds_attempts=(parent_ds,),
            source="encrypted_recursive",
        ),
        None,
    )


def validate_dnssec_from_encrypted(
    evidence: EncryptedDnsEvidence | None,
    *,
    now: float | None = None,
) -> EncryptedDnssecValidation:
    """Validate signed zone material recovered over independent DoH paths.

    This is deliberately promotion-only. Encrypted recursive fallback may turn
    otherwise unavailable direct evidence into SECURE only when both configured
    HTTPS resolvers agree on DS/DNSKEY/SOA/NS, both report AD=1 for every required
    RRset, and the scanner's existing local cryptographic validator succeeds for
    each resolver's own response material. It never converts fallback failures
    into BROKEN or UNSIGNED because those states require stronger direct/chain
    evidence than an unavailable local port-53 path can provide safely.
    """
    if evidence is None or not evidence.attempted:
        return EncryptedDnssecValidation(
            ENCRYPTED_DNSSEC_UNKNOWN,
            "Encrypted DNSSEC fallback was not attempted.",
        )

    rrsets = _rrsets_by_type(evidence)
    missing_consensus = [
        qtype
        for qtype in ENCRYPTED_DNSSEC_REQUIRED_RRTYPES
        if qtype not in rrsets or rrsets[qtype].status != RRSET_CONSENSUS
    ]
    if missing_consensus:
        return EncryptedDnssecValidation(
            ENCRYPTED_DNSSEC_UNKNOWN,
            "Encrypted DNSSEC fallback lacks two-resolver consensus for: "
            + ", ".join(missing_consensus)
            + ".",
        )

    resolver_names = tuple(name for name, _url in evidence.resolvers)
    if len(resolver_names) < 2:
        return EncryptedDnssecValidation(
            ENCRYPTED_DNSSEC_UNKNOWN,
            "Encrypted DNSSEC fallback requires at least two independent resolvers.",
        )

    results: list[EncryptedDnssecResolverValidation] = []
    for resolver_name in resolver_names:
        resolver_evidence, error = _build_resolver_evidence(evidence, resolver_name)
        if resolver_evidence is None:
            results.append(
                EncryptedDnssecResolverValidation(
                    resolver_name,
                    ENCRYPTED_DNSSEC_UNKNOWN,
                    error or "Encrypted DNSSEC evidence is incomplete.",
                )
            )
            continue

        analysis = analyze_dnssec_evidence(resolver_evidence, now=now)
        results.append(
            EncryptedDnssecResolverValidation(
                resolver_name,
                analysis.state.value,
                analysis.reason,
                analysis=analysis,
                evidence=resolver_evidence,
            )
        )

    secure = [item for item in results if item.status == DnssecState.SECURE.value]
    if len(secure) == len(resolver_names):
        selected = secure[0]
        return EncryptedDnssecValidation(
            ENCRYPTED_DNSSEC_SECURE,
            "Two independent DNS-over-HTTPS resolvers agreed on the required DNSSEC RRsets, "
            "reported authenticated data, and each response path passed local DS-to-DNSKEY "
            "and DNSKEY/SOA/NS signature validation.",
            resolver_results=tuple(results),
            selected_evidence=selected.evidence,
            selected_analysis=selected.analysis,
        )

    states = ", ".join(f"{item.resolver_name}={item.status}" for item in results)
    return EncryptedDnssecValidation(
        ENCRYPTED_DNSSEC_UNKNOWN,
        "Encrypted DNSSEC material was not promoted to a final state because both "
        f"independent resolver paths did not validate securely ({states}).",
        resolver_results=tuple(results),
    )


def encrypted_dnssec_validation_report_data(
    validation: EncryptedDnssecValidation | None,
) -> dict[str, Any]:
    if validation is None:
        return {
            "status": ENCRYPTED_DNSSEC_UNKNOWN,
            "attempted": False,
            "reason": "Encrypted DNSSEC validation was not evaluated.",
            "trust_basis": "two_validating_doh_resolvers_plus_local_crypto",
            "local_cryptographic_validation": True,
            "authenticated_data_required": True,
            "resolvers": [],
        }

    return {
        "status": validation.status,
        "attempted": bool(validation.resolver_results),
        "reason": validation.reason,
        "trust_basis": "two_validating_doh_resolvers_plus_local_crypto",
        "local_cryptographic_validation": True,
        "authenticated_data_required": True,
        "resolvers": [
            {
                "name": item.resolver_name,
                "status": item.status,
                "reason": item.reason,
            }
            for item in validation.resolver_results
        ],
    }


__all__ = [
    "ENCRYPTED_DNSSEC_REQUIRED_RRTYPES",
    "ENCRYPTED_DNSSEC_SECURE",
    "ENCRYPTED_DNSSEC_UNKNOWN",
    "EncryptedDnssecResolverValidation",
    "EncryptedDnssecValidation",
    "encrypted_dnssec_validation_report_data",
    "validate_dnssec_from_encrypted",
]
