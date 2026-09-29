from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ...models import DnsQueryResult, DnsQueryState
from .dnssec import DnssecEvidence


class DnssecDenialMechanism(StrEnum):
    """Observed DNSSEC authenticated-denial mechanism."""

    NSEC = "nsec"
    NSEC3 = "nsec3"
    UNKNOWN = "unknown"


class DnssecDenialPosture(StrEnum):
    """Advisory posture for the observed denial mechanism/parameters."""

    CURRENT = "current"
    ADVISORY = "advisory"
    REVIEW = "review"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Nsec3ParameterSummary:
    """Observed NSEC3 parameters from one bounded negative response."""

    algorithms: tuple[int, ...] = ()
    flags: tuple[int, ...] = ()
    iterations: tuple[int, ...] = ()
    salts: tuple[str, ...] = ()
    opt_out_observed: bool = False
    reserved_flag_values: tuple[int, ...] = ()
    zero_iterations: bool | None = None
    empty_salt: bool | None = None
    chain_parameters_consistent: bool | None = None


@dataclass(frozen=True)
class DnssecDenialAnalysis:
    """Pure issue #17 denial-of-existence posture analysis."""

    mechanism: DnssecDenialMechanism
    posture: DnssecDenialPosture
    reason: str
    observable: bool = False
    nsec_count: int = 0
    nsec3_count: int = 0
    nsec3param_count: int = 0
    nsec3: Nsec3ParameterSummary | None = None
    advisories: tuple[str, ...] = ()


def _section_records(section: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Return (rtype, rdata) rows from stored RRset text."""
    records: list[tuple[str, str]] = []
    for rrset_text in section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            records.append((parts[3].upper(), parts[4].strip()))
    return tuple(records)


def _parse_nsec3_rdata(rdata: str) -> tuple[int, int, int, str] | None:
    parts = str(rdata).split()
    if len(parts) < 5:
        return None
    try:
        algorithm = int(parts[0])
        flags = int(parts[1])
        iterations = int(parts[2])
    except (TypeError, ValueError):
        return None
    if not 0 <= algorithm <= 255 or not 0 <= flags <= 255 or not 0 <= iterations <= 65535:
        return None
    salt = parts[3].upper()
    return algorithm, flags, iterations, salt


def _parse_nsec3param_rdata(rdata: str) -> tuple[int, int, int, str] | None:
    parts = str(rdata).split()
    if len(parts) != 4:
        return None
    try:
        algorithm = int(parts[0])
        flags = int(parts[1])
        iterations = int(parts[2])
    except (TypeError, ValueError):
        return None
    if not 0 <= algorithm <= 255 or not 0 <= flags <= 255 or not 0 <= iterations <= 65535:
        return None
    salt = parts[3].upper()
    return algorithm, flags, iterations, salt


def _nsec3_summary(
    nsec3_records: tuple[tuple[int, int, int, str], ...],
) -> Nsec3ParameterSummary:
    algorithms = tuple(sorted({row[0] for row in nsec3_records}))
    flags = tuple(sorted({row[1] for row in nsec3_records}))
    iterations = tuple(sorted({row[2] for row in nsec3_records}))
    salts = tuple(sorted({row[3] for row in nsec3_records}))
    reserved_flag_values = tuple(sorted({flag for flag in flags if flag & ~0x01}))
    chain_parameters = {(row[0], row[2], row[3]) for row in nsec3_records}
    return Nsec3ParameterSummary(
        algorithms=algorithms,
        flags=flags,
        iterations=iterations,
        salts=salts,
        opt_out_observed=any(flag & 0x01 for flag in flags),
        reserved_flag_values=reserved_flag_values,
        zero_iterations=all(value == 0 for value in iterations) if iterations else None,
        empty_salt=all(value == "-" for value in salts) if salts else None,
        chain_parameters_consistent=(len(chain_parameters) == 1 if chain_parameters else None),
    )


def _unknown(reason: str) -> DnssecDenialAnalysis:
    return DnssecDenialAnalysis(
        mechanism=DnssecDenialMechanism.UNKNOWN,
        posture=DnssecDenialPosture.UNKNOWN,
        reason=reason,
    )


def analyze_dnssec_denial(evidence: DnssecEvidence | None) -> DnssecDenialAnalysis:
    """Analyze one bounded DNSSEC-aware negative response without network I/O.

    RFC 9276 makes NSEC3 iteration and salt guidance operational/advisory. This
    analyzer therefore exposes those parameters without changing DNSSEC chain
    validity or scoring. It also treats unassigned/future NSEC3 hash algorithms
    conservatively instead of calling them insecure solely because they are
    unknown to this scanner version.
    """
    if evidence is None or evidence.denial_probe is None:
        return _unknown("DNSSEC denial-of-existence evidence was not collected.")

    result: DnsQueryResult = evidence.denial_probe.result
    if result.failed:
        return _unknown(
            f"DNSSEC denial-of-existence evidence is unavailable ({result.state.value})."
        )
    if result.aa is not True:
        return _unknown("DNSSEC denial-of-existence response was not authoritative.")
    if result.state not in {
        DnsQueryState.NXDOMAIN,
        DnsQueryState.NO_ANSWER,
        DnsQueryState.ANSWER,
    }:
        return _unknown(
            f"DNSSEC denial-of-existence response is inconclusive ({result.state.value})."
        )

    records = _section_records(result.answer_section) + _section_records(
        result.authority_section
    )
    nsec = tuple(rdata for rtype, rdata in records if rtype == "NSEC")
    raw_nsec3 = tuple(rdata for rtype, rdata in records if rtype == "NSEC3")
    raw_nsec3param = tuple(
        rdata for rtype, rdata in records if rtype == "NSEC3PARAM"
    )
    parsed_nsec3 = tuple(
        parsed
        for parsed in (_parse_nsec3_rdata(value) for value in raw_nsec3)
        if parsed is not None
    )
    parsed_nsec3param = tuple(
        parsed
        for parsed in (_parse_nsec3param_rdata(value) for value in raw_nsec3param)
        if parsed is not None
    )

    if nsec and raw_nsec3:
        return DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.UNKNOWN,
            posture=DnssecDenialPosture.REVIEW,
            reason="The same bounded response exposed both NSEC and NSEC3 denial records.",
            observable=True,
            nsec_count=len(nsec),
            nsec3_count=len(raw_nsec3),
            nsec3param_count=len(raw_nsec3param),
            advisories=("mixed_nsec_nsec3",),
        )

    if nsec:
        return DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.NSEC,
            posture=DnssecDenialPosture.CURRENT,
            reason=(
                "NSEC denial-of-existence records were observed. RFC 9276 prefers NSEC "
                "when NSEC3-specific operational or security properties are not needed."
            ),
            observable=True,
            nsec_count=len(nsec),
            nsec3param_count=len(raw_nsec3param),
        )

    if not raw_nsec3:
        if raw_nsec3param:
            return DnssecDenialAnalysis(
                mechanism=DnssecDenialMechanism.UNKNOWN,
                posture=DnssecDenialPosture.UNKNOWN,
                reason=(
                    "NSEC3PARAM metadata was observable, but the bounded response did not "
                    "contain an NSEC3 denial record."
                ),
                observable=True,
                nsec3param_count=len(raw_nsec3param),
            )
        return _unknown(
            "The bounded DNSSEC-aware response did not expose NSEC or NSEC3 denial records."
        )

    if len(parsed_nsec3) != len(raw_nsec3):
        return DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.NSEC3,
            posture=DnssecDenialPosture.UNKNOWN,
            reason="At least one observed NSEC3 record could not be parsed reliably.",
            observable=True,
            nsec3_count=len(raw_nsec3),
            nsec3param_count=len(raw_nsec3param),
        )

    summary = _nsec3_summary(parsed_nsec3)
    advisories: list[str] = []

    # The current IANA NSEC3 hash registry assigns only algorithm 1 (SHA-1).
    # Unknown future values remain UNKNOWN rather than being treated as unsafe.
    if any(value != 1 for value in summary.algorithms):
        advisories.append("unknown_nsec3_hash_algorithm")
        return DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.NSEC3,
            posture=DnssecDenialPosture.UNKNOWN,
            reason=(
                "The response uses an NSEC3 hash algorithm outside the scanner's current "
                "known registry snapshot; no security conclusion is inferred."
            ),
            observable=True,
            nsec3_count=len(raw_nsec3),
            nsec3param_count=len(raw_nsec3param),
            nsec3=summary,
            advisories=tuple(advisories),
        )

    if summary.reserved_flag_values:
        advisories.append("reserved_nsec3_flags")
    if summary.chain_parameters_consistent is False:
        advisories.append("inconsistent_nsec3_chain_parameters")
    if summary.zero_iterations is False:
        advisories.append("nonzero_iterations")
    if summary.empty_salt is False:
        advisories.append("salt_present")
    if summary.opt_out_observed:
        advisories.append("opt_out_observed")

    if "reserved_nsec3_flags" in advisories or "inconsistent_nsec3_chain_parameters" in advisories:
        posture = DnssecDenialPosture.REVIEW
        reason = "Observed NSEC3 proof records contain inconsistent parameters or reserved flag bits."
    elif advisories:
        posture = DnssecDenialPosture.ADVISORY
        reason = (
            "NSEC3 is in use with parameters that differ from RFC 9276's baseline guidance "
            "of zero extra iterations and an empty salt, or Opt-Out was observed."
        )
    else:
        posture = DnssecDenialPosture.CURRENT
        reason = (
            "NSEC3 is in use with SHA-1, zero extra iterations, an empty salt, and no "
            "Opt-Out flag in the bounded proof, matching RFC 9276 baseline parameters."
        )

    # NSEC3PARAM is only supplemental publisher metadata. If present and
    # parseable, mismatches are surfaced as review evidence but do not replace
    # the parameters actually observed on the NSEC3 proof records.
    if raw_nsec3param:
        if len(parsed_nsec3param) != len(raw_nsec3param):
            advisories.append("unparseable_nsec3param")
            posture = DnssecDenialPosture.REVIEW
        else:
            proof_chain = {(row[0], row[2], row[3]) for row in parsed_nsec3}
            param_chain = {(row[0], row[2], row[3]) for row in parsed_nsec3param}
            if not param_chain.issubset(proof_chain):
                advisories.append("nsec3param_mismatch")
                posture = DnssecDenialPosture.REVIEW

    return DnssecDenialAnalysis(
        mechanism=DnssecDenialMechanism.NSEC3,
        posture=posture,
        reason=reason,
        observable=True,
        nsec3_count=len(raw_nsec3),
        nsec3param_count=len(raw_nsec3param),
        nsec3=summary,
        advisories=tuple(advisories),
    )


__all__ = [
    "DnssecDenialAnalysis",
    "DnssecDenialMechanism",
    "DnssecDenialPosture",
    "Nsec3ParameterSummary",
    "analyze_dnssec_denial",
]
