from __future__ import annotations

from dataclasses import dataclass

from .dnssec import DnssecEvidence
from .dnssec_policy import (
    DNSSEC_POLICY_SNAPSHOT,
    DnssecAlgorithmPolicy,
    DnssecDigestPolicy,
    DnssecPolicyPosture,
    dnssec_algorithm_policy,
    dnssec_digest_policy,
)


_POSTURE_RANK = {
    DnssecPolicyPosture.RECOMMENDED: 0,
    DnssecPolicyPosture.PERMITTED: 1,
    DnssecPolicyPosture.UNKNOWN: 2,
    DnssecPolicyPosture.NOT_RECOMMENDED: 3,
    DnssecPolicyPosture.PROHIBITED: 4,
}


@dataclass(frozen=True)
class DnssecAlgorithmObservation:
    """Observed DNSSEC algorithm with current signing/validation posture."""

    number: int
    source: str
    description: str | None
    mnemonic: str | None
    signing_posture: DnssecPolicyPosture
    validation_posture: DnssecPolicyPosture
    use_for_signing: str | None = None
    use_for_validation: str | None = None
    sha1_based: bool = False
    retired: bool = False
    private_use: bool = False


@dataclass(frozen=True)
class DnssecDigestObservation:
    """Observed DS digest with current delegation/validation posture."""

    number: int
    description: str | None
    delegation_posture: DnssecPolicyPosture
    validation_posture: DnssecPolicyPosture
    use_for_delegation: str | None = None
    use_for_validation: str | None = None
    sha1_based: bool = False
    retired: bool = False
    private_use: bool = False


@dataclass(frozen=True)
class DnssecAlgorithmPostureAnalysis:
    """Pure issue #17 algorithm/digest posture derived from existing evidence."""

    posture: DnssecPolicyPosture
    reason: str
    snapshot_version: str = DNSSEC_POLICY_SNAPSHOT.version
    algorithm_registry_updated: str = DNSSEC_POLICY_SNAPSHOT.algorithm_registry_updated
    digest_registry_updated: str = DNSSEC_POLICY_SNAPSHOT.digest_registry_updated
    dnskey_algorithms: tuple[DnssecAlgorithmObservation, ...] = ()
    ds_algorithms: tuple[DnssecAlgorithmObservation, ...] = ()
    ds_digests: tuple[DnssecDigestObservation, ...] = ()
    sha1_signing_algorithms: tuple[int, ...] = ()
    sha1_delegation_digests: tuple[int, ...] = ()
    retired_algorithms: tuple[int, ...] = ()
    retired_digests: tuple[int, ...] = ()

    @property
    def observable(self) -> bool:
        return bool(self.dnskey_algorithms or self.ds_algorithms or self.ds_digests)


def _rdata_values(section: tuple[str, ...], rdtype: str) -> tuple[str, ...]:
    target = rdtype.upper()
    values: list[str] = []
    for rrset_text in section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[3].upper() == target:
                values.append(parts[4].strip())
    return tuple(values)


def _dnskey_algorithms(evidence: DnssecEvidence) -> tuple[int, ...]:
    if evidence.selected_dnskey is None:
        return ()
    result = evidence.selected_dnskey.result
    algorithms: set[int] = set()
    for rdata in _rdata_values(result.answer_section, "DNSKEY"):
        parts = rdata.split()
        if len(parts) < 4:
            continue
        try:
            number = int(parts[2])
        except (TypeError, ValueError):
            continue
        if 0 <= number <= 255:
            algorithms.add(number)
    return tuple(sorted(algorithms))


def _ds_rows(evidence: DnssecEvidence) -> tuple[tuple[int, int], ...]:
    if evidence.parent_ds is None:
        return ()
    result = evidence.parent_ds.result
    rows: set[tuple[int, int]] = set()
    for rdata in _rdata_values(result.answer_section, "DS"):
        parts = rdata.split()
        if len(parts) < 4:
            continue
        try:
            algorithm = int(parts[1])
            digest = int(parts[2])
        except (TypeError, ValueError):
            continue
        if 0 <= algorithm <= 255 and 0 <= digest <= 255:
            rows.add((algorithm, digest))
    return tuple(sorted(rows))


def _algorithm_observation(number: int, source: str) -> DnssecAlgorithmObservation:
    entry: DnssecAlgorithmPolicy | None = dnssec_algorithm_policy(number)
    if entry is None:
        return DnssecAlgorithmObservation(
            number=number,
            source=source,
            description=None,
            mnemonic=None,
            signing_posture=DnssecPolicyPosture.UNKNOWN,
            validation_posture=DnssecPolicyPosture.UNKNOWN,
        )
    return DnssecAlgorithmObservation(
        number=number,
        source=source,
        description=entry.description,
        mnemonic=entry.mnemonic,
        signing_posture=entry.signing_posture,
        validation_posture=entry.validation_posture,
        use_for_signing=entry.use_for_signing.value,
        use_for_validation=entry.use_for_validation.value,
        sha1_based=entry.sha1_based,
        retired=entry.retired,
        private_use=entry.private_use,
    )


def _digest_observation(number: int) -> DnssecDigestObservation:
    entry: DnssecDigestPolicy | None = dnssec_digest_policy(number)
    if entry is None:
        return DnssecDigestObservation(
            number=number,
            description=None,
            delegation_posture=DnssecPolicyPosture.UNKNOWN,
            validation_posture=DnssecPolicyPosture.UNKNOWN,
        )
    return DnssecDigestObservation(
        number=number,
        description=entry.description,
        delegation_posture=entry.delegation_posture,
        validation_posture=entry.validation_posture,
        use_for_delegation=entry.use_for_delegation.value,
        use_for_validation=entry.use_for_validation.value,
        sha1_based=entry.sha1_based,
        retired=entry.retired,
        private_use=entry.private_use,
    )


def _aggregate_posture(
    algorithms: tuple[DnssecAlgorithmObservation, ...],
    digests: tuple[DnssecDigestObservation, ...],
) -> DnssecPolicyPosture:
    postures = [item.signing_posture for item in algorithms]
    postures.extend(item.delegation_posture for item in digests)
    if not postures:
        return DnssecPolicyPosture.UNKNOWN
    return max(postures, key=_POSTURE_RANK.__getitem__)


def _reason(posture: DnssecPolicyPosture, *, observable: bool) -> str:
    if not observable:
        return "No parseable DNSKEY/DS algorithm material was available for posture analysis."
    if posture == DnssecPolicyPosture.PROHIBITED:
        return (
            "At least one observed signing algorithm or DS digest is prohibited "
            "for new DNSSEC use by the current policy snapshot."
        )
    if posture == DnssecPolicyPosture.NOT_RECOMMENDED:
        return (
            "At least one observed signing algorithm is permitted for validation "
            "but is not recommended for current DNSSEC signing."
        )
    if posture == DnssecPolicyPosture.UNKNOWN:
        return (
            "At least one observed algorithm or digest is not recognized by the "
            "current policy snapshot; no insecure conclusion is inferred."
        )
    if posture == DnssecPolicyPosture.PERMITTED:
        return (
            "Observed DNSSEC material is permitted by the current policy snapshot "
            "but is not uniformly in the recommended set."
        )
    return "Observed DNSSEC signing algorithms and DS digests are in the current recommended set."


def analyze_dnssec_algorithm_posture(
    evidence: DnssecEvidence | None,
) -> DnssecAlgorithmPostureAnalysis:
    """Evaluate observed DNSKEY/DS policy without performing network I/O.

    Signing/delegation posture is intentionally separate from validation support.
    For example, current policy prohibits RSASHA1 for new signing while still
    recommending validator support. Unknown future registry values remain UNKNOWN.
    """
    if evidence is None:
        return DnssecAlgorithmPostureAnalysis(
            posture=DnssecPolicyPosture.UNKNOWN,
            reason="DNSSEC evidence was not collected.",
        )

    dnskey_numbers = _dnskey_algorithms(evidence)
    ds_rows = _ds_rows(evidence)
    ds_algorithm_numbers = tuple(sorted({row[0] for row in ds_rows}))
    digest_numbers = tuple(sorted({row[1] for row in ds_rows}))

    dnskey_algorithms = tuple(
        _algorithm_observation(number, "dnskey") for number in dnskey_numbers
    )
    ds_algorithms = tuple(
        _algorithm_observation(number, "ds") for number in ds_algorithm_numbers
    )
    ds_digests = tuple(_digest_observation(number) for number in digest_numbers)

    # Operator posture is driven by actual child signing material plus DS digest
    # choice. DS algorithm numbers are retained as supporting delegation evidence,
    # but they do not duplicate the child signing algorithms in aggregation.
    posture = _aggregate_posture(dnskey_algorithms, ds_digests)
    observable = bool(dnskey_algorithms or ds_algorithms or ds_digests)

    return DnssecAlgorithmPostureAnalysis(
        posture=posture,
        reason=_reason(posture, observable=observable),
        dnskey_algorithms=dnskey_algorithms,
        ds_algorithms=ds_algorithms,
        ds_digests=ds_digests,
        sha1_signing_algorithms=tuple(
            sorted({item.number for item in dnskey_algorithms if item.sha1_based})
        ),
        sha1_delegation_digests=tuple(
            sorted({item.number for item in ds_digests if item.sha1_based})
        ),
        retired_algorithms=tuple(
            sorted(
                {
                    item.number
                    for item in (*dnskey_algorithms, *ds_algorithms)
                    if item.retired
                }
            )
        ),
        retired_digests=tuple(
            sorted({item.number for item in ds_digests if item.retired})
        ),
    )


__all__ = [
    "DnssecAlgorithmObservation",
    "DnssecAlgorithmPostureAnalysis",
    "DnssecDigestObservation",
    "analyze_dnssec_algorithm_posture",
]
