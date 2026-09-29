from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


DNSSEC_POLICY_SNAPSHOT_VERSION = "2026-08-10-iana-dnssec-policy"
DNSSEC_ALGORITHM_REGISTRY_UPDATED = "2026-08-10"
DNSSEC_DS_DIGEST_REGISTRY_UPDATED = "2026-01-13"


class DnssecRequirement(StrEnum):
    """One recommendation value copied from the versioned IANA snapshot."""

    MUST = "must"
    RECOMMENDED = "recommended"
    MAY = "may"
    NOT_RECOMMENDED = "not_recommended"
    MUST_NOT = "must_not"
    UNKNOWN = "unknown"


class DnssecPolicyPosture(StrEnum):
    """Operator-facing posture derived from an IANA usage recommendation."""

    RECOMMENDED = "recommended"
    PERMITTED = "permitted"
    NOT_RECOMMENDED = "not_recommended"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


def requirement_posture(requirement: DnssecRequirement) -> DnssecPolicyPosture:
    """Map a registry requirement to the scanner's stable posture vocabulary."""
    if requirement in {DnssecRequirement.MUST, DnssecRequirement.RECOMMENDED}:
        return DnssecPolicyPosture.RECOMMENDED
    if requirement == DnssecRequirement.MAY:
        return DnssecPolicyPosture.PERMITTED
    if requirement == DnssecRequirement.NOT_RECOMMENDED:
        return DnssecPolicyPosture.NOT_RECOMMENDED
    if requirement == DnssecRequirement.MUST_NOT:
        return DnssecPolicyPosture.PROHIBITED
    return DnssecPolicyPosture.UNKNOWN


def posture_allows_use(posture: DnssecPolicyPosture) -> bool | None:
    """Return True/False for known policy, None for an unknown future value."""
    if posture == DnssecPolicyPosture.PROHIBITED:
        return False
    if posture == DnssecPolicyPosture.UNKNOWN:
        return None
    return True


@dataclass(frozen=True)
class DnssecAlgorithmPolicy:
    """Frozen IANA DNS Security Algorithm Numbers recommendation row."""

    number: int
    description: str
    mnemonic: str
    use_for_signing: DnssecRequirement
    use_for_validation: DnssecRequirement
    implement_for_signing: DnssecRequirement
    implement_for_validation: DnssecRequirement
    sha1_based: bool = False
    retired: bool = False
    private_use: bool = False

    @property
    def signing_posture(self) -> DnssecPolicyPosture:
        return requirement_posture(self.use_for_signing)

    @property
    def validation_posture(self) -> DnssecPolicyPosture:
        return requirement_posture(self.use_for_validation)


@dataclass(frozen=True)
class DnssecDigestPolicy:
    """Frozen IANA Delegation Signer Digest Algorithms recommendation row."""

    number: int
    description: str
    use_for_delegation: DnssecRequirement
    use_for_validation: DnssecRequirement
    implement_for_delegation: DnssecRequirement
    implement_for_validation: DnssecRequirement
    sha1_based: bool = False
    retired: bool = False
    private_use: bool = False

    @property
    def delegation_posture(self) -> DnssecPolicyPosture:
        return requirement_posture(self.use_for_delegation)

    @property
    def validation_posture(self) -> DnssecPolicyPosture:
        return requirement_posture(self.use_for_validation)


@dataclass(frozen=True)
class DnssecPolicySnapshot:
    """Versioned, offline DNSSEC algorithm-policy snapshot used by the scanner."""

    version: str
    algorithm_registry_updated: str
    digest_registry_updated: str
    algorithms: Mapping[int, DnssecAlgorithmPolicy]
    digests: Mapping[int, DnssecDigestPolicy]


MUST = DnssecRequirement.MUST
RECOMMENDED = DnssecRequirement.RECOMMENDED
MAY = DnssecRequirement.MAY
NOT_RECOMMENDED = DnssecRequirement.NOT_RECOMMENDED
MUST_NOT = DnssecRequirement.MUST_NOT


# Snapshot of the IANA DNS Security Algorithm Numbers registry as updated
# 2026-08-10. Only rows with explicit DNSSEC policy columns are materialized;
# unassigned/reserved/blank rows intentionally resolve as UNKNOWN.
_ALGORITHM_ROWS = (
    DnssecAlgorithmPolicy(1, "RSA/MD5 (DEPRECATED, see 5)", "RSAMD5", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT, retired=True),
    DnssecAlgorithmPolicy(3, "DSA/SHA1", "DSA", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT, sha1_based=True),
    DnssecAlgorithmPolicy(5, "RSA/SHA-1", "RSASHA1", MUST_NOT, RECOMMENDED, NOT_RECOMMENDED, MUST, sha1_based=True),
    DnssecAlgorithmPolicy(6, "DSA-NSEC3-SHA1", "DSA-NSEC3-SHA1", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT, sha1_based=True),
    DnssecAlgorithmPolicy(7, "RSASHA1-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1", MUST_NOT, RECOMMENDED, NOT_RECOMMENDED, MUST, sha1_based=True),
    DnssecAlgorithmPolicy(8, "RSA/SHA-256", "RSASHA256", RECOMMENDED, RECOMMENDED, MUST, MUST),
    DnssecAlgorithmPolicy(10, "RSA/SHA-512", "RSASHA512", NOT_RECOMMENDED, RECOMMENDED, NOT_RECOMMENDED, MUST),
    DnssecAlgorithmPolicy(12, "GOST R 34.10-2001 (DEPRECATED)", "ECC-GOST", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT, retired=True),
    DnssecAlgorithmPolicy(13, "ECDSA Curve P-256 with SHA-256", "ECDSAP256SHA256", RECOMMENDED, RECOMMENDED, MUST, MUST),
    DnssecAlgorithmPolicy(14, "ECDSA Curve P-384 with SHA-384", "ECDSAP384SHA384", MAY, RECOMMENDED, MAY, RECOMMENDED),
    DnssecAlgorithmPolicy(15, "Ed25519", "ED25519", RECOMMENDED, RECOMMENDED, RECOMMENDED, RECOMMENDED),
    DnssecAlgorithmPolicy(16, "Ed448", "ED448", MAY, RECOMMENDED, MAY, RECOMMENDED),
    DnssecAlgorithmPolicy(17, "SM2 signing algorithm with SM3 hashing algorithm", "SM2SM3", MAY, MAY, MAY, MAY),
    DnssecAlgorithmPolicy(18, "ML-DSA-44", "MLDSA44", MAY, MAY, MAY, MAY),
    DnssecAlgorithmPolicy(23, "GOST R 34.10-2012", "ECC-GOST12", MAY, MAY, MAY, MAY),
    DnssecAlgorithmPolicy(253, "private algorithm", "PRIVATEDNS", MAY, MAY, MAY, MAY, private_use=True),
    DnssecAlgorithmPolicy(254, "private algorithm OID", "PRIVATEOID", MAY, MAY, MAY, MAY, private_use=True),
)


# Snapshot of the IANA DS Digest Algorithms registry as updated 2026-01-13.
# Unassigned/reserved/private-use ranges without explicit recommendation columns
# intentionally resolve as UNKNOWN.
_DIGEST_ROWS = (
    DnssecDigestPolicy(0, "Reserved", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT),
    DnssecDigestPolicy(1, "SHA-1", MUST_NOT, RECOMMENDED, MUST_NOT, MUST, sha1_based=True),
    DnssecDigestPolicy(2, "SHA-256", RECOMMENDED, RECOMMENDED, MUST, MUST),
    DnssecDigestPolicy(3, "GOST R 34.11-94 (DEPRECATED)", MUST_NOT, MUST_NOT, MUST_NOT, MUST_NOT, retired=True),
    DnssecDigestPolicy(4, "SHA-384", MAY, RECOMMENDED, MAY, RECOMMENDED),
    DnssecDigestPolicy(5, "GOST R 34.11-2012", MAY, MAY, MAY, MAY),
    DnssecDigestPolicy(6, "SM3", MAY, MAY, MAY, MAY),
)


DNSSEC_ALGORITHM_POLICY: Mapping[int, DnssecAlgorithmPolicy] = MappingProxyType(
    {entry.number: entry for entry in _ALGORITHM_ROWS}
)
DNSSEC_DIGEST_POLICY: Mapping[int, DnssecDigestPolicy] = MappingProxyType(
    {entry.number: entry for entry in _DIGEST_ROWS}
)

DNSSEC_POLICY_SNAPSHOT = DnssecPolicySnapshot(
    version=DNSSEC_POLICY_SNAPSHOT_VERSION,
    algorithm_registry_updated=DNSSEC_ALGORITHM_REGISTRY_UPDATED,
    digest_registry_updated=DNSSEC_DS_DIGEST_REGISTRY_UPDATED,
    algorithms=DNSSEC_ALGORITHM_POLICY,
    digests=DNSSEC_DIGEST_POLICY,
)


def dnssec_algorithm_policy(number: int) -> DnssecAlgorithmPolicy | None:
    """Return a known snapshot row, or None for unassigned/future algorithms."""
    return DNSSEC_ALGORITHM_POLICY.get(int(number))


def dnssec_digest_policy(number: int) -> DnssecDigestPolicy | None:
    """Return a known snapshot row, or None for unassigned/future digests."""
    return DNSSEC_DIGEST_POLICY.get(int(number))


def dnssec_algorithm_signing_posture(number: int) -> DnssecPolicyPosture:
    entry = dnssec_algorithm_policy(number)
    return entry.signing_posture if entry is not None else DnssecPolicyPosture.UNKNOWN


def dnssec_algorithm_validation_posture(number: int) -> DnssecPolicyPosture:
    entry = dnssec_algorithm_policy(number)
    return entry.validation_posture if entry is not None else DnssecPolicyPosture.UNKNOWN


def dnssec_digest_delegation_posture(number: int) -> DnssecPolicyPosture:
    entry = dnssec_digest_policy(number)
    return entry.delegation_posture if entry is not None else DnssecPolicyPosture.UNKNOWN


def dnssec_digest_validation_posture(number: int) -> DnssecPolicyPosture:
    entry = dnssec_digest_policy(number)
    return entry.validation_posture if entry is not None else DnssecPolicyPosture.UNKNOWN


__all__ = [
    "DNSSEC_ALGORITHM_POLICY",
    "DNSSEC_ALGORITHM_REGISTRY_UPDATED",
    "DNSSEC_DIGEST_POLICY",
    "DNSSEC_DS_DIGEST_REGISTRY_UPDATED",
    "DNSSEC_POLICY_SNAPSHOT",
    "DNSSEC_POLICY_SNAPSHOT_VERSION",
    "DnssecAlgorithmPolicy",
    "DnssecDigestPolicy",
    "DnssecPolicyPosture",
    "DnssecPolicySnapshot",
    "DnssecRequirement",
    "dnssec_algorithm_policy",
    "dnssec_algorithm_signing_posture",
    "dnssec_algorithm_validation_posture",
    "dnssec_digest_delegation_posture",
    "dnssec_digest_policy",
    "dnssec_digest_validation_posture",
    "posture_allows_use",
    "requirement_posture",
]
