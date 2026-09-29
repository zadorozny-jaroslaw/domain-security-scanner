from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

import dns.dnssec
import dns.exception
import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rrset

from ...models import DnsQueryResult, DnsQueryState
from .dnssec import DnssecEvidence, DnssecQueryEvidence


DNSSEC_POLICY_VERSION = "2025-11-rfc9904-rfc9905-rfc9906"

# RFC 9904 moved the canonical recommendation status to the IANA registries.
# RFC 9905 subsequently requires RSASHA1 algorithms 5/7 to be treated as
# unsupported by validating resolvers, while RFC 9906 does the same for
# ECC-GOST algorithm 12 and GOST DS digest 3. Algorithms not denied here are
# still subject to local dnspython/cryptography support at validation time.
_DNSSEC_DENY_VALIDATE_ALGORITHMS = frozenset({1, 3, 5, 6, 7, 12})
_DNSSEC_DENY_VALIDATE_DS_DIGESTS = frozenset({0, 3})


class DnssecValidationPolicy(dns.dnssec.Policy):
    """Versioned DNSSEC validation policy snapshot used by issue #16."""

    def ok_to_sign(self, key) -> bool:
        return int(key.algorithm) not in _DNSSEC_DENY_VALIDATE_ALGORITHMS

    def ok_to_validate(self, key) -> bool:
        return int(key.algorithm) not in _DNSSEC_DENY_VALIDATE_ALGORITHMS

    def ok_to_create_ds(self, algorithm) -> bool:
        return int(algorithm) not in _DNSSEC_DENY_VALIDATE_DS_DIGESTS

    def ok_to_validate_ds(self, algorithm) -> bool:
        return int(algorithm) not in _DNSSEC_DENY_VALIDATE_DS_DIGESTS


DNSSEC_VALIDATION_POLICY = DnssecValidationPolicy()


class DnssecState(StrEnum):
    """Explicit issue #16 DNSSEC result states."""

    UNSIGNED = "unsigned"
    SECURE = "secure"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class DnssecStepOutcome(StrEnum):
    """Outcome of one bounded DNSSEC analysis step."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class DnssecSignatureSummary:
    """Signature-window and cryptographic observations for one RRset."""

    total: int = 0
    current: int = 0
    expired: int = 0
    not_yet_valid: int = 0
    valid: int = 0
    invalid: int = 0
    unsupported: int = 0


@dataclass(frozen=True)
class DnssecValidationStep:
    """Structured result for one DNSSEC validation capability."""

    name: str
    outcome: DnssecStepOutcome
    message: str
    signatures: DnssecSignatureSummary | None = None


@dataclass(frozen=True)
class DnssecAnalysis:
    """Pure analysis result consumed later by findings/report integration."""

    state: DnssecState
    reason: str
    policy_version: str = DNSSEC_POLICY_VERSION
    ds_count: int = 0
    dnskey_count: int = 0
    matched_key_tags: tuple[int, ...] = ()
    steps: tuple[DnssecValidationStep, ...] = ()


@dataclass(frozen=True)
class _DsMatchResult:
    step: DnssecValidationStep
    matched_keys: tuple[object, ...] = ()
    matched_key_tags: tuple[int, ...] = ()


def _parse_rrset_text(rrset_text: str) -> dns.rrset.RRset:
    """Rebuild one RRset from the evidence layer's stable text representation."""
    rows = []
    owner = ttl = rdclass = rdtype = None

    for line in str(rrset_text).splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) != 5:
            raise ValueError("Malformed DNS RRset text")
        row_owner, row_ttl, row_class, row_type, rdata = parts
        identity = (
            row_owner,
            int(row_ttl),
            row_class.upper(),
            row_type.upper(),
        )
        if owner is None:
            owner, ttl, rdclass, rdtype = identity
        elif identity != (owner, ttl, rdclass, rdtype):
            raise ValueError("Mixed DNS RRsets in one evidence entry")
        rows.append(rdata)

    if owner is None or not rows:
        raise ValueError("Empty DNS RRset text")

    return dns.rrset.from_text(owner, ttl, rdclass, rdtype, *rows)


def _answer_rrsets(result: DnsQueryResult) -> tuple[dns.rrset.RRset, ...]:
    return tuple(_parse_rrset_text(text) for text in result.answer_section)


def _find_rrset(
    rrsets: tuple[dns.rrset.RRset, ...],
    rdtype: str,
) -> dns.rrset.RRset | None:
    target = dns.rdatatype.from_text(rdtype)
    return next((rrset for rrset in rrsets if rrset.rdtype == target), None)


def _rrsig_for_type(
    rrsets: tuple[dns.rrset.RRset, ...],
    covered_type: str,
) -> dns.rrset.RRset | None:
    target = dns.rdatatype.from_text(covered_type)
    source = _find_rrset(rrsets, "RRSIG")
    if source is None:
        return None

    filtered = dns.rrset.RRset(source.name, source.rdclass, source.rdtype)
    filtered.ttl = source.ttl
    for signature in source:
        if signature.type_covered == target:
            filtered.add(signature, source.ttl)
    return filtered if len(filtered) else None


def _key_rdataset(keys: tuple[object, ...], template: dns.rrset.RRset):
    rdataset = dns.rdataset.Rdataset(template.rdclass, template.rdtype)
    for key in keys:
        rdataset.add(key, template.ttl)
    return rdataset


def _query_result(evidence: DnssecQueryEvidence | None) -> DnsQueryResult | None:
    return evidence.result if evidence is not None else None


def _query_unavailable_step(name: str, result: DnsQueryResult | None) -> DnssecValidationStep:
    if result is None:
        message = "Required DNS evidence was not collected."
    else:
        message = f"Required DNS evidence is unavailable ({result.state.value})."
    return DnssecValidationStep(name, DnssecStepOutcome.UNKNOWN, message)


def _validate_signature_set(
    *,
    name: str,
    rrset: dns.rrset.RRset,
    rrsigset: dns.rrset.RRset | None,
    trusted_keys: tuple[object, ...],
    key_template: dns.rrset.RRset,
    now: float,
    policy: DnssecValidationPolicy,
) -> DnssecValidationStep:
    """Validate one RRset while preserving time/unsupported distinctions."""
    if rrsigset is None or not len(rrsigset):
        return DnssecValidationStep(
            name,
            DnssecStepOutcome.FAIL,
            f"{name} has no RRSIG evidence.",
            DnssecSignatureSummary(),
        )

    trusted_rdataset = _key_rdataset(trusted_keys, key_template)
    keys = {rrset.name: trusted_rdataset}

    current = expired = not_yet_valid = valid = invalid = unsupported = 0
    signatures = tuple(rrsigset)

    for signature in signatures:
        if signature.expiration < now:
            expired += 1
            continue
        if signature.inception > now:
            not_yet_valid += 1
            continue
        current += 1

        candidate_keys = tuple(
            key
            for key in trusted_keys
            if int(key.algorithm) == int(signature.algorithm)
            and dns.dnssec.key_id(key) == signature.key_tag
        )
        if not candidate_keys:
            invalid += 1
            continue

        if not any(policy.ok_to_validate(key) for key in candidate_keys):
            unsupported += 1
            continue

        try:
            dns.dnssec.validate_rrsig(
                rrset,
                signature,
                keys,
                now=now,
                policy=policy,
            )
        except dns.exception.UnsupportedAlgorithm:
            unsupported += 1
        except dns.dnssec.ValidationFailure:
            invalid += 1
        else:
            valid += 1

    summary = DnssecSignatureSummary(
        total=len(signatures),
        current=current,
        expired=expired,
        not_yet_valid=not_yet_valid,
        valid=valid,
        invalid=invalid,
        unsupported=unsupported,
    )

    if valid:
        notes = []
        if expired:
            notes.append(f"{expired} expired")
        if not_yet_valid:
            notes.append(f"{not_yet_valid} not-yet-valid")
        if invalid:
            notes.append(f"{invalid} invalid")
        if unsupported:
            notes.append(f"{unsupported} unsupported")
        suffix = f" Other signatures: {', '.join(notes)}." if notes else ""
        return DnssecValidationStep(
            name,
            DnssecStepOutcome.PASS,
            f"{name} has a valid current DNSSEC signature.{suffix}",
            summary,
        )

    if unsupported:
        return DnssecValidationStep(
            name,
            DnssecStepOutcome.UNKNOWN,
            f"{name} could not be fully validated because a relevant algorithm is unsupported.",
            summary,
        )

    if current == 0 and expired and not_yet_valid:
        message = f"{name} has only expired or not-yet-valid signatures."
    elif current == 0 and expired:
        message = f"{name} has only expired signatures."
    elif current == 0 and not_yet_valid:
        message = f"{name} has only not-yet-valid signatures."
    else:
        message = f"{name} signatures did not validate with authenticated DNSKEY material."

    return DnssecValidationStep(
        name,
        DnssecStepOutcome.FAIL,
        message,
        summary,
    )


def _match_ds_to_dnskeys(
    zone: str,
    ds_rrset: dns.rrset.RRset,
    dnskey_rrset: dns.rrset.RRset,
    *,
    policy: DnssecValidationPolicy,
) -> _DsMatchResult:
    matched_keys = []
    indeterminate = 0

    for ds_record in ds_rrset:
        if int(ds_record.algorithm) in _DNSSEC_DENY_VALIDATE_ALGORITHMS:
            indeterminate += 1
            continue

        candidates = tuple(
            key
            for key in dnskey_rrset
            if int(key.algorithm) == int(ds_record.algorithm)
            and dns.dnssec.key_id(key) == ds_record.key_tag
        )
        if not candidates:
            continue

        try:
            if not policy.ok_to_validate_ds(ds_record.digest_type):
                indeterminate += 1
                continue
        except (TypeError, ValueError):
            indeterminate += 1
            continue

        evaluated = False
        for key in candidates:
            if not policy.ok_to_validate(key):
                indeterminate += 1
                continue
            try:
                zone_name = dns.name.from_text(
                    zone if str(zone).endswith(".") else f"{zone}."
                )
                generated = dns.dnssec.make_ds(
                    zone_name,
                    key,
                    ds_record.digest_type,
                    policy=policy,
                    validating=True,
                )
            except (dns.exception.UnsupportedAlgorithm, ValueError, TypeError):
                indeterminate += 1
                continue
            evaluated = True
            if generated == ds_record:
                matched_keys.append(key)

        # A digest-capable comparison was possible and simply did not match;
        # that is conclusive mismatch evidence, so no extra marker is needed.
        _ = evaluated

    unique = {}
    for key in matched_keys:
        unique[(int(key.algorithm), dns.dnssec.key_id(key), key.to_text())] = key
    matched = tuple(unique.values())
    tags = tuple(sorted({dns.dnssec.key_id(key) for key in matched}))

    if matched:
        return _DsMatchResult(
            DnssecValidationStep(
                "DS to DNSKEY",
                DnssecStepOutcome.PASS,
                f"At least one parent DS record matches child DNSKEY material (key tags: {', '.join(map(str, tags))}).",
            ),
            matched,
            tags,
        )

    if indeterminate:
        return _DsMatchResult(
            DnssecValidationStep(
                "DS to DNSKEY",
                DnssecStepOutcome.UNKNOWN,
                "No supported DS-to-DNSKEY match was proven; at least one candidate uses an unsupported validation algorithm or digest.",
            )
        )

    return _DsMatchResult(
        DnssecValidationStep(
            "DS to DNSKEY",
            DnssecStepOutcome.FAIL,
            "Parent DS records do not match any child DNSKEY record.",
        )
    )


def _analysis(
    state: DnssecState,
    reason: str,
    *,
    ds_count: int = 0,
    dnskey_count: int = 0,
    matched_key_tags: tuple[int, ...] = (),
    steps: list[DnssecValidationStep] | tuple[DnssecValidationStep, ...] = (),
) -> DnssecAnalysis:
    return DnssecAnalysis(
        state=state,
        reason=reason,
        ds_count=ds_count,
        dnskey_count=dnskey_count,
        matched_key_tags=matched_key_tags,
        steps=tuple(steps),
    )


def analyze_dnssec_evidence(
    evidence: DnssecEvidence,
    *,
    now: float | None = None,
    policy: DnssecValidationPolicy = DNSSEC_VALIDATION_POLICY,
) -> DnssecAnalysis:
    """Classify bounded DNSSEC evidence as unsigned/secure/broken/unknown.

    The analyzer performs no network I/O. It authenticates the child DNSKEY
    RRset from parent DS material, then uses the authenticated DNSKEY RRset to
    validate the deterministic apex RRsets collected by ``dnssec.py``.
    """
    validation_time = time.time() if now is None else float(now)
    steps: list[DnssecValidationStep] = []

    parent_result = _query_result(evidence.parent_ds)
    if parent_result is None or parent_result.failed:
        step = _query_unavailable_step("Parent DS", parent_result)
        steps.append(step)
        return _analysis(
            DnssecState.UNKNOWN,
            step.message,
            steps=steps,
        )

    if parent_result.state == DnsQueryState.NO_ANSWER:
        step = DnssecValidationStep(
            "Parent DS",
            DnssecStepOutcome.NOT_APPLICABLE,
            "Parent delegation contains no DS RRset.",
        )
        steps.append(step)
        return _analysis(
            DnssecState.UNSIGNED,
            "No DS record exists at the parent delegation.",
            steps=steps,
        )

    if parent_result.state != DnsQueryState.ANSWER:
        step = DnssecValidationStep(
            "Parent DS",
            DnssecStepOutcome.UNKNOWN,
            f"Parent DS evidence is inconclusive ({parent_result.state.value}).",
        )
        steps.append(step)
        return _analysis(DnssecState.UNKNOWN, step.message, steps=steps)

    try:
        parent_rrsets = _answer_rrsets(parent_result)
        ds_rrset = _find_rrset(parent_rrsets, "DS")
    except (ValueError, dns.exception.DNSException) as exc:
        step = DnssecValidationStep(
            "Parent DS",
            DnssecStepOutcome.UNKNOWN,
            f"Parent DS evidence could not be parsed: {exc}",
        )
        steps.append(step)
        return _analysis(DnssecState.UNKNOWN, step.message, steps=steps)

    if ds_rrset is None or not len(ds_rrset):
        step = DnssecValidationStep(
            "Parent DS",
            DnssecStepOutcome.UNKNOWN,
            "Parent returned an answer but no parseable DS RRset was present.",
        )
        steps.append(step)
        return _analysis(DnssecState.UNKNOWN, step.message, steps=steps)

    ds_count = len(ds_rrset)
    steps.append(
        DnssecValidationStep(
            "Parent DS",
            DnssecStepOutcome.PASS,
            f"Collected {ds_count} parent DS record(s).",
        )
    )

    dnskey_result = _query_result(evidence.selected_dnskey)
    if dnskey_result is None or dnskey_result.failed:
        step = _query_unavailable_step("Child DNSKEY", dnskey_result)
        steps.append(step)
        return _analysis(
            DnssecState.UNKNOWN,
            step.message,
            ds_count=ds_count,
            steps=steps,
        )

    if dnskey_result.state in {DnsQueryState.NO_ANSWER, DnsQueryState.NXDOMAIN}:
        step = DnssecValidationStep(
            "Child DNSKEY",
            DnssecStepOutcome.FAIL,
            "Parent DS exists but the authoritative child provides no DNSKEY RRset.",
        )
        steps.append(step)
        return _analysis(
            DnssecState.BROKEN,
            step.message,
            ds_count=ds_count,
            steps=steps,
        )

    if dnskey_result.state != DnsQueryState.ANSWER:
        step = DnssecValidationStep(
            "Child DNSKEY",
            DnssecStepOutcome.UNKNOWN,
            f"Child DNSKEY evidence is inconclusive ({dnskey_result.state.value}).",
        )
        steps.append(step)
        return _analysis(
            DnssecState.UNKNOWN,
            step.message,
            ds_count=ds_count,
            steps=steps,
        )

    try:
        dnskey_rrsets = _answer_rrsets(dnskey_result)
        dnskey_rrset = _find_rrset(dnskey_rrsets, "DNSKEY")
        dnskey_rrsig = _rrsig_for_type(dnskey_rrsets, "DNSKEY")
    except (ValueError, dns.exception.DNSException) as exc:
        step = DnssecValidationStep(
            "Child DNSKEY",
            DnssecStepOutcome.UNKNOWN,
            f"Child DNSKEY evidence could not be parsed: {exc}",
        )
        steps.append(step)
        return _analysis(
            DnssecState.UNKNOWN,
            step.message,
            ds_count=ds_count,
            steps=steps,
        )

    if dnskey_rrset is None or not len(dnskey_rrset):
        step = DnssecValidationStep(
            "Child DNSKEY",
            DnssecStepOutcome.FAIL,
            "Parent DS exists but the authoritative DNSKEY answer contains no DNSKEY RRset.",
        )
        steps.append(step)
        return _analysis(
            DnssecState.BROKEN,
            step.message,
            ds_count=ds_count,
            steps=steps,
        )

    dnskey_count = len(dnskey_rrset)
    steps.append(
        DnssecValidationStep(
            "Child DNSKEY",
            DnssecStepOutcome.PASS,
            f"Collected {dnskey_count} child DNSKEY record(s).",
        )
    )

    ds_match = _match_ds_to_dnskeys(
        evidence.zone,
        ds_rrset,
        dnskey_rrset,
        policy=policy,
    )
    steps.append(ds_match.step)
    if ds_match.step.outcome == DnssecStepOutcome.UNKNOWN:
        return _analysis(
            DnssecState.UNKNOWN,
            ds_match.step.message,
            ds_count=ds_count,
            dnskey_count=dnskey_count,
            steps=steps,
        )
    if ds_match.step.outcome == DnssecStepOutcome.FAIL:
        return _analysis(
            DnssecState.BROKEN,
            ds_match.step.message,
            ds_count=ds_count,
            dnskey_count=dnskey_count,
            steps=steps,
        )

    dnskey_validation = _validate_signature_set(
        name="DNSKEY RRset",
        rrset=dnskey_rrset,
        rrsigset=dnskey_rrsig,
        trusted_keys=ds_match.matched_keys,
        key_template=dnskey_rrset,
        now=validation_time,
        policy=policy,
    )
    steps.append(dnskey_validation)
    if dnskey_validation.outcome == DnssecStepOutcome.UNKNOWN:
        return _analysis(
            DnssecState.UNKNOWN,
            dnskey_validation.message,
            ds_count=ds_count,
            dnskey_count=dnskey_count,
            matched_key_tags=ds_match.matched_key_tags,
            steps=steps,
        )
    if dnskey_validation.outcome == DnssecStepOutcome.FAIL:
        return _analysis(
            DnssecState.BROKEN,
            dnskey_validation.message,
            ds_count=ds_count,
            dnskey_count=dnskey_count,
            matched_key_tags=ds_match.matched_key_tags,
            steps=steps,
        )

    apex_by_type = {item.qtype.upper(): item for item in evidence.apex_rrsets}
    authenticated_keys = tuple(dnskey_rrset)

    for qtype in ("SOA", "NS"):
        query = apex_by_type.get(qtype)
        result = _query_result(query)
        if result is None or result.failed:
            step = _query_unavailable_step(f"Apex {qtype}", result)
            steps.append(step)
            return _analysis(
                DnssecState.UNKNOWN,
                step.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

        if result.state in {DnsQueryState.NO_ANSWER, DnsQueryState.NXDOMAIN}:
            step = DnssecValidationStep(
                f"Apex {qtype}",
                DnssecStepOutcome.FAIL,
                f"Authoritative apex {qtype} RRset is absent.",
            )
            steps.append(step)
            return _analysis(
                DnssecState.BROKEN,
                step.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

        if result.state != DnsQueryState.ANSWER:
            step = DnssecValidationStep(
                f"Apex {qtype}",
                DnssecStepOutcome.UNKNOWN,
                f"Apex {qtype} evidence is inconclusive ({result.state.value}).",
            )
            steps.append(step)
            return _analysis(
                DnssecState.UNKNOWN,
                step.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

        try:
            rrsets = _answer_rrsets(result)
            rrset = _find_rrset(rrsets, qtype)
            rrsig = _rrsig_for_type(rrsets, qtype)
        except (ValueError, dns.exception.DNSException) as exc:
            step = DnssecValidationStep(
                f"Apex {qtype}",
                DnssecStepOutcome.UNKNOWN,
                f"Apex {qtype} evidence could not be parsed: {exc}",
            )
            steps.append(step)
            return _analysis(
                DnssecState.UNKNOWN,
                step.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

        if rrset is None or not len(rrset):
            step = DnssecValidationStep(
                f"Apex {qtype}",
                DnssecStepOutcome.FAIL,
                f"Authoritative answer contains no apex {qtype} RRset.",
            )
            steps.append(step)
            return _analysis(
                DnssecState.BROKEN,
                step.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

        rrset_validation = _validate_signature_set(
            name=f"Apex {qtype}",
            rrset=rrset,
            rrsigset=rrsig,
            trusted_keys=authenticated_keys,
            key_template=dnskey_rrset,
            now=validation_time,
            policy=policy,
        )
        steps.append(rrset_validation)
        if rrset_validation.outcome == DnssecStepOutcome.UNKNOWN:
            return _analysis(
                DnssecState.UNKNOWN,
                rrset_validation.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )
        if rrset_validation.outcome == DnssecStepOutcome.FAIL:
            return _analysis(
                DnssecState.BROKEN,
                rrset_validation.message,
                ds_count=ds_count,
                dnskey_count=dnskey_count,
                matched_key_tags=ds_match.matched_key_tags,
                steps=steps,
            )

    return _analysis(
        DnssecState.SECURE,
        "Parent DS matches an authenticated DNSKEY RRset and the selected apex SOA/NS RRsets validate.",
        ds_count=ds_count,
        dnskey_count=dnskey_count,
        matched_key_tags=ds_match.matched_key_tags,
        steps=steps,
    )


__all__ = [
    "DNSSEC_POLICY_VERSION",
    "DNSSEC_VALIDATION_POLICY",
    "DnssecAnalysis",
    "DnssecSignatureSummary",
    "DnssecState",
    "DnssecStepOutcome",
    "DnssecValidationPolicy",
    "DnssecValidationStep",
    "analyze_dnssec_evidence",
]
