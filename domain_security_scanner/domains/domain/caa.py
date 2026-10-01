from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlsplit

import dns.rdata
import dns.rdataclass
import dns.rdatatype


CAA_CRITICAL_FLAG = 0x80
CAA_RESERVED_FLAGS = 0x7F
RECOGNIZED_CAA_TAGS = frozenset({"issue", "issuewild", "iodef"})

_LDH_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_ISSUER_DOMAIN_RE = re.compile(rf"^{_LDH_LABEL}(?:\.{_LDH_LABEL})*$")
_PARAMETER_TAG_RE = re.compile(rf"^{_LDH_LABEL}$")
_PARAMETER_VALUE_RE = re.compile(r"^[\x21-\x3A\x3C-\x7E]*$")


def caa_lookup_names(name: str) -> tuple[str, ...]:
    """Return RFC 8659 tree-climb names, excluding only the DNS root dot."""
    normalized = str(name or "").strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("CAA lookup name cannot be empty")
    labels = normalized.split(".")
    if any(not label for label in labels):
        raise ValueError(f"Invalid DNS name for CAA lookup: {name!r}")
    return tuple(".".join(labels[index:]) for index in range(len(labels)))


def _decode_value(value: bytes) -> tuple[str, bool]:
    try:
        return value.decode("ascii"), True
    except UnicodeDecodeError:
        return value.decode("ascii", errors="backslashreplace"), False


def _parse_issue_value(value: str) -> dict[str, Any]:
    """Parse RFC 8659 issue/issuewild value syntax conservatively.

    RFC 8659 requires a malformed issue-value to be treated like an empty
    issuer-domain-name. The returned ``forbids_issuance`` flag reflects that
    per-record processing rule; RRset-level additive authorization is handled
    by :func:`analyze_caa_records`.
    """
    issuer_part, separator, parameter_text = value.partition(";")
    issuer = issuer_part.strip()

    if issuer and not _ISSUER_DOMAIN_RE.fullmatch(issuer):
        return {
            "value_valid": False,
            "issuer_domain": None,
            "parameters": [],
            "forbids_issuance": True,
            "value_error": "invalid issuer-domain-name",
        }

    parameters: list[dict[str, str]] = []
    if separator and parameter_text.strip():
        for raw_parameter in parameter_text.split(";"):
            parameter = raw_parameter.strip()
            if not parameter or "=" not in parameter:
                return {
                    "value_valid": False,
                    "issuer_domain": None,
                    "parameters": [],
                    "forbids_issuance": True,
                    "value_error": "invalid issue parameter syntax",
                }
            tag, parameter_value = parameter.split("=", 1)
            tag = tag.strip()
            parameter_value = parameter_value.strip()
            if (
                not _PARAMETER_TAG_RE.fullmatch(tag)
                or not _PARAMETER_VALUE_RE.fullmatch(parameter_value)
            ):
                return {
                    "value_valid": False,
                    "issuer_domain": None,
                    "parameters": [],
                    "forbids_issuance": True,
                    "value_error": "invalid issue parameter syntax",
                }
            parameters.append(
                {
                    "tag": tag.lower(),
                    "value": parameter_value,
                }
            )

    issuer_domain = issuer.lower() or None
    return {
        "value_valid": True,
        "issuer_domain": issuer_domain,
        "parameters": parameters,
        "forbids_issuance": issuer_domain is None,
    }


def _parse_iodef_value(value: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None

    scheme = parsed.scheme.lower() if parsed else ""
    valid = False
    if parsed and scheme == "mailto":
        valid = bool(parsed.path)
    elif parsed and scheme in {"http", "https"}:
        valid = bool(parsed.netloc)

    result: dict[str, Any] = {
        "value_valid": valid,
        "iodef_scheme": scheme or None,
    }
    if not valid:
        result["value_error"] = "iodef must use a non-empty mailto, http, or https URL"
    return result


def parse_caa_record(record: str) -> dict[str, Any]:
    """Parse one dnspython CAA presentation string into structured evidence."""
    raw = str(record)
    try:
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.CAA,
            raw,
        )
    except Exception as exc:
        return {
            "raw": raw,
            "syntax_valid": False,
            "parse_error": str(exc) or exc.__class__.__name__,
        }

    try:
        tag = rdata.tag.decode("ascii").lower()
    except UnicodeDecodeError:
        return {
            "raw": raw,
            "syntax_valid": False,
            "parse_error": "CAA tag is not ASCII",
        }

    value, ascii_value = _decode_value(rdata.value)
    flags = int(rdata.flags)
    parsed: dict[str, Any] = {
        "raw": raw,
        "syntax_valid": True,
        "flags": flags,
        "critical": bool(flags & CAA_CRITICAL_FLAG),
        "reserved_flags": flags & CAA_RESERVED_FLAGS,
        "tag": tag,
        "value": value,
        "recognized": tag in RECOGNIZED_CAA_TAGS,
    }

    if tag in {"issue", "issuewild"}:
        if ascii_value:
            parsed.update(_parse_issue_value(value))
        else:
            parsed.update(
                {
                    "value_valid": False,
                    "issuer_domain": None,
                    "parameters": [],
                    "forbids_issuance": True,
                    "value_error": "issue value is not ASCII",
                }
            )
    elif tag == "iodef":
        if ascii_value:
            parsed.update(_parse_iodef_value(value))
        else:
            parsed.update(
                {
                    "value_valid": False,
                    "iodef_scheme": None,
                    "value_error": "iodef value is not ASCII",
                }
            )
    else:
        # Unknown properties may define arbitrary value sub-formats. Preserve
        # their data without pretending to validate semantics we do not know.
        parsed["value_valid"] = None

    return parsed


def analyze_caa_records(records: list[str] | tuple[str, ...]) -> dict[str, Any]:
    parsed_records = [parse_caa_record(record) for record in records]
    syntax_errors = [
        record["raw"]
        for record in parsed_records
        if not record.get("syntax_valid", False)
    ]
    semantic_errors = [
        record["raw"]
        for record in parsed_records
        if record.get("syntax_valid", False)
        and record.get("recognized", False)
        and record.get("value_valid") is False
    ]

    valid_structural = [
        record for record in parsed_records if record.get("syntax_valid", False)
    ]
    recognized_tags = sorted(
        {record["tag"] for record in valid_structural if record.get("recognized")}
    )
    unknown_tags = sorted(
        {record["tag"] for record in valid_structural if not record.get("recognized")}
    )
    critical_unknown_tags = sorted(
        {
            record["tag"]
            for record in valid_structural
            if record.get("critical") and not record.get("recognized")
        }
    )

    issue_records = [record for record in valid_structural if record.get("tag") == "issue"]
    issuewild_records = [
        record for record in valid_structural if record.get("tag") == "issuewild"
    ]
    iodef_records = [record for record in valid_structural if record.get("tag") == "iodef"]

    fqdn_issuers = sorted(
        {
            record["issuer_domain"]
            for record in issue_records
            if record.get("issuer_domain")
        }
    )
    wildcard_source = issuewild_records if issuewild_records else issue_records
    wildcard_issuers = sorted(
        {
            record["issuer_domain"]
            for record in wildcard_source
            if record.get("issuer_domain")
        }
    )

    return {
        "record_count": len(records),
        "parsed_records": parsed_records,
        "recognized_tags": recognized_tags,
        "unknown_tags": unknown_tags,
        "critical_unknown_tags": critical_unknown_tags,
        "unknown_critical_blocks_unsupported_issuers": bool(critical_unknown_tags),
        "reserved_flag_records": [
            record["raw"]
            for record in valid_structural
            if record.get("reserved_flags", 0)
        ],
        "syntax_error_records": syntax_errors,
        "malformed_value_records": semantic_errors,
        "has_issue": bool(issue_records),
        "has_issuewild": bool(issuewild_records),
        "has_iodef": bool(iodef_records),
        "fqdn_issuers": fqdn_issuers,
        "wildcard_issuers": wildcard_issuers,
        "fqdn_issuance_restricted": bool(issue_records),
        "wildcard_issuance_restricted": bool(wildcard_source),
        "fqdn_issuance_forbidden": bool(issue_records) and not fqdn_issuers,
        "wildcard_issuance_forbidden": bool(wildcard_source) and not wildcard_issuers,
        "iodef_urls": [
            record["value"]
            for record in iodef_records
            if record.get("value_valid") is True
        ],
    }


def collect_caa_policy(
    target_name: str,
    query_result: Callable[[str, str], Any],
) -> dict[str, Any]:
    """Collect the RFC 8659 Relevant CAA RRset with conservative failures.

    The query callback must return an object compatible with ``DnsQueryResult``:
    it needs ``state``, ``records``, ``failed`` and optional ``error`` fields.
    Lookup stops at the first non-empty RRset. Any DNS failure before an
    effective RRset is found makes the result unknown instead of allowing a
    higher ancestor to masquerade as the effective policy.
    """
    lookup_chain: list[dict[str, Any]] = []
    effective_name: str | None = None
    effective_records: list[str] = []
    failed_lookup: dict[str, Any] | None = None

    for name in caa_lookup_names(target_name):
        result = query_result(name, "CAA")
        state = getattr(result.state, "value", str(result.state))
        records = list(result.records)
        step: dict[str, Any] = {
            "name": name,
            "state": state,
            "records": records,
        }
        if getattr(result, "error", None):
            step["error"] = result.error
        lookup_chain.append(step)

        if result.failed:
            failed_lookup = {
                "name": name,
                "state": state,
                "error": getattr(result, "error", None),
            }
            break

        if records:
            effective_name = name
            effective_records = records
            break

    analysis = analyze_caa_records(effective_records)
    if failed_lookup is not None:
        analysis["state"] = "unknown"
    elif effective_name is not None:
        analysis["state"] = "effective"
    else:
        analysis["state"] = "absent"

    return {
        "lookup_chain": lookup_chain,
        "effective_name": effective_name,
        "records": analysis.pop("parsed_records"),
        "analysis": analysis,
        "lookup_failure": failed_lookup,
    }


__all__ = [
    "CAA_CRITICAL_FLAG",
    "RECOGNIZED_CAA_TAGS",
    "analyze_caa_records",
    "caa_lookup_names",
    "collect_caa_policy",
    "parse_caa_record",
]
