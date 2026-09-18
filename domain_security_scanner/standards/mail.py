from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit


_MX_RE = re.compile(r"^\s*(\d{1,5})\s+(\S+)\s*$")


def analyze_mx_records(records: Iterable[str]) -> dict:
    """Parse MX RDATA and identify RFC 7505 Null MX semantics.

    A valid Null MX is exactly one MX RR whose preference is 0 and whose
    exchange is the DNS root label (``.``). A Null MX must not coexist with
    any other MX RR.
    """

    parsed: list[dict[str, int | str]] = []
    errors: list[str] = []

    for raw_value in records:
        raw = str(raw_value).strip()
        match = _MX_RE.fullmatch(raw)
        if not match:
            errors.append(f"invalid MX RDATA: {raw}")
            continue

        preference = int(match.group(1))
        if preference > 65535:
            errors.append(f"invalid MX preference: {raw}")
            continue

        exchange_raw = match.group(2)
        exchange = "." if exchange_raw == "." else exchange_raw.rstrip(".").lower()
        parsed.append(
            {
                "preference": preference,
                "exchange": exchange,
                "raw": raw,
            }
        )

    root_exchange = [row for row in parsed if row["exchange"] == "."]
    valid_null_mx = (
        not errors
        and len(parsed) == 1
        and parsed[0]["preference"] == 0
        and parsed[0]["exchange"] == "."
    )

    if root_exchange and not valid_null_mx:
        if len(parsed) > 1:
            errors.append("Null MX must be the only MX record")
        if any(row["preference"] != 0 for row in root_exchange):
            errors.append("Null MX must use preference 0")

    return {
        "valid": not errors,
        "null_mx": valid_null_mx,
        "record_count": len(parsed),
        "records": parsed,
        "errors": errors,
    }


_STS_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")
_STS_EXTENSION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_STS_EXTENSION_VALUE_RE = re.compile(r"^[\x21-\x3A\x3C\x3E-\x7E]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _valid_ascii_domain(value: str) -> bool:
    if not value or len(value) > 253 or not value.isascii():
        return False
    labels = value.rstrip(".").split(".")
    return bool(labels) and all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def analyze_mta_sts_txt(records: Iterable[str]) -> dict:
    """Validate RFC 8461 MTA-STS policy-indicator TXT records."""

    values = [str(value).strip() for value in records]
    declared = [value for value in values if re.match(r"^v=STSv1(?:\s*;|$)", value)]
    candidates = [value for value in values if re.match(r"^v=STSv1\s*;", value)]
    errors: list[str] = []

    if not declared:
        return {
            "configured": False,
            "valid": False,
            "candidate_count": 0,
            "record": None,
            "id": None,
            "errors": [],
        }

    if len(candidates) != 1:
        if not candidates:
            errors.append("MTA-STS TXT record must begin with 'v=STSv1;'")
        else:
            errors.append("exactly one usable MTA-STS TXT record is required")
        return {
            "configured": True,
            "valid": False,
            "candidate_count": len(candidates),
            "record": candidates[0] if len(candidates) == 1 else None,
            "id": None,
            "errors": errors,
        }

    record = candidates[0]
    if not record.isascii():
        errors.append("MTA-STS TXT record must be US-ASCII")

    terms = [part.strip() for part in record.split(";")]
    if terms and terms[-1] == "":
        terms.pop()
    if not terms or terms[0] != "v=STSv1":
        errors.append("v=STSv1 must be the first field")

    policy_id: str | None = None
    for term in terms[1:]:
        if not term or "=" not in term:
            errors.append(f"invalid MTA-STS TXT field: {term or '<empty>'}")
            continue
        key, value = term.split("=", 1)
        if key != key.strip() or value != value.strip():
            errors.append(f"invalid whitespace around '=' in field: {term}")
            continue
        if key == "id":
            if policy_id is not None:
                errors.append("duplicate id field")
            elif not _STS_ID_RE.fullmatch(value):
                errors.append("id must contain 1-32 ASCII letters or digits")
            else:
                policy_id = value
            continue
        if not _STS_EXTENSION_NAME_RE.fullmatch(key):
            errors.append(f"invalid extension field name: {key}")
        elif not _STS_EXTENSION_VALUE_RE.fullmatch(value):
            errors.append(f"invalid extension value for {key}")

    if policy_id is None:
        errors.append("required id field is missing or invalid")

    return {
        "configured": True,
        "valid": not errors,
        "candidate_count": 1,
        "record": record,
        "id": policy_id,
        "errors": errors,
    }


def parse_mta_sts_policy(text: str) -> dict:
    """Parse and validate an RFC 8461 HTTPS policy body."""

    errors: list[str] = []
    warnings: list[str] = []
    fields: dict[str, str] = {}
    mx_patterns: list[str] = []

    raw_lines = str(text or "").splitlines()
    while raw_lines and not raw_lines[-1].strip():
        raw_lines.pop()

    for raw_line in raw_lines:
        if not raw_line.strip():
            errors.append("blank lines are not valid MTA-STS policy fields")
            continue
        if ":" not in raw_line:
            errors.append(f"invalid policy field: {raw_line.strip()}")
            continue
        key, value = raw_line.split(":", 1)
        if key != key.strip():
            errors.append(f"invalid whitespace before ':' in field: {raw_line.strip()}")
            continue
        value = value.strip()
        if not key or not value:
            errors.append(f"invalid policy field: {raw_line.strip()}")
            continue

        if key == "mx":
            mx_patterns.append(value.rstrip(".").lower())
            continue

        if key in fields:
            warnings.append(f"duplicate {key} field ignored after first value")
            continue
        fields[key] = value

    if fields.get("version") != "STSv1":
        errors.append("version must be STSv1")

    mode = fields.get("mode")
    if mode not in {"enforce", "testing", "none"}:
        errors.append("mode must be enforce, testing, or none")

    max_age: int | None = None
    max_age_raw = fields.get("max_age")
    if max_age_raw is None or not re.fullmatch(r"\d{1,10}", max_age_raw):
        errors.append("max_age must be a non-negative integer")
    else:
        max_age = int(max_age_raw)
        if max_age > 31557600:
            errors.append("max_age must not exceed 31557600 seconds")

    for pattern in mx_patterns:
        domain = pattern[2:] if pattern.startswith("*.") else pattern
        if "*" in domain or not _valid_ascii_domain(domain):
            errors.append(f"invalid mx pattern: {pattern}")
        elif pattern.startswith("*.") and domain.count(".") < 1:
            errors.append(f"invalid wildcard mx pattern: {pattern}")

    if mode != "none" and not mx_patterns:
        errors.append("at least one mx field is required unless mode is none")
    if mode == "none" and mx_patterns:
        warnings.append("mx fields are ignored when mode is none")
    if max_age == 0:
        warnings.append("max_age=0 causes the policy to expire immediately")

    return {
        "valid": not errors,
        "version": fields.get("version"),
        "mode": mode,
        "max_age": max_age,
        "mx": mx_patterns,
        "extensions": {
            key: value
            for key, value in fields.items()
            if key not in {"version", "mode", "max_age"}
        },
        "errors": errors,
        "warnings": warnings,
    }


def mta_sts_mx_matches(host: str, pattern: str) -> bool:
    """Apply RFC 8461's literal/left-most-label wildcard MX matching."""

    candidate = str(host).lower().rstrip(".")
    rule = str(pattern).lower().rstrip(".")
    if rule.startswith("*."):
        suffix = rule[2:]
        if not candidate.endswith("." + suffix):
            return False
        return len(candidate.split(".")) == len(suffix.split(".")) + 1
    return candidate == rule


def analyze_mta_sts_mx_coverage(mx_hosts: Iterable[str], patterns: Iterable[str]) -> dict:
    hosts = [str(host).lower().rstrip(".") for host in mx_hosts if host and host != "."]
    rules = [str(pattern).lower().rstrip(".") for pattern in patterns]
    unmatched = [host for host in hosts if not any(mta_sts_mx_matches(host, rule) for rule in rules)]
    return {
        "mx_hosts": hosts,
        "matched": [host for host in hosts if host not in unmatched],
        "unmatched": unmatched,
        "complete": not unmatched,
    }


_TLSRPT_EXTENSION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_TLSRPT_EXTENSION_VALUE_RE = re.compile(r"^[\x21-\x3A\x3C\x3E-\x7E]+$")


def _validate_tls_rpt_uri(uri: str) -> str | None:
    if not uri:
        return "empty rua URI"
    if "!" in uri:
        return f"TLS-RPT URI contains an unencoded '!': {uri}"

    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    if scheme not in {"mailto", "https"}:
        return f"unsupported TLS-RPT rua URI scheme: {scheme or '<missing>'}"
    if scheme == "mailto":
        address = parsed.path
        if not address or "@" not in address or any(ch.isspace() for ch in address):
            return f"invalid mailto TLS-RPT URI: {uri}"
    elif not parsed.netloc or parsed.hostname is None:
        return f"invalid https TLS-RPT URI: {uri}"
    return None


def analyze_tls_rpt_txt(records: Iterable[str]) -> dict:
    """Validate an RFC 8460 TLSRPT policy from `_smtp._tls` TXT records."""

    values = [str(value).strip() for value in records]
    declared = [value for value in values if re.match(r"^v=TLSRPTv1(?:\s*;|$)", value)]
    candidates = [value for value in values if re.match(r"^v=TLSRPTv1\s*;", value)]
    errors: list[str] = []

    if not declared:
        return {
            "configured": False,
            "valid": False,
            "candidate_count": 0,
            "record": None,
            "rua": [],
            "extensions": {},
            "errors": [],
        }

    if len(candidates) != 1:
        if not candidates:
            errors.append("TLS-RPT TXT record must begin with 'v=TLSRPTv1;'")
        else:
            errors.append("exactly one usable TLS-RPT TXT record is required")
        return {
            "configured": True,
            "valid": False,
            "candidate_count": len(candidates),
            "record": candidates[0] if len(candidates) == 1 else None,
            "rua": [],
            "extensions": {},
            "errors": errors,
        }

    record = candidates[0]
    terms = [part.strip() for part in record.split(";")]
    if terms and terms[-1] == "":
        terms.pop()
    if not terms or terms[0] != "v=TLSRPTv1":
        errors.append("v=TLSRPTv1 must be the first field")

    rua: list[str] = []
    extensions: dict[str, list[str]] = {}
    for term in terms[1:]:
        if not term or "=" not in term:
            errors.append(f"invalid TLS-RPT field: {term or '<empty>'}")
            continue
        key, value = term.split("=", 1)
        if key != key.strip() or value != value.strip():
            errors.append(f"invalid whitespace around '=' in field: {term}")
            continue
        if key == "rua":
            destinations = [item.strip() for item in value.split(",") if item.strip()]
            if not destinations:
                errors.append("rua must contain at least one URI")
                continue
            for destination in destinations:
                uri_error = _validate_tls_rpt_uri(destination)
                if uri_error:
                    errors.append(uri_error)
                else:
                    rua.append(destination)
            continue

        if not _TLSRPT_EXTENSION_NAME_RE.fullmatch(key):
            errors.append(f"invalid TLS-RPT extension field name: {key}")
        elif not _TLSRPT_EXTENSION_VALUE_RE.fullmatch(value):
            errors.append(f"invalid TLS-RPT extension value for {key}")
        else:
            extensions.setdefault(key, []).append(value)

    if not rua:
        errors.append("required rua field is missing or has no valid URI")

    return {
        "configured": True,
        "valid": not errors,
        "candidate_count": 1,
        "record": record,
        "rua": rua,
        "extensions": extensions,
        "errors": errors,
    }
