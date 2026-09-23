from __future__ import annotations

import re
from typing import Any


_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def normalize_http_version(value: object) -> str | None:
    """Normalize common client-library HTTP version representations."""
    if value is None:
        return None
    if isinstance(value, int):
        return {
            9: "0.9",
            10: "1.0",
            11: "1.1",
            20: "2",
            30: "3",
        }.get(value, str(value))
    text = str(value).strip()
    if not text:
        return None
    if text.upper().startswith("HTTP/"):
        text = text[5:]
    return text or None


def _split_http_list(value: str) -> list[str]:
    """Split a comma-list without breaking quoted-string parameter values."""
    items: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in str(value or ""):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == "," and not quoted:
            items.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    items.append("".join(current).strip())
    return items


def _split_semicolon_parameters(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in str(value or ""):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return parts


def _parse_content_length_values(values: list[str]) -> dict[str, Any]:
    members: list[str] = []
    errors: list[str] = []
    for field_value in values:
        split = str(field_value).split(",")
        members.extend(part.strip() for part in split)

    parsed: list[int] = []
    for member in members:
        if not member or not member.isdigit():
            errors.append(
                f"invalid Content-Length value: {member or '(empty)'}"
            )
            continue
        parsed.append(int(member))

    distinct = sorted(set(parsed))
    conflicting = len(distinct) > 1
    if conflicting:
        errors.append("conflicting Content-Length values were received")

    content_length = (
        parsed[0]
        if parsed and not conflicting and len(parsed) == len(members)
        else None
    )
    duplicate_identical = (
        len(parsed) > 1
        and len(parsed) == len(members)
        and len(distinct) == 1
    )

    return {
        "raw_values": values,
        "members": members,
        "parsed_values": parsed,
        "content_length": content_length,
        "duplicate_identical": duplicate_identical,
        "conflicting": conflicting,
        "errors": errors,
    }


def _parse_transfer_encoding_values(values: list[str]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []

    for field_value in values:
        for raw_entry in _split_http_list(field_value):
            if not raw_entry:
                errors.append("empty Transfer-Encoding list member")
                continue
            parts = _split_semicolon_parameters(raw_entry)
            coding = parts[0].strip()
            if not _TOKEN_RE.fullmatch(coding):
                errors.append(f"invalid transfer-coding token: {coding or '(empty)'}")
                continue

            params = [part for part in parts[1:] if part]
            name = coding.lower()
            if name == "chunked" and params:
                warnings.append(
                    "chunked transfer coding has parameters; RFC 9112 says these should be treated as an error"
                )
            entries.append({
                "name": name,
                "raw": raw_entry,
                "parameters": params,
            })

    codings = [entry["name"] for entry in entries]
    chunked_count = sum(1 for coding in codings if coding == "chunked")
    if chunked_count > 1:
        errors.append("chunked transfer coding appears more than once")

    return {
        "raw_values": values,
        "entries": entries,
        "codings": codings,
        "chunked_count": chunked_count,
        "chunked_final": bool(codings and codings[-1] == "chunked"),
        "errors": errors,
        "warnings": warnings,
    }


def analyze_http1_response_framing(
    *,
    http_version: object,
    status_code: int,
    request_method: str = "GET",
    content_length_values: list[str] | tuple[str, ...] = (),
    transfer_encoding_values: list[str] | tuple[str, ...] = (),
    connection_values: list[str] | tuple[str, ...] = (),
    raw_header_fidelity: bool = False,
) -> dict[str, Any]:
    """Passively analyze observable RFC 9112 response-framing metadata.

    This does not inspect raw response bytes, chunk boundaries, trailer syntax,
    premature EOF, or extra bytes after a message. It is intentionally limited
    to metadata already exposed by the normal HTTP client.
    """
    version = normalize_http_version(http_version)
    status = int(status_code)
    method = str(request_method or "GET").upper()
    content_lengths = [str(v).strip() for v in content_length_values]
    transfer_encodings = [str(v).strip() for v in transfer_encoding_values]
    connections = [str(v).strip() for v in connection_values if str(v).strip()]

    cl = _parse_content_length_values(content_lengths)
    te = _parse_transfer_encoding_values(transfer_encodings)

    errors = list(cl["errors"]) + list(te["errors"])
    warnings = list(te["warnings"])
    notes: list[str] = []

    connection_tokens = {
        token.strip().lower()
        for value in connections
        for token in value.split(",")
        if token.strip()
    }
    connection_close = "close" in connection_tokens

    body_forbidden = (
        method == "HEAD"
        or 100 <= status < 200
        or status in {204, 304}
    )

    if transfer_encodings and content_lengths:
        errors.append(
            "Transfer-Encoding and Content-Length are both present; Transfer-Encoding overrides Content-Length and the message ought to be handled as an error"
        )

    if version == "1.0" and transfer_encodings:
        errors.append(
            "Transfer-Encoding on an HTTP/1.0 response is faulty framing under RFC 9112"
        )

    if cl["duplicate_identical"]:
        notes.append(
            "multiple identical Content-Length values were received and can be normalized to one value"
        )

    if te["chunked_count"] == 1 and not te["chunked_final"]:
        notes.append(
            "chunked is not the final transfer coding; RFC 9112 therefore uses connection close to delimit this response"
        )

    applicable = version == "1.1"

    if body_forbidden:
        framing = "no-body"
    elif transfer_encodings:
        framing = "chunked" if te["chunked_final"] else "close-delimited-transfer-encoding"
        if not te["chunked_final"]:
            notes.append(
                "response completion depends on connection close; passive metadata cannot verify the raw close boundary"
            )
    elif cl["content_length"] is not None and not cl["errors"]:
        framing = "content-length"
    elif cl["errors"]:
        framing = "invalid-content-length"
    else:
        framing = "close-delimited"
        notes.append(
            "no Transfer-Encoding or Content-Length was observed; RFC 9112 permits close-delimited responses but recommends explicit framing when possible"
        )

    if version is None:
        notes.append(
            "the HTTP client did not expose the response protocol version; RFC 9112 applicability cannot be established"
        )
    elif version not in {"1.0", "1.1"}:
        notes.append(
            f"observed HTTP/{version}; RFC 9112 HTTP/1.1 response framing is not applicable"
        )

    return {
        "observed": version is not None,
        "applicable": applicable,
        "http_version": version,
        "status_code": status,
        "request_method": method,
        "framing": framing,
        "body_forbidden_by_status_or_method": body_forbidden,
        "content_length_values": cl["members"],
        "content_length": cl["content_length"],
        "duplicate_identical_content_length": cl["duplicate_identical"],
        "conflicting_content_length": cl["conflicting"],
        "transfer_encoding_values": transfer_encodings,
        "transfer_codings": te["codings"],
        "chunked_count": te["chunked_count"],
        "chunked_final": te["chunked_final"],
        "connection_values": connections,
        "connection_close_declared": connection_close,
        "raw_header_fidelity": bool(raw_header_fidelity),
        "valid": not errors,
        "review": bool(errors or warnings),
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "coverage": "parsed response metadata only",
        "raw_wire_checked": False,
        "body_length_verified": False,
        "chunk_boundaries_verified": False,
        "trailers_verified": False,
    }


__all__ = [
    "analyze_http1_response_framing",
    "normalize_http_version",
]
