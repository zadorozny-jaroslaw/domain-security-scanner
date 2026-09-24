from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from .web import is_well_formed_uri_reference


_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_REGISTERED_REL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9.-]*$")
_MEDIA_TYPE_RE = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
)


def _is_quoted_string(value: str) -> bool:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return False
    escaped = False
    for char in value[1:-1]:
        code = ord(char)
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"' or code < 0x20 or code == 0x7F:
            return False
    return not escaped


def _unquote(value: str) -> str:
    if not _is_quoted_string(value):
        return value
    return re.sub(r"\\(.)", r"\1", value[1:-1])


def _split_link_values(field_value: str) -> list[str]:
    """Split a Link field without breaking commas in <> targets or quotes."""
    values: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    in_target = False

    for char in str(field_value or ""):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"' and not in_target:
            quoted = not quoted
            current.append(char)
            continue
        if not quoted:
            if char == "<":
                in_target = True
            elif char == ">":
                in_target = False
            elif char == "," and not in_target:
                item = "".join(current).strip()
                if item:
                    values.append(item)
                current = []
                continue
        current.append(char)

    item = "".join(current).strip()
    if item:
        values.append(item)
    return values


def _split_parameters(value: str) -> tuple[list[str], bool]:
    """Split semicolon parameters; return parts plus quote-balance state."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
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
    return parts, not quoted and not escaped


def _valid_uri_reference(value: str) -> bool:
    # RFC 3986 permits an empty relative reference, which resolves to the base.
    return value == "" or is_well_formed_uri_reference(value)


def _parse_relation_types(value: str) -> tuple[list[str], list[str], list[str]]:
    relations: list[str] = []
    errors: list[str] = []
    warnings: list[str] = []
    for relation in str(value or "").split():
        if _REGISTERED_REL_RE.fullmatch(relation):
            normalized = relation.lower()
            relations.append(normalized)
            if relation != normalized:
                warnings.append(
                    f"registered relation type should use lowercase serialization: {relation}"
                )
            continue
        if is_well_formed_uri_reference(relation, require_absolute=True):
            relations.append(relation)
            continue
        errors.append(f"invalid link relation type: {relation}")
    if not relations and not errors:
        errors.append("rel parameter must contain at least one relation type")
    return relations, errors, warnings


def _parse_link_value(raw: str, context_url: str) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    value = str(raw or "").strip()

    target: str | None = None
    resolved_target: str | None = None
    params: dict[str, list[str | None]] = {}
    parameter_order: list[dict[str, str | None]] = []

    if not value.startswith("<"):
        errors.append("link-value must start with '<'")
        return {
            "raw": value,
            "target": None,
            "resolved_target": None,
            "context": context_url,
            "resolved_context": context_url,
            "relations": [],
            "parameters": {},
            "parameter_order": [],
            "errors": errors,
            "warnings": warnings,
            "valid": False,
        }

    end = value.find(">", 1)
    if end < 0:
        errors.append("link-value target is missing closing '>'")
        return {
            "raw": value,
            "target": None,
            "resolved_target": None,
            "context": context_url,
            "resolved_context": context_url,
            "relations": [],
            "parameters": {},
            "parameter_order": [],
            "errors": errors,
            "warnings": warnings,
            "valid": False,
        }

    target = value[1:end]
    if not _valid_uri_reference(target):
        errors.append("link target is not a valid URI-reference")
    else:
        resolved_target = urljoin(context_url, target)

    remainder = value[end + 1 :].strip()
    if remainder and not remainder.startswith(";"):
        errors.append("unexpected data after link target")
    elif remainder:
        param_parts, balanced = _split_parameters(remainder[1:])
        if not balanced:
            errors.append("unterminated quoted-string in link parameters")
        for part in param_parts:
            if not part:
                errors.append("empty Link parameter")
                continue
            if "=" in part:
                raw_name, raw_value = part.split("=", 1)
                name = raw_name.strip()
                encoded = raw_value.strip()
                if not _TOKEN_RE.fullmatch(name):
                    errors.append(f"invalid Link parameter name: {name or '(empty)'}")
                    continue
                if not encoded:
                    errors.append(f"Link parameter {name} has an empty serialized value")
                    continue
                if encoded.startswith('"'):
                    if not _is_quoted_string(encoded):
                        errors.append(f"invalid quoted-string for Link parameter {name}")
                        continue
                    parsed_value: str | None = _unquote(encoded)
                elif _TOKEN_RE.fullmatch(encoded):
                    parsed_value = encoded
                else:
                    errors.append(f"invalid Link parameter value for {name}")
                    continue
            else:
                name = part.strip()
                if not _TOKEN_RE.fullmatch(name):
                    errors.append(f"invalid Link parameter name: {name or '(empty)'}")
                    continue
                parsed_value = None

            key = name.lower()
            params.setdefault(key, []).append(parsed_value)
            parameter_order.append({"name": key, "value": parsed_value})

    rel_values = params.get("rel", [])
    relations: list[str] = []
    if not rel_values:
        errors.append("missing required rel parameter")
    else:
        if len(rel_values) > 1:
            warnings.append("rel parameter appears more than once; later occurrences are ignored")
        first_rel = rel_values[0]
        if first_rel is None:
            errors.append("rel parameter requires a value")
        else:
            relations, rel_errors, rel_warnings = _parse_relation_types(first_rel)
            errors.extend(rel_errors)
            warnings.extend(rel_warnings)

    if "rev" in params:
        warnings.append("rev parameter is deprecated by RFC 8288")

    for name in ("media", "title", "title*", "type"):
        if len(params.get(name, [])) > 1:
            warnings.append(
                f"{name} parameter appears more than once; later occurrences are ignored"
            )

    type_values = params.get("type", [])
    if type_values and type_values[0] is not None:
        if not _MEDIA_TYPE_RE.fullmatch(str(type_values[0])):
            errors.append("type parameter is not a valid media type hint")

    anchor_values = params.get("anchor", [])
    resolved_context = context_url
    if anchor_values:
        if len(anchor_values) > 1:
            warnings.append("anchor parameter appears more than once; context is ambiguous")
        anchor = anchor_values[0]
        if anchor is None:
            errors.append("anchor parameter requires a URI-reference value")
        elif not _valid_uri_reference(anchor):
            errors.append("anchor parameter is not a valid URI-reference")
        else:
            resolved_context = urljoin(context_url, anchor)

    return {
        "raw": value,
        "target": target,
        "resolved_target": resolved_target,
        "context": context_url,
        "resolved_context": resolved_context,
        "relations": relations,
        "parameters": params,
        "parameter_order": parameter_order,
        "errors": errors,
        "warnings": warnings,
        "valid": not errors,
    }


def analyze_link_headers(
    header_values: list[str] | tuple[str, ...] = (),
    *,
    context_url: str,
) -> dict[str, Any]:
    """Parse and validate RFC 8288 Link response header fields.

    The analysis is deliberately passive: link targets are never dereferenced.
    Missing Link fields are informational because RFC 8288 does not require a
    generic Web response to publish them.
    """
    values = [str(value).strip() for value in header_values if str(value).strip()]
    links: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []

    for field_index, field_value in enumerate(values, start=1):
        raw_links = _split_link_values(field_value)
        if not raw_links:
            errors.append(f"Link field {field_index} contains no link-value")
            continue
        for raw in raw_links:
            parsed = _parse_link_value(raw, context_url)
            links.append(parsed)
            errors.extend(parsed["errors"])
            warnings.extend(parsed["warnings"])

    relation_types = sorted(
        {relation for link in links for relation in link.get("relations", [])}
    )
    relation_counts = {
        relation: sum(
            1 for link in links if relation in link.get("relations", [])
        )
        for relation in relation_types
    }

    return {
        "present": bool(values),
        "valid": not errors,
        "review": bool(errors or warnings),
        "header_values": values,
        "link_count": len(links),
        "links": links,
        "relation_types": relation_types,
        "relation_counts": relation_counts,
        "errors": errors,
        "warnings": warnings,
        "targets_dereferenced": False,
    }


__all__ = ["analyze_link_headers"]
