from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_UPPER_HEX = set("0123456789ABCDEF")
_HOST_BAD_CHAR_RE = re.compile(r"[\x00-\x20\x7f\\/?#@]")
_IPV_FUTURE_RE = re.compile(r"^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&\'()*+,;=:-]+$")


def _is_quoted_string(value: str) -> bool:
    value = str(value or "")
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
    value = str(value or "")
    if not _is_quoted_string(value):
        return value
    return re.sub(r"\\(.)", r"\1", value[1:-1])


def _split_http_list(value: str) -> tuple[list[str], bool]:
    """Split an HTTP comma-list while preserving commas inside quoted strings."""
    members: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    had_empty = False

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
            member = "".join(current).strip()
            if member:
                members.append(member)
            else:
                had_empty = True
            current = []
            continue
        current.append(char)

    member = "".join(current).strip()
    if member:
        members.append(member)
    elif str(value or "").strip().endswith(","):
        had_empty = True

    return members, bool(not quoted and not escaped and not had_empty)


def _split_parameters(value: str) -> tuple[list[str], bool]:
    """Split semicolon parameters while preserving semicolons in quoted strings."""
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
    return parts, bool(not quoted and not escaped)


def _validate_protocol_id(value: str) -> tuple[list[str], list[str]]:
    """Validate RFC 7838 percent-encoded ALPN protocol-id serialization."""
    errors: list[str] = []
    warnings: list[str] = []
    value = str(value or "")

    if not value or not _TOKEN_RE.fullmatch(value):
        errors.append("protocol-id must be a non-empty HTTP token")
        return errors, warnings

    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue

        if index + 2 >= len(value):
            errors.append("protocol-id contains an incomplete percent-encoding")
            break

        pair = value[index + 1:index + 3]
        if any(char not in _UPPER_HEX for char in pair):
            if re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
                errors.append("protocol-id percent-encoding must use uppercase hex digits")
            else:
                errors.append("protocol-id contains an invalid percent-encoding")
            index += 3
            continue

        decoded = chr(int(pair, 16))
        if decoded != "%" and _TOKEN_RE.fullmatch(decoded):
            errors.append(
                f"protocol-id unnecessarily percent-encodes token character: %{pair}"
            )
        index += 3

    return errors, warnings


def _validate_host(host: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    host = str(host or "")

    if not host:
        return errors, warnings

    if any(ord(char) > 0x7F for char in host):
        errors.append("internationalized alternative host must use an ASCII A-label")
        return errors, warnings

    if _HOST_BAD_CHAR_RE.search(host):
        errors.append("alternative host contains characters not valid in uri-host")
        return errors, warnings
    if re.search(r"%(?![0-9A-Fa-f]{2})", host):
        errors.append("alternative host contains an invalid percent-encoding")
        return errors, warnings

    if host.startswith("["):
        if not host.endswith("]"):
            errors.append("IP-literal alternative host must use closing bracket syntax")
            return errors, warnings
        literal = host[1:-1]
        if _IPV_FUTURE_RE.fullmatch(literal):
            return errors, warnings
        try:
            ipaddress.IPv6Address(literal)
        except ValueError:
            errors.append("alternative host contains an invalid IP-literal")
        return errors, warnings

    if ":" in host:
        errors.append("IPv6 alternative host must be enclosed in brackets")
        return errors, warnings

    try:
        parsed = urlsplit(f"https://{host}/")
        _ = parsed.hostname
    except ValueError:
        errors.append("alternative host is not a valid uri-host")
        return errors, warnings

    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        errors.append("alternative host is not a valid uri-host")

    return errors, warnings


def _parse_alt_authority(
    serialized: str,
    *,
    origin_host: str | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    serialized = str(serialized or "").strip()

    result: dict[str, Any] = {
        "serialized": serialized or None,
        "authority": None,
        "host": None,
        "resolved_host": origin_host,
        "port": None,
        "uses_origin_host": False,
        "host_changed": False,
    }

    if not _is_quoted_string(serialized):
        errors.append("alt-authority must use quoted-string serialization")
        return result, errors, warnings

    authority = _unquote(serialized)
    result["authority"] = authority

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or closing + 1 >= len(authority) or authority[closing + 1] != ":":
            errors.append("alt-authority must contain [uri-host]:port")
            return result, errors, warnings
        host = authority[:closing + 1]
        port_text = authority[closing + 2:]
    else:
        if ":" not in authority:
            errors.append("alt-authority must contain uri-host:port")
            return result, errors, warnings
        host, port_text = authority.rsplit(":", 1)

    host_errors, host_warnings = _validate_host(host)
    errors.extend(host_errors)
    warnings.extend(host_warnings)

    if not port_text or not port_text.isdigit():
        errors.append("alternative service port must contain decimal digits")
        port = None
    else:
        port = int(port_text)
        if not 1 <= port <= 65535:
            warnings.append("alternative service port is outside the usable 1-65535 range")

    result["host"] = host or None
    result["resolved_host"] = host.strip("[]") if host else origin_host
    result["port"] = port
    result["uses_origin_host"] = not bool(host)
    if host and origin_host:
        normalized_host = host.strip("[]").lower().rstrip(".")
        normalized_origin = str(origin_host).lower().rstrip(".")
        result["host_changed"] = normalized_host != normalized_origin

    return result, errors, warnings


def _parse_parameter(part: str) -> tuple[str | None, str | None, bool, list[str]]:
    errors: list[str] = []
    if "=" not in part:
        return None, None, False, ["Alt-Svc parameter requires name=value syntax"]

    raw_name, raw_value = part.split("=", 1)
    name = raw_name.strip()
    encoded = raw_value.strip()

    if not _TOKEN_RE.fullmatch(name):
        errors.append(f"invalid Alt-Svc parameter name: {name or '(empty)'}")
        return None, None, False, errors
    if not encoded:
        errors.append(f"Alt-Svc parameter {name} has an empty value")
        return name.lower(), None, False, errors

    quoted = encoded.startswith('"')
    if quoted:
        if not _is_quoted_string(encoded):
            errors.append(f"invalid quoted-string for Alt-Svc parameter {name}")
            return name.lower(), None, True, errors
        value = _unquote(encoded)
    elif _TOKEN_RE.fullmatch(encoded):
        value = encoded
    else:
        errors.append(f"invalid Alt-Svc parameter value for {name}")
        return name.lower(), None, False, errors

    return name.lower(), value, quoted, errors


def _parse_alt_value(raw: str, *, origin_host: str | None, response_age: int | None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    value = str(raw or "").strip()

    parameters: dict[str, list[str]] = {}
    parameter_order: list[dict[str, Any]] = []
    unknown_parameters: list[str] = []

    serialized_parts, balanced = _split_parameters(value)
    if not balanced:
        errors.append("unterminated quoted-string in Alt-Svc value")
    first = serialized_parts[0] if serialized_parts else ""
    parameter_parts = serialized_parts[1:]

    if "=" not in first:
        errors.append("alternative service must contain protocol-id=alt-authority")
        protocol_id = first.strip() or None
        authority_serialized = None
    else:
        raw_protocol, authority_serialized = first.split("=", 1)
        protocol_id = raw_protocol.strip()
        authority_serialized = authority_serialized.strip()

    if protocol_id is not None:
        protocol_errors, protocol_warnings = _validate_protocol_id(protocol_id)
        errors.extend(protocol_errors)
        warnings.extend(protocol_warnings)

    authority, authority_errors, authority_warnings = _parse_alt_authority(
        authority_serialized or "",
        origin_host=origin_host,
    )
    errors.extend(authority_errors)
    warnings.extend(authority_warnings)

    for part in parameter_parts:
        if not part:
            errors.append("empty Alt-Svc parameter")
            continue
        name, parameter_value, quoted, param_errors = _parse_parameter(part)
        errors.extend(param_errors)
        if name is None or parameter_value is None:
            continue
        parameters.setdefault(name, []).append(parameter_value)
        parameter_order.append(
            {"name": name, "value": parameter_value, "quoted": quoted}
        )

    for name, values in parameters.items():
        if name in {"ma", "persist"} and len(values) > 1:
            warnings.append(f"{name} parameter appears more than once; value is ambiguous")
        if name not in {"ma", "persist"}:
            unknown_parameters.append(name)

    ma = 86400
    ma_values = parameters.get("ma", [])
    if ma_values:
        first_entry = next(
            (entry for entry in parameter_order if entry["name"] == "ma"),
            None,
        )
        ma_value = ma_values[0]
        if first_entry and first_entry["quoted"]:
            errors.append("ma parameter must use unquoted delta-seconds")
        if not ma_value.isdigit():
            errors.append("ma parameter must be a non-negative integer")
        else:
            ma = int(ma_value)

    persist = False
    persist_values = parameters.get("persist", [])
    if persist_values:
        first_entry = next(
            (entry for entry in parameter_order if entry["name"] == "persist"),
            None,
        )
        persist_value = persist_values[0]
        if first_entry and first_entry["quoted"]:
            errors.append("persist parameter must use the unquoted value 1")
        if persist_value == "1":
            persist = True
        else:
            warnings.append("persist value other than 1 is ignored by RFC 7838")

    age = response_age if isinstance(response_age, int) and response_age >= 0 else None
    remaining_freshness = max(0, ma - age) if age is not None else None

    return {
        "raw": value,
        "protocol_id": protocol_id,
        "authority": authority,
        "parameters": parameters,
        "parameter_order": parameter_order,
        "unknown_parameters": sorted(set(unknown_parameters)),
        "ma": ma,
        "ma_defaulted": not bool(ma_values),
        "persist": persist,
        "response_age": age,
        "remaining_freshness": remaining_freshness,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
    }


def analyze_alt_svc_headers(
    header_values: list[str] | tuple[str, ...] = (),
    *,
    origin_url: str,
    response_age: int | None = None,
) -> dict[str, Any]:
    """Parse RFC 7838 Alt-Svc response fields without contacting alternatives.

    Missing Alt-Svc is informational. Unknown extension parameters are retained
    and ignored for conformance purposes. The analysis never opens a connection
    to an advertised alternative service.
    """
    values = [str(value).strip() for value in header_values if str(value).strip()]
    errors: list[str] = []
    warnings: list[str] = []
    members: list[str] = []

    try:
        origin_host = urlsplit(origin_url).hostname
    except ValueError:
        origin_host = None
        errors.append("origin URL is not valid enough to resolve inherited Alt-Svc host")

    for field_index, field_value in enumerate(values, start=1):
        field_members, structurally_valid = _split_http_list(field_value)
        if not structurally_valid:
            errors.append(f"Alt-Svc field {field_index} has an invalid comma-list")
        if not field_members:
            errors.append(f"Alt-Svc field {field_index} contains no value")
        members.extend(field_members)

    clear_members = [member for member in members if member == "clear"]
    alternative_members = [member for member in members if member != "clear"]
    clear = bool(clear_members)

    if clear and alternative_members:
        errors.append(
            'Alt-Svc "clear" must not be combined with alternative services'
        )
    if len(clear_members) > 1:
        errors.append('Alt-Svc "clear" must be the sole field value')

    alternatives = [
        _parse_alt_value(
            member,
            origin_host=origin_host,
            response_age=response_age,
        )
        for member in alternative_members
    ]
    for alternative in alternatives:
        errors.extend(alternative["errors"])
        warnings.extend(alternative["warnings"])

    protocol_ids = [alt["protocol_id"] for alt in alternatives if alt["protocol_id"]]
    changed_hosts = [
        alt["authority"]["resolved_host"]
        for alt in alternatives
        if alt["authority"].get("host_changed")
    ]

    return {
        "present": bool(values),
        "valid": not errors,
        "review": bool(errors or warnings),
        "header_values": values,
        "clear": clear,
        "alternative_count": len(alternatives),
        "alternatives": alternatives,
        "protocol_ids": protocol_ids,
        "changed_hosts": changed_hosts,
        "errors": errors,
        "warnings": warnings,
        "alternatives_contacted": False,
    }


__all__ = ["analyze_alt_svc_headers"]
