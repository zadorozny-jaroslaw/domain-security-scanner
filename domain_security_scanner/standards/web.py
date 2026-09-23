from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlsplit


_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_BAD_URI_CHAR_RE = re.compile(r"[\x00-\x20\x7f]")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def is_well_formed_uri_reference(value: str, *, require_absolute: bool = False) -> bool:
    """Practical RFC 3986 URI-reference validation for scanner-controlled fields.

    This deliberately validates the generic structure needed by the scanner
    rather than attempting to implement every scheme-specific rule.
    """
    value = str(value or "").strip()
    if not value or _BAD_URI_CHAR_RE.search(value) or _BAD_PERCENT_RE.search(value):
        return False
    try:
        parsed = urlsplit(value)
        # Force urllib to validate bracketed IPv6/ports when present.
        _ = parsed.hostname
        _ = parsed.port
    except (TypeError, ValueError):
        return False
    if parsed.scheme and not _SCHEME_RE.fullmatch(parsed.scheme):
        return False
    if parsed.scheme.lower() in {"http", "https"} and not parsed.netloc:
        return False
    if require_absolute and not parsed.scheme:
        return False
    return True


def analyze_redirect(status_code: int, location: str, source_url: str) -> dict[str, Any]:
    """Analyze an HTTP redirect using RFC 9110 Location/3xx semantics."""
    status_code = int(status_code)
    location = str(location or "").strip()
    redirect_status = status_code in {301, 302, 303, 307, 308}
    valid_location = bool(location) and is_well_formed_uri_reference(location)
    resolved = urljoin(source_url, location) if valid_location else None
    secure_target = bool(
        redirect_status
        and resolved
        and urlsplit(resolved).scheme.lower() == "https"
    )
    return {
        "status_code": status_code,
        "location": location or None,
        "redirect_status": redirect_status,
        "valid_location": valid_location,
        "resolved_location": resolved,
        "secure_target": secure_target,
    }


def _unquote_http_token(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        body = value[1:-1]
        return re.sub(r"\\(.)", r"\1", body)
    return value


def analyze_hsts(header_values: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """Validate Strict-Transport-Security syntax and active-policy state.

    RFC 6797 requires max-age, unique directives, and at most one server-sent
    STS field. Unknown syntactically valid directives are retained but ignored.
    """
    values = [str(v).strip() for v in header_values if str(v).strip()]
    result: dict[str, Any] = {
        "present": bool(values),
        "valid": False,
        "active": False,
        "max_age": None,
        "include_subdomains": False,
        "unknown_directives": [],
        "errors": [],
        "warnings": [],
        "header_values": values,
    }
    if not values:
        return result

    if len(values) > 1:
        result["errors"].append("server sent more than one Strict-Transport-Security field")

    value = values[0]
    seen: set[str] = set()
    directives: dict[str, str | None] = {}
    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" in part:
            name, raw_value = part.split("=", 1)
            name = name.strip()
            raw_value = raw_value.strip()
            if not _TOKEN_RE.fullmatch(name) or not raw_value:
                result["errors"].append(f"invalid HSTS directive syntax: {part}")
                continue
            # directive-value is token or quoted-string. This practical parser
            # accepts a quoted string with HTTP-style backslash escaping.
            if raw_value.startswith('"'):
                if len(raw_value) < 2 or not raw_value.endswith('"'):
                    result["errors"].append(f"invalid quoted HSTS directive value: {part}")
                    continue
            elif not _TOKEN_RE.fullmatch(raw_value):
                result["errors"].append(f"invalid HSTS directive value: {part}")
                continue
            parsed_value: str | None = _unquote_http_token(raw_value)
        else:
            name = part.strip()
            if not _TOKEN_RE.fullmatch(name):
                result["errors"].append(f"invalid HSTS directive syntax: {part}")
                continue
            parsed_value = None

        key = name.lower()
        if key in seen:
            result["errors"].append(f"duplicate HSTS directive: {name}")
            continue
        seen.add(key)
        directives[key] = parsed_value

    max_age = directives.get("max-age")
    if max_age is None:
        result["errors"].append("missing required max-age directive")
    elif not str(max_age).isdigit():
        result["errors"].append("max-age must contain only decimal digits")
    else:
        result["max_age"] = int(max_age)

    if "includesubdomains" in directives:
        if directives["includesubdomains"] is not None:
            result["errors"].append("includeSubDomains must not have a value")
        else:
            result["include_subdomains"] = True

    known = {"max-age", "includesubdomains"}
    result["unknown_directives"] = [name for name in directives if name not in known]

    result["valid"] = not result["errors"]
    result["active"] = bool(result["valid"] and (result["max_age"] or 0) > 0)
    if result["valid"] and result["max_age"] == 0:
        result["warnings"].append("max-age=0 disables the HSTS policy")
    return result


def _split_http_list(value: str) -> list[str]:
    """Split an HTTP comma-list without breaking quoted-string values."""
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
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        items.append(item)
    return items


def _is_http_quoted_string(value: str) -> bool:
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


def analyze_http_cache_policy(
    cache_control_values: list[str] | tuple[str, ...] = (),
    *,
    expires_values: list[str] | tuple[str, ...] = (),
    age_values: list[str] | tuple[str, ...] = (),
    pragma_values: list[str] | tuple[str, ...] = (),
    warning_values: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Analyze response caching metadata using conservative RFC 9111 semantics.

    The helper validates syntax and highlights ambiguity/deprecated response
    metadata. It intentionally does not assume that a public Web page ought to
    be cacheable or non-cacheable; absence of Cache-Control is informational.
    Unknown extension directives are retained and accepted.
    """
    cache_values = [str(v).strip() for v in cache_control_values if str(v).strip()]
    expires = [str(v).strip() for v in expires_values if str(v).strip()]
    age_headers = [str(v).strip() for v in age_values if str(v).strip()]
    pragma = [str(v).strip() for v in pragma_values if str(v).strip()]
    obsolete_warning = [str(v).strip() for v in warning_values if str(v).strip()]

    errors: list[str] = []
    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    directives: dict[str, list[str | None]] = {}

    for field_value in cache_values:
        for raw_directive in _split_http_list(field_value):
            if "=" in raw_directive:
                raw_name, raw_value = raw_directive.split("=", 1)
                name = raw_name.strip()
                argument = raw_value.strip()
                if not _TOKEN_RE.fullmatch(name) or not argument:
                    errors.append(f"invalid Cache-Control directive syntax: {raw_directive}")
                    continue
                quoted = argument.startswith('"')
                if quoted:
                    if not _is_http_quoted_string(argument):
                        errors.append(f"invalid quoted Cache-Control value: {raw_directive}")
                        continue
                elif not _TOKEN_RE.fullmatch(argument):
                    errors.append(f"invalid Cache-Control value: {raw_directive}")
                    continue
                value: str | None = _unquote_http_token(argument)
            else:
                name = raw_directive.strip()
                if not _TOKEN_RE.fullmatch(name):
                    errors.append(f"invalid Cache-Control directive syntax: {raw_directive}")
                    continue
                argument = None
                quoted = False
                value = None

            key = name.lower()
            entries.append({
                "name": key,
                "value": value,
                "raw_value": argument,
                "quoted": quoted,
            })
            directives.setdefault(key, []).append(value)

    response_no_argument = {
        "must-revalidate",
        "must-understand",
        "no-store",
        "no-transform",
        "proxy-revalidate",
        "public",
    }
    request_only = {"max-stale", "min-fresh", "only-if-cached"}
    known_response = response_no_argument | {
        "max-age",
        "s-maxage",
        "no-cache",
        "private",
    }

    for entry in entries:
        name = entry["name"]
        value = entry["value"]
        if name in response_no_argument and value is not None:
            errors.append(f"{name} response directive must not have an argument")
        elif name in {"max-age", "s-maxage"}:
            if value is None:
                errors.append(f"{name} response directive requires delta-seconds")
            elif entry["quoted"]:
                errors.append(f"{name} response directive must use an unquoted delta-seconds value")
            elif not str(value).isdigit():
                errors.append(f"{name} response directive must be a non-negative integer")
        elif name in {"no-cache", "private"} and value is not None:
            if not entry["quoted"]:
                warnings.append(f"qualified {name} should use a quoted field-name list")
            field_names = [item.strip() for item in str(value).split(",")]
            if not field_names or any(not _TOKEN_RE.fullmatch(item) for item in field_names):
                errors.append(f"qualified {name} contains an invalid field-name list")
        elif name in request_only:
            warnings.append(f"request-only cache directive appears in a response: {name}")

    duplicate_directives = sorted(
        name for name, values in directives.items() if len(values) > 1
    )
    for name in duplicate_directives:
        if name in known_response or name in request_only:
            warnings.append(f"duplicate Cache-Control directive: {name}")

    if "no-cache" in directives and ({"max-age", "s-maxage"} & directives.keys()):
        warnings.append(
            "freshness directive coexists with no-cache; the more restrictive revalidation rule applies"
        )
    if "no-store" in directives and "public" in directives:
        warnings.append(
            "public coexists with no-store; the more restrictive no-store rule applies"
        )
    if "private" in directives and "public" in directives:
        warnings.append(
            "public coexists with private; the more restrictive private rule applies"
        )

    age_members: list[str] = []
    for value in age_headers:
        age_members.extend(_split_http_list(value))
    age = None
    if len(age_members) > 1:
        warnings.append("multiple Age values were received; RFC 9111 uses the first member")
    if age_members:
        if age_members[0].isdigit():
            age = int(age_members[0])
        else:
            errors.append("Age must be a non-negative integer")

    expires_at = None
    expires_valid = None
    if len(expires) > 1:
        warnings.append("multiple Expires field values were received")
    if expires:
        try:
            parsed = parsedate_to_datetime(expires[0])
            if parsed is None:
                raise ValueError("unparseable HTTP-date")
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            expires_at = parsed.astimezone(timezone.utc).isoformat()
            expires_valid = True
        except (TypeError, ValueError, OverflowError):
            expires_valid = False
            warnings.append(
                "invalid Expires date is interpreted as already expired by RFC 9111"
            )

    if pragma:
        warnings.append(
            "Pragma in a response is deprecated and does not reliably replace Cache-Control"
        )
    if obsolete_warning:
        warnings.append("Warning response header is obsoleted by RFC 9111")

    unknown_directives = sorted(name for name in directives if name not in known_response and name not in request_only)
    max_age_values = directives.get("max-age", [])
    s_maxage_values = directives.get("s-maxage", [])
    max_age = int(max_age_values[0]) if max_age_values and str(max_age_values[0]).isdigit() else None
    s_maxage = int(s_maxage_values[0]) if s_maxage_values and str(s_maxage_values[0]).isdigit() else None

    if s_maxage is not None:
        freshness_source = "s-maxage"
    elif max_age is not None:
        freshness_source = "max-age"
    elif expires:
        freshness_source = "expires" if expires_valid else "expires-invalid"
    else:
        freshness_source = "heuristic/unspecified"

    return {
        "present": bool(cache_values or expires or age_headers or pragma or obsolete_warning),
        "cache_control_present": bool(cache_values),
        "valid": not errors,
        "review": bool(errors or warnings),
        "cache_control_values": cache_values,
        "directives": directives,
        "duplicate_directives": duplicate_directives,
        "unknown_directives": unknown_directives,
        "max_age": max_age,
        "s_maxage": s_maxage,
        "expires_values": expires,
        "expires_at": expires_at,
        "expires_valid": expires_valid,
        "age_values": age_members,
        "age": age,
        "pragma_values": pragma,
        "warning_values": obsolete_warning,
        "freshness_source": freshness_source,
        "no_store": "no-store" in directives,
        "no_cache": "no-cache" in directives,
        "private": "private" in directives,
        "public": "public" in directives,
        "errors": errors,
        "warnings": warnings,
    }

def _parse_content_type(value: str) -> tuple[str, dict[str, str]]:
    parts = [part.strip() for part in str(value or "").split(";")]
    media_type = parts[0].lower() if parts else ""
    params: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        params[key.strip().lower()] = val.strip().strip('"').lower()
    return media_type, params


def _parse_rfc3339(value: str) -> datetime | None:
    value = str(value or "").strip()
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
        value,
    ):
        return None
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _security_txt_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-----") or line.lower().startswith("hash:"):
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]+(.+?)\s*$", line)
        if not match:
            continue
        fields.setdefault(match.group(1).lower(), []).append(match.group(2).strip())
    return fields


def analyze_security_txt(
    *,
    status_code: int,
    text: str,
    content_type: str,
    requested_url: str,
    final_url: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the core RFC 9116 requirements for a fetched security.txt."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    fields = _security_txt_fields(text)
    errors: list[str] = []
    warnings: list[str] = []

    media_type, content_params = _parse_content_type(content_type)
    charset = content_params.get("charset")

    if int(status_code) != 200:
        errors.append(f"security.txt returned HTTP {status_code}")
    if urlsplit(requested_url).scheme.lower() != "https":
        errors.append("security.txt must be requested over HTTPS")
    if urlsplit(requested_url).path != "/.well-known/security.txt":
        errors.append("security.txt must use the /.well-known/security.txt path")
    if not is_well_formed_uri_reference(final_url, require_absolute=True):
        errors.append("final security.txt URL is not a valid absolute URI")
    elif urlsplit(final_url).scheme.lower() != "https":
        errors.append("security.txt redirect chain must remain on HTTPS")
    elif urlsplit(final_url).hostname != urlsplit(requested_url).hostname:
        warnings.append("security.txt redirected to a different host; manual trust review is recommended")

    if media_type != "text/plain":
        errors.append("Content-Type must be text/plain")
    if charset is None:
        errors.append("Content-Type must declare charset=utf-8")
    elif charset not in {"utf-8", "utf8"}:
        errors.append("Content-Type charset must be utf-8")

    contacts = fields.get("contact", [])
    if not contacts:
        errors.append("missing required Contact field")
    invalid_contacts: list[str] = []
    for contact in contacts:
        if not is_well_formed_uri_reference(contact, require_absolute=True):
            invalid_contacts.append(contact)
            continue
        parsed = urlsplit(contact)
        if parsed.scheme.lower() in {"http", "https"} and parsed.scheme.lower() != "https":
            invalid_contacts.append(contact)
    if invalid_contacts:
        errors.append("invalid Contact URI(s): " + ", ".join(invalid_contacts[:3]))

    expires_values = fields.get("expires", [])
    expires_at = None
    if len(expires_values) != 1:
        errors.append("security.txt must contain exactly one Expires field")
    else:
        expires_at = _parse_rfc3339(expires_values[0])
        if expires_at is None:
            errors.append("Expires must be a valid RFC 3339 date-time")
        elif expires_at <= now:
            errors.append("security.txt is expired")

    canonicals = fields.get("canonical", [])
    invalid_canonicals = [
        value for value in canonicals
        if not is_well_formed_uri_reference(value, require_absolute=True)
        or urlsplit(value).scheme.lower() != "https"
    ]
    if invalid_canonicals:
        errors.append("invalid Canonical URI(s): " + ", ".join(invalid_canonicals[:3]))
    if canonicals and requested_url not in canonicals:
        warnings.append("retrieval URI is not listed in Canonical fields")

    return {
        "present": int(status_code) == 200,
        "valid": not errors,
        "status_code": int(status_code),
        "requested_url": requested_url,
        "final_url": final_url,
        "content_type": content_type or None,
        "fields": fields,
        "contacts": contacts,
        "expires": expires_values[0] if len(expires_values) == 1 else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "canonicals": canonicals,
        "errors": errors,
        "warnings": warnings,
    }


def analyze_set_cookie_header(header: str) -> dict[str, Any]:
    """Analyze one Set-Cookie field against RFC 10025 server requirements."""
    raw = str(header or "")
    parts = [part.strip() for part in raw.split(";")]
    errors: list[str] = []
    warnings: list[str] = []
    if not parts or "=" not in parts[0]:
        return {
            "raw": raw,
            "name": None,
            "value": None,
            "secure": False,
            "httponly": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "rfc_errors": ["invalid Set-Cookie cookie-pair"],
            "rfc_warnings": [],
        }

    name, value = parts[0].split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        errors.append("cookie name must not be empty")

    attrs: dict[str, str | None] = {}
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            attr_name, attr_value = part.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_value = attr_value.strip()
        else:
            attr_name = part.strip().lower()
            attr_value = None
        if not attr_name:
            errors.append("empty cookie attribute name")
            continue
        if attr_name in attrs:
            errors.append(f"duplicate cookie attribute: {attr_name}")
            continue
        attrs[attr_name] = attr_value

    secure = "secure" in attrs
    httponly = "httponly" in attrs
    same_site_raw = attrs.get("samesite")
    same_site = same_site_raw.strip() if isinstance(same_site_raw, str) else None
    domain = attrs.get("domain")
    path = attrs.get("path")

    if same_site is not None and same_site.lower() not in {"strict", "lax", "none"}:
        errors.append(f"invalid SameSite value: {same_site}")
    if same_site is not None and same_site.lower() == "none" and not secure:
        errors.append("SameSite=None requires Secure")

    lower_name = name.lower()
    if lower_name.startswith("__secure-") and not secure:
        errors.append("__Secure- cookie prefix requires Secure")
    if lower_name.startswith("__host-"):
        if not secure:
            errors.append("__Host- cookie prefix requires Secure")
        if domain is not None:
            errors.append("__Host- cookie prefix forbids Domain")
        if path != "/":
            errors.append("__Host- cookie prefix requires Path=/")

    return {
        "raw": raw,
        "name": name or None,
        "value": value,
        "secure": secure,
        "httponly": httponly,
        "samesite": same_site,
        "domain": domain,
        "path": path,
        "rfc_errors": errors,
        "rfc_warnings": warnings,
    }


__all__ = [
    "analyze_hsts",
    "analyze_http_cache_policy",
    "analyze_redirect",
    "analyze_security_txt",
    "analyze_set_cookie_header",
    "is_well_formed_uri_reference",
]
