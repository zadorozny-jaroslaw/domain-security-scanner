from __future__ import annotations

import re
from datetime import datetime, timezone
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
    "analyze_redirect",
    "analyze_security_txt",
    "analyze_set_cookie_header",
    "is_well_formed_uri_reference",
]
