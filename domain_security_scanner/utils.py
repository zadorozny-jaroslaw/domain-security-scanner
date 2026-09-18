from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional
from urllib.parse import urlparse


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/")[0].strip(".")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}", value):
        raise ValueError(f"Nieprawidłowa domena: {value}")
    return value

COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "com.pl", "net.pl", "org.pl", "biz.pl", "info.pl",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr",
}

def fallback_root_domain(host: str) -> str:
    host = normalize_domain(host)
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in COMMON_MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def is_in_scope_host(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    return host == domain or host.endswith("." + domain)

def days_until(value: str) -> Optional[int]:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None

