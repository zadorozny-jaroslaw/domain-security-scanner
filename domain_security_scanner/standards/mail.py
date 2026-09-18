from __future__ import annotations

import re
from typing import Iterable


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
