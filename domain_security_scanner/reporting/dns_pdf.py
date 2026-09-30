from __future__ import annotations

from typing import Any


_STATUS_LABELS = {
    "pass": "OK",
    "warn": "REVIEW",
    "fail": "ACTION",
    "info": "INFO",
    "unknown": "VERIFY",
}


def status_label(status: str) -> str:
    return _STATUS_LABELS.get(str(status or "unknown").lower(), "VERIFY")


def _dnssec_row(dns: dict[str, Any]) -> dict[str, str]:
    state = str((dns.get("dnssec") or {}).get("status") or "unknown").lower()
    if state == "secure":
        return {
            "status": "pass",
            "item": "DNSSEC",
            "value": "SECURE - bounded DNSSEC validation completed successfully.",
        }
    if state == "unsigned":
        return {
            "status": "warn",
            "item": "DNSSEC",
            "value": "UNSIGNED - no DNSSEC chain of trust was observed; this is not a broken chain.",
        }
    if state == "broken":
        return {
            "status": "fail",
            "item": "DNSSEC",
            "value": "BROKEN - collected DNSSEC evidence failed validation.",
        }
    return {
        "status": "unknown",
        "item": "DNSSEC",
        "value": "VERIFY - DNSSEC could not be classified reliably from the available evidence.",
    }


def _delegation_row(dns: dict[str, Any]) -> dict[str, str]:
    delegation = dns.get("delegation") or {}
    if not delegation.get("available"):
        return {
            "status": "unknown",
            "item": "Delegation",
            "value": "Parent delegation could not be verified reliably.",
        }

    consistent = delegation.get("consistent")
    complete = bool(delegation.get("complete"))
    if consistent is True:
        return {
            "status": "pass",
            "item": "Delegation",
            "value": "Parent and authoritative child NS views are consistent.",
        }
    if consistent is False and complete:
        return {
            "status": "fail",
            "item": "Delegation",
            "value": "Confirmed parent/child nameserver mismatch.",
        }
    if consistent is False:
        return {
            "status": "warn",
            "item": "Delegation",
            "value": "Parent/child nameserver mismatch was observed, but child evidence is incomplete.",
        }
    return {
        "status": "unknown",
        "item": "Delegation",
        "value": "Parent/child nameserver consistency could not be determined.",
    }


def _authoritative_ns_row(dns: dict[str, Any]) -> dict[str, str]:
    soa = dns.get("soa") or {}
    consistent = soa.get("ns_rrset_consistent")
    if consistent is True:
        return {
            "status": "pass",
            "item": "Authoritative NS RRset",
            "value": "Observed authoritative apex NS RRsets are consistent.",
        }
    if consistent is False:
        return {
            "status": "warn",
            "item": "Authoritative NS RRset",
            "value": "Observed authoritative apex NS RRsets disagree.",
        }
    return {
        "status": "unknown",
        "item": "Authoritative NS RRset",
        "value": "Authoritative apex NS RRset consistency could not be determined.",
    }


def _open_recursion_row(dns: dict[str, Any]) -> dict[str, str]:
    recursion = dns.get("open_recursion") or {}
    state = str(recursion.get("status") or "unknown").lower()
    if state == "open":
        names = ", ".join(recursion.get("open_servers") or [])
        suffix = f" on: {names}" if names else "."
        return {
            "status": "fail",
            "item": "Open recursion",
            "value": "Externally available recursion was confirmed" + suffix,
        }
    if state == "closed":
        return {
            "status": "pass",
            "item": "Open recursion",
            "value": "Controlled recursion probes did not confirm open recursion.",
        }
    return {
        "status": "unknown",
        "item": "Open recursion",
        "value": "Open recursion could not be confirmed or excluded reliably.",
    }


def _caa_row(dns: dict[str, Any]) -> dict[str, str]:
    caa = dns.get("caa") or {}
    analysis = caa.get("analysis") or {}
    state = str(analysis.get("state") or "unknown").lower()
    effective_name = caa.get("effective_name")

    if state == "unknown":
        return {
            "status": "unknown",
            "item": "CAA",
            "value": "Effective CAA policy could not be resolved reliably.",
        }
    if state == "absent":
        return {
            "status": "warn",
            "item": "CAA",
            "value": "No effective CAA RRset was found in the RFC 8659 lookup chain.",
        }

    source = effective_name or "the effective owner name"
    malformed = analysis.get("syntax_error_records") or analysis.get("malformed_value_records") or []
    if malformed:
        return {
            "status": "warn",
            "item": "CAA",
            "value": f"Effective CAA RRset at {source} contains malformed records or values.",
        }
    return {
        "status": "pass",
        "item": "CAA",
        "value": f"Effective CAA RRset was resolved at {source}.",
    }


def _normalized_dns_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _worst_status(statuses: list[str]) -> str:
    severity = {"pass": 0, "info": 1, "unknown": 2, "warn": 3, "fail": 4}
    return max(statuses, key=lambda status: severity.get(status, 2), default="unknown")


def _delegation_authority_row(
    report: dict[str, Any],
    dns: dict[str, Any],
) -> dict[str, str]:
    delegation = _delegation_row(dns)
    authoritative_ns = _authoritative_ns_row(dns)
    open_recursion = _open_recursion_row(dns)
    caa = _caa_row(dns)

    clauses = [f"Delegation: {status_label(delegation['status'])}"]

    recursion_clause = f"Open recursion: {status_label(open_recursion['status'])}"
    open_servers = (dns.get("open_recursion") or {}).get("open_servers") or []
    if open_recursion["status"] == "fail" and open_servers:
        recursion_clause += " on " + ", ".join(open_servers)
    clauses.append(recursion_clause)

    secondary_statuses = []
    if authoritative_ns["status"] != "pass":
        clauses.append(
            f"Apex NS RRset: {status_label(authoritative_ns['status'])}"
        )
        secondary_statuses.append(authoritative_ns["status"])

    target_name = _normalized_dns_name(
        report.get("target_domain") or report.get("root_domain")
    )
    effective_caa_name = _normalized_dns_name(
        (dns.get("caa") or {}).get("effective_name")
    )
    inherited_caa = bool(
        target_name
        and effective_caa_name
        and effective_caa_name != target_name
    )
    if caa["status"] != "pass" or inherited_caa:
        caa_clause = f"CAA: {status_label(caa['status'])}"
        if effective_caa_name:
            caa_clause += f" at {effective_caa_name}"
        clauses.append(caa_clause)
        secondary_statuses.append(caa["status"])

    combined_status = _worst_status(
        [delegation["status"], open_recursion["status"], *secondary_statuses]
    )
    return {
        "status": combined_status,
        "item": "Delegation / authority",
        "value": ". ".join(clauses) + ".",
    }


def dns_posture_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    """Return a compact customer-facing DNS summary for the PDF report.

    The function consumes only the additive v1.3 ``report['dns']`` structure and
    keeps unknown/unverifiable states explicit instead of turning them into failures.
    The PDF summary intentionally uses two rows: DNSSEC plus a compact delegation /
    authoritative-DNS roll-up. Detailed individual findings remain in ``checks``.
    """
    dns = report.get("dns") or {}
    return [
        _dnssec_row(dns),
        _delegation_authority_row(report, dns),
    ]


__all__ = ["dns_posture_rows", "status_label"]
