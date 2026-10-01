from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from .encrypted_dns import (
    ENCRYPTED_DNS_USABLE,
    RRSET_CONSENSUS,
    EncryptedDnsEvidence,
)

RECOVERY_SOURCE = "rdap_registry_plus_encrypted_dns"


@dataclass(frozen=True)
class DnsZoneRecovery:
    """Zone-level recovery that never claims per-authoritative-server attribution."""

    zone: str
    available: bool
    source: str = RECOVERY_SOURCE
    registry_nameservers: tuple[str, ...] = ()
    encrypted_nameservers: tuple[str, ...] = ()
    registry_zone_consistent: bool | None = None
    redundancy_confirmed: bool = False
    addressable_nameservers: tuple[str, ...] = ()
    all_nameservers_addressable: bool | None = None
    alias_free: bool | None = None
    alias_names: tuple[str, ...] = ()
    in_bailiwick_nameservers: tuple[str, ...] = ()
    glue_required: bool | None = None
    dnssec_validation_status: str | None = None


def _normalize_name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _normalized_names(values: Iterable[Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                name
                for value in values
                if (name := _normalize_name(value))
            }
        )
    )


def _rrset_values(
    evidence: EncryptedDnsEvidence | None,
    qtype: str,
) -> tuple[str, ...]:
    if evidence is None:
        return ()
    target = str(qtype).upper()
    for rrset in evidence.rrsets:
        if rrset.qtype == target and rrset.status == RRSET_CONSENSUS:
            return _normalized_names(rrset.rdata) if target == "NS" else tuple(rrset.rdata)
    return ()


def build_dns_zone_recovery(
    rdap: Any,
    encrypted_dns: EncryptedDnsEvidence | None,
    encrypted_dnssec_validation: Any = None,
) -> DnsZoneRecovery:
    """Build conservative registry/zone recovery from encrypted evidence.

    This recovery is intentionally zone-level. It can confirm the registry NS
    set, redundant nameservers, and encrypted A/AAAA observability, but it does
    not prove that a particular authoritative server IP answered the scanner.
    """
    rdap = rdap if isinstance(rdap, dict) else {}
    zone = _normalize_name(
        getattr(encrypted_dns, "zone", None)
        or rdap.get("root_domain")
    )
    registry_nameservers = _normalized_names(rdap.get("nameservers") or ())
    encrypted_nameservers = _rrset_values(encrypted_dns, "NS")

    encrypted_usable = bool(
        encrypted_dns is not None
        and encrypted_dns.attempted
        and encrypted_dns.status == ENCRYPTED_DNS_USABLE
        and encrypted_nameservers
    )

    registry_zone_consistent: bool | None = None
    if registry_nameservers and encrypted_nameservers:
        registry_zone_consistent = registry_nameservers == encrypted_nameservers

    nameserver_by_name = {
        _normalize_name(item.name): item
        for item in (getattr(encrypted_dns, "nameservers", ()) or ())
        if _normalize_name(getattr(item, "name", ""))
    }
    expected_nameservers = encrypted_nameservers if encrypted_usable else ()
    addressable_nameservers = tuple(
        name
        for name in expected_nameservers
        if name in nameserver_by_name
        and bool(nameserver_by_name[name].confirmed_addressable)
    )
    if (
        expected_nameservers
        and all(name in nameserver_by_name for name in expected_nameservers)
        and len(addressable_nameservers) == len(expected_nameservers)
    ):
        all_nameservers_addressable: bool | None = True
    else:
        # Encrypted host lookups are promotion-only: missing/partial evidence does
        # not prove a nameserver lacks addresses.
        all_nameservers_addressable = None

    alias_names = tuple(
        name
        for name in expected_nameservers
        if name in nameserver_by_name
        and nameserver_by_name[name].alias_status == "alias"
    )
    if expected_nameservers and all(name in nameserver_by_name for name in expected_nameservers):
        statuses = tuple(nameserver_by_name[name].alias_status for name in expected_nameservers)
        if all(status == "direct" for status in statuses):
            alias_free: bool | None = True
        elif alias_names:
            alias_free = False
        else:
            alias_free = None
    else:
        alias_free = None

    in_bailiwick = tuple(
        name
        for name in expected_nameservers
        if zone and (name == zone or name.endswith("." + zone))
    )
    glue_required = bool(in_bailiwick) if expected_nameservers else None

    validation_status = getattr(encrypted_dnssec_validation, "status", None)
    validation_status = getattr(validation_status, "value", validation_status)

    return DnsZoneRecovery(
        zone=zone,
        available=encrypted_usable,
        registry_nameservers=registry_nameservers,
        encrypted_nameservers=encrypted_nameservers,
        registry_zone_consistent=registry_zone_consistent,
        redundancy_confirmed=bool(
            registry_zone_consistent is True
            and len(encrypted_nameservers) >= 2
        ),
        addressable_nameservers=addressable_nameservers,
        all_nameservers_addressable=all_nameservers_addressable,
        alias_free=alias_free,
        alias_names=alias_names,
        in_bailiwick_nameservers=in_bailiwick,
        glue_required=glue_required,
        dnssec_validation_status=(str(validation_status) if validation_status else None),
    )


def recover_delegation_findings(findings, recovery: DnsZoneRecovery):
    """Promote only previously unknown delegation checks from stronger zone evidence."""
    recovered = []
    ns_text = ", ".join(recovery.encrypted_nameservers)

    for finding in findings:
        if getattr(finding, "status", None) != "unknown" or not recovery.available:
            recovered.append(finding)
            continue

        if finding.name == "Name server redundancy" and recovery.redundancy_confirmed:
            recovered.append(
                replace(
                    finding,
                    status="pass",
                    message=(
                        f"RDAP registry metadata and two independent DNS-over-HTTPS resolvers "
                        f"agree on {len(recovery.encrypted_nameservers)} nameservers: {ns_text}."
                    ),
                    earned=finding.weight,
                    applicable=True,
                )
            )
            continue

        if (
            finding.name == "DNS delegation consistency"
            and recovery.registry_zone_consistent is True
        ):
            recovered.append(
                replace(
                    finding,
                    status="pass",
                    message=(
                        "Registry/RDAP nameserver metadata matches the encrypted apex NS RRset "
                        "returned consistently by two independent resolvers. Direct parent-wire "
                        "attribution remains unavailable from this network, so the evidence source "
                        "is registry plus encrypted zone observation."
                    ),
                    earned=finding.weight,
                    applicable=True,
                )
            )
            continue

        if (
            finding.name == "Nameserver addressability"
            and recovery.all_nameservers_addressable is True
        ):
            recovered.append(
                replace(
                    finding,
                    status="pass",
                    message=(
                        "Each recovered registry/zone nameserver has a direct A or AAAA record "
                        "observed independently through both encrypted DNS resolvers."
                    ),
                    earned=finding.weight,
                    applicable=True,
                )
            )
            continue

        if finding.name == "Delegation glue" and recovery.glue_required is False:
            recovered.append(
                replace(
                    finding,
                    status="info",
                    message=(
                        "The recovered nameserver set is entirely out-of-bailiwick for the assessed "
                        "zone; parent-side glue is not required for these NS targets."
                    ),
                    weight=0,
                    earned=0,
                    applicable=False,
                )
            )
            continue

        if finding.name == "Nameserver target aliasing":
            if recovery.alias_free is True:
                recovered.append(
                    replace(
                        finding,
                        status="pass",
                        message=(
                            "Encrypted A/AAAA observations confirm direct address RRsets for all "
                            "recovered NS targets; no CNAME dependency was observed at those owners."
                        ),
                        weight=0,
                        earned=0,
                        applicable=True,
                    )
                )
                continue
            if recovery.alias_free is False and recovery.alias_names:
                recovered.append(
                    replace(
                        finding,
                        status="warn",
                        message=(
                            "Two encrypted DNS paths observed CNAME dependency for delegated NS "
                            "targets: " + ", ".join(recovery.alias_names) + "."
                        ),
                        weight=0,
                        earned=0,
                        applicable=True,
                    )
                )
                continue

        recovered.append(finding)

    return tuple(recovered)


def dns_zone_recovery_report_data(recovery: DnsZoneRecovery | None) -> dict[str, Any]:
    if recovery is None:
        return {
            "available": False,
            "source": RECOVERY_SOURCE,
            "registry_nameservers": [],
            "encrypted_nameservers": [],
            "registry_zone_consistent": None,
            "redundancy_confirmed": False,
            "all_nameservers_addressable": None,
            "alias_free": None,
            "glue_required": None,
        }

    return {
        "available": recovery.available,
        "source": recovery.source,
        "zone": recovery.zone,
        "registry_nameservers": list(recovery.registry_nameservers),
        "encrypted_nameservers": list(recovery.encrypted_nameservers),
        "registry_zone_consistent": recovery.registry_zone_consistent,
        "redundancy_confirmed": recovery.redundancy_confirmed,
        "addressable_nameservers": list(recovery.addressable_nameservers),
        "all_nameservers_addressable": recovery.all_nameservers_addressable,
        "alias_free": recovery.alias_free,
        "alias_names": list(recovery.alias_names),
        "in_bailiwick_nameservers": list(recovery.in_bailiwick_nameservers),
        "glue_required": recovery.glue_required,
        "dnssec_validation_status": recovery.dnssec_validation_status,
        "scope": {
            "zone_level_only": True,
            "per_authoritative_server_attribution": False,
            "promotion_only_for_scored_delegation_checks": True,
        },
    }


__all__ = [
    "DnsZoneRecovery",
    "RECOVERY_SOURCE",
    "build_dns_zone_recovery",
    "dns_zone_recovery_report_data",
    "recover_delegation_findings",
]
