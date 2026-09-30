from __future__ import annotations

from copy import deepcopy
from typing import Any


_SUSPECT_DIRECT_PATH = {"suspected_interception", "mixed"}


def _rrset_values(dns: dict[str, Any], qtype: str) -> tuple[str, ...]:
    encrypted = dns.get("encrypted_recursive") or {}
    rrsets = encrypted.get("rrsets") or {}
    rrset = rrsets.get(str(qtype).upper()) or {}
    if str(rrset.get("status") or "").lower() != "consensus":
        return ()
    return tuple(
        str(value).strip()
        for value in (rrset.get("rdata") or ())
        if str(value).strip()
    )


def _direct_path_suspect(dns: dict[str, Any]) -> bool:
    path = dns.get("path_integrity") or {}
    return str(path.get("status") or "unknown").lower() in _SUSPECT_DIRECT_PATH


def _encrypted_dnssec_secure(dns: dict[str, Any]) -> bool:
    dnssec = dns.get("dnssec") or {}
    return (
        str(dnssec.get("status") or "unknown").lower() == "secure"
        and str(dnssec.get("validation_source") or "").lower()
        == "encrypted_recursive"
    )


def _soa_serial(soa_rdata: tuple[str, ...]) -> str | None:
    if len(soa_rdata) != 1:
        return None
    parts = soa_rdata[0].split()
    if len(parts) != 7:
        return None
    return parts[2]


def recover_customer_dns_checks(
    checks: list[dict[str, Any]],
    dns: dict[str, Any],
) -> list[dict[str, Any]]:
    """Reduce dependent VERIFY noise when a trusted encrypted zone view exists.

    Direct per-server checks are never promoted to PASS merely because DoH works.
    The only promoted check is zone-level SOA service: two validating encrypted
    resolvers supplied the same SOA and the scanner locally validated RRSIG(SOA).
    Checks that specifically require per-server attribution become informational
    when the direct port-53 path is known to be untrustworthy.
    """
    if not _direct_path_suspect(dns):
        return [dict(check) for check in checks]

    soa = _rrset_values(dns, "SOA")
    ns = _rrset_values(dns, "NS")
    secure = _encrypted_dnssec_secure(dns)
    serial = _soa_serial(soa)

    recovered: list[dict[str, Any]] = []
    for source in checks:
        check = dict(source)
        if str(check.get("status") or "").lower() != "unknown":
            recovered.append(check)
            continue

        name = str(check.get("name") or "")

        if name == "Authoritative SOA service" and secure and soa:
            check.update(
                status="pass",
                message=(
                    "Strefa publikuje podpisany apex SOA, zgodny w dwóch niezależnych "
                    "resolverach DNS-over-HTTPS. Scanner lokalnie zwalidował RRSIG(SOA); "
                    "bezpośrednie przypisanie odpowiedzi do konkretnego serwera "
                    "autorytatywnego pozostaje niedostępne z tej sieci."
                ),
                earned=check.get("weight", 0) or 0,
                applicable=True,
            )
            recovered.append(check)
            continue

        if name == "Authoritative SOA consistency" and secure and soa:
            check.update(
                status="info",
                message=(
                    "Dwa niezależne resolvery DoH zwróciły ten sam, kryptograficznie "
                    "zwalidowany SOA na poziomie strefy. Spójność pomiędzy każdym "
                    "autorytatywnym NS nie została zmierzona bezpośrednio, ponieważ "
                    "lokalna ścieżka portu 53 jest przechwytywana."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        if name == "Authoritative SOA serial" and secure and soa:
            serial_text = f" {serial}" if serial else ""
            check.update(
                status="info",
                message=(
                    f"Zaobserwowano podpisany SOA serial{serial_text} zgodnie przez dwa "
                    "niezależne resolvery DoH. Równość seriala pomiędzy każdym "
                    "autorytatywnym NS nie została bezpośrednio zmierzona z tej sieci."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        if name == "Authoritative NS RRset consistency" and secure and ns:
            check.update(
                status="info",
                message=(
                    "Dwa niezależne resolvery DoH zwróciły ten sam, zwalidowany DNSSEC "
                    "apex NS RRset. Bezpośrednie porównanie RRsetu pomiędzy każdym "
                    "autorytatywnym endpointem pozostaje niedostępne z tej sieci."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        if name == "Authoritative EDNS(0)":
            check.update(
                status="info",
                message=(
                    "Per-server EDNS(0) nie został oceniony, ponieważ bezpośrednia "
                    "ścieżka DNS na porcie 53 wykazuje przechwycenie/przepisywanie."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        if name == "Authoritative negative DNS":
            check.update(
                status="info",
                message=(
                    "Per-server negative-DNS/wildcard probing nie jest oceniane z tej "
                    "lokalizacji, ponieważ bezpośrednia ścieżka DNS na porcie 53 jest "
                    "niewiarygodna. Ten stan jest doradczy i nie wpływa na scoring."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        if name == "DNSSEC denial of existence" and secure:
            check.update(
                status="info",
                message=(
                    "Łańcuch DNSSEC oraz wybrane apex RRsety zostały poprawnie "
                    "zwalidowane. Typ mechanizmu denial-of-existence (NSEC/NSEC3) nie "
                    "został sklasyfikowany z tej lokalizacji; jest to obserwacja "
                    "doradcza i nie wpływa na scoring."
                ),
                earned=0,
                applicable=False,
            )
            recovered.append(check)
            continue

        recovered.append(check)

    return recovered


def enrich_dns_records_for_report(
    dns_records: dict[str, Any],
    root_domain: str,
    dns: dict[str, Any],
) -> dict[str, Any]:
    """Add consensus NS/SOA to the report-only legacy DNS inventory.

    Existing values are never replaced. The scanner's internal ``dns_records``
    object is not mutated, preserving legacy collection semantics while allowing
    the PDF appendix to show trusted records recovered through HTTPS/443.
    """
    result = deepcopy(dns_records or {})
    root = str(root_domain or "").strip()
    if not root:
        return result

    encrypted = dns.get("encrypted_recursive") or {}
    if not encrypted.get("attempted") or str(encrypted.get("status") or "") != "usable":
        return result

    ns = _rrset_values(dns, "NS")
    soa = _rrset_values(dns, "SOA")
    if not ns and not soa:
        return result

    records = result.setdefault(root, {})
    if ns and not records.get("NS"):
        records["NS"] = list(ns)
    if soa and not records.get("SOA"):
        records["SOA"] = list(soa)
    return result


__all__ = [
    "enrich_dns_records_for_report",
    "recover_customer_dns_checks",
]
