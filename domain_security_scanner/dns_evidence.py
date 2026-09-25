from __future__ import annotations

import dns.exception
import dns.resolver

from .models import DnsQueryResult, DnsQueryState


class DnsEvidenceMixin:
    """Shared recursive DNS query/evidence helpers.

    This is the first v1.3 DNS infrastructure step. It intentionally preserves
    the existing recursive-resolver behavior and cache identity so Domain, Mail,
    and Discovery callers continue to behave exactly as before.

    Direct authoritative queries, transport-aware evidence, richer response
    metadata, and context-aware cache identities are added in later #13 steps.
    """

    @staticmethod
    def _recursive_dns_cache_key(host: str, rtype: str) -> tuple[str, str]:
        """Return the legacy recursive cache key in one centralized place."""
        return host.lower().rstrip("."), rtype.upper()

    def dns_query_result(self, host: str, rtype: str) -> DnsQueryResult:
        """Return cached recursive DNS evidence.

        Absence and resolver failure remain distinct. This method deliberately
        preserves the pre-v1.3 public/internal behavior while moving generic DNS
        ownership out of the Mail scan group.
        """
        host_key, rtype_key = self._recursive_dns_cache_key(host, rtype)
        cache_key = (host_key, rtype_key)

        cached = self.dns_query_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            ans = self.resolver.resolve(
                host_key,
                rtype_key,
                raise_on_no_answer=False,
            )
            if ans.rrset is None:
                result = DnsQueryResult(
                    host_key,
                    rtype_key,
                    DnsQueryState.NO_ANSWER,
                )
            else:
                result = DnsQueryResult(
                    host_key,
                    rtype_key,
                    DnsQueryState.ANSWER,
                    tuple(record.to_text() for record in ans),
                )
        except dns.resolver.NXDOMAIN:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.NXDOMAIN,
            )
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.TIMEOUT,
                error=str(exc),
            )
        except dns.resolver.NoNameservers as exc:
            state = (
                DnsQueryState.SERVFAIL
                if "SERVFAIL" in str(exc).upper()
                else DnsQueryState.ERROR
            )
            result = DnsQueryResult(
                host_key,
                rtype_key,
                state,
                error=str(exc),
            )
        except Exception as exc:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.ERROR,
                error=str(exc),
            )

        self.dns_query_cache[cache_key] = result
        return result

    def dns_query(self, host: str, rtype: str) -> list[str]:
        """Compatibility wrapper returning records for inventory/report output."""
        return list(self.dns_query_result(host, rtype).records)

    @staticmethod
    def _dns_unavailable_message(result: DnsQueryResult) -> str:
        """Return the existing short human-readable resolver failure label."""
        labels = {
            DnsQueryState.TIMEOUT: "timeout",
            DnsQueryState.SERVFAIL: "SERVFAIL",
            DnsQueryState.ERROR: "resolver error",
        }
        return labels.get(result.state, result.state.value)
