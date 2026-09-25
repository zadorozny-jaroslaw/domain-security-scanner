from __future__ import annotations

import dns.exception
import dns.resolver

from .models import (
    DnsQueryCacheKey,
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


class DnsEvidenceMixin:
    """Shared DNS query/evidence helpers.

    Recursive callers keep the existing ``dns_query_result(host, rtype)`` and
    ``dns_query(host, rtype)`` APIs. Cache identity is now context-complete so
    future direct authoritative UDP/TCP queries cannot collide with recursive
    evidence or with evidence from another authoritative server.
    """

    @staticmethod
    def _dns_cache_key(
        host: str,
        rtype: str,
        *,
        mode: DnsQueryMode | str,
        transport: DnsTransport | str | None = None,
        server_name: str | None = None,
        server_ip: str | None = None,
    ) -> DnsQueryCacheKey:
        """Build a normalized cache key for one DNS query context."""
        return DnsQueryCacheKey.build(
            host,
            rtype,
            mode=mode,
            transport=transport,
            server_name=server_name,
            server_ip=server_ip,
        )

    @classmethod
    def _recursive_dns_cache_key(
        cls,
        host: str,
        rtype: str,
    ) -> DnsQueryCacheKey:
        """Return the context-complete key for normal recursive resolution."""
        return cls._dns_cache_key(
            host,
            rtype,
            mode=DnsQueryMode.RECURSIVE,
        )

    def dns_cached_result(
        self,
        host: str,
        rtype: str,
    ) -> DnsQueryResult | None:
        """Return cached recursive evidence without issuing a new query."""
        return self.dns_query_cache.get(
            self._recursive_dns_cache_key(host, rtype)
        )

    def dns_query_result(self, host: str, rtype: str) -> DnsQueryResult:
        """Return cached recursive DNS evidence.

        Absence and resolver failure remain distinct. Recursive callers retain
        their existing method signature and behavior.
        """
        cache_key = self._recursive_dns_cache_key(host, rtype)
        host_key = cache_key.qname
        rtype_key = cache_key.qtype

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
                    query_mode=DnsQueryMode.RECURSIVE,
                )
            else:
                result = DnsQueryResult(
                    host_key,
                    rtype_key,
                    DnsQueryState.ANSWER,
                    tuple(record.to_text() for record in ans),
                    query_mode=DnsQueryMode.RECURSIVE,
                )
        except dns.resolver.NXDOMAIN:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.NXDOMAIN,
                query_mode=DnsQueryMode.RECURSIVE,
            )
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.TIMEOUT,
                error=str(exc),
                query_mode=DnsQueryMode.RECURSIVE,
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
                query_mode=DnsQueryMode.RECURSIVE,
            )
        except Exception as exc:
            result = DnsQueryResult(
                host_key,
                rtype_key,
                DnsQueryState.ERROR,
                error=str(exc),
                query_mode=DnsQueryMode.RECURSIVE,
            )

        self.dns_query_cache[cache_key] = result
        return result

    def dns_query(self, host: str, rtype: str) -> list[str]:
        """Compatibility wrapper returning records for inventory/report output."""
        return list(self.dns_query_result(host, rtype).records)

    @staticmethod
    def _dns_unavailable_message(result: DnsQueryResult) -> str:
        """Return the existing short human-readable query failure label."""
        labels = {
            DnsQueryState.TIMEOUT: "timeout",
            DnsQueryState.SERVFAIL: "SERVFAIL",
            DnsQueryState.TRANSPORT_ERROR: "transport error",
            DnsQueryState.ERROR: "resolver error",
        }
        return labels.get(result.state, result.state.value)
