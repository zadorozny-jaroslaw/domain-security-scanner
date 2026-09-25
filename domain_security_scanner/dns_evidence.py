from __future__ import annotations

import re
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
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
    ``dns_query(host, rtype)`` APIs. Direct authoritative queries target one
    explicit server address and transport at a time so evidence remains scoped
    to the server that produced it.
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

    @classmethod
    def _authoritative_dns_cache_key(
        cls,
        host: str,
        rtype: str,
        *,
        server_ip: str,
        server_name: str | None = None,
        transport: DnsTransport | str = DnsTransport.UDP,
    ) -> DnsQueryCacheKey:
        """Return a server- and transport-specific authoritative cache key."""
        return cls._dns_cache_key(
            host,
            rtype,
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=transport,
            server_name=server_name,
            server_ip=server_ip,
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

    def authoritative_dns_cached_result(
        self,
        host: str,
        rtype: str,
        *,
        server_ip: str,
        server_name: str | None = None,
        transport: DnsTransport | str = DnsTransport.UDP,
    ) -> DnsQueryResult | None:
        """Return cached evidence for one authoritative server/transport."""
        return self.dns_query_cache.get(
            self._authoritative_dns_cache_key(
                host,
                rtype,
                server_ip=server_ip,
                server_name=server_name,
                transport=transport,
            )
        )

    def dns_query_result(self, host: str, rtype: str) -> DnsQueryResult:
        """Return cached recursive DNS evidence."""
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
    def _sanitize_dns_error(exc: BaseException) -> str:
        """Return a bounded, single-line error suitable for stored evidence."""
        text = re.sub(r"\s+", " ", str(exc or "")).strip()
        if not text:
            text = exc.__class__.__name__
        return text[:240]

    @staticmethod
    def _dns_section_text(section) -> tuple[str, ...]:
        """Serialize DNS RRsets while preserving section ownership/type context."""
        return tuple(rrset.to_text() for rrset in section)

    @staticmethod
    def _dns_answer_records(response) -> tuple[str, ...]:
        """Flatten answer-section RDATA for compatibility-friendly consumers."""
        return tuple(
            rdata.to_text()
            for rrset in response.answer
            for rdata in rrset
        )

    @staticmethod
    def _authoritative_state(response) -> DnsQueryState:
        """Map a direct DNS response into the scanner evidence state model."""
        if response.flags & dns.flags.TC:
            # A truncated response is incomplete evidence. In particular, an
            # empty truncated answer must never become conclusive NO_ANSWER.
            return DnsQueryState.TRUNCATED

        rcode = response.rcode()
        if rcode == dns.rcode.SERVFAIL:
            return DnsQueryState.SERVFAIL

        # NOERROR/NXDOMAIN only become conclusive authoritative evidence when
        # the target server actually sets AA. An AA=0 response can be a referral,
        # cache/intermediary response, or evidence that this server is not
        # authoritative for the queried name; it must never become record absence.
        if rcode in {dns.rcode.NOERROR, dns.rcode.NXDOMAIN} and not (
            response.flags & dns.flags.AA
        ):
            return DnsQueryState.NOT_AUTHORITATIVE

        if rcode == dns.rcode.NOERROR:
            return (
                DnsQueryState.ANSWER
                if response.answer
                else DnsQueryState.NO_ANSWER
            )
        if rcode == dns.rcode.NXDOMAIN:
            return DnsQueryState.NXDOMAIN
        return DnsQueryState.ERROR

    def authoritative_dns_query_result(
        self,
        host: str,
        rtype: str,
        *,
        server_ip: str,
        server_name: str | None = None,
        transport: DnsTransport | str = DnsTransport.UDP,
        timeout: float = 3.0,
    ) -> DnsQueryResult:
        """Query one DNS server directly over an explicit transport.

        The result represents evidence about exactly this server address and
        transport. A timeout, truncated response, transport error, SERVFAIL, or
        other error is cached as that server's evidence only.
        """
        cache_key = self._authoritative_dns_cache_key(
            host,
            rtype,
            server_ip=server_ip,
            server_name=server_name,
            transport=transport,
        )
        cached = self.dns_query_cache.get(cache_key)
        if cached is not None:
            return cached

        qname = cache_key.qname
        qtype = cache_key.qtype
        transport_value = cache_key.transport or DnsTransport.UDP

        started = time.perf_counter()
        response = None
        state = DnsQueryState.ERROR
        error = None

        try:
            query = dns.message.make_query(
                qname,
                qtype,
                use_edns=0,
            )
            query.flags &= ~dns.flags.RD

            if transport_value == DnsTransport.UDP:
                response = dns.query.udp(
                    query,
                    cache_key.server_ip,
                    timeout=timeout,
                    raise_on_truncation=False,
                )
            else:
                response = dns.query.tcp(
                    query,
                    cache_key.server_ip,
                    timeout=timeout,
                )

            state = self._authoritative_state(response)
            if state == DnsQueryState.TRUNCATED:
                error = "DNS response was truncated; retry explicitly over TCP"
            elif state == DnsQueryState.NOT_AUTHORITATIVE:
                error = "DNS response was not authoritative (AA=0)"
            elif state == DnsQueryState.ERROR:
                error = f"DNS RCODE {dns.rcode.to_text(response.rcode())}"

        except dns.exception.Timeout as exc:
            state = DnsQueryState.TIMEOUT
            error = self._sanitize_dns_error(exc)
        except (ConnectionError, OSError, EOFError) as exc:
            state = DnsQueryState.TRANSPORT_ERROR
            error = self._sanitize_dns_error(exc)
        except Exception as exc:
            state = DnsQueryState.ERROR
            error = self._sanitize_dns_error(exc)

        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

        if response is None:
            result = DnsQueryResult(
                qname,
                qtype,
                state,
                error=error,
                query_mode=DnsQueryMode.AUTHORITATIVE,
                transport=transport_value,
                server_name=cache_key.server_name,
                server_ip=cache_key.server_ip,
                elapsed_ms=elapsed_ms,
            )
        else:
            has_edns = response.edns >= 0
            result = DnsQueryResult(
                qname,
                qtype,
                state,
                self._dns_answer_records(response),
                error=error,
                query_mode=DnsQueryMode.AUTHORITATIVE,
                transport=transport_value,
                server_name=cache_key.server_name,
                server_ip=cache_key.server_ip,
                rcode=dns.rcode.to_text(response.rcode()),
                aa=bool(response.flags & dns.flags.AA),
                tc=bool(response.flags & dns.flags.TC),
                edns_version=response.edns if has_edns else None,
                edns_payload=response.payload if has_edns else None,
                edns_flags=response.ednsflags if has_edns else None,
                answer_section=self._dns_section_text(response.answer),
                authority_section=self._dns_section_text(response.authority),
                additional_section=self._dns_section_text(response.additional),
                elapsed_ms=elapsed_ms,
            )

        self.dns_query_cache[cache_key] = result
        return result

    @staticmethod
    def _dns_unavailable_message(result: DnsQueryResult) -> str:
        """Return the existing short human-readable query failure label."""
        labels = {
            DnsQueryState.TIMEOUT: "timeout",
            DnsQueryState.SERVFAIL: "SERVFAIL",
            DnsQueryState.NOT_AUTHORITATIVE: "non-authoritative response",
            DnsQueryState.TRUNCATED: "truncated response",
            DnsQueryState.TRANSPORT_ERROR: "transport error",
            DnsQueryState.ERROR: "resolver error",
        }
        return labels.get(result.state, result.state.value)
