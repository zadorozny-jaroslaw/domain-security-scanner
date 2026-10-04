from __future__ import annotations

import logging
import re
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .models import (
    DnsQueryCacheKey,
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)
from .runtime_logging import TRACE_LEVEL


logger = logging.getLogger(__name__)


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
        edns_version: int | None = None,
        edns_payload: int | None = None,
        want_dnssec: bool = False,
        recursion_desired: bool = False,
    ) -> DnsQueryCacheKey:
        """Build a normalized cache key for one DNS query context."""
        return DnsQueryCacheKey.build(
            host,
            rtype,
            mode=mode,
            transport=transport,
            server_name=server_name,
            server_ip=server_ip,
            edns_version=edns_version,
            edns_payload=edns_payload,
            want_dnssec=want_dnssec,
            recursion_desired=recursion_desired,
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
        edns_version: int | None = None,
        edns_payload: int | None = None,
        want_dnssec: bool = False,
        recursion_desired: bool = False,
    ) -> DnsQueryCacheKey:
        """Return a context-complete authoritative query profile."""
        return cls._dns_cache_key(
            host,
            rtype,
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=transport,
            server_name=server_name,
            server_ip=server_ip,
            edns_version=edns_version,
            edns_payload=edns_payload,
            want_dnssec=want_dnssec,
            recursion_desired=recursion_desired,
        )

    @staticmethod
    def _trace_recursive_dns_result(
        result: DnsQueryResult,
        *,
        cache_hit: bool,
        elapsed_ms: float | None = None,
    ) -> None:
        """Emit bounded recursive DNS diagnostics without record/error payloads."""
        if cache_hit:
            logger.log(
                TRACE_LEVEL,
                "DNS cache hit: recursive %s %s -> %s",
                result.qname,
                result.qtype,
                result.state.value,
            )
            return

        logger.log(
            TRACE_LEVEL,
            "DNS recursive: %s %s -> %s (%.3fms)",
            result.qname,
            result.qtype,
            result.state.value,
            elapsed_ms if elapsed_ms is not None else 0.0,
        )

    @staticmethod
    def _trace_authoritative_dns_result(
        result: DnsQueryResult,
        *,
        cache_hit: bool,
    ) -> None:
        """Emit bounded direct-DNS diagnostics without record/error payloads."""
        transport = (
            result.transport.value
            if isinstance(result.transport, DnsTransport)
            else str(result.transport or "udp")
        )
        server_ip = result.server_ip or "unknown"

        if cache_hit:
            logger.log(
                TRACE_LEVEL,
                "DNS cache hit: authoritative %s %s via %s %s -> %s",
                result.qname,
                result.qtype,
                transport,
                server_ip,
                result.state.value,
            )
            return

        logger.log(
            TRACE_LEVEL,
            "DNS authoritative: %s %s via %s %s -> %s (%.3fms)",
            result.qname,
            result.qtype,
            transport,
            server_ip,
            result.state.value,
            result.elapsed_ms if result.elapsed_ms is not None else 0.0,
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
        edns_version: int | None = None,
        edns_payload: int | None = None,
        want_dnssec: bool = False,
        recursion_desired: bool = False,
    ) -> DnsQueryResult | None:
        """Return cached evidence for one authoritative query profile."""
        return self.dns_query_cache.get(
            self._authoritative_dns_cache_key(
                host,
                rtype,
                server_ip=server_ip,
                server_name=server_name,
                transport=transport,
                edns_version=edns_version,
                edns_payload=edns_payload,
                want_dnssec=want_dnssec,
                recursion_desired=recursion_desired,
            )
        )

    def dns_query_result(self, host: str, rtype: str) -> DnsQueryResult:
        """Return cached recursive DNS evidence."""
        cache_key = self._recursive_dns_cache_key(host, rtype)
        host_key = cache_key.qname
        rtype_key = cache_key.qtype

        cached = self.dns_query_cache.get(cache_key)
        if cached is not None:
            self._trace_recursive_dns_result(cached, cache_hit=True)
            return cached

        started = time.perf_counter()
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

        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        self.dns_query_cache[cache_key] = result
        self._trace_recursive_dns_result(
            result,
            cache_hit=False,
            elapsed_ms=elapsed_ms,
        )
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
    def _section_has_rtype(section, rtype: str) -> bool:
        """Return True when a DNS message section contains the requested RR type."""
        target = rtype.upper()
        return any(
            rrset.rdtype == dns.rdatatype.from_text(target)
            for rrset in section
        )

    @classmethod
    def _authoritative_state(
        cls,
        response,
        *,
        require_authoritative: bool = True,
    ) -> DnsQueryState:
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
        if (
            require_authoritative
            and rcode in {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}
            and not (response.flags & dns.flags.AA)
        ):
            return DnsQueryState.NOT_AUTHORITATIVE

        if rcode == dns.rcode.NOERROR:
            if response.answer:
                return DnsQueryState.ANSWER

            # RFC 2308 requires authoritative negative answers to include the
            # zone SOA in the authority section. Without it, the response is not
            # strong enough evidence to classify the RRset as absent.
            if cls._section_has_rtype(response.authority, "SOA"):
                return DnsQueryState.NO_ANSWER
            return DnsQueryState.ERROR

        if rcode == dns.rcode.NXDOMAIN:
            if cls._section_has_rtype(response.authority, "SOA"):
                return DnsQueryState.NXDOMAIN
            return DnsQueryState.ERROR

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
        edns_version: int | None = None,
        edns_payload: int | None = None,
        want_dnssec: bool = False,
        recursion_desired: bool = False,
    ) -> DnsQueryResult:
        """Query one DNS server directly over an explicit transport/profile.

        ``edns_version=None`` sends an ordinary DNS query without EDNS. Passing
        ``edns_version=0`` with a bounded payload creates a distinct EDNS(0)
        observation. ``want_dnssec=True`` requests DNSSEC records using the DO
        bit and is also part of the cache identity. ``recursion_desired=True``
        sets RD for the controlled issue #19 open-recursion observation; normal
        authoritative queries continue to clear RD.

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
            edns_version=edns_version,
            edns_payload=edns_payload,
            want_dnssec=want_dnssec,
            recursion_desired=recursion_desired,
        )
        cached = self.dns_query_cache.get(cache_key)
        if cached is not None:
            self._trace_authoritative_dns_result(cached, cache_hit=True)
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
                use_edns=cache_key.edns_version,
                want_dnssec=cache_key.want_dnssec,
                payload=cache_key.edns_payload,
                request_payload=cache_key.edns_payload,
            )
            if cache_key.recursion_desired:
                query.flags |= dns.flags.RD
            else:
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

            state = self._authoritative_state(
                response,
                require_authoritative=not cache_key.recursion_desired,
            )
            if state == DnsQueryState.TRUNCATED:
                error = "DNS response was truncated; retry explicitly over TCP"
            elif state == DnsQueryState.NOT_AUTHORITATIVE:
                error = "DNS response was not authoritative (AA=0)"
            elif state == DnsQueryState.ERROR:
                rcode_text = dns.rcode.to_text(response.rcode())
                if (
                    response.rcode() in {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}
                    and bool(response.flags & dns.flags.AA)
                    and not self._section_has_rtype(response.authority, "SOA")
                ):
                    error = (
                        "Authoritative negative response did not include SOA "
                        "evidence"
                    )
                else:
                    error = f"DNS RCODE {rcode_text}"

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

        common = dict(
            error=error,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=transport_value,
            server_name=cache_key.server_name,
            server_ip=cache_key.server_ip,
            request_edns_version=cache_key.edns_version,
            request_edns_payload=cache_key.edns_payload,
            request_want_dnssec=cache_key.want_dnssec,
            request_recursion_desired=cache_key.recursion_desired,
            elapsed_ms=elapsed_ms,
        )

        if response is None:
            result = DnsQueryResult(
                qname,
                qtype,
                state,
                **common,
            )
        else:
            has_edns = response.edns >= 0
            result = DnsQueryResult(
                qname,
                qtype,
                state,
                self._dns_answer_records(response),
                rcode=dns.rcode.to_text(response.rcode()),
                aa=bool(response.flags & dns.flags.AA),
                tc=bool(response.flags & dns.flags.TC),
                edns_version=response.edns if has_edns else None,
                edns_payload=response.payload if has_edns else None,
                edns_flags=response.ednsflags if has_edns else None,
                answer_section=self._dns_section_text(response.answer),
                authority_section=self._dns_section_text(response.authority),
                additional_section=self._dns_section_text(response.additional),
                rd=bool(response.flags & dns.flags.RD),
                ra=bool(response.flags & dns.flags.RA),
                **common,
            )

        self.dns_query_cache[cache_key] = result
        self._trace_authoritative_dns_result(result, cache_hit=False)
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
