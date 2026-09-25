# Shared DNS evidence layer

The v1.3 DNS work uses a shared evidence layer so recursive lookups and direct
authoritative queries can be represented without conflating record absence with
network or protocol failure.

The implementation lives in `domain_security_scanner/dns_evidence.py` and uses
the typed DNS models in `domain_security_scanner/models.py`.

## Compatibility

Existing recursive callers keep the established interfaces:

```python
dns_query_result(host, rtype)
dns_query(host, rtype)
```

This allows the Domain, Discovery, and Mail scan groups to continue using the
normal configured resolver without knowing about authoritative-query details.

Direct authoritative queries use a separate API:

```python
authoritative_dns_query_result(
    host,
    rtype,
    server_ip=...,
    server_name=...,
    transport=...,
)
```

The target is a literal IPv4 or IPv6 address. IPv6 addresses are canonicalized
before they participate in cache identity.

## Evidence model

`DnsQueryResult` preserves the compatibility fields `host`, `rtype`, `records`,
and `error`, and adds DNS-specific context where it is observable:

- query mode: recursive or authoritative;
- explicit UDP/TCP transport for direct queries;
- authoritative server name and IP;
- RCODE;
- AA and TC flags;
- EDNS version, payload, and flags;
- answer, authority, and additional sections;
- elapsed query time.

The `qname` and `qtype` properties are aliases for the existing `host` and
`rtype` fields.

## Result states

The shared state model distinguishes:

| State | Meaning |
| --- | --- |
| `answer` | usable positive answer evidence |
| `no_answer` | authoritative NODATA/no-answer evidence |
| `nxdomain` | authoritative non-existence evidence |
| `timeout` | query timed out |
| `servfail` | server returned SERVFAIL |
| `not_authoritative` | response did not set AA where authoritative evidence was required |
| `truncated` | TC was set; the response is incomplete |
| `transport_error` | TCP/UDP transport failed |
| `error` | other resolver/protocol/evidence error |

Only `no_answer` and `nxdomain` are treated as record absence. Timeout,
SERVFAIL, non-authoritative, truncated, transport-error, and generic error
states are unavailable/inconclusive evidence.

## Authoritative-query behavior

Direct authoritative requests:

- clear the RD flag;
- target exactly one supplied server IP;
- use exactly the requested UDP or TCP transport;
- do not silently convert UDP evidence into TCP evidence;
- preserve TC so callers can explicitly request a separate TCP query;
- cache each server/transport/query context independently.

A failure from one authoritative server is therefore evidence about that server,
not a zone-wide conclusion.

## Negative DNS evidence

Negative conclusions are deliberately conservative.

For direct authoritative evidence:

- `NOERROR` with an empty answer becomes `no_answer` only when AA is set and
  the authority section contains SOA evidence;
- `NXDOMAIN` becomes conclusive only when AA is set and the authority section
  contains SOA evidence;
- `AA=0` becomes `not_authoritative`;
- a truncated response remains `truncated`;
- an authoritative-looking negative response without SOA evidence remains
  `error`/inconclusive.

This follows the DNS negative-caching model in RFC 2308 and prevents referrals,
intermediary responses, incomplete replies, or malformed negative responses from
being promoted into confident record absence.

## Cache identity

`DnsQueryCacheKey` includes:

```text
qname
qtype
mode
transport
server_name
server_ip
```

Recursive lookups leave transport/server fields unset because the high-level
resolver may choose or retry transport internally. Direct authoritative queries
always record the explicit transport and server endpoint.

## Safety and scope

The evidence layer is low-impact infrastructure. It does not itself enumerate
all authoritative servers or perform broad probing. It does not perform:

- AXFR/IXFR;
- DNS fuzzing;
- amplification testing;
- high-volume recursion tests;
- malformed-packet testing.

Later v1.3 checks can build delegation, transport, consistency, DNSSEC, CAA,
negative-DNS, and recursion analysis on this evidence layer while retaining the
same conservative failure semantics.

## Standards context

The evidence transport and message model is based on the normal DNS behavior
defined by RFC 1034 and RFC 1035. EDNS metadata follows RFC 6891. Conservative
negative-answer handling uses RFC 2308.

These references support the shared evidence infrastructure; the project's
`docs/STANDARDS.md` registry remains focused on standards that directly define
implemented user-facing scanner checks.
