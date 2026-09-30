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

## Direct-path integrity and encrypted recovery

v1.3 also evaluates whether direct responses can be trusted as coming from the
intended destination. A single unusual flag is not enough to call a path
intercepted. The path-integrity layer combines signals such as unexpected
recursion availability on RD=0 requests, referral-like apex responses, wrong
referral owners, or AA responses that omit the requested apex RRset.

When the aggregate direct path is `suspected_interception` or mixed, the Domain
scan can make a bounded encrypted fallback through two independent validating
DNS-over-HTTPS resolvers. That fallback is explicitly `recursive` evidence over
HTTPS/443. It can recover zone-level SOA/NS/DS/DNSKEY and nameserver A/AAAA
material, but it does not acquire the identity of a specific authoritative
endpoint.

For DNSSEC, consensus material from the encrypted path can be promoted only
after local DS-to-DNSKEY and RRSIG validation succeeds. For ordinary
authoritative checks, the fallback cannot turn per-server transport, EDNS,
SOA-serial consistency, negative-DNS, or open-recursion uncertainty into a
server-specific pass.

For operator-facing examples, interpretation guidance, and diagnostics for
Pi-hole/router/VPN/ISP DNS rewriting, see
[DNS_TROUBLESHOOTING.md](DNS_TROUBLESHOOTING.md).

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

## Delegation evidence built on this layer

Issue #14 now uses the shared evidence primitives to build structured delegation
state in `domain_security_scanner/domains/domain/delegation.py` and pure analysis
in `delegation_analysis.py`.

The delegation collector:

- obtains the immediate parent-side referral independently from the child's
  recursive apex NS result;
- retains the parent referral's delegated NS names and glue;
- records recursive A/AAAA/CNAME evidence for every delegated NS;
- combines resolved addresses and observed referral glue into usable endpoint
  candidates without treating lookup failure as confirmed no-address;
- performs bounded direct UDP apex-NS queries against delegated servers;
- keeps per-server and per-endpoint query evidence rather than promoting one
  endpoint failure into a zone-wide conclusion.

The analyzer derives parent/child NS consistency only from positively
authoritative (`AA=1`) child apex NS answers. A timeout, transport failure, or
incomplete endpoint sample remains unknown. A nameserver is only classified as
lame when positive non-authoritative evidence is sufficient and no retained
unprobed endpoint could still change that server-level conclusion.

The completed integration exposes this richer evidence under the additive
public `dns` object while retaining the legacy `dns_records` surface. Recursive,
direct-authoritative, and encrypted-recursive provenance remain distinct in the
serialized report, and the PDF renders a compact customer-facing DNS posture.

See [DNS_DELEGATION.md](DNS_DELEGATION.md) for the delegation model.

## Safety and scope

The evidence layer is low-impact infrastructure. It does not itself enumerate
all authoritative servers or perform broad probing. It does not perform:

- AXFR/IXFR;
- DNS fuzzing;
- amplification testing;
- high-volume recursion tests;
- malformed-packet testing.

The completed v1.3 Domain/DNS stack builds delegation, bounded authoritative
transport/SOA/NS observations, DNSSEC, CAA, negative-DNS/wildcard, recursion,
path-integrity, and encrypted recovery on this evidence model while retaining
the same conservative failure semantics.

## Standards context

The evidence transport and message model is based on the normal DNS behavior
defined by RFC 1034 and RFC 1035. EDNS metadata follows RFC 6891. Conservative
negative-answer handling uses RFC 2308.

These references support the shared evidence infrastructure; the project's
`docs/STANDARDS.md` registry remains focused on standards that directly define
implemented user-facing scanner checks.
