# v1.3.0 DNS implementation plan

## Release theme

**Authoritative DNS & DNSSEC Posture**

v1.3.0 should deepen the `domain` scan group enough that DNS is no longer only an inventory/record-presence feature.

The release should remain low-impact and externally observable. The scanner should query public DNS infrastructure conservatively and should not perform intrusive DNS testing.

## Design principles

### Preserve evidence quality

DNS conclusions must continue to distinguish:

- positive answers;
- authoritative no-data responses;
- NXDOMAIN;
- timeout;
- SERVFAIL;
- transport failure;
- malformed/unusable evidence;
- genuinely unavailable evidence.

A timeout must not become "record missing". A failure from one authoritative server must not automatically become a zone-wide failure.

### Separate recursive and authoritative DNS

The current simple resolver path is useful for normal inventory, mail checks, and discovery.

v1.3.0 should add a distinct direct-authoritative path so the scanner can truthfully compare individual authoritative servers.

The shared DNS layer should support evidence such as:

```text
qname
qtype
server_name
server_ip
query_mode: recursive | authoritative
transport: udp | tcp
state
rcode
authoritative
truncated
edns
records
authority_records
additional_records
elapsed_ms
error
```

The query cache must include enough context to avoid treating results from different authoritative servers or transports as equivalent.

### Keep standards logic separate from network I/O

Prefer small analyzers that accept structured evidence and return structured conclusions.

This makes RFC behavior testable without live DNS and keeps network failures separate from standards parsing.

## Workstream 1 - Shared DNS evidence layer

### Required

- Move generic DNS query/evidence helpers out of the mail scanner.
- Keep the current cached recursive lookup behavior for existing callers.
- Add direct authoritative querying.
- Support UDP and TCP.
- Capture response code and AA/TC flags.
- Capture authority/additional sections when useful.
- Capture EDNS presence/version where observable.
- Keep timeout/SERVFAIL/error states explicit.
- Extend cache keys for query mode, server, transport, and relevant query options.
- Preserve existing public JSON fields unless intentionally changed.

### Acceptance criteria

- Existing mail/domain/discovery tests continue to pass.
- Recursive and authoritative evidence cannot collide in cache.
- Tests cover answer, no-answer, NXDOMAIN, timeout, SERVFAIL, and transport failure.
- No existing check starts treating unavailable DNS evidence as a confirmed absence.

## Workstream 2 - Delegation and authoritative nameservers

### Checks

#### Nameserver redundancy

Keep the current minimum-two-nameserver posture check, but base it on delegation evidence rather than only RDAP metadata when authoritative DNS evidence is available.

#### Parent/child NS consistency

Compare:

- NS delegation returned by the parent;
- apex NS RRset returned by the child authoritative servers.

Report stale or inconsistent delegation conservatively.

#### Lame delegation

For every delegated nameserver:

- resolve usable server addresses;
- query the zone directly;
- confirm it returns authoritative evidence for the zone.

A delegated server that is reachable but not authoritative should be a high-priority finding.

#### Nameserver addressability

Record A/AAAA evidence for every delegated NS.

Do not classify temporary lookup failure as "no address".

#### Glue

For in-bailiwick nameservers:

- collect parent-side glue;
- compare it with current authoritative address records where possible;
- identify missing or materially inconsistent glue.

Treat migration/transitional differences conservatively unless they cause actual resolution failure.

#### NS target aliasing

Detect invalid/problematic NS targets that resolve through CNAME-style aliasing rather than directly to address records.

### Primary standards

- RFC 1034
- RFC 1035
- RFC 1912
- RFC 2181
- RFC 2182

## Workstream 3 - Authoritative transport and consistency

### UDP/TCP availability

Query each authoritative server directly with a small SOA request over:

- UDP;
- TCP.

TCP support is required for modern DNS operation and should be assessed separately from UDP reachability.

### SOA consistency

Collect authoritative SOA from each available server and compare:

- MNAME;
- serial;
- refresh;
- retry;
- expire;
- negative-cache/minimum field.

A serial mismatch alone should normally be `REVIEW`, because a scan may observe normal propagation.

A delegated server that does not provide an authoritative SOA is a stronger failure.

### NS RRset consistency

Compare apex NS answers from authoritative servers.

Material disagreement should be reported separately from simple SOA serial skew.

### EDNS(0)

Perform a small bounded EDNS(0) observation.

Do not turn v1.3.0 into an EDNS compliance test suite. The goal is to identify obvious cases where ordinary DNS works but valid EDNS queries are mishandled.

### Primary standards

- RFC 6891
- RFC 7766
- RFC 8906
- RFC 9210
- RFC 2308

## Workstream 4 - DNSSEC validation

DNSSEC should move from "delegation detected" to structured validation.

### Required evidence

Collect:

- DS from the parent/delegation path;
- DNSKEY from the child zone;
- RRSIG evidence required to validate selected RRsets.

### Required checks

#### DS to DNSKEY match

Determine whether at least one delegation DS corresponds to a currently published DNSKEY.

A DS with no usable matching DNSKEY is a high-priority failure because validating resolvers may reject the zone.

#### DNSKEY RRset validation

Validate the DNSKEY RRset where sufficient evidence is available.

#### Selected apex RRset validation

Validate a small, deterministic set of signed apex RRsets rather than attempting to validate every record in the zone.

#### Signature time validity

Detect:

- expired signatures;
- not-yet-valid signatures;
- unverifiable signatures.

#### DNSSEC state

Expose an explicit state such as:

```text
unsigned
secure
broken
unknown
```

Do not report `secure` merely because a DS exists.

### Algorithm policy

Use current IANA DNSSEC algorithm/digest policy as the operational source of truth.

Relevant standards include:

- RFC 4033
- RFC 4034
- RFC 4035
- RFC 9904
- RFC 9905
- RFC 9906

Do not hard-code an obsolete RFC 8624-era policy table as though it were current.

Prefer a versioned internal policy snapshot so scanner scoring does not change unexpectedly because an external registry changed during a scan.

Record the policy snapshot date/version in code or structured evidence.

### NSEC/NSEC3

If DNSSEC is enabled:

- identify NSEC vs NSEC3 where practical;
- record NSEC3 parameters;
- apply RFC 9276 guidance conservatively.

NSEC3 parameter recommendations should normally be advisory/non-scoring.

## Workstream 5 - CAA correctness

The current CAA behavior should be replaced with an RFC-correct effective-policy lookup.

### Required

For an exact target such as:

```text
shop.eu.example.com
```

walk upward as required to determine the first applicable CAA RRset, rather than checking only the exact target and registered root.

Record:

```text
lookup_chain
effective_name
records
analysis
```

### Parse

- flags;
- property tag;
- value;
- `issue`;
- `issuewild`;
- `iodef`;
- unknown tags;
- issuer-critical handling.

### Additional advisory support

If time permits, parse RFC 8657 ACME-related CAA parameters such as:

- `accounturi`;
- `validationmethods`.

### Primary standards

- RFC 8659
- RFC 8657

## Workstream 6 - Negative DNS, wildcard, and recursion observations

### Negative-answer evidence

Use a generated, clearly non-existent label under the zone and observe authoritative behavior.

Record whether the response is:

- NXDOMAIN;
- NODATA;
- wildcard answer;
- unavailable/unknown.

Where applicable, record authoritative SOA evidence from the negative response.

### Wildcard DNS

If randomized labels consistently resolve, report wildcard behavior as informational context rather than automatically as a security failure.

### Open recursion

Perform one controlled out-of-zone recursive query against each authoritative server.

If an authoritative server provides recursion to an arbitrary external client, report it as a security issue.

Do not measure amplification or send high-volume recursion probes.

### Primary standards

- RFC 2308
- RFC 5358

## JSON/report model

Keep existing `dns_records` for compatibility.

Add a richer additive DNS structure along these lines:

```json
{
  "dns": {
    "delegation": {
      "parent_ns": [],
      "child_ns": [],
      "consistent": null,
      "glue": {}
    },
    "authoritative_servers": [],
    "soa": {
      "consistent": null,
      "serials": {}
    },
    "dnssec": {
      "status": "unknown",
      "ds": [],
      "dnskeys": [],
      "matching_keys": [],
      "algorithms": [],
      "rrsig": {},
      "denial": {}
    },
    "caa": {
      "lookup_chain": [],
      "effective_name": null,
      "records": [],
      "analysis": {}
    },
    "negative_response": {},
    "wildcard": {}
  }
}
```

The exact schema may evolve during implementation, but it should remain additive and structured.

## Scoring guidance

Score infrastructure failures more heavily than advisory RFC observations.

### High importance

- lame delegated nameserver;
- delegated nameserver unreachable;
- delegated NS with no usable address;
- materially broken parent/child delegation;
- DS present with no matching DNSKEY;
- invalid/expired DNSSEC signatures;
- DNSSEC cryptographic validation failure;
- externally available open recursion.

### Medium/low importance

- only one authoritative NS;
- TCP failure on one of several otherwise healthy servers;
- material authoritative RRset disagreement;
- malformed effective CAA policy.

### Advisory/non-scoring by default

- temporary SOA serial skew;
- EDNS implementation observations;
- NSEC vs NSEC3;
- non-preferred but still permitted DNSSEC parameters;
- wildcard behavior;
- informational CDS/CDNSKEY evidence.

Do not make the score a count of implemented RFCs.

## Explicitly deferred beyond v1.3.0

- default AXFR/IXFR attempts;
- malformed-packet or protocol fuzzing;
- DNS amplification testing;
- ASN/provider/geolocation diversity scoring;
- DANE/TLSA;
- SVCB/HTTPS deep validation;
- complete CDS/CDNSKEY lifecycle validation;
- exhaustive DNSSEC validation of every zone RRset.

## Suggested implementation order

1. Shared DNS evidence layer.
2. Delegation and authoritative nameserver checks.
3. UDP/TCP, SOA, NS consistency, and bounded EDNS evidence.
4. DNSSEC validation and algorithm policy.
5. CAA processing.
6. Negative DNS, wildcard, and open recursion checks.
7. JSON/PDF integration and scoring calibration.
8. Authorized real-world smoke tests and release documentation.

## Release gate

Before v1.3.0:

- all unit tests pass;
- DNS-specific tests cover success, failure, and unavailable-evidence states;
- `--scan domain` works without unrelated scan groups;
- existing `mail` and `discovery` behavior remains compatible;
- no DNS test unexpectedly performs high-volume or intrusive probing;
- generated JSON distinguishes recursive evidence from individual authoritative-server evidence;
- generated PDF explains major delegation and DNSSEC problems in customer-friendly language;
- authorized smoke tests include at least:
  - a normal unsigned domain;
  - a correctly DNSSEC-signed domain;
  - a domain with multiple authoritative servers;
  - controlled fixtures/mocks for broken DNSSEC and lame delegation;
- README, standards documentation, changelog, example report, and release checklist are updated as applicable.

No new DNS RFC scope should be added after stabilization begins. Unfinished optional work should move to a later release rather than delaying or destabilizing v1.3.0.
