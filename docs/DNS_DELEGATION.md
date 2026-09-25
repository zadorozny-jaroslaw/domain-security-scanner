# DNS delegation and nameserver posture

Issue #14 adds the first user-facing authoritative-DNS posture layer for v1.3.0.
It builds on the shared DNS evidence primitives documented in
[DNS_EVIDENCE.md](DNS_EVIDENCE.md) and keeps network collection separate from
pure analysis and finding generation.

## Scope

The implementation evaluates the registered/root domain's delegation without
attempting zone transfers, DNS fuzzing, amplification testing, nameserver
fingerprinting, or broad server enumeration.

It answers six practical questions:

1. What NS set does the parent actually delegate?
2. Does each delegated NS have usable address evidence?
3. Can each delegated NS provide authoritative service for the zone?
4. Do authoritative child apex NS answers agree with the parent delegation?
5. Is required in-bailiwick glue present and consistent with observed addresses?
6. Does any delegated NS target depend on a CNAME alias?

## Collection path

### 1. Parent-side delegation

The scanner derives the immediate DNS parent from the registered/root domain,
queries that parent NS set through the configured recursive resolver, resolves
candidate parent-server addresses, and sends a bounded direct UDP NS query for
the child zone to a parent authoritative server.

A normal referral has `AA=0` for the child, so referral extraction uses the raw
`NOERROR` authority/additional sections rather than misinterpreting the parent
as authoritative for the child.

The accepted referral records:

- delegated child NS names;
- A/AAAA glue present in the additional section for those delegated names;
- the parent server name/IP that supplied the usable referral;
- all attempted parent direct-query evidence.

A truncated parent response is not accepted as a complete referral.

### 2. Delegated nameserver address evidence

For every nameserver in the parent delegation, the scanner retains separate
recursive results for:

- `A`;
- `AAAA`;
- `CNAME`.

A/AAAA lookup failure is kept separate from conclusive address absence. Parent
referral glue can also supply a usable direct-query endpoint when recursive
address resolution is unavailable.

### 3. Bounded direct authority evidence

The scanner sends direct UDP apex-NS queries to representative endpoints for
each delegated NS.

The current #14 strategy is intentionally server-level rather than exhaustive
endpoint testing:

- one deterministic endpoint is tested first for every delegated NS;
- when that endpoint positively returns authoritative (`AA=1`) apex NS
  evidence, no additional #14 endpoint probe is needed for that server;
- when the first endpoint is inconclusive/non-authoritative, at most one
  fallback endpoint is tested;
- unprobed candidate addresses remain explicitly recorded.

This keeps the scan low-impact and leaves exhaustive transport/address-family
consistency to issue #15.

## Analysis semantics

Network collection is converted into structured conclusions by pure analysis
helpers. Those helpers do not perform DNS I/O.

### Nameserver redundancy

The existing 3-point nameserver-redundancy check now uses the parent delegation
instead of only RDAP nameserver metadata.

- at least two delegated NS names: pass;
- one delegated NS: review;
- unavailable parent delegation: unknown/not applicable.

### Parent/child NS consistency

Child NS views are accepted only from positive direct answers that:

- return `NOERROR`;
- set `AA=1`;
- are not truncated;
- contain the apex NS RRset in the answer section.

A confirmed observed child RRset that differs from the parent delegation is
reported for review. The wording explicitly allows for DNS migration/propagation
states.

If available child evidence agrees with the parent but other delegated servers
remain unverified, the result stays unknown rather than being promoted to a
confident pass.

### Delegated nameserver authority / lame delegation

The scanner distinguishes:

- authoritative service;
- mixed endpoint evidence;
- positive non-authoritative evidence;
- authoritative answers lacking the expected apex NS data;
- timeout/transport/error evidence;
- no-address/unprobed evidence.

A delegated nameserver is labelled lame only when the collected positive
non-authoritative evidence is sufficient at the server level. If an unprobed
candidate endpoint could still change that conclusion, the result remains
unknown.

Timeouts are never treated as lame delegation.

### Nameserver addressability

A nameserver is reported as having no usable address only when A and AAAA are
conclusively absent and no usable glue endpoint exists.

Resolver/network failure remains unknown.

### In-bailiwick glue

A nameserver is in-bailiwick when its name is the zone itself or is below the
zone.

For those delegated NS names, the scanner records parent referral glue and,
when recursive address evidence is usable, compares the glue addresses with the
currently observed A/AAAA addresses.

The analysis distinguishes:

- required glue present and matching;
- required glue missing;
- glue present but differing from observed addresses;
- glue present but comparison unavailable because current address evidence
  failed.

Out-of-bailiwick delegated NS names do not require parent glue and are reported
as informational for this check.

### NS target aliasing

RFC 2181 Section 10.3 requires NS targets not to be aliases. The scanner retains
an explicit CNAME lookup for every delegated NS target.

A confirmed CNAME is reported for review. A failed CNAME lookup remains unknown.

## User-facing findings

Issue #14 emits these Domain findings:

| Finding | Current score behavior |
| --- | --- |
| Name server redundancy | existing weight 3 retained |
| DNS delegation consistency | non-scoring |
| Delegated nameserver authority | non-scoring |
| Nameserver addressability | non-scoring |
| Delegation glue | non-scoring |
| Nameserver target aliasing | non-scoring |

The richer delegation findings stay at weight 0 until the dedicated v1.3
JSON/PDF/scoring integration work calibrates DNS scoring as a whole.

## Internal evidence vs public report schema

The scanner currently retains structured evidence in the internal delegation
and delegation-analysis models and emits the user-facing findings through the
normal `checks` list.

The existing public `dns_records` structure is preserved. A richer additive
public DNS/delegation JSON object and corresponding PDF integration remain part
of the later v1.3 integration work.

## Conservative evidence rules

The #14 implementation follows the project-wide DNS evidence policy:

- timeout is unavailable evidence, not record absence;
- resolver/network error is not "NS has no address";
- one endpoint failure is not automatically a zone-wide failure;
- a partial child view is not enough to prove complete parent/child consistency;
- parent/child differences are described as observed differences rather than
  automatic outage claims;
- glue differences are reported descriptively and do not by themselves claim
  resolution failure;
- lame delegation requires positive non-authoritative evidence.

## Standards

The implementation uses the following references directly:

- RFC 1034 and RFC 1035 for the DNS delegation/referral/message model;
- RFC 1912 for common operational delegation errors and lame-delegation
  terminology/guidance;
- RFC 2181 Section 10.3 for the rule that NS targets must not be aliases;
- RFC 2182 for authoritative-server redundancy/reachability guidance;
- RFC 9471 for current in-domain glue requirements in referral responses.

See [STANDARDS.md](STANDARDS.md) for the project standards registry.

## Deferred from issue #14

The following remain outside this slice:

- systematic UDP/TCP availability comparison;
- SOA collection/consistency;
- authoritative NS consistency beyond the #14 child-apex view needed for
  delegation comparison;
- EDNS behavior;
- DNSSEC cryptographic validation;
- ASN/provider/geographic diversity scoring;
- AXFR/IXFR;
- nameserver software fingerprinting.

Those transport/zone-consistency items are handled by the next v1.3 DNS
workstream rather than expanding the #14 query budget.
