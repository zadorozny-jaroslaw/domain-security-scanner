# DNS delegation and nameserver posture

Issue #14 introduced the first user-facing authoritative-DNS posture layer for v1.3.0.
The completed v1.3 integration now combines that delegation model with bounded
authoritative SOA/NS transport evidence, DNSSEC, negative-DNS/open-recursion
analysis, path-integrity detection, encrypted zone-level recovery, scoring, and
reporting. It builds on the shared DNS evidence primitives documented in
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

This keeps the delegation slice low-impact. Later v1.3 stages add bounded
representative UDP/TCP SOA/NS/EDNS observations; the project still does not
perform exhaustive per-address transport probing.

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

The final v1.3 integration emits these Domain findings:

| Finding | Current score behavior |
| --- | --- |
| Name server redundancy | weight 3 |
| DNS delegation consistency | weight 6 |
| Delegated nameserver authority | weight 7 |
| Nameserver addressability | weight 7 |
| Delegation glue | advisory / non-scoring |
| Nameserver target aliasing | advisory / non-scoring |

Unknown or path-untrusted cases remain not applicable even when a finding has a
nominal weight. Later trusted evidence can promote an earlier unknown result only
when it supports the same claim: for example, RDAP registry NS plus two-resolver
encrypted apex-NS consensus can recover zone-level consistency, but cannot prove
that a particular authoritative endpoint answered the scanner.

## Internal evidence vs public report schema

The scanner retains structured evidence in the internal delegation and
delegation-analysis models and exposes the integrated result under the additive
public `dns` object. The delegation report includes parent/child sets, glue,
per-nameserver recursive address evidence, and direct authoritative query
context. Query mode, server IP/name, and transport remain explicit.

The existing public `dns_records` structure is preserved for compatibility.
Trusted encrypted consensus can add previously unavailable NS/SOA values to the
report copy without replacing already-observed legacy values. The PDF renders a
compact DNS posture summary plus the normal DNS appendix.

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

## v1.3 integration boundaries

The broader v1.3 work now adds bounded UDP/TCP authoritative transport evidence,
SOA/NS comparison, advisory EDNS observations, DNSSEC cryptographic validation,
negative-DNS/wildcard/open-recursion analysis, RFC 8659 CAA policy evaluation,
and customer-facing JSON/PDF/scoring integration.

The release still deliberately excludes:

- exhaustive probing of every authoritative IP/address family;
- ASN/provider/geographic diversity scoring;
- AXFR/IXFR;
- DNS fuzzing or malformed-packet testing;
- amplification measurement;
- nameserver software fingerprinting;
- DANE/TLSA;
- deep SVCB/HTTPS validation;
- complete CDS/CDNSKEY lifecycle validation.

If direct port-53 traffic appears intercepted, zone-level registry/DoH evidence
may recover claims such as NS consistency, addressability, signed SOA
observability, and bounded DNSSEC validation. Per-server authority, transport,
EDNS, negative-DNS, SOA-serial consistency, and open-recursion conclusions are
not inferred from that encrypted recursive fallback.
