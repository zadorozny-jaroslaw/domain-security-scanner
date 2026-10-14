# v1.6.0 candidate: DNS SVCB/HTTPS service-binding evidence

**Status:** exploratory planning only. No v1.6 milestone scope or implementation
issues are approved by this document. Complete the v1.4 release and the selected
v1.5 TLS work before confirming a v1.6 commitment.

**Primary standard:** [RFC 9460](https://www.rfc-editor.org/info/rfc9460),
*Service Binding and Parameter Specification via the DNS (SVCB and HTTPS
Resource Records)*. SVCB and HTTPS records advertise service endpoints and
connection parameters. Their presence is optional; record absence is not a
security failure.

## Why this follows v1.5

The scanner already distinguishes exact web targets from the registered/root
domain, has a shared DNS evidence layer, and records bounded TLS observations.
v1.5 is planned to clarify TLS 1.2/1.3, deprecated protocol versions, and
certificate identity. v1.6 can build on those foundations by explaining what
the domain **advertises in DNS for its HTTPS service**, without pretending that
the scanner has contacted or authenticated advertised alternative endpoints.

The user-facing result should answer: "What HTTPS service-binding records are
published for this hostname, what do they say, and is the observable syntax
usable?" It must not answer "Does that advertised endpoint work?" without a
separately approved, safely bounded check.

## Proposed initial scope

1. **Observe the HTTPS RR at the exact web host.** Query DNS RR type HTTPS (65)
   for the requested web target, not automatically for its registered/root
   domain. Capture the queried name, response/evidence status, resolver context,
   record data, and TTL where available. Reuse shared DNS lookup/caching and
   error handling where practical. Designate the owning existing scan group
   during issue design (Web is the initial candidate); do not silently enable
   findings for unselected groups.
2. **Interpret RFC 9460's two modes.** Preserve each record's SvcPriority and
   TargetName. Priority 0 means AliasMode; positive priority means ServiceMode.
   Represent service preferences without treating priority as a quality score.
   Account for mixed-mode RRsets and CNAMEs; only consider a bounded number of
   AliasMode follow-ups, with loop detection and a small query budget.
3. **Parse parameters conservatively.** Consider `mandatory`, `alpn`,
   `no-default-alpn`, `port`, `ipv4hint`, and `ipv6hint`. Check observable
   syntax and mutually dependent fields where specified. Track unrecognized
   keys; an unknown key listed in `mandatory` makes that record unusable to a
   client that cannot interpret it, not necessarily misconfigured for all
   clients. Keep address hints as hints, not verified A/AAAA or reachability.
   Keep `ech` and other extension parameters opaque until their own standards
   and usable evidence are explicitly scoped.
4. **Add understandable report evidence.** Prefer additive JSON under a
   well-defined web/DNS service-binding subsection, with effective scan-group
   ownership, source/provenance, and per-record parsed and raw values. Present
   concise explanatory PDF information; start advisory/non-scoring. Distinguish
   malformed records from valid but optional or client-specific configurations.
5. **Add deterministic tests.** Cover no record, multiple ServiceMode records,
   AliasMode, mixed modes, CNAME and alias loops, query limits, malformed
   parameters, known and unknown mandatory keys, contradictory parameters,
   NXDOMAIN/NODATA versus resolver failure, and uncertain/incomplete evidence.
   Mock all external requests in unit and CLI regression tests.

**SVCB RR type (64):** RFC 9460 also defines generic SVCB. v1.6 may share a
parser for both types, but additional live SVCB queries need a specific service
scheme/mapping and user benefit. Do not scan guessed `_service` labels or
arbitrary ports. For ordinary HTTP/HTTPS origins, RFC 9460 defines the HTTPS
record type rather than a generic SVCB query.

## Reporting and uncertainty policy

- `NOERROR` with proven no-data and incomplete/SERVFAIL/timeout responses are
  different evidence states; inability to observe a record remains `VERIFY` or
  `UNKNOWN`, not "record missing" or a security failure.
- An absent HTTPS RR is normal and should not reduce the security score.
- Advertised `alpn`, `port`, address hints, and future parameters are **claims
  in DNS**, not proof that a listener exists, a protocol is supported, an ECH
  handshake succeeds, or a certificate matches the original origin.
- DNSSEC validation or trusted encrypted-recursive recovery, when available,
  must preserve its existing provenance and may not be inferred from an
  ordinary recursive response. No promise of authenticity from unsigned data.
- Unknown extension keys remain parseable/preserved where possible. Do not
  mark a record malicious or insecure simply because a local parser or TLS
  library does not support an extension.
- HTTPS DNS records, the Web `Alt-Svc` response header, HSTS, and actual TLS
  handshakes are distinct observations; report them without equating them.
- Keep current authorization, CLI exit-code semantics, report compatibility,
  scan-scope selection, and the low-impact external-check boundary unchanged.

## Candidate delivery slices (not yet issues)

| Slice | Deliverable | Rough effort* |
| --- | --- | --- |
| A | Scoped HTTPS DNS collection, evidence states and fixtures | 2–3 engineering days |
| B | RFC 9460 record and SvcParam interpretation, bounded alias logic | 3–5 engineering days |
| C | Additive JSON/PDF presentation and regression coverage | 2–4 engineering days |
| Optional D | Generic SVCB for **one explicitly approved** non-HTTP service mapping | Estimate separately |

*Early sizing for a solo maintainer, not a schedule or commitment; DNS library
behavior, encoding edge cases, and Windows/Linux CI may change effort.

## Out of scope by default

- No new port scanning, high-volume probes, cipher sweeps, or connections to
  arbitrary SVCB/HTTPS-advertised addresses, targets, or alternative ports.
- No ECH implementation/handshake validation, QUIC/HTTP/3 transport testing,
  or DNS HTTPS records acting as an active browser upgrade mechanism.
- No DNS-over-HTTPS/DDR resolver discovery implementation, broad SVCB service
  enumeration, or guesses about unregistered service labels.
- No DANE/TLSA implementation, new DNSSEC trust claims, or automatic security
  severity scoring based solely on service-binding presence/absence.
- No changes to the existing JSON/PDF schema beyond reviewed additive fields,
  and no changes to user authorization or scan-group behavior by default.

## Draft acceptance gate

- All added queries are bounded, scoped to the authorized target and selected
  group, and reuse appropriate DNS evidence/provenance handling.
- Parser fixtures cover RFC 9460 modes, parameters, duplicates/invalid cases,
  unknown mandatory parameters, and alias-loop/query-budget limits.
- Malformed or confirmed unusable records are differentiated from optional
  configuration choices and unobservable evidence, with conservative language.
- Additive JSON and customer-facing PDF sections remain coherent for selected
  and skipped scan groups; scoring is unchanged unless separately approved.
- No extra connections are made to advertised endpoints and no unsupported
  conclusions are drawn about ECH, HTTP/3, DNSSEC, or endpoint reachability.
- Cross-platform automated regression tests and explicitly authorized,
  low-impact smoke checks pass before a future v1.6 release.

## References and ownership

- [RFC 9460](https://www.rfc-editor.org/info/rfc9460) — authoritative protocol
  definition; sections 2, 7–9 are particularly relevant.
- [Project roadmap](ROADMAP.md) — candidate release sequencing.
- [DNS evidence model](DNS_EVIDENCE.md) — uncertainty, query provenance,
  caching and bounded observations.
- [Scan group orchestration](SCAN_GROUPS.md) — scope and prerequisite rules.
- [Project scope](SCOPE.md) — safety and low-impact boundaries.

Move the chosen slices into small milestone issues after confirming the v1.5
release scope, and refine acceptance criteria against the implemented DNS APIs.
