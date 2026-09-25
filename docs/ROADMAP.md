# Project roadmap

This roadmap records release direction and major scope decisions for Domain Security Scanner.

It is intentionally lightweight. The roadmap answers **where the project is going**. GitHub Issues should describe individual implementation units, acceptance criteria, technical decisions, and follow-up work.

## Planning model

The project uses three layers of planning:

1. **Roadmap** - release goals, boundaries, and longer-term direction.
2. **GitHub Issues** - concrete implementation work for the active release.
3. **Pull requests** - reviewed code and documentation changes that close or advance those issues.

For a solo-maintained project, avoid unnecessary process overhead. GitHub Projects, story points, sprint ceremonies, and large label taxonomies are not required unless the project grows enough to benefit from them.

## Current release: v1.3.0

### Theme

**Authoritative DNS & DNSSEC Posture**

The goal of v1.3.0 is to make the `domain` scan group substantially deeper and more trustworthy by moving from simple recursive DNS inventory toward direct assessment of authoritative DNS infrastructure.

The release should answer these questions clearly:

- Is the delegation coherent?
- Are delegated authoritative servers reachable?
- Are delegated servers actually authoritative for the zone?
- Do authoritative servers expose consistent zone state?
- Does required DNS transport work correctly?
- Is DNSSEC absent, valid, broken, or unverifiable?
- What CAA policy is effectively applicable to the scanned name?
- Which DNS conclusions are unavailable because evidence could not be obtained?

See [V1_3_DNS_PLAN.md](V1_3_DNS_PLAN.md) for the detailed implementation scope and release gate.

### Release boundaries

v1.3.0 should remain a low-impact external posture scan.

In scope:

- shared DNS evidence/query infrastructure;
- parent/child delegation comparison;
- lame delegation detection;
- nameserver reachability and addressability;
- authoritative UDP/TCP checks;
- authoritative SOA and NS consistency;
- practical EDNS(0) evidence;
- DNSSEC DS/DNSKEY/signature validation;
- current DNSSEC algorithm-policy checks;
- RFC-correct CAA inheritance and parsing;
- negative-answer and wildcard observations;
- conservative open-recursion detection;
- JSON/report integration, tests, documentation, and scoring calibration.

Out of scope for this release:

- DNS fuzzing or malformed-packet testing;
- amplification measurement;
- default AXFR/zone-transfer attempts;
- exhaustive resolver implementation testing;
- ASN/geolocation/provider-diversity scoring;
- DANE/TLSA validation;
- SVCB/HTTPS-record deep validation;
- complete CDS/CDNSKEY automation lifecycle assessment.

### v1.3.0 completion criteria

v1.3.0 is ready when a `--scan domain` run can reliably explain:

> The parent delegates the domain to these authoritative servers; each server's reachability and authority status is known; the servers' zone state is compared; DNS transport evidence is recorded; DNSSEC is classified as unsigned, valid, broken, or unverifiable; and the effective CAA policy is determined using the DNS tree.

All new checks must preserve the project's conservative evidence rule: resolver errors, timeouts, and unavailable evidence must not be presented as proof of absence or failure.

## Next candidate: v1.4.0

### Theme

**TLS & Certificate Posture**

Candidate scope after v1.3.0:

- certificate identity and SAN/wildcard handling;
- chain and issuer evidence;
- key type/size and signature algorithm;
- TLS 1.2/1.3 posture and bounded legacy/weak configuration checks;
- revocation/stapling evidence where reliably observable;
- clearer TLS-specific reporting and JSON structure.

The final v1.4.0 scope should be decided after v1.3.0 is released and its follow-up issues are reviewed.

## Later candidates

Potential later release themes include:

- deeper Web policy analysis;
- additional mail standards and operational checks;
- DANE/TLSA;
- SVCB/HTTPS records;
- report-to-report comparison/baseline mode;
- JSON schema/versioning improvements;
- additional automation/CI-oriented output controls.

These are directional ideas, not commitments. Prefer a coherent release theme over adding unrelated checks simply because an RFC exists.
