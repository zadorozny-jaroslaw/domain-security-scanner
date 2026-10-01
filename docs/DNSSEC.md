# DNSSEC validation and posture

Issue #16 replaces the previous DS/RDAP presence check with bounded DNSSEC
validation based on direct authoritative evidence. Issue #17 adds current
algorithm-policy posture and bounded authenticated denial-of-existence analysis
without turning advisory policy into additional score weight.

## Validation scope

The scanner collects and validates:

- parent-side DS evidence from the parent authoritative path;
- child DNSKEY and RRSIG(DNSKEY) evidence;
- DS-to-DNSKEY correspondence;
- the DNSKEY RRset;
- deterministic signed apex `SOA` and `NS` RRsets;
- RRSIG inception and expiration windows.

The scanner does **not** validate every RRset in the zone and must not describe a
`secure` result as complete whole-zone validation.

## Validation states

- `unsigned` — complete parent evidence shows no DS at the delegation;
- `secure` — a supported DS matches DNSKEY material, the DNSKEY RRset validates,
  and the selected apex SOA/NS RRsets validate with current signatures;
- `broken` — complete evidence proves a material DNSSEC failure, such as DS with
  no matching DNSKEY or a cryptographically invalid/expired required signature;
- `unknown` — required evidence is unavailable or local cryptographic support is
  insufficient to make a reliable conclusion.

Timeout, SERVFAIL, transport errors, truncated evidence without a usable TCP
fallback, and unsupported local cryptography remain `unknown` rather than being
converted into `broken`.

## Query bounds

DNSSEC queries use EDNS(0) with the DO bit and a 1232-byte advertised payload.
Collection reuses authoritative endpoints already established by the delegation
checks, probes at most two child endpoints for DNSKEY evidence, and retries a
DNSSEC query over TCP only when the UDP response is truncated. When the parent
authoritatively proves that no DS RRset exists, collection stops immediately and
does not issue child DNSKEY/SOA/NS or denial queries because they cannot change
the `unsigned` classification.

When #19 has already generated bounded high-entropy negative names, #17 reuses
the first of those names for one additional DNSSEC-aware authoritative query on
the selected child endpoint. This is the only extra denial-of-existence query.
The generated QNAME is not serialized into the public report.

## Current algorithm policy snapshot

Issue #17 keeps an offline, versioned snapshot of the IANA DNSSEC policy tables.
Normal scans do not fetch IANA dynamically, so results cannot silently change
because an external registry changed between two scans.

Current snapshot metadata:

- snapshot version: `2026-08-10-iana-dnssec-policy`;
- DNS Security Algorithm Numbers registry: `2026-08-10`;
- DS Digest Algorithms registry: `2026-01-13`.

The scanner preserves the IANA distinction between:

- use for DNSSEC signing/delegation;
- use for DNSSEC validation;
- implementation for signing/delegation;
- implementation for validation.

Operator posture is reported as `recommended`, `permitted`, `not_recommended`,
`prohibited`, or `unknown`. Unknown future algorithm/digest numbers remain
`unknown`; they are not treated as insecure merely because this scanner snapshot
does not recognize them.

This distinction matters for SHA-1. Current policy prohibits RSASHA1 algorithms
5/7 for new DNSSEC signing while still requiring/recommending validator support.
Likewise, SHA-1 DS digest 1 is prohibited for new delegation but remains a
validation capability. Retired ECC-GOST algorithm 12 and GOST R 34.11-94 digest
3 are handled explicitly as prohibited/retired.

Algorithm posture is additional evidence only. It does not claim that the
DNSSEC chain is cryptographically valid when the validation evidence is
unavailable or incomplete.

## NSEC / NSEC3 posture

The bounded negative DNSSEC response is inspected for observable authenticated
denial data:

- `NSEC`;
- `NSEC3`;
- supplemental `NSEC3PARAM` metadata when present.

For NSEC3 the scanner records hash algorithm, flags, iterations, salt, Opt-Out,
and whether observed proof-chain parameters are internally consistent.

RFC 9276 recommends NSEC when NSEC3-specific properties are not needed. When
NSEC3 is used, its publisher baseline is SHA-1 (algorithm 1), zero additional
iterations, and an empty salt. Extra iterations and a non-empty salt are exposed
as advisory posture. Opt-Out is also advisory because it can be appropriate for
very large, sparsely signed delegation zones; a bounded external scan cannot
infer the zone operator's full deployment context.

Reserved flag bits, mixed NSEC/NSEC3 evidence, or inconsistent observable chain
parameters are reported for review. Unknown future NSEC3 hash algorithms remain
`unknown` rather than being classified as insecure.

NSEC3 parameter posture is non-scoring by default.

## Report model

Existing `dns_records` remains unchanged. Structured DNSSEC evidence is exposed
under `dns.dnssec`.

Issue #16 fields remain available, including validation state, DS/DNSKEY
material, matching key tags, validation steps, signature summaries, query
endpoints, and bounded validation scope.

Issue #17 adds:

- `dns.dnssec.algorithm_policy` — current offline snapshot metadata and observed
  DNSKEY/DS algorithm posture;
- `dns.dnssec.denial` — observed NSEC/NSEC3 mechanism and parameter posture;
- `dns.dnssec.queries.denial_probe` — bounded query metadata without the random
  generated QNAME;
- `scope.denial_probe_limit: 1`.

The existing `dns.dnssec.policy_version` field remains the validation-policy
identifier introduced by #16 for backward compatibility. The newer IANA policy
snapshot has its own explicit `algorithm_policy.snapshot_version` field.

## Standards

Relevant standards and registries include:

- RFC 4033 — DNSSEC validation model and security states;
- RFC 4034 — DS, DNSKEY and RRSIG resource records;
- RFC 4035 — authenticated delegation and validation processing;
- RFC 9276 — NSEC3 iteration, salt, and Opt-Out deployment guidance;
- RFC 9904 — DNSSEC cryptographic algorithm recommendation update process;
- RFC 9905 — RSASHA1 / RSASHA1-NSEC3-SHA1 deprecation;
- RFC 9906 — ECC-GOST / GOST digest retirement;
- IANA DNS Security Algorithm Numbers registry;
- IANA Delegation Signer Digest Algorithms registry.
