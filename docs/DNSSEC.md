# DNSSEC validation

Issue #16 replaces the previous DS/RDAP presence check with bounded DNSSEC
validation based on direct authoritative evidence.

## Scope

The scanner collects and validates:

- parent-side DS evidence from the parent authoritative path;
- child DNSKEY and RRSIG(DNSKEY) evidence;
- DS-to-DNSKEY correspondence;
- the DNSKEY RRset;
- deterministic signed apex `SOA` and `NS` RRsets;
- RRSIG inception and expiration windows.

The scanner does **not** validate every RRset in the zone and must not describe a
`secure` result as complete whole-zone validation.

## States

- `unsigned` — complete parent evidence shows no DS at the delegation;
- `secure` — a supported DS matches DNSKEY material, the DNSKEY RRset validates,
  and the selected apex SOA/NS RRsets validate with current signatures;
- `broken` — complete evidence proves a material DNSSEC failure, such as DS with
  no matching DNSKEY or a cryptographically invalid/expired required signature;
- `unknown` — required evidence is unavailable or local cryptographic support is
  insufficient to make a reliable conclusion.

Timeout, SERVFAIL, transport errors, truncated evidence without a usable TCP
fallback, and unsupported validation algorithms remain `unknown` rather than
being converted into `broken`.

## Query bounds

DNSSEC queries use EDNS(0) with the DO bit and a 1232-byte advertised payload.
Collection reuses authoritative endpoints already established by the delegation
checks, probes at most two child endpoints for DNSKEY evidence, and retries a
DNSSEC query over TCP only when the UDP response is truncated. When the parent
authoritatively proves that no DS RRset exists, collection stops immediately and
does not issue child DNSKEY/SOA/NS queries because they cannot change the
`unsigned` classification.

## Algorithm policy

The implementation uses the versioned policy snapshot
`2025-11-rfc9904-rfc9905-rfc9906`. The policy is explicit so scanner results do
not silently drift when a library default or an external registry changes.

Relevant standards:

- RFC 4033 — DNSSEC validation model and security states;
- RFC 4034 — DS, DNSKEY and RRSIG resource records;
- RFC 4035 — authenticated delegation and validation processing;
- RFC 9904 — current DNSSEC algorithm recommendation update process;
- RFC 9905 — RSASHA1 / RSASHA1-NSEC3-SHA1 deprecation;
- RFC 9906 — ECC-GOST / GOST digest deprecation.

## Report model

Existing `dns_records` remains unchanged. DNSSEC adds structured evidence under
`dns.dnssec`, including state, policy version, DS/DNSKEY material, matching key
tags, validation steps, signature summaries, query endpoints, and the explicit
bounded-validation scope. `scope.validation_targets` lists the deterministic RRsets
the validator is designed to check, while `scope.validated_rrsets` contains only
RRsets whose cryptographic validation actually completed successfully. An unsigned
zone therefore reports an empty `validated_rrsets` list.
