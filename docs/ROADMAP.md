# Project roadmap

This roadmap records release direction and major scope decisions for Domain Security Scanner.

It is intentionally lightweight. The roadmap answers **where the project is going**. GitHub Milestones define the scope of an upcoming release, GitHub Issues describe individual implementation units, and pull requests contain the reviewed implementation.

Completed release history belongs in `CHANGELOG.md` and GitHub Releases rather than remaining as an active roadmap section.

## Planning model

The project uses four layers of planning:

1. **Roadmap** - release themes, boundaries, and longer-term direction.
2. **GitHub Milestones** - the planned scope of a specific upcoming release.
3. **GitHub Issues** - concrete implementation work assigned to that milestone.
4. **Pull requests** - reviewed code and documentation changes that close or advance those issues.

For a solo-maintained project, avoid unnecessary process overhead. GitHub Projects, story points, sprint ceremonies, and large label taxonomies are not required unless the project grows enough to benefit from them.

Normal feature/minor releases target a **two-week iteration**. Security fixes, dependency patches, and production hotfixes are prioritized for release as soon as practical after validation and are not held for the normal cadence.

See [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) for the branch, milestone, prerelease, release, and urgent-patch process.

## Current planned release: v1.5.0

### Theme

**TLS & Certificate Posture**

v1.5.0 focuses on clearer, standards-grounded evidence for HTTPS certificate
identity and TLS protocol posture on the **exact requested web host**. It builds
on the current TLS checks; it does not expand the default scanner into an
exhaustive cipher enumerator or a port scanner.

### Selected RFCs (six)

| RFC | Planned external check | Key boundary |
| --- | --- | --- |
| [RFC 9325](https://www.rfc-editor.org/info/rfc9325) | Apply contemporary TLS security recommendations to observed negotiation and configuration evidence | Bounded HTTPS/TLS posture only; no DTLS scanning and no claims based on untested cipher suites |
| [RFC 8446](https://www.rfc-editor.org/info/rfc8446) | Record and interpret confirmed TLS 1.3 negotiation, protocol and selected cipher | Do not imply every optional TLS 1.3 feature was tested |
| [RFC 5246](https://www.rfc-editor.org/info/rfc5246) | Record and interpret confirmed TLS 1.2 negotiation and cipher information | TLS 1.2 is not automatically a failure merely because TLS 1.3 exists |
| [RFC 8996](https://www.rfc-editor.org/info/rfc8996) | Detect confirmed TLS 1.0 and TLS 1.1 support, which has been deprecated | If the client cannot probe an old version, record unknown rather than claiming the server rejects it |
| [RFC 7568](https://www.rfc-editor.org/info/rfc7568) | Assess observable SSLv3 support or state that the local client cannot test it | Modern TLS libraries often disable SSLv3; never infer server support or rejection from a locally unavailable probe |
| [RFC 9525](https://www.rfc-editor.org/info/rfc9525) | Assess HTTPS certificate DNS service identity using SAN DNS-IDs and valid wildcard matching | Trust chain and hostname-verification errors must be distinguished from transport or unavailable evidence; do not use CN-only identity fallback |

These are the **selected v1.5 RFCs**, not a list of all RFCs worth supporting.
The concrete checks and acceptance criteria will be split into focused GitHub
issues. RFC 9325 supplies security recommendations; RFCs 5246 and 8446 provide
protocol context. RFCs 8996 and 7568 cover obsolete versions, while RFC 9525
covers certificate service identity.

### Proposed implementation workstreams

1. **Protocol evidence and classification** — reuse the existing bounded TLS
   1.2/1.3/legacy probes; separate confirmed negotiation, confirmed rejection,
   and cases that cannot be tested with the host's OpenSSL/Python runtime.
   Map observations to the RFC 9325, 8996, and 7568 recommendations.
2. **Certificate identity** — review SAN DNS-IDs, wildcard/name matching and
   trust-verification outcomes for the exact target using RFC 9525. Keep
   untrusted/incomplete certificate information separate from verified identity.
3. **Report integration and regression coverage** — add focused evidence and
   concise findings to existing TLS JSON/PDF outputs, preserve scoring policy
   unless a deliberate scoped change is reviewed, and test Windows/Linux runtime
   differences with mocked handshakes and deterministic fixtures.

### Completion and safety requirements

- Only perform small, bounded TLS connections to the authorized web target;
  no broad port scanning, exploitation, cipher-suite sweeps, or load testing.
- Avoid converting local TLS-library limitations, timeouts, or ambiguous
  handshakes into confident server-side pass/fail findings.
- Clearly distinguish an insecure **observed** configuration from an
  unobservable or unsupported protocol probe (`VERIFY`/`UNKNOWN`).
- Do not let scan-group selection or CLI verbosity change the security evidence;
  preserve the documented CLI exit-code and output-stream contract.
- Keep additive report changes backwards-compatible where possible and cover
  certificate identity, protocol policy, unsupported probe paths, and false
  positives with automated tests.
- Pass full regression tests and perform an explicitly authorized, low-impact
  smoke test before release. The release date and issue scope remain subject to
  milestone review; completing v1.4.0 publication is a separate prerequisite.

## Next candidate: v1.6.0

### Theme

**DNS SVCB/HTTPS Service-Binding Visibility**

Proposed foundation: [RFC 9460](https://www.rfc-editor.org/info/rfc9460).
Following v1.5 TLS/certificate posture, v1.6 would add bounded, passive DNS
service-binding evidence for the **exact requested web target**. The first
iteration should prioritize HTTPS (type 65) records for the assessed HTTPS
origin; general SVCB (type 64) support for other services is a later option
that needs a defined, safe query-name mapping. No new scan group is assumed.

Candidate scope:

- distinguish AliasMode (priority 0) and ServiceMode (priority > 0), including
  targets, priorities, record sets, and bounded alias handling;
- parse and retain recognized SvcParams such as `mandatory`, `alpn`,
  `no-default-alpn`, `port`, `ipv4hint`, and `ipv6hint`; preserve unknown keys
  without inventing security conclusions;
- separate valid, malformed, unusable, absent, and unobservable DNS evidence;
- expose additive, advisory JSON/PDF evidence consistent with existing scan
  selection, provenance, and `VERIFY`/`UNKNOWN` rules;
- use only bounded DNS queries. Do not connect to advertised targets or ports,
  interpret address hints as verified reachability, or treat record absence as
  a security failure.

See [the preliminary v1.6 plan](V1_6_SVCB_HTTPS_PLAN.md) for potential work
slices, uncertainties, safe non-goals, and a draft acceptance gate. The final
scope and effort should be selected through GitHub issues after v1.5.

## Later candidates

Other possible future release themes include:

- deeper Web policy analysis;
- additional mail standards and operational checks;
- DNSSEC-backed DANE/TLSA (separate trust and certificate-validation project);
- broader SVCB scheme mappings beyond the HTTPS origin;
- JSON schema/versioning improvements.

These are directional ideas, not commitments. Prefer one cohesive release theme
over adding unrelated checks simply because an RFC exists.
