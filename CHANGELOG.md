# Changelog

All notable project changes are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add explicit `scan` and `diff` CLI commands with command-specific arguments and dedicated execution handlers.
- Add interactive scan-authorization confirmation when `--authorized` is omitted in a terminal; `--authorized` remains the non-interactive confirmation path and skips the prompt.
- Add command-focused CLI regression coverage for help output, scan/diff routing, removed legacy syntax, scan-limit validation, and interactive/non-interactive authorization behavior.
- Add installable Python project metadata with `domeval` as the preferred console command and `domain-security-scan` as a compatibility alias.
- Add `python -m domain_security_scanner` as a supported module entry point while retaining `domain_security_scan.py` as the source-tree compatibility wrapper.
- Add entry-point regression tests and CI smoke coverage for installed console commands and module execution.

### Changed

- Make a hard cut from the earlier flat CLI forms: scans now use `scan DOMAIN ...` and report comparison uses `diff OLD_JSON NEW_JSON`.
- Reject malformed or removed command forms during argument parsing before scanner activity begins.
- Improve CLI help with English descriptions, representative examples, command-specific options, and compact `1-100` scan-limit descriptions.
- Keep `diff` as a local report operation that does not require scan authorization.
- Prefer the shorter `domeval` executable in user-facing examples while retaining the longer installed alias and existing package/file naming conventions.
- Install the project itself in CI so package metadata and generated console entry points are exercised on supported Windows and Linux runners.

## [1.3.0] - 2026-09-30

### Added
- Fix security.txt detection so HTTP 200 HTML soft-404 pages and cross-host redirects to unrelated pages are reported as not found instead of as invalid security.txt files, while still validating genuine security.txt files served through cross-host redirects.
- Add `--json-only` to skip PDF generation while preserving the normal structured JSON report.
- Add a shared DNS evidence layer used by Domain, Discovery, and Mail recursive lookups.
- Add direct single-server authoritative DNS queries over explicit UDP or TCP.
- Capture authoritative DNS RCODE, AA/TC flags, EDNS metadata, answer/authority/additional sections, elapsed time, and server context.
- Add query-context cache identities that separate recursive vs authoritative evidence, authoritative server endpoints, and UDP vs TCP.
- Add explicit non-authoritative, truncated, transport-failure, and other unavailable-evidence states so they cannot be mistaken for record absence.
- Add parent-side delegation discovery from direct parent referrals, including delegated NS and referral glue evidence.
- Add per-delegated-nameserver A/AAAA/CNAME evidence plus bounded direct UDP authority probes.
- Add pure delegation analysis for parent/child NS consistency, lame delegation, nameserver addressability, in-bailiwick glue, and NS target aliasing.
- Add customer-facing Domain findings for delegation consistency, delegated nameserver authority, nameserver addressability, delegation glue, and nameserver target aliasing.
- Add bounded authoritative-server SOA/NS observations over explicit UDP/TCP plus advisory EDNS(0) comparison.
- Add authoritative negative-response, wildcard-DNS, and open-recursion evidence with positive-evidence requirements.
- Add DNSSEC chain/posture validation for parent DS, child DNSKEY, DS-to-DNSKEY matching, RRSIG validation on DNSKEY/SOA/NS, algorithm/digest policy, and denial-of-existence posture.
- Add RFC 8659 effective CAA tree-walk analysis, including inherited policy, syntax, critical properties, and issuer semantics.
- Add an additive structured `dns` JSON object covering delegation, authoritative servers, SOA, DNSSEC, CAA, negative DNS, wildcard, open recursion, path integrity, encrypted-recursive recovery, and zone-level recovery while retaining `dns_records`.
- Add direct-DNS path-integrity detection so transparent port-53 interception or rewriting is not misattributed to the intended authoritative server.
- Add bounded DNS-over-HTTPS fallback through Cloudflare and Google when the direct DNS path is suspect, with local cryptographic DNSSEC validation of consensus material.
- Add a compact customer-facing DNS posture section to PDF reports and surface trusted recovered NS/SOA records in the DNS appendix.
- Add a v1.3 DNS release-validation matrix that maps required controlled fixtures and authorized smoke cases to regression tests.

### Changed

- Move generic DNS lookup ownership out of the Mail scan group into shared DNS infrastructure.
- Require authoritative negative DNS evidence to set AA and include SOA evidence before `NO_ANSWER` or `NXDOMAIN` is treated as conclusive absence.
- Keep direct authoritative failures scoped to the queried server/transport instead of promoting one server failure into a zone-wide conclusion.
- Preserve the existing recursive `dns_query_result()` / `dns_query()` interfaces and current public JSON fields while the richer v1.3 DNS model is integrated incrementally.
- Base the existing weighted nameserver-redundancy check on the observed parent delegation instead of only RDAP nameserver metadata.
- Keep resolver/network failures and incomplete delegated-server evidence as `UNKNOWN`; only positive non-authoritative evidence can support a lame-delegation conclusion.
- Bound #14 direct authority probing to representative endpoints and stop after positive authority evidence, while retaining unprobed endpoint evidence for later transport/consistency work.
- Calibrate v1.3 DNS scoring by security/availability impact instead of RFC check count: strong weights for confirmed delegation/authority/addressability failures, broken DNSSEC, and confirmed open recursion; lower weights for selective transport/RRset/CAA issues; advisory SOA/EDNS/wildcard/denial-mechanism observations remain non-scoring.
- Preserve `UNKNOWN`/`VERIFY` as not applicable to scoring even when a finding has a nominal weight.
- Distinguish DNSSEC `secure`, `unsigned`, `broken`, and `unknown`; unsigned receives partial hygiene credit while cryptographic breakage receives none.
- Require open-recursion findings to be backed by positive recursive behavior attributable to the same authoritative endpoint; RD/RA flags alone are insufficient.
- Reconcile later stronger authoritative or encrypted zone evidence without overwriting the provenance or per-server meaning of direct observations.
- Preserve the legacy top-level `caa` and `dns_records` compatibility surfaces while adding richer DNS evidence and trusted additive NS/SOA report values.
- Keep Domain-only scans independent of unrelated groups and preserve Mail/Discovery behavior through the shared DNS evidence layer.
- Document Cloudflare/Google DNS-over-HTTPS fallback as an external data source used only when direct DNS path integrity is suspect.

### Fixed

- Avoid false authoritative/open-recursion conclusions when local routers, Pi-hole enforcement, VPNs, firewalls, or ISP DNS interception rewrite traffic sent to explicit port-53 destinations.
- Avoid reporting inconclusive SOA observations as customer-facing warnings; trusted encrypted SOA evidence can confirm zone-level service without claiming per-authoritative-server consistency.
- Keep direct-path interception, timeout, resolver failure, and incomplete endpoint samples as `VERIFY` instead of converting them into confirmed DNS infrastructure failures.

## [1.2.0] - 2026-09-24

### Added

- Add selectable scan groups for `domain`, `discovery`, `mail`, `tls`, `web`, and `cms` through `--scan` and `--skip`.
- Add scan-scope metadata to JSON reports, including requested, skipped, overlapping, effective groups, and selection warnings.
- Add scan-scope and overlap/selection warnings to the PDF report.
- Add RFC 9111 HTTP cache-policy analysis as advisory Web evidence.
- Add passive RFC 8288 `Link` header parsing and relation inventory without dereferencing advertised targets.
- Add passive RFC 7838 `Alt-Svc` parsing without connecting to advertised alternative services.
- Add passive RFC 9112 HTTP/1.1 response-framing metadata analysis for observable `Content-Length` / `Transfer-Encoding` conditions.
- Add structured Web evidence under `http.cache`, `http.links`, `http.alt_svc`, and `http.http1_framing`.

### Changed

- Split scanner behavior into six functional group packages under `domain_security_scanner/domains/` and centralize selection, prerequisite, and execution ordering in `domain_security_scanner/orchestration.py`.
- Make `--skip` higher priority than `--scan` when both options are supplied; overlapping groups are explicitly reported and not scanned.
- Keep prerequisite context available without emitting findings or score contribution for unselected groups.
- Make PDF technical sections scope-aware so skipped groups are not rendered as unverified or missing.
- Scope the External Security Hygiene Score to applicable weighted findings from the effective selected groups; scores from different scopes are therefore not directly comparable.
- Remove transitional flat mixin compatibility modules after the CLI and `Scanner` moved fully to the grouped package layout.
- Tighten existing Web checks against RFC 9110/3986 redirect semantics, RFC 6797 HSTS, RFC 9116/8615 `security.txt`, and RFC 10025 cookie requirements while keeping posture-only hardening separate from protocol conformance.
- Keep the new Link, Alt-Svc, cache, and HTTP/1.1 checks advisory/non-scoring; Link targets and Alt-Svc alternatives are not contacted, and RFC 9112 does not add a raw HTTP probe.

## [1.1.0] - 2026-09-18

### Added

- Add RFC 7505 Null MX parsing and validation, including detection of invalid mixed Null MX/ordinary MX configurations.
- Add a lightweight internal standards registry and dedicated mail-standard parsing helpers.
- Add RFC 8461 MTA-STS validation for the DNS policy indicator, HTTPS response, policy syntax, modes, `max_age`, and MX-pattern coverage.
- Add RFC 8460 TLS-RPT policy validation, including required `rua` destinations, URI scheme validation, multiple-policy detection, and extension-field handling.
- Add an additive `host_inventory` report object that classifies discovered names as live, historical, unresolved, DNS-unknown, or not assessed.

### Changed

- Split the monolithic scanner into focused package modules while preserving the existing `domain_security_scan.py` CLI entry point and report compatibility.
- Introduce typed check status/category and score result models with centralized validation while preserving serialized report values.
- Preserve DNS lookup evidence states so timeouts, SERVFAIL responses and resolver errors are not treated as missing records.
- Cache DNS query results during a scan to avoid repeating identical lookups.
- Mark DNS-dependent checks as `UNKNOWN` and exclude them from scoring when required DNS evidence is unavailable.
- Track incomplete nested SPF DNS evidence so lookup-budget checks do not report a confident pass after resolver failures.
- Split discovered-host reporting into current DNS, historical CT/NXDOMAIN, unresolved, DNS-unknown, and not-assessed groups; keep the PDF DNS appendix focused on hosts with current records.

### Fixed

- Prevent transient DNS resolver failures from being misreported and scored as conclusively missing mail or domain-security records.

## [1.0.1] - 2026-09-17

### Fixed

- Require TLS 1.2 or newer for the scanner's normal TLS connection path.
- Preserve the separate legacy-TLS capability probe for intentionally testing TLS 1.0 and TLS 1.1 support.
- Address the CodeQL `py/insecure-protocol` finding for standard TLS checks.

## [1.0.0] - 2026-09-17

### Added

- Registered/root-domain discovery for subdomain web targets
- RDAP registration metadata and domain-expiry checks
- DNSSEC, CAA, nameserver and DNS inventory checks
- Passive Certificate Transparency hostname discovery
- Same-site crawl and public email-address inventory
- HTTPS/TLS certificate and redirect checks
- Legacy TLS 1.0/1.1 detection
- Mixed-content detection
- Session/auth cookie security-attribute checks
- HTTP security-header checks
- SPF duplicate-record, syntax and recursive DNS lookup-budget analysis
- Extended DMARC syntax, policy, reporting and alignment analysis
- Common-selector DKIM checks with conservative unknown handling
- MTA-STS and TLS-RPT checks
- Passive CMS/platform detection
- CMS release-currency checks for common CMS platforms
- Server/framework version-disclosure checks
- Customer-friendly color-coded PDF reporting
- JSON output
- External Security Hygiene Score
- Customer-facing "why it matters" explanations
- Non-commercial source-available license

### Project infrastructure

- Public-repository README and documentation
- CI smoke tests for supported Python versions
- Issue and pull-request templates
- Contribution, security and community conduct guidelines
