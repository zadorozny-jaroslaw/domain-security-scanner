# Changelog

All notable project changes are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
