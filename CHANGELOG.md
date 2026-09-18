# Changelog

All notable project changes are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add RFC 7505 Null MX parsing and validation, including detection of invalid mixed Null MX/ordinary MX configurations.
- Add a small internal standards reference registry for standards-backed checks.
- Add RFC 8461 MTA-STS validation for the DNS policy indicator, HTTPS response, policy syntax, modes, `max_age`, and MX-pattern coverage.
- Add RFC 8460 TLS-RPT policy validation, including required `rua` destinations, URI scheme validation, multiple-policy detection, and extension-field handling.

### Changed

- Preserve DNS lookup evidence states so timeouts, SERVFAIL responses and resolver errors are not treated as missing records.
- Cache DNS query results during a scan to avoid repeating identical lookups.
- Mark DNS-dependent checks as `UNKNOWN` and exclude them from scoring when required DNS evidence is unavailable.
- Track incomplete nested SPF DNS evidence so lookup-budget checks do not report a confident pass after resolver failures.
- Split discovered-host reporting into current DNS, historical CT/NXDOMAIN, unresolved, DNS-unknown, and not-assessed groups; keep the DNS appendix focused on hosts with current records.

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
