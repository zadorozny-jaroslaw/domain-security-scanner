# Domain Security Scanner

**Version 1.0.1** - low-impact external security posture checks for domains you own or are explicitly authorized to assess.

> **Source-available / non-commercial license.** This project is free for personal, educational, research, evaluation, testing, and internal non-commercial use. Commercial use requires separate written permission from Jarosław Zadorożny. See [LICENSE](LICENSE).
>
> **Authorization required.** Do not scan systems you do not own or have explicit permission to assess.

The scanner takes a domain or subdomain, performs passive and low-impact external checks, and produces a customer-friendly **PDF report** plus structured **JSON** output. It intentionally does not exploit vulnerabilities, brute-force credentials, scan port ranges, perform denial-of-service tests, or attempt to access non-public data.

## Example report

The example below was generated against a maintainer-controlled WordPress test host.

[Open the full example PDF](docs/example-report.pdf)

![Example report - page 1](docs/example-report-page-1.png)

## Highlights

- Exact web-target checks while registration and mail checks follow the registered/root domain
- RDAP, DNSSEC, CAA, nameserver and expiry checks
- Certificate Transparency subdomain discovery through `crt.sh`
- DNS inventory with resolver-error awareness and same-site crawling
- HTTPS/TLS certificate analysis and legacy TLS detection
- HTTP-to-HTTPS redirect and mixed-content checks
- Customer-facing HTTP security-header findings
- Session/auth cookie flag checks (`Secure`, `HttpOnly`, `SameSite`)
- SPF syntax, duplicate-record and recursive DNS lookup-budget analysis
- DMARC policy, syntax, reporting and alignment analysis
- DKIM common-selector checks with conservative `UNKNOWN` handling
- RFC 7505 Null MX detection and validation
- MTA-STS and TLS-RPT checks
- Passive CMS/platform fingerprinting and version discovery
- Live CMS release-currency checks for common CMS platforms
- Server/framework version-disclosure checks
- Color-coded PDF findings with short "why it matters" explanations
- External Security Hygiene Score from 0 to 100

## Requirements

- Python **3.11+** recommended
- Internet access for DNS/RDAP/CT lookups and selected upstream release checks
- Windows, Linux, or macOS

The PDF generator uses Unicode fonts already installed on the host OS. Font files are not bundled with this repository.

## Quick start

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/zadorozny-jaroslaw/domain-security-scanner.git
cd domain-security-scanner
python -m venv .venv
```

Activate it:

**Windows PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the installed project version:

```bash
python domain_security_scan.py --version
```

Run an authorized scan:

```bash
python domain_security_scan.py example.com --authorized
```

The default output is:

```text
security-report-example.com.pdf
security-report-example.com.json
```

## Usage

```text
python domain_security_scan.py DOMAIN --authorized [--max-pages N] [--max-hosts N] [--out PREFIX]
```

Examples:

```bash
python domain_security_scan.py shop.example.com --authorized
python domain_security_scan.py example.com --authorized --max-pages 15 --max-hosts 20
python domain_security_scan.py example.com --authorized --out customer-example
```

The `--authorized` flag is deliberately mandatory.

## Web target vs registered/root domain

The command-line value is treated as the **exact web target**. For example, if you scan:

```text
app.eu.example.com
```

HTTP, HTTPS, TLS, cookie, mixed-content and web-platform checks stay on that host.

The scanner then walks RDAP upward to identify the registered/root domain (for example `example.com`). Registration, expiry, nameserver, DNSSEC and mail-security checks are run against that root domain. If RDAP is unavailable, a conservative fallback is used.

This avoids treating a website subdomain as if it were the organization's mail domain.

## What it checks

### Domain and DNS

- RDAP root-domain discovery
- registrar and nameservers
- domain-expiry visibility
- transfer-prohibited status where externally visible
- DNSSEC indication (`DS` / RDAP)
- CAA
- `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `CAA`, and selected `DS` records
- passive Certificate Transparency hostname discovery

### Mail posture

- MX, including RFC 7505 Null MX semantics
- SPF presence and policy
- duplicate SPF records
- practical SPF syntax validation
- recursive SPF DNS lookup-budget estimate against the 10-term limit
- DMARC syntax and policy (`p`, `sp`, `pct`)
- DMARC aggregate reporting (`rua`)
- DKIM/SPF alignment modes (`adkim`, `aspf`)
- common-selector DKIM discovery (absence is not treated as proof that DKIM is missing)
- MTA-STS
- TLS-RPT

### Web and TLS

- HTTPS and certificate validity/expiry
- negotiated TLS protocol and cipher
- TLS 1.0 / 1.1 legacy-protocol checks
- HTTP-to-HTTPS redirect
- mixed HTTP content on HTTPS pages
- sensitive/session cookie flags
- HSTS
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- frame/clickjacking protection
- `security.txt`
- server/framework version disclosure

### CMS/platform

Passive detection currently includes common signals for:

- WordPress
- Drupal
- Joomla
- Ghost
- TYPO3
- Shopify
- Wix
- Squarespace
- Webflow

The scanner does **not** probe `/wp-admin`, `/readme.html`, plugin directories, login pages, or CMS-specific enumeration endpoints merely to identify a platform.

When a high-confidence version is publicly disclosed, supported CMSes can be compared with current upstream release information. A newer release is a **review/update** finding, not automatic proof of a vulnerability.

## Report statuses

| Status | Meaning |
| --- | --- |
| 🟢 `OK` | Healthy/current for the check performed |
| 🟡 `REVIEW` | Hardening or update recommended |
| 🔴 `ACTION` | Failure or higher-priority issue requiring review |
| 🔵 `INFO` | Informational finding |
| ⚪ `VERIFY` | Cannot be established reliably from the external scan |

WARN and FAIL findings include a short **Why it matters** explanation. The wording describes exposure or hardening value without claiming that compromise has occurred.

## Scoring

The score is intentionally named **External Security Hygiene Score**, not a general "security score."

Only applicable weighted checks contribute to the denominator. Unknown/unverifiable checks are excluded rather than penalized. DNS timeouts, SERVFAIL responses and resolver errors are treated as unavailable evidence rather than as proof that a record is absent. Several useful findings - including CMS release currency - are informational or advisory and intentionally have no score weight.

See [docs/SCORING.md](docs/SCORING.md) for the scoring philosophy.

## External services and privacy

The scanner talks to the target and to a small number of public infrastructure/release services, including RDAP sources, `crt.sh`, and upstream CMS release sources. No API keys are required for the default checks.

Before using the scanner in a privacy-sensitive environment, read [docs/DATA_SOURCES.md](docs/DATA_SOURCES.md), which documents what is queried externally.

## Safety and scope

This project is designed as an **external posture / hygiene check**, not a penetration-testing framework.

The default project scope intentionally excludes:

- vulnerability exploitation
- credential attacks or brute force
- broad port scanning
- DoS/load testing
- accessing non-public data
- authenticated tenant or endpoint assessment
- automatic claims that a detected software version is vulnerable

See [docs/SCOPE.md](docs/SCOPE.md).

## Limitations

- This is not a penetration test or a guarantee of security.
- External observation cannot assess MFA, backups, endpoint protection, internal permissions, offboarding, or tenant configuration.
- DKIM cannot always be discovered without knowing the selector.
- DNSSEC presence is detected, but the scanner does not perform full cryptographic chain validation.
- `.pl` Registry Lock may require manual verification at the registrar.
- Certificate Transparency is historical by design; discovered hostnames may no longer resolve.
- SPF lookup count is a static worst-case estimate; macros and runtime DNS behavior can affect exact evaluation.
- Cookie analysis is limited to cookies externally visible during the unauthenticated crawl/redirect chain.
- Legacy TLS results depend partly on what the local TLS library can test; uncertain cases are reported as `VERIFY`.
- Passive CMS detection can miss intentionally hidden or heavily proxied platforms.

See [`docs/STANDARDS.md`](docs/STANDARDS.md) for the RFC/standards registry and the exact standards-backed checks implemented by the scanner.

## Project structure

The scanner is organized as a Python package while keeping `domain_security_scan.py` as the backward-compatible command-line entry point. The package split is organizational only: the scan flow, checks, scoring behavior, JSON schema, PDF output, and CLI arguments remain unchanged.

```text
domain_security_scan.py              # compatibility CLI entry point
domain_security_scanner/
├── __init__.py                       # public package API
├── version.py                        # scanner version
├── constants.py                      # shared scanner constants
├── models.py                         # typed check/status/category/score result models
├── utils.py                          # domain/date helper functions
├── base.py                           # shared Scanner state
├── rdap.py                           # RDAP/domain checks
├── dns_mail.py                       # DNS and mail-security checks
├── inventory.py                      # CT discovery, crawl, DNS inventory
├── web_tls.py                        # HTTP/TLS/cookie/header checks
├── cms.py                            # passive CMS detection/currency checks
├── scanner.py                        # scan orchestration and scoring
├── cli.py                            # argument parsing and output handling
└── reporting/
    ├── __init__.py
    └── pdf.py                        # PDF rendering
```

This layout is intended to make later changes easier to isolate. Shared result models validate check categories/statuses centrally while preserving the existing JSON representation. For example, report rendering can evolve without mixing PDF code into DNS or TLS checks, while the top-level script remains compatible with the existing documented commands.

## Contributing

Contributions are welcome when they preserve the project's low-impact, evidence-based posture-check scope.

Before opening a large pull request, read [CONTRIBUTING.md](CONTRIBUTING.md). In particular, new findings should minimize false positives, explain why they matter, and avoid turning the default scanner into an exploitation framework.

## Security issues in this project

Please do **not** publish scanner vulnerabilities, secrets, customer reports, or sensitive target details in a public issue. Follow [SECURITY.md](SECURITY.md).

## Releases and versioning

The project uses semantic versioning:

- `1.0.x` - compatible bug fixes
- `1.x.0` - compatible new checks/features
- `2.0.0` - breaking behavior or interface changes

See [CHANGELOG.md](CHANGELOG.md) and [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## License

Copyright © 2026 **Jarosław Zadorożny**.

This repository uses a **custom non-commercial source-available license**. It is not an OSI-approved open-source license because commercial use is restricted.

Personal, educational, academic, research, evaluation, testing, and internal non-commercial use are permitted under the terms in [LICENSE](LICENSE). Paid scans, consulting, managed services, SaaS, resale, or other commercial use require separate written permission from Jarosław Zadorożny.
