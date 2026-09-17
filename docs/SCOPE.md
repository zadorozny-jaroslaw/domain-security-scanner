# Project scope and design rules

Domain Security Scanner is intentionally a **low-impact external posture checker**.

## In scope

Checks are suitable for the default scanner when they are:

- passive or low-impact;
- externally observable without credentials;
- reasonably deterministic;
- useful to a domain owner or small-business administrator;
- explainable in customer-friendly language;
- designed to minimize false positives;
- safe to run with explicit authorization against normal production services.

Examples include DNS/RDAP inspection, TLS handshakes, normal HTTP requests, public Certificate Transparency data, mail-authentication records, security headers, passive CMS fingerprinting, and release-currency checks.

## Out of scope for the default scanner

Do not add the following as default features without an explicit project-scope decision:

- exploit attempts or exploit verification;
- credential attacks, password spraying, or brute force;
- broad port scanning or service enumeration;
- denial-of-service or load testing;
- directory/file brute forcing;
- authenticated tenant, endpoint, or internal-network assessment;
- automatic secret harvesting;
- aggressive CMS/plugin enumeration;
- claims that a version is vulnerable solely because it is not the latest release.

## Finding quality

A new finding should answer four questions:

1. **What evidence was observed?**
2. **Why can it matter?**
3. **What is the likely false-positive condition?**
4. **What safe remediation guidance can be given?**

Use `PASS`, `WARN`, `FAIL`, `INFO`, and `UNKNOWN` conservatively. If external verification is not reliable, prefer `UNKNOWN` over a confident negative claim.

## Authorization

The CLI deliberately requires `--authorized`. Contributors should not remove or weaken that guardrail in normal project operation.
