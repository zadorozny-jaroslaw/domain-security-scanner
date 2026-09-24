# Scan groups and orchestration

Domain Security Scanner is split into six public scan groups. The command-line interface can run the complete default scope or a selected subset without changing the underlying low-impact design.

## Public groups

The canonical group order is:

```text
domain, discovery, mail, tls, web, cms
```

| Group | Responsibility | Main target/context |
| --- | --- | --- |
| `domain` | RDAP, registrar/expiry, nameservers, DNSSEC, CAA and root-domain DNS posture | registered/root domain |
| `discovery` | Certificate Transparency discovery, same-site crawl, discovered-host DNS inventory and live/historical classification | web target plus registered/root-domain context |
| `mail` | MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT | registered/root domain |
| `tls` | HTTPS certificate, expiry, negotiated protocol/cipher and legacy TLS support | exact web target |
| `web` | HTTP redirect, HTTP headers, cookies, mixed content, `security.txt`, server disclosure | exact web target |
| `cms` | passive CMS/platform detection and release-currency checks | exact web target plus upstream release metadata when needed |

There are currently no public aliases such as `all` or `infra`. The accepted names are exactly the six values above.

## CLI selection rules

With no selection flags, the scanner runs all six groups:

```bash
python domain_security_scan.py example.com --authorized
```

Use `--scan` to include only listed groups:

```bash
python domain_security_scan.py example.com --authorized --scan mail,web
```

Use `--skip` to remove groups from the default full scan:

```bash
python domain_security_scan.py example.com --authorized --skip discovery,cms
```

Both flags may be present. `--skip` has higher priority:

```bash
python domain_security_scan.py example.com --authorized \
  --scan domain,mail,web \
  --skip mail
```

The effective scope in that example is `domain,web`. The CLI prints a warning whenever both options are supplied because the combination may be redundant. If any group appears in both lists, a second warning names the overlapping group(s) and confirms that they will not be scanned.

Group lists are comma-separated, case-insensitive, and deduplicated. Internally, effective selections are normalized back to canonical group order.

If all groups are removed, the scanner warns that no functional scan groups remain and produces a context-only report with no scan findings.

## Findings versus prerequisite context

A selected group can depend on context normally owned by another group. Prerequisite execution does **not** automatically enable that other group's findings.

Two shared prerequisites currently exist:

1. `domain`, `discovery`, and `mail` need registered/root-domain context. The orchestrator therefore runs the RDAP/root lookup when any of those groups is selected.
2. `web` and `cms` share the HTTPS homepage response. When only `cms` is selected, the homepage is fetched once for CMS fingerprinting without running Web findings such as redirect, header, cookie, mixed-content, or `security.txt` checks.

The scanner tracks the active owner of each orchestration step. If a prerequisite step belongs to an unselected group, findings emitted under that group are suppressed. This is what prevents prerequisite work from changing the score or report findings for the selected scope.

Prerequisite context can still populate structured evidence used by selected groups. The PDF hides technical sections for unselected groups, while JSON can retain context needed to explain the selected checks.

## Execution plan

`domain_security_scanner/orchestration.py` owns the canonical execution policy. For the default full scan, the effective plan is:

```text
1. domain:     rdap_lookup
2. domain:     collect_domain_dns
3. mail:       collect_mail_dns
4. discovery:  discover_ct_subdomains
5. discovery:  crawl
6. discovery:  collect_subdomain_dns
7. tls:        check_tls
8. web:        check_http
9. cms:        check_cms_currency
```

For a partial scan, the orchestration layer keeps only required steps plus the minimum prerequisite context. It also ensures shared context such as the HTTPS homepage is fetched once when both `web` and `cms` are selected.

`Scanner.run()` intentionally remains small: it builds the execution plan, resolves the named method for each step, and executes it under the step's owning group.

## Scoring semantics

The External Security Hygiene Score applies to the **effective selected scope**, not to groups that were skipped.

Only checks that are both:

- emitted by selected groups; and
- applicable with a positive weight

contribute to the score denominator.

Unselected prerequisite findings are suppressed before scoring. `UNKNOWN`/unverifiable checks remain excluded according to the normal scoring rules.

Because the denominator changes with scope, partial-scan scores are not directly comparable with full-scan scores or with scores produced from a different group selection. For example, a Web-only score intentionally contains no TLS, Mail, Domain, Discovery, or CMS points.

See [SCORING.md](SCORING.md) for the general scoring philosophy.

## Report metadata

JSON reports include:

- `scan_groups`: canonical effective groups that were actually selected;
- `scan_selection.requested`: original `--scan` request, or `null` when the default full scope was used;
- `scan_selection.skipped`: groups explicitly provided through `--skip`;
- `scan_selection.overlap`: groups present in both requested and skipped lists;
- `scan_selection.effective`: the final effective scope;
- `scan_selection.warnings`: CLI selection warnings preserved for report rendering.

The PDF displays the effective scanned/skipped groups and repeats selection warnings. Technical detail sections for skipped groups are omitted so an unassessed area is not presented as `VERIFY`, missing, or failed.

Older JSON reports that predate `scan_groups` are rendered as full-scope reports for backward-compatible PDF generation.

## Package layout

Each functional group lives under `domain_security_scanner/domains/`:

```text
domain_security_scanner/
├── orchestration.py
├── scanner.py
└── domains/
    ├── domain/
    ├── discovery/
    ├── mail/
    ├── tls/
    ├── web/
    └── cms/
```

The old transitional flat compatibility modules were removed after the scanner and CLI moved fully to the grouped package layout.

## Adding or changing a group

When changing orchestration behavior:

1. keep the public group name stable unless the interface change is intentional;
2. add the group implementation under `domain_security_scanner/domains/`;
3. update `SCAN_GROUPS` and the execution rules in `orchestration.py`;
4. make prerequisite ownership explicit rather than enabling another group's findings implicitly;
5. add tests for the individual plan, combinations, score isolation, and report scope;
6. update README and this document when the public behavior changes.

Avoid coupling selection directly to check categories such as `Web` or `Mail`. Scan groups are the execution/reporting boundary; existing category strings remain part of the report model and can be shared by historically related findings.
