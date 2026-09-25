# External data sources and network behavior

The scanner performs external network requests. This document explains the main destinations so operators understand what data can leave their machine.

## Scan-group selection and network behavior

The default scan runs all six functional groups: `domain`, `discovery`, `mail`, `tls`, `web`, and `cms`. Operators can restrict the effective scope with `--scan` or remove groups with `--skip`.

Skipping a group prevents that group's findings from running, but a selected group can still require limited prerequisite context owned by another group. In particular:

- `domain`, `discovery`, and `mail` can require RDAP/root-domain discovery;
- `cms` can require one HTTPS homepage request even when `web` findings are not selected.

Prerequisite work is deliberately limited to context needed by the selected group. It does not enable the skipped group's findings or score contribution. See [SCAN_GROUPS.md](SCAN_GROUPS.md) for the execution model.

## Target-controlled services

Depending on the selected groups, the scanner may query the authorized target/root domain using:

- DNS through the system-configured resolver;
- HTTP and HTTPS;
- TLS handshakes;
- `https://mta-sts.<root-domain>/.well-known/mta-sts.txt` only after a usable RFC 8461 MTA-STS TXT indicator is found; redirects are not followed and normal HTTPS certificate validation remains enabled;
- `https://<web-target>/.well-known/security.txt` when Web checks are selected.

The shared v1.3 DNS evidence layer also supports explicit direct queries to one supplied authoritative-server IP over UDP or TCP. Direct authoritative evidence is server- and transport-specific, clears the recursion-desired flag, and does not silently retry UDP evidence over TCP.

When the `domain` group is selected, the v1.3 delegation check now uses that layer to obtain parent-side delegation evidence and evaluate delegated nameservers. It can:

- resolve the immediate parent zone's NS set through the configured recursive resolver;
- resolve addresses for candidate parent authoritative servers;
- send a bounded direct UDP NS query to a parent server to obtain the child referral;
- retain delegated NS names and referral glue from authority/additional sections;
- resolve A, AAAA, and CNAME evidence for each delegated NS;
- send a bounded direct UDP apex-NS query to representative delegated-server endpoints, using at most one fallback endpoint when the first probe does not positively establish authority.

These direct requests can therefore be visible not only to the authorized domain's authoritative DNS provider but also to the relevant parent-zone authoritative infrastructure. They are deliberately small and server-specific. TCP/UDP transport comparison, SOA consistency, and EDNS observations belong to the separate v1.3 authoritative-consistency workstream.

Direct-authoritative support does not perform zone transfers, amplification measurement, malformed-packet testing, or high-volume DNS probing.

Normal scan outputs can therefore be visible in the target's DNS, web-server, reverse-proxy, CDN, firewall, and relevant parent-zone DNS logs.

Several standards-backed Web checks reuse the already-fetched HTTPS homepage response and do **not** create additional target requests: RFC 9111 cache metadata, RFC 8288 `Link`, RFC 7838 `Alt-Svc`, and the passive RFC 9112 HTTP/1.1 framing check. `Link` targets are not dereferenced, advertised `Alt-Svc` alternatives are not contacted, and the RFC 9112 check does not open a raw socket or send a separate HTTP/1.1 probe.

A CMS-only scan reuses the HTTPS homepage as passive detection context but does not perform the Web group's HTTP redirect probe or `security.txt` request.

## Public infrastructure services

### IANA RDAP bootstrap

Used to discover the appropriate RDAP service for a TLD when selected groups require registered/root-domain context:

```text
https://data.iana.org/rdap/dns.json
```

For `.pl`, the scanner can use the NASK RDAP service as a fallback/registry source.

### Certificate Transparency search

When the `discovery` group is selected, passive hostname history is queried through:

```text
https://crt.sh/
```

The queried root domain is sent to this service. Certificate Transparency data is historical; returned names may no longer exist. The scanner re-checks discovered names against its low-impact common DNS inventory and separates CT names that now return NXDOMAIN from hosts with current records. A DNS timeout, SERVFAIL, or resolver error is never labelled historical; it remains an unknown DNS state. Names with no records in the queried common record types but without conclusive NXDOMAIN are shown as currently unresolved rather than historical.

## CMS release information

When the `cms` group is selected and a supported CMS is confidently detected with a public version, release-currency checks can query public upstream sources, currently including:

- WordPress release/version API (`api.wordpress.org`)
- Joomla public GitHub release feed
- Ghost public GitHub release feed
- Drupal release-history service (`updates.drupal.org`)

These requests are for project release metadata. The target domain itself is not required as a parameter for the CMS release lookup.

## Reports and local data

PDF and JSON reports are written locally to the path/prefix selected by the operator. The project does not include a telemetry or report-upload feature.

Reports may contain domain names, IP addresses, DNS records, public email addresses, software versions, configuration findings, and scan-scope metadata. Treat customer reports as potentially sensitive operational data and do not commit them to a public repository.
