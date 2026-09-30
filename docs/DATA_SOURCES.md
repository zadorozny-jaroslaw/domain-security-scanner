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

The shared v1.3 DNS evidence layer supports explicit direct queries to one supplied authoritative-server IP over UDP or TCP. Direct authoritative evidence is server- and transport-specific, clears the recursion-desired flag, and keeps UDP and TCP evidence separate instead of silently treating one as the other.

When the `domain` group is selected, bounded DNS work can:

- resolve the immediate parent zone's NS set through the configured recursive resolver;
- resolve addresses for candidate parent authoritative servers;
- send bounded direct UDP child-delegation queries to representative parent authoritative endpoints;
- retain delegated NS names and referral glue from authority/additional sections;
- resolve A, AAAA, and CNAME evidence for delegated NS targets;
- send bounded direct apex-NS probes to delegated-server endpoints;
- compare representative authoritative SOA behavior over UDP and TCP and make a bounded EDNS(0) observation;
- perform small negative-DNS, wildcard, and out-of-zone recursion probes where the same endpoint can first be attributed reliably to the assessed zone.

The scanner also evaluates direct-DNS path integrity. Signals such as unexpected recursion availability on RD=0 requests combined with referral-like or wrong-owner responses can mark the path as suspected interception/rewriting. Suspect responses are not treated as proof of the intended server's behavior.

For troubleshooting examples covering forced DNS redirection, Pi-hole/router/VPN interception, SOA/DNSSEC interpretation, and report diagnostics, see [DNS_TROUBLESHOOTING.md](DNS_TROUBLESHOOTING.md).

These direct requests can therefore be visible not only to the authorized domain's authoritative DNS provider but also to the relevant parent-zone authoritative infrastructure. They remain deliberately small and server-specific.

Direct-authoritative support does not perform zone transfers, amplification measurement, malformed-packet testing, DNS fuzzing, or high-volume DNS probing.

Normal scan outputs can therefore be visible in the target's DNS, web-server, reverse-proxy, CDN, firewall, and relevant parent-zone DNS logs.

Several standards-backed Web checks reuse the already-fetched HTTPS homepage response and do **not** create additional target requests: RFC 9111 cache metadata, RFC 8288 `Link`, RFC 7838 `Alt-Svc`, and the passive RFC 9112 HTTP/1.1 framing check. `Link` targets are not dereferenced, advertised `Alt-Svc` alternatives are not contacted, and the RFC 9112 check does not open a raw socket or send a separate HTTP/1.1 probe.

A CMS-only scan reuses the HTTPS homepage as passive detection context but does not perform the Web group's HTTP redirect probe or `security.txt` request.

## Public infrastructure services and encrypted DNS fallback

### DNS-over-HTTPS fallback

When the `domain` group detects a suspect or mixed direct-DNS path, the scanner can use two independent validating DNS-over-HTTPS services over HTTPS/443:

```text
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
```

The fallback is bounded and zone-level. It can request SOA, NS, DS, and DNSKEY material for the registered/root domain plus A/AAAA evidence for recovered nameserver targets. The queried domain and nameserver hostnames are therefore disclosed to both providers when the fallback is used.

The scanner requires independent agreement for recovered RRsets and performs its own local DNSSEC checks before promoting a DNSSEC result to `secure`; it does not rely on a single provider's AD flag as proof. Encrypted recursive evidence is explicitly labelled as such and is not presented as a response from a specific authoritative server.

The fallback is intended to preserve useful evidence when a local router, Pi-hole enforcement rule, VPN, firewall, or ISP transparently redirects port 53. If direct per-server attribution is unavailable, transport, EDNS, SOA-serial consistency, negative-DNS, and open-recursion checks for a particular authoritative server remain `VERIFY`/informational rather than being inferred from DoH.

For practical interpretation of this condition, including the difference between merely using Pi-hole as the configured resolver and forcibly redirecting all port-53 traffic, see [DNS_TROUBLESHOOTING.md](DNS_TROUBLESHOOTING.md).

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
