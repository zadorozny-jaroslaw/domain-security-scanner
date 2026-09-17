# External data sources and network behavior

The scanner performs external network requests. This document explains the main destinations so operators understand what data can leave their machine.

## Target-controlled services

The scanner may query the authorized target/root domain using:

- DNS through the system-configured resolver;
- HTTP and HTTPS;
- TLS handshakes;
- `https://mta-sts.<root-domain>/.well-known/mta-sts.txt` when applicable;
- `https://<web-target>/.well-known/security.txt`.

Normal scan outputs can therefore be visible in the target's DNS, web-server, reverse-proxy, CDN, or firewall logs.

## Public infrastructure services

### IANA RDAP bootstrap

Used to discover the appropriate RDAP service for a TLD:

```text
https://data.iana.org/rdap/dns.json
```

For `.pl`, the scanner can use the NASK RDAP service as a fallback/registry source.

### Certificate Transparency search

Passive hostname history is queried through:

```text
https://crt.sh/
```

The queried root domain is sent to this service. Certificate Transparency data is historical; returned names may no longer exist.

## CMS release information

When a supported CMS is confidently detected with a public version, release-currency checks can query public upstream sources, currently including:

- WordPress release/version API (`api.wordpress.org`)
- Joomla public GitHub release feed
- Ghost public GitHub release feed
- Drupal release-history service (`updates.drupal.org`)

These requests are for project release metadata. The target domain itself is not required as a parameter for the CMS release lookup.

## Reports and local data

PDF and JSON reports are written locally to the path/prefix selected by the operator. The project does not include a telemetry or report-upload feature.

Reports may contain domain names, IP addresses, DNS records, public email addresses, software versions, and configuration findings. Treat customer reports as potentially sensitive operational data and do not commit them to a public repository.
