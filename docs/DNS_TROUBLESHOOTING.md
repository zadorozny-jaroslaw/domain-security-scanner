# DNS troubleshooting: intercepted or rewritten direct DNS

The scanner performs bounded direct DNS queries to authoritative and parent DNS
server IP addresses when the `domain` scan group is enabled. In some networks,
outbound DNS on UDP/TCP port 53 is transparently redirected, proxied, filtered,
or rewritten before it reaches the intended IP.

This can make an otherwise healthy public DNS zone look inconsistent from the
scanner's local network.

Typical environments where this can happen include:

- routers or firewalls with "force DNS" / DNS-redirection rules;
- Pi-hole, Unbound, AdGuard, or similar resolvers combined with NAT/firewall
  rules that redirect all outbound port-53 traffic to the local resolver;
- VPN clients or enterprise security agents that capture DNS;
- parental-control or endpoint-security DNS filtering;
- managed networks that force a local recursive resolver;
- ISP-side transparent DNS interception.

Using Pi-hole as the system-configured recursive resolver is **not by itself**
the same as interception. The problematic case is when the network also forces
queries that the scanner intentionally sends to a specific authoritative IP
back through Pi-hole or another recursive resolver.

## Why this affects SOA, delegation, and DNSSEC observations

A direct authoritative query is supposed to test the behavior of a specific DNS
endpoint. For example, an apex SOA request sent directly to an authoritative
server with recursion disabled should normally return authoritative evidence for
that zone.

If a router or resolver silently intercepts the packet, the scanner can receive
a syntactically valid DNS response that did **not** come from the intended
authoritative endpoint.

Examples of suspicious combinations include:

- recursion availability (`RA`) appearing on a query sent with `RD=0`;
- a referral-like response where an apex answer was expected;
- an authority-section owner that does not match the queried name;
- `AA=1` while the requested apex RRset is missing;
- a direct SOA/NS query returning no usable SOA/NS evidence even though normal
  recursive DNS resolves the zone.

No single flag proves interception. In particular, `RA=1` alone is not treated
as sufficient evidence. The scanner combines multiple response-shape and
provenance signals before marking the path as suspect.

When this happens, raw direct responses must not be interpreted as proof that an
authoritative nameserver is lame, unreachable, inconsistent, recursively open,
or missing SOA data.

## How the scanner represents this case

The main JSON location is:

```text
dns.path_integrity
```

Typical output can look like:

```json
{
  "status": "suspected_interception",
  "basis": "direct_delegation_and_authoritative",
  "transports": {
    "udp": {
      "status": "suspected_interception"
    },
    "tcp": {
      "status": "suspected_interception"
    }
  },
  "signals": [
    "unexpected_ra_on_rd0",
    "referral_like_apex_response",
    "aa_without_requested_apex_rrset"
  ]
}
```

The exact signals depend on the responses seen from the current scan location.

When the aggregate direct path is `suspected_interception` or `mixed`, affected
per-server checks are kept conservative. Typical examples are:

```text
Delegated nameserver authority     VERIFY
Authoritative DNS transport        VERIFY
Authoritative open recursion       VERIFY
Authoritative SOA consistency      INFO / VERIFY
Authoritative SOA serial           INFO / VERIFY
Authoritative EDNS(0)              INFO / VERIFY
```

`UNKNOWN` / `VERIFY` findings are excluded from the weighted score. A local
network problem therefore does not become an automatic DNS security failure.

## Encrypted recursive recovery

When the direct path is suspect, the scanner can perform a bounded fallback over
HTTPS/443 using two independent validating DNS-over-HTTPS resolvers.

The fallback can recover zone-level evidence such as:

- apex SOA;
- apex NS;
- parent DS;
- child DNSKEY;
- A/AAAA records for recovered nameserver targets.

This evidence is recorded under:

```text
dns.encrypted_recursive
```

A usable fallback may allow the scanner to recover statements such as:

```text
Encrypted DNS fallback             PASS
Authoritative SOA service          PASS
DNS delegation consistency         PASS
Nameserver addressability          PASS
```

These are **zone-level** conclusions. They do not mean that the scanner directly
tested every authoritative endpoint successfully.

### DNSSEC

For DNSSEC, the scanner does not trust the HTTPS transport or resolver AD flag
alone.

Promotion to:

```text
dns.dnssec.status = secure
```

through the encrypted fallback requires:

1. agreement between both configured validating DoH resolvers;
2. authenticated DNSSEC context from those resolver paths;
3. local DS-to-DNSKEY matching;
4. local cryptographic validation of the collected DNSKEY RRset;
5. local validation of the selected apex SOA and NS signatures.

A secure result obtained this way is therefore a real bounded cryptographic
validation of the collected chain and selected apex RRsets.

It is still **not** proof that every RRset in the zone was validated, and it does
not restore per-authoritative-server attribution.

## Why SOA may be visible in the appendix while per-server SOA remains unknown

This is expected when the local port-53 path is intercepted.

For example, the scanner can have:

```text
Authoritative SOA service          PASS
Authoritative SOA consistency      INFO
Authoritative SOA serial           INFO
```

and still retain `unknown` direct per-server SOA state internally.

The distinction is:

- encrypted consensus can prove that the **zone publishes a signed SOA** and can
  report its observed serial;
- recursive encrypted evidence cannot prove that every individual authoritative
  server currently returns the same SOA serial;
- therefore per-server consistency is not silently converted into a PASS.

The recovered trusted SOA can also be copied into the report-only legacy
`dns_records` appendix so users can see the current zone-level record without
changing the provenance of the richer `dns` evidence.

## Checking a report in PowerShell

Useful fields can be inspected directly from the JSON report:

```powershell
$r = Get-Content .\security-report-example.com.json -Raw | ConvertFrom-Json

$r.dns.path_integrity |
  ConvertTo-Json -Depth 12

$r.dns.encrypted_recursive |
  ConvertTo-Json -Depth 12

$r.dns.dnssec |
  ConvertTo-Json -Depth 12
```

To focus on checks that usually depend on direct authoritative attribution:

```powershell
$r.checks |
  Where-Object {
    $_.name -in @(
      "Delegated nameserver authority",
      "Authoritative DNS transport",
      "Authoritative open recursion",
      "Authoritative SOA service",
      "Authoritative SOA consistency",
      "Authoritative SOA serial",
      "Authoritative NS RRset consistency",
      "Authoritative EDNS(0)"
    )
  } |
  Format-Table status, name, applicable, weight, earned, message -Wrap
```

## Optional direct comparison with `dig`

If `dig` is available, an operator can compare the network behavior manually.

First obtain one authoritative nameserver IP from the report, then run a bounded
query such as:

```bash
dig @<authoritative-ip> example.com SOA +norecurse
dig @<authoritative-ip> example.com NS +norecurse
dig @<authoritative-ip> example.com SOA +norecurse +tcp
```

For an apex SOA query to a real authoritative endpoint, the requested SOA should
normally be present and authoritative.

If a completely different network path produces normal authoritative responses
while the original network consistently produces recursive/referral-like
responses, that is strong operational evidence that the original path is being
rewritten.

Do not infer interception from `RA` alone, and do not use high-volume probing to
diagnose the issue.

## What to check on the local network

If interception is suspected:

1. inspect router/firewall NAT rules for UDP/53 and TCP/53 redirection;
2. check VPN DNS enforcement or enterprise endpoint-security policies;
3. if Pi-hole/Unbound/AdGuard is present, determine whether clients merely use it
   as their configured resolver or whether the gateway forcibly redirects all
   DNS traffic to it;
4. compare the scan from another authorized network that does not force port 53,
   such as an isolated test network;
5. keep the original report: it correctly documents that per-server evidence was
   not trustworthy from that location.

Do not permanently disable organizational DNS controls merely to make a scanner
report greener. If per-server authoritative evidence is required, run the
authorized assessment from a network where direct UDP/TCP port-53 traffic is
allowed to reach the intended destination without transparent rewriting.

## Interpreting the PDF

A report produced from an intercepted path can legitimately contain both:

```text
DNSSEC                         OK / SECURE
Delegation                    OK
Encrypted DNS                 OK
Direct per-server DNS         VERIFY
```

This is not contradictory.

It means the scanner has enough independent zone-level evidence to validate
selected DNS posture, while the local network prevents reliable attribution of
direct responses to individual authoritative endpoints.

The detailed JSON should be used when determining exactly which statements were
recovered through encrypted recursive evidence and which direct checks remained
unverifiable.

## Privacy note

The encrypted fallback sends the assessed zone name and selected nameserver
hostnames to both configured DNS-over-HTTPS providers when it is triggered.

See [DATA_SOURCES.md](DATA_SOURCES.md) for the exact external services and data
flow, and [DNS_EVIDENCE.md](DNS_EVIDENCE.md) for the evidence/provenance model.
