# Negative DNS, wildcard, and authoritative recursion observations

Issue #19 extends the v1.3 `domain` scan with a small, bounded set of direct DNS observations. The goal is to distinguish authoritative negative-response behavior, identify likely wildcard DNS behavior, and detect authoritative infrastructure that unexpectedly provides recursive resolution to an external client.

The check remains a low-impact posture observation. It does not enumerate random subdomains, measure DNS amplification, benchmark recursive resolver performance, send malformed DNS messages, or attempt DNS rebinding tests.

## Standards

The implementation is based primarily on:

- RFC 2308 — negative DNS response and negative-caching semantics;
- RFC 5358 / BCP 140 — guidance to avoid exposing recursive DNS service to unintended external clients.

RFC 2308 distinguishes NXDOMAIN from NODATA and requires authoritative negative responses used by the scanner to carry usable SOA authority evidence. RFC 5358 recommends limiting recursive service to intended clients and, for authoritative-only servers, disabling recursion where practical.

## Collection bounds

For each delegated authoritative nameserver, the scanner reuses the primary endpoint already selected by the bounded authoritative-DNS workstream. It does not create a new endpoint fallback tree.

At most three additional UDP queries are sent per authoritative nameserver:

1. one `A` query for the first generated high-entropy child name with RD cleared;
2. one `A` query for a second generated high-entropy child name with RD cleared;
3. one `A` query for a stable RFC 2606 example name outside the assessed zone with RD set.

Each query uses the same short direct-query timeout used by the issue #19 collector. There are no retry loops or response-size/amplification measurements.

## Negative-response states

Two generated names are used so the scanner does not infer wildcard behavior from a single random answer.

The zone-level negative-response status is:

- `nxdomain` — all collected randomized-name probes consistently returned authoritative NXDOMAIN evidence;
- `nodata` — all probes consistently returned authoritative NODATA evidence (`NOERROR` without the requested RRset, with usable negative SOA evidence);
- `wildcard` — both randomized names produced positive authoritative answers;
- `unknown` — evidence is incomplete, unavailable, mixed, or otherwise insufficient for a single conclusion.

SOA records observed in the authority section are retained in structured evidence for NXDOMAIN/NODATA analysis.

A timeout, transport failure, SERVFAIL, truncated response, non-authoritative response, or malformed negative response is never converted into confirmed record absence.

## Wildcard behavior

Wildcard DNS is contextual information, not automatically a security defect.

When both bounded randomized names return positive authoritative answers, the scanner reports likely wildcard behavior as `INFO` and records the affected authoritative servers. It also records whether the observed answer sets were identical after normalization, but equality is not required to recognize likely wildcard-style behavior because synthesized answers can differ by queried owner name or backend behavior.

If complete probes consistently return NXDOMAIN or NODATA, the JSON reports `wildcard.status: not_observed` for this bounded observation. Incomplete or conflicting evidence reports `unknown` rather than claiming wildcard absence.

## Open-recursion observation

The recursion probe is intentionally separate from normal authoritative queries. Normal direct-authoritative requests continue to clear the RD bit. The issue #19 probe uses `RD=1`, and the query cache includes the recursion-request profile so the two observations cannot collide.

The result stores both the request recursion intent and the response RD/RA flags.

The scanner classifies recursion conservatively:

- `open` — the server returned a conclusive non-authoritative result for the out-of-zone query with `RD=1`, `RA=1`, and `AA=0`;
- `closed` — the server explicitly returned `REFUSED` for the controlled recursive query;
- `unknown` — timeout, SERVFAIL, transport failure, ambiguous flags, an authoritative answer, or any other response that does not positively establish either case.

The RA flag alone is not proof of open recursion. Likewise, a timeout is not proof that recursion is disabled.

If any tested authoritative server positively demonstrates open recursion, the zone-level recursion state is `open`. The zone is `closed` only when every tested server explicitly refuses the recursive query; otherwise it remains `unknown`.

## Findings and scoring

Issue #19 emits the following Domain findings:

- `Authoritative negative DNS` — PASS/INFO/UNKNOWN depending on the bounded negative-response behavior;
- `Wildcard DNS` — INFO when likely wildcard behavior is observed;
- `Authoritative open recursion` — FAIL when recursive service is positively demonstrated, PASS when all tested servers explicitly refuse it, otherwise UNKNOWN.

These new findings currently have score weight `0`. Open recursion is treated as a security failure in the report, but assigning a new score weight is deliberately deferred to the broader v1.3 scoring-calibration work so this feature does not silently rebalance the existing External Security Hygiene Score.

## JSON output

The public JSON keeps the existing `dns_records` compatibility structure and adds issue #19 evidence under `dns`:

```json
{
  "dns": {
    "negative_response": {
      "status": "nxdomain",
      "complete": true,
      "zone": "example.com",
      "query_type": "A",
      "probe_count": 2,
      "generated_probe_names_serialized": false,
      "servers": []
    },
    "wildcard": {
      "status": "not_observed",
      "servers": []
    },
    "open_recursion": {
      "status": "closed",
      "probe_name": "example.net",
      "query_type": "A",
      "probes_per_server": 1,
      "amplification_measurement": false,
      "open_servers": [],
      "closed_servers": [],
      "unknown_servers": [],
      "servers": []
    }
  }
}
```

Per-server evidence includes the selected server IP, individual negative-probe outcomes, stable answer RDATA, retained SOA evidence, recursion state/reason, DNS state/RCODE, AA/TC, the recursion request flag, response RD/RA flags, transport, and bounded query error information. The exact high-entropy negative probe names are intentionally kept out of public JSON so otherwise equivalent scans do not produce meaningless report-diff churn solely because fresh probe labels are generated for every scan.

The scanner reports observations from the external scan location only. ACLs, anycast routing, split-horizon behavior, source-address policy, and transient network conditions can cause another client location to observe different behavior.
