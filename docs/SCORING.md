# Scoring philosophy

The **External Security Hygiene Score** is a bounded summary of the checks this scanner can perform from the public Internet. It is not a probability of compromise, a compliance score, or a substitute for a security assessment.

## Principles

1. **Only applicable checks count.** If a check cannot be established reliably from outside, it is normally marked `VERIFY`/`UNKNOWN` and excluded from the weighted denominator.
2. **Configuration quality is not the same as compromise.** Missing hardening controls can reduce the score without implying that an attack has occurred.
3. **Informational checks may have zero weight.** Useful observations such as CMS release currency or technology disclosure can be shown without materially changing the score.
4. **False confidence is worse than uncertainty.** When the scanner cannot verify a condition, it prefers an explicit unknown result instead of assuming safety. DNS timeouts, SERVFAIL responses and resolver errors are treated as unavailable evidence, not as proof that a DNS record is absent.
5. **The score is scoped.** Only findings from the effective selected scan groups can contribute to the denominator. Work performed only to collect prerequisite context for a skipped group does not contribute findings or points.
6. **Weight changes are versioned.** Material changes to scoring behavior should be documented in `CHANGELOG.md`.

## Selected scan scope

By default, all six scan groups are selected: `domain`, `discovery`, `mail`, `tls`, `web`, and `cms`.

When `--scan` and/or `--skip` changes the effective scope, the score summarizes only the weighted checks emitted by those selected groups. The orchestration layer may still perform limited prerequisite work, such as RDAP/root-domain discovery for a Mail-only scan or an HTTPS homepage fetch for a CMS-only scan. Findings owned by an unselected prerequisite group are suppressed before scoring.

This means scores from different scan scopes are **not directly comparable**. A Web-only result can be numerically much lower or higher than a full-scan result because Domain, Mail, TLS, Discovery, and CMS checks are not part of that denominator. The PDF and JSON therefore record the effective scope alongside the score.

If selection removes every functional group, the CLI warns that the report contains no scan findings. Such a context-only result should not be interpreted as a meaningful security-hygiene assessment.

See [SCAN_GROUPS.md](SCAN_GROUPS.md) for selection, prerequisite, and orchestration semantics.

## Main weighted areas

- domain/DNS hygiene
- mail authentication and policy
- HTTPS/TLS posture
- selected web hardening controls

Discovery and CMS include useful evidence and findings, but not every observation has a positive score weight. The exact weights live alongside the checks in the `domain_security_scanner` package so the report always reflects the code that generated it.

## v1.3 delegation integration status

Issue #14 changes the evidence source for the existing **Name server redundancy** check: its existing 3-point weight is now based on the parent-side DNS delegation when that evidence is available, rather than only on RDAP nameserver metadata.

The new detailed delegation findings are currently non-scoring (`weight=0`):

- DNS delegation consistency;
- Delegated nameserver authority;
- Nameserver addressability;
- Delegation glue;
- Nameserver target aliasing.

Unavailable parent referrals, resolver failures, timeouts, and otherwise incomplete evidence remain `UNKNOWN`/not applicable and do not reduce the score. Weight calibration for the richer v1.3 DNS findings is intentionally deferred to the dedicated JSON/PDF/scoring integration work so scoring is changed once, with the complete DNS evidence model in view.

## Interpreting the score

The current labels are intentionally broad:

- **90-100** - Strong
- **75-89** - Good
- **60-74** - Needs improvement
- **0-59** - Priority remediation

A lower score should be used to prioritize review, not as evidence that the organization has been breached. A high score likewise does not prove that internal systems, identities, endpoints, backups, or cloud tenants are secure.

The label should always be read together with the report's **Scan scope** section. A strong partial-scope score says only that the applicable weighted checks in that selected scope scored strongly; it does not imply that skipped areas were assessed.

## Mail applicability

A valid RFC 7505 Null MX is treated as an intentional declaration that the domain does not accept inbound mail. The MX check can therefore pass on a valid Null MX, while receiver-side controls such as MTA-STS and TLS-RPT are excluded from the weighted denominator as not applicable. SPF and DMARC remain independently evaluated because they concern sender identity and anti-spoofing posture.
