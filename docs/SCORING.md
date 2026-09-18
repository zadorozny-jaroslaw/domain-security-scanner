# Scoring philosophy

The **External Security Hygiene Score** is a bounded summary of the checks this scanner can perform from the public Internet. It is not a probability of compromise, a compliance score, or a substitute for a security assessment.

## Principles

1. **Only applicable checks count.** If a check cannot be established reliably from outside, it is normally marked `VERIFY`/`UNKNOWN` and excluded from the weighted denominator.
2. **Configuration quality is not the same as compromise.** Missing hardening controls can reduce the score without implying that an attack has occurred.
3. **Informational checks may have zero weight.** Useful observations such as CMS release currency or technology disclosure can be shown without materially changing the score.
4. **False confidence is worse than uncertainty.** When the scanner cannot verify a condition, it prefers an explicit unknown result instead of assuming safety. DNS timeouts, SERVFAIL responses and resolver errors are treated as unavailable evidence, not as proof that a DNS record is absent.
5. **Weight changes are versioned.** Material changes to scoring behavior should be documented in `CHANGELOG.md`.

## Main weighted areas

- domain/DNS hygiene
- mail authentication and policy
- HTTPS/TLS posture
- selected web hardening controls

The exact weights live alongside the checks in the `domain_security_scanner` package so the report always reflects the code that generated it.

## Interpreting the score

The current labels are intentionally broad:

- **90-100** - Strong
- **75-89** - Good
- **60-74** - Needs improvement
- **0-59** - Priority remediation

A lower score should be used to prioritize review, not as evidence that the organization has been breached. A high score likewise does not prove that internal systems, identities, endpoints, backups, or cloud tenants are secure.
## Mail applicability

A valid RFC 7505 Null MX is treated as an intentional declaration that the domain does not accept inbound mail. The MX check can therefore pass on a valid Null MX, while receiver-side controls such as MTA-STS and TLS-RPT are excluded from the weighted denominator as not applicable. SPF and DMARC remain independently evaluated because they concern sender identity and anti-spoofing posture.

