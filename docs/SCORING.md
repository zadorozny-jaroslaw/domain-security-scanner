# Scoring philosophy

The **External Security Hygiene Score** is a bounded summary of the checks this scanner can perform from the public Internet. It is not a probability of compromise, a compliance score, or a substitute for a security assessment.

## Principles

1. **Only applicable checks count.** If a check cannot be established reliably from outside, it is normally marked `VERIFY`/`UNKNOWN` and excluded from the weighted denominator.
2. **Configuration quality is not the same as compromise.** Missing hardening controls can reduce the score without implying that an attack has occurred.
3. **Informational checks may have zero weight.** Useful observations such as CMS release currency or technology disclosure can be shown without materially changing the score.
4. **False confidence is worse than uncertainty.** When the scanner cannot verify a condition, it prefers an explicit unknown result instead of assuming safety.
5. **Weight changes are versioned.** Material changes to scoring behavior should be documented in `CHANGELOG.md`.

## Main weighted areas

- domain/DNS hygiene
- mail authentication and policy
- HTTPS/TLS posture
- selected web hardening controls

The exact weights live in `domain_security_scan.py` so the report always reflects the code that generated it.

## Interpreting the score

The current labels are intentionally broad:

- **90-100** - Strong
- **75-89** - Good
- **60-74** - Needs improvement
- **0-59** - Priority remediation

A lower score should be used to prioritize review, not as evidence that the organization has been breached. A high score likewise does not prove that internal systems, identities, endpoints, backups, or cloud tenants are secure.
