# Standards reference registry

The scanner keeps a small internal registry of standards that directly define checks implemented by the project. The registry lives in `domain_security_scanner/standards/registry.py` and provides stable metadata such as the RFC number, title, canonical RFC Editor URL, and scanner scope.

The registry is intentionally small. It is not a general RFC database and does not copy RFC text into the project. Validation logic remains in focused scanner modules, while the registry provides consistent references for findings, tests, and documentation.

## Implemented standards

| Standard | Scanner coverage | Canonical reference |
| --- | --- | --- |
| RFC 7505 | Null MX detection and validation | https://www.rfc-editor.org/info/rfc7505 |
| RFC 8461 | MTA-STS TXT indicator, HTTPS policy, modes and MX-pattern coverage | https://www.rfc-editor.org/info/rfc8461 |

### RFC 7505 — Null MX

The scanner recognizes a valid Null MX only when the domain publishes exactly one MX record with preference `0` and exchange `.`. A Null MX mixed with any other MX record is treated as invalid.

A valid Null MX is interpreted as an explicit declaration that the domain does not accept inbound mail. Receiver-side controls such as MTA-STS and TLS-RPT are therefore marked not applicable for that domain. Sender-side identity controls such as SPF and DMARC are still evaluated because Null MX alone does not prove how the domain is used as a sender identity.

### RFC 8461 — MTA-STS

The scanner validates the `_mta-sts.<domain>` TXT policy indicator, including the required `v=STSv1` and `id` fields. When the indicator is usable, it fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` with normal TLS certificate verification and with HTTP redirects disabled.

The HTTPS policy parser validates `version`, `mode`, `max_age`, and `mx` fields, including the RFC maximum `max_age` value and left-most-label wildcard matching. In `enforce` or `testing` mode, the policy's MX patterns are compared with the domain's published MX hosts. Unknown extension fields are retained/ignored rather than treated as errors.
