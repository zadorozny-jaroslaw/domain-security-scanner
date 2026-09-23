# Standards reference registry

The scanner keeps a small internal registry of standards that directly define checks implemented by the project. The registry lives in `domain_security_scanner/standards/registry.py` and provides stable metadata such as the RFC number, title, canonical RFC Editor URL, and scanner scope.

The registry is intentionally small. It is not a general RFC database and does not copy RFC text into the project. Validation logic remains in focused scanner modules, while the registry provides consistent references for findings, tests, and documentation.

## Implemented standards

| Standard | Scanner coverage | Canonical reference |
| --- | --- | --- |
| RFC 3986 | URI/URI-reference validation used by redirects and `security.txt` fields | https://www.rfc-editor.org/info/rfc3986 |
| RFC 6797 | HSTS syntax, required `max-age`, duplicate directives, active/inactive policy | https://www.rfc-editor.org/info/rfc6797 |
| RFC 7505 | Null MX detection and validation | https://www.rfc-editor.org/info/rfc7505 |
| RFC 8460 | TLS-RPT TXT policy, `rua` destinations and extension handling | https://www.rfc-editor.org/info/rfc8460 |
| RFC 8461 | MTA-STS TXT indicator, HTTPS policy, modes and MX-pattern coverage | https://www.rfc-editor.org/info/rfc8461 |
| RFC 8615 | `/.well-known/` location used by `security.txt` | https://www.rfc-editor.org/info/rfc8615 |
| RFC 9110 | HTTP redirect status and `Location` semantics | https://www.rfc-editor.org/info/rfc9110 |
| RFC 9116 | `security.txt` location, media type, required fields and expiry | https://www.rfc-editor.org/info/rfc9116 |
| RFC 10025 | `Set-Cookie` syntax/security semantics, SameSite and secure cookie prefixes | https://www.rfc-editor.org/info/rfc10025 |

## Web standards

### RFC 9110 + RFC 3986 — HTTP redirects and `Location`

The HTTP-to-HTTPS check now treats `301`, `302`, `303`, `307`, and `308` as redirect responses that can carry a `Location` URI-reference. The scanner validates the `Location` value as a practical RFC 3986 URI-reference, resolves relative references against the original HTTP target, and only reports a successful HTTP-to-HTTPS upgrade when the resolved target uses the `https` scheme.

This means a relative redirect such as `Location: /home` from an `http://` request is still a redirect, but it is not counted as an HTTPS upgrade because resolving it retains the `http` scheme.

### RFC 6797 — HTTP Strict Transport Security (HSTS)

The scanner no longer treats mere presence of `Strict-Transport-Security` as a successful HSTS configuration.

It validates the policy structure used by RFC 6797, including:

- required `max-age`;
- decimal `max-age` value, including quoted values;
- directives appearing at most once;
- valueless `includeSubDomains`;
- syntactically valid unknown extension directives being ignored rather than rejected;
- more than one server-sent STS field being reported as invalid server output.

A syntactically valid `max-age=0` policy is recognized as valid protocol syntax but is reported as an inactive HSTS policy because it instructs user agents to remove/disable the cached HSTS policy.

### RFC 10025 — Cookies: HTTP State Management Mechanism

The existing cookie hardening check is now split conceptually into two kinds of evidence:

1. RFC-defined `Set-Cookie` requirements that can make server output invalid or cause a conforming user agent to reject a cookie; and
2. project hardening recommendations for sensitive/session-like cookies.

RFC-backed validation currently checks:

- duplicate cookie attributes in one `Set-Cookie` field;
- valid `SameSite` values;
- the `SameSite=None` requirement for `Secure`;
- `__Secure-` cookies requiring `Secure`;
- `__Host-` cookies requiring `Secure`, `Path=/`, and no `Domain` attribute;
- non-empty cookie names.

The existing scanner policy still recommends `Secure`, `HttpOnly`, and an explicit `SameSite` value for cookies heuristically identified as session/authentication sensitive. Those recommendations are intentionally described as hardening rather than universal RFC conformance requirements.

RFC 10025 obsoletes RFC 6265, so new scanner references use RFC 10025.

### RFC 9116 + RFC 8615 + RFC 3986 — `security.txt`

The scanner requests the registered well-known location:

```text
https://<web-target>/.well-known/security.txt
```

A present file is validated for the core externally testable requirements, including:

- successful retrieval over HTTPS;
- the `/.well-known/security.txt` path;
- `Content-Type: text/plain` with UTF-8 charset;
- at least one `Contact` field;
- exactly one `Expires` field;
- a valid RFC 3339 expiry that has not already passed;
- URI syntax for `Contact` and `Canonical` values;
- HTTPS for web-based `Contact`/`Canonical` URIs;
- a warning when `Canonical` is present but does not list the retrieval URI;
- a warning when the redirect chain ends on a different host, because trust then needs additional review.

`security.txt` remains informational/advisory and has no score weight. A malformed or expired file can therefore be shown as `REVIEW` without changing the External Security Hygiene Score.

## Mail standards

### RFC 7505 — Null MX

The scanner recognizes a valid Null MX only when the domain publishes exactly one MX record with preference `0` and exchange `.`. A Null MX mixed with any other MX record is treated as invalid.

A valid Null MX is interpreted as an explicit declaration that the domain does not accept inbound mail. Receiver-side controls such as MTA-STS and TLS-RPT are therefore marked not applicable for that domain. Sender-side identity controls such as SPF and DMARC are still evaluated because Null MX alone does not prove how the domain is used as a sender identity.

### RFC 8461 — MTA-STS

The scanner validates the `_mta-sts.<domain>` TXT policy indicator, including the required `v=STSv1` and `id` fields. When the indicator is usable, it fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` with normal TLS certificate verification and with HTTP redirects disabled.

The HTTPS policy parser validates `version`, `mode`, `max_age`, and `mx` fields, including the RFC maximum `max_age` value and left-most-label wildcard matching. In `enforce` or `testing` mode, the policy's MX patterns are compared with the domain's published MX hosts. Unknown extension fields are retained/ignored rather than treated as errors.

### RFC 8460 — SMTP TLS Reporting (TLS-RPT)

The scanner validates the `_smtp._tls.<domain>` TXT policy instead of treating any string containing `v=TLSRPTv1` as a successful configuration. It requires one usable versioned policy and at least one valid `rua` reporting URI.

`mailto:` and `https:` reporting destinations are accepted. Unknown syntactically valid extension fields are ignored for compliance purposes, matching RFC 8460's extensibility requirement. Multiple usable TLS-RPT policy records, missing `rua`, malformed URIs, and unsupported URI schemes are reported as invalid configuration.
