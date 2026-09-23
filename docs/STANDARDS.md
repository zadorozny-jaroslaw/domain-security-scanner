# Standards reference registry

The scanner keeps a small internal registry of standards that directly define checks implemented by the project. The registry lives in `domain_security_scanner/standards/registry.py` and provides stable metadata such as the RFC number, title, canonical RFC Editor URL, and scanner scope.

The registry is intentionally small. It is not a general RFC database and does not copy RFC text into the project. Validation logic remains in focused scanner modules, while the registry provides consistent references for findings, tests, and documentation.

## Implemented standards

| Standard | Scanner coverage | Canonical reference |
| --- | --- | --- |
| RFC 3986 | URI/URI-reference validation used by redirects, Web Linking, and `security.txt` fields | https://www.rfc-editor.org/info/rfc3986 |
| RFC 6797 | HSTS syntax, required `max-age`, duplicate directives, active/inactive policy | https://www.rfc-editor.org/info/rfc6797 |
| RFC 7505 | Null MX detection and validation | https://www.rfc-editor.org/info/rfc7505 |
| RFC 7838 | HTTP `Alt-Svc` syntax, alternative authorities, freshness and persistence parameters | https://www.rfc-editor.org/info/rfc7838 |
| RFC 8288 | HTTP `Link` header serialization, relation types, targets, contexts and selected target attributes | https://www.rfc-editor.org/info/rfc8288 |
| RFC 8460 | TLS-RPT TXT policy, `rua` destinations and extension handling | https://www.rfc-editor.org/info/rfc8460 |
| RFC 8461 | MTA-STS TXT indicator, HTTPS policy, modes and MX-pattern coverage | https://www.rfc-editor.org/info/rfc8461 |
| RFC 8615 | `/.well-known/` location used by `security.txt` | https://www.rfc-editor.org/info/rfc8615 |
| RFC 9110 | HTTP redirect status and `Location` semantics | https://www.rfc-editor.org/info/rfc9110 |
| RFC 9111 | HTTP cache-policy syntax, freshness metadata, ambiguity and deprecated response `Pragma` | https://www.rfc-editor.org/info/rfc9111 |
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

### RFC 7838 — HTTP Alternative Services (`Alt-Svc`)

The scanner passively analyzes the HTTP `Alt-Svc` response header without connecting to any advertised alternative service. The check is advisory/non-scoring: RFC 7838 makes alternative services optional, and the scanner cannot safely establish the advertised service's authority without actually opening a connection and validating it for the original origin.

The analyzer covers the externally observable `Alt-Svc` serialization defined by RFC 7838, including:

- the special case-sensitive `clear` value and invalid `clear`/alternative mixtures;
- multiple alternatives in server preference order;
- ALPN `protocol-id` token syntax, including canonical uppercase percent-encoding and the rule against percent-encoding token characters unnecessarily;
- quoted `alt-authority` values containing an optional host plus a required port;
- same-host shorthand such as `h3=":443"`, where the origin host is inherited;
- bracketed IPv6 alternative hosts;
- internationalized hostnames requiring ASCII A-label form;
- `ma` as an unquoted non-negative delta-seconds value, with RFC 7838's default freshness lifetime of 24 hours when it is absent;
- response `Age`, when already available from the RFC 9111 cache analysis, to show the remaining advertised freshness lifetime;
- `persist=1`, while other `persist` values are retained as review evidence and treated as ignored;
- unknown extension parameters, which RFC 7838 requires recipients to ignore rather than reject.

A missing `Alt-Svc` header is informational. A well-formed advertisement is also informational. `REVIEW` is emitted only for malformed or ambiguous serialization, non-canonical protocol identifiers, unusable authority data, or parameter values that RFC 7838 says cannot be applied as advertised.

The scanner records host changes because RFC 7838 treats alternative services as authoritative for the original origin only when the client has reasonable assurance that the alternative is valid for that origin. This implementation deliberately does **not** connect to the advertised host, negotiate its ALPN protocol, or validate its certificate. Structured evidence therefore includes `alternatives_contacted: false`.

This check covers the HTTP `Alt-Svc` response field only. It does not inspect HTTP/2 `ALTSVC` frames or validate client-sent `Alt-Used` request fields.

### RFC 8288 — Web Linking

The scanner passively analyzes the HTTP `Link` response header without dereferencing any advertised target. The check is advisory/non-scoring because RFC 8288 does not require every Web response to publish links, and link relations are application-specific.

The analyzer currently covers the externally observable serialization rules that are useful for a low-impact posture scan:

- one or more comma-separated link-values across `Link` response fields;
- link targets enclosed in `<...>` and validated as RFC 3986 URI-references;
- relative targets resolved against the final response URL for report evidence only;
- required `rel` parameter and multiple relation types in one `rel` value;
- registered relation names plus extension relation types expressed as absolute URIs;
- relative `anchor` values resolved against the response URL to derive link context;
- repeated `hreflang`, which RFC 8288 explicitly permits;
- duplicate `rel`, `media`, `title`, `title*`, or `type` parameters surfaced for review where the RFC specifies later occurrences are ignored;
- deprecated `rev` surfaced for review;
- practical media-type syntax validation for the `type` target attribute;
- unknown extension link parameters retained instead of rejected.

A missing `Link` header is informational. A syntactically valid Link header is also informational. `REVIEW` is emitted only for malformed/ambiguous serialization or deprecated constructs. The scanner never follows Link targets automatically; this intentionally follows RFC 8288's security guidance around trusting and dereferencing links supplied in HTTP headers.

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

### RFC 9111 — HTTP Caching

The scanner now records and analyzes response caching metadata without assuming that every public page should use a particular cache policy. The check is deliberately advisory and has no score weight.

It parses repeated `Cache-Control` field values and validates the core RFC 9111 response directives, including:

- `max-age` and `s-maxage` as unquoted non-negative delta-seconds;
- valueless directives such as `no-store`, `public`, and `must-revalidate`;
- qualified `private` / `no-cache` field-name lists;
- extension directives, which are retained rather than rejected;
- duplicate directives and conflicting directives as review-worthy ambiguity, while preserving the RFC rule that the more restrictive semantics apply;
- `Age` as a non-negative integer, including the RFC behavior of using the first member when multiple values are received;
- `Expires` as HTTP-date metadata, with malformed dates treated as already expired rather than as proof of unsafe caching;
- response `Pragma` as deprecated and not a reliable substitute for `Cache-Control`;
- the legacy `Warning` response field as obsoleted by RFC 9111.

A response with no explicit `Cache-Control` / `Expires` policy remains informational because RFC 9111 permits heuristic freshness in applicable cases. A syntactically consistent policy is also informational rather than scored as a security pass. The scanner reports `REVIEW` only when the observed metadata is malformed, duplicated/ambiguous, contradictory in a way that merits operator review, or relies on deprecated response `Pragma`.

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
