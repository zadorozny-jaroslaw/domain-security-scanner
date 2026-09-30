# Project roadmap

This roadmap records release direction and major scope decisions for Domain Security Scanner.

It is intentionally lightweight. The roadmap answers **where the project is going**. GitHub Milestones define the scope of an upcoming release, GitHub Issues describe individual implementation units, and pull requests contain the reviewed implementation.

Completed release history belongs in `CHANGELOG.md` and GitHub Releases rather than remaining as an active roadmap section.

## Planning model

The project uses four layers of planning:

1. **Roadmap** - release themes, boundaries, and longer-term direction.
2. **GitHub Milestones** - the planned scope of a specific upcoming release.
3. **GitHub Issues** - concrete implementation work assigned to that milestone.
4. **Pull requests** - reviewed code and documentation changes that close or advance those issues.

For a solo-maintained project, avoid unnecessary process overhead. GitHub Projects, story points, sprint ceremonies, and large label taxonomies are not required unless the project grows enough to benefit from them.

Normal feature/minor releases target a **two-week iteration**. Security fixes, dependency patches, and production hotfixes are prioritized for release as soon as practical after validation and are not held for the normal cadence.

See [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) for the branch, milestone, prerelease, release, and urgent-patch process.

## Current planned release: v1.4.0

### Theme

**CLI Readiness & Automation**

Target cadence: **the two-week release iteration following v1.3.0**.

The goal of v1.4.0 is to turn the existing command-line entry point into a predictable, discoverable, automation-friendly interface suitable for normal operator use, shell pipelines, CI, and future packaging.

The release should improve how users invoke and integrate the scanner without materially changing the security checks themselves.

Primary scope:

- explicit command structure for scanning and report comparison;
- improved built-in help, examples, option grouping, and language consistency;
- controlled verbose and quiet execution modes;
- defined stdout/stderr behavior;
- machine-readable JSON output suitable for shell pipelines;
- stable execution-error and exit-code semantics;
- installable CLI and `python -m` entry points;
- regression tests covering the public CLI contract;
- user-facing documentation for interactive and automation workflows.

Existing output and comparison work developed before this milestone, including JSON-only output and semantic report comparison, should be treated as foundations rather than duplicated implementations.

The release should preserve compatibility with the current scanner invocation where practical while establishing a cleaner command structure for future development.

See [V1_4_CLI_PLAN.md](V1_4_CLI_PLAN.md) for the detailed implementation scope and release gate.

### v1.4.0 completion criteria

v1.4.0 is ready when an operator can reliably:

> discover the available commands through built-in help; run an authorized scan with predictable progress and error behavior; consume machine-readable JSON without human-oriented output corrupting it; compare existing reports without performing a scan; invoke the scanner through supported Python/package entry points; and depend on documented exit codes and CLI behavior in automation.

CLI changes must not weaken authorization requirements, change security findings merely because presentation mode changes, or turn unavailable external evidence into execution failure when the scanner can represent that evidence as UNKNOWN/VERIFY.

## Next candidate: v1.5.0

### Theme

**TLS & Certificate Posture**

Candidate scope after v1.4.0:

- certificate identity and SAN/wildcard handling;
- chain and issuer evidence;
- key type/size and signature algorithm;
- TLS 1.2/1.3 posture and bounded legacy/weak configuration checks;
- revocation/stapling evidence where reliably observable;
- clearer TLS-specific reporting and JSON structure.

The final v1.5.0 scope should be decided after v1.4.0 is released and its follow-up issues are reviewed.

## Later candidates

Potential later release themes include:

- deeper Web policy analysis;
- additional mail standards and operational checks;
- DANE/TLSA;
- SVCB/HTTPS records;
- JSON schema/versioning improvements.

These are directional ideas, not commitments. Prefer a coherent release theme over adding unrelated checks simply because an RFC exists.
