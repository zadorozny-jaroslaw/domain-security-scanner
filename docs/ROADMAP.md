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

## v1.4.0 — CLI Readiness & Automation (release preparation)

The v1.4 workstreams have been implemented on the release-preparation branch,
but **v1.4.0 is not yet a published release**. Stable publication requires the
release PR to `main`, release validation, an annotated `v1.4.0` tag on `main`,
and a GitHub Release. Do not tag this feature branch or `develop`.

Delivered: explicit `scan` and `diff` commands; improved English help; verbose
and quiet modes; stream-safe JSON stdout; stable CLI exit codes; installable and
module entry points; regression tests; and automation/user documentation.
The `--json-only` mode and semantic report comparison predate v1.4 and were
reused, not reimplemented, in this release.

- [CLI reference](CLI_REFERENCE.md) — supported user-facing interface.
- [Exit-code contract](CLI_EXIT_CODES.md) — automation and failure semantics.
- [v1.4 implementation plan](V1_4_CLI_PLAN.md) — preserved historical planning record.
- [Release checklist](RELEASE_CHECKLIST.md) — remaining gates and publishing workflow.
- [Changelog](../CHANGELOG.md) — implementation and release summary.

This roadmap does not repeat the completed v1.4 workstream checklists; GitHub
milestone/issues and the release checklist track the remaining release gate.

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
