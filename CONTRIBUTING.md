# Contributing

Thanks for helping improve Domain Security Scanner.

## Before you start

Read [docs/SCOPE.md](docs/SCOPE.md). The project deliberately stays on the **passive / low-impact external posture** side of the line.

For substantial behavior changes, open a feature request before investing significant implementation time. Work planned for a specific release should be assigned to that release's GitHub Milestone.

## Development setup

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Then:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python domain_security_scan.py --version
```

## Branching workflow

Normal feature, bug-fix, documentation, refactor, and dependency work should use a short-lived topic branch based on `develop`, then return to `develop` through a pull request.

Use branch names such as:

```text
feature/<topic>
fix/<topic>
docs/<topic>
deps/<topic>
```

`develop` is the prerelease integration branch. `main` is reserved for released code.

Do not push routine implementation changes directly to either long-lived branch. The normal release path is a release pull request from `develop` to `main`, and every pull request merged into `main` represents a versioned release.

Urgent security fixes, dependency patches, and production hotfixes may use the documented emergency patch flow when waiting for the normal release cadence would delay an important fix.

The repository uses squash merging for pull requests. After a normal squash-merged release pull request, the maintainer realigns `develop` with the released `main` before new feature work begins.

See [docs/DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) for milestone planning, the two-week release cadence, prerelease semantics, emergency patch handling, and release synchronization steps.

## Pull-request expectations

Keep changes focused. A new check should:

- have a clear external signal;
- minimize false positives;
- prefer `UNKNOWN` when reliable external verification is impossible;
- explain why the finding matters without alarmist claims;
- include safe remediation guidance;
- avoid destructive or intrusive behavior;
- document material behavior/limitations in README or `docs/`;
- add or update tests when practical.

Normal topic pull requests should target `develop`. Pull requests to `main` are release pull requests, not routine development integration.

Do not commit real customer reports, secrets, API tokens, credentials, private email lists, or sensitive target inventories.

## Style

- Python 3.11+ compatibility is the baseline.
- Prefer the standard library where practical.
- Avoid new runtime dependencies unless they materially improve reliability.
- Keep customer-facing language factual and concise.
- Preserve Unicode/Polish text correctly as UTF-8.

## Licensing of contributions

By submitting a contribution, you agree that it may be distributed under the repository's existing **Jarosław Zadorożny Non-Commercial License 1.0**.

If you cannot contribute under those terms, do not submit the pull request.
