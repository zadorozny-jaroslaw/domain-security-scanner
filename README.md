# v1.4.0 release preparation — step 1 of 4: cleanup

**Branch:** `feature/32-document-cli-interface`

This package contains **only the first cleanup slice**. There is no v1.5 RFC
plan, no v1.6 plan, no CHANGELOG release rollover, and no version bump.

## Changes

- `docs/ROADMAP.md` — replace the completed v1.4 milestone's lengthy active
  plan with a short release-preparation summary and links to live documentation.
  Leave the existing v1.5/v1.6 candidate text alone for subsequent slices.
- `docs/V1_4_CLI_PLAN.md` — label the original implementation plan as a
  historical design document; do not delete the record.
- `docs/RELEASE_CHECKLIST.md` — add a concrete v1.4 CLI release validation section
  while preserving all existing DNS, safety, and release checks.

## Apply

Extract this ZIP anywhere **outside** the repository. Open PowerShell in the
repository root:

```powershell
git switch feature/32-document-cli-interface
git status --short
& 'C:\path\to\extracted\APPLY_CLEANUP.ps1'
```

Or apply the patch yourself from the repository root:

```powershell
git apply --check 'C:\path\to\extracted\01-cleanup.patch'
git apply 'C:\path\to\extracted\01-cleanup.patch'
```

The patch approach preserves all unrelated existing lines of the three files.
The helper script checks the branch and a clean working tree; it applies but
**does not automatically commit or push** changes.

## Validate, commit, push

```powershell
git diff --check
git diff --stat
git diff -- docs/ROADMAP.md docs/V1_4_CLI_PLAN.md docs/RELEASE_CHECKLIST.md

git add docs/ROADMAP.md docs/V1_4_CLI_PLAN.md docs/RELEASE_CHECKLIST.md
git commit -m "docs(roadmap): archive v1.4 workstreams and add CLI release gate"
git push origin feature/32-document-cli-interface
```

**Expected:** one commit, three documentation files. No runtime behavior changed.
Once this is committed, move to step 2 (v1.5 planning) separately.
