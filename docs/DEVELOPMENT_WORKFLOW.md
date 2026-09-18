# Development workflow

Domain Security Scanner uses a lightweight two-branch release model with short-lived topic branches.

## Long-lived branches

### `main`

`main` represents released/stable code.

- Release tags such as `v1.1.0` point to commits on `main`.
- Feature development should not start from `main`.
- Normal development changes should not be pushed directly to `main`.

### `develop`

`develop` is the integration branch for the next release.

- New feature, fix, and refactor branches start from current `develop`.
- Completed topic branches return to `develop` through pull requests.
- Release preparation, including the version and changelog update, is finalized on `develop` before the release PR.
- Small maintainer-only documentation or release-metadata changes may be committed directly to `develop` when they do not alter scanner behavior.

## Topic branches

Use short-lived branches with focused scope, for example:

```text
feature/result-models
feature/mail-rfc-standards
fix/dns-timeout-handling
docs/release-workflow
```

Create a topic branch from an up-to-date `develop`:

```bash
git checkout develop
git pull --ff-only origin develop
git checkout -b feature/<topic>
git push -u origin feature/<topic>
```

Keep unrelated changes out of the branch. Add tests and documentation with the behavior they describe rather than deferring them to an unrelated later PR.

## Topic pull requests

Open topic pull requests with:

```text
base: develop
compare: feature/<topic>   # or fix/<topic>, docs/<topic>
```

Before merging:

- run the unit tests;
- run compile checks when Python code changed;
- review generated PDF output when report layout changed;
- confirm uncertainty is handled conservatively for externally unavailable evidence;
- confirm the change remains within the documented low-impact scope.

The repository uses **Squash and merge** for pull requests. Delete finished topic branches after their work is safely present in `develop`.

## Release flow

When `develop` is ready for release:

1. finalize the semantic version, README version, and `CHANGELOG.md` on `develop`;
2. run the complete release validation and an authorized smoke test;
3. push the finalized `develop` branch;
4. open a pull request with **base `main`** and **compare `develop`**;
5. review CI, security/code-scanning results, and the complete release diff;
6. squash-merge the release pull request;
7. pull the new `main` locally and rerun the version check and unit tests;
8. create an annotated `vX.Y.Z` tag on `main` and push the tag;
9. publish the GitHub Release from that tag.

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for the detailed release checklist.

## Realigning `develop` after a squash release

Squash merging the release PR creates a new commit on `main` instead of preserving the individual `develop` commit ancestry. Even when the file contents are equivalent, the branch histories therefore need to be realigned before the next development cycle.

Only perform the reset after confirming that no new work has been added to `develop` since the release PR was finalized.

```bash
git fetch origin
git checkout develop
git reset --hard origin/main
git push --force-with-lease origin develop
```

Never replace `--force-with-lease` with an unconditional force push. If the lease fails, inspect the new remote commits before doing anything else.

After realignment, `main` and `develop` should point at the same released commit. New topic branches can then start from `develop`.

## Cleaning up merged topic branches

After the release or after confirming a topic branch is safely represented in `develop`, remove stale branches as appropriate:

```bash
git branch -D feature/<topic>
git push origin --delete feature/<topic>
git fetch --prune
```

With squash merges, Git may not recognize the original topic commit as an ancestor, so `git branch -d` can refuse even when the content was merged. Use `-D` only after verifying the work is present in `develop` or the released `main`.

## Branch-state checks

Useful checks before starting or releasing work:

```bash
git status
git branch --show-current
git fetch origin
git log --oneline --decorate -10
```

Before realigning branches after a release, also inspect whether either remote branch contains unique commits:

```bash
git log origin/main..origin/develop --oneline
git log origin/develop..origin/main --oneline
```

If either command shows unexpected work, resolve that history deliberately instead of resetting a branch blindly.
