# Development workflow

Domain Security Scanner uses a milestone-driven two-branch release model with short-lived topic branches.

The default rule is simple: implementation work happens on a topic branch, reviewed changes enter a long-lived branch through a pull request, and `main` contains released code only.

## Planning model

Use four levels of planning:

1. `docs/ROADMAP.md` records release direction, boundaries, and longer-term themes.
2. GitHub Milestones define the planned scope of a specific release such as `v1.4.0`.
3. GitHub Issues describe concrete implementation units and acceptance criteria assigned to a release milestone.
4. Pull requests contain the reviewed implementation and should reference the issue they advance or close.

Create or confirm the target milestone before normal implementation work for a release begins. Issues intended for that release should be assigned to the milestone. Moving an issue to another milestone is an explicit scope decision, not an invisible schedule slip.

Close the milestone after the corresponding release has been published.

For a solo-maintained project, keep issue tracking intentionally small. Prefer a handful of meaningful issues per release over one issue per tiny code change. GitHub Projects, story points, sprint ceremonies, and elaborate label systems are optional and should only be added if they solve a real coordination problem.

The roadmap is not a substitute for a milestone, a milestone is not a substitute for an implementation issue, and an issue is not a substitute for tests or documentation.

## Release cadence and priority

Normal feature/minor releases target a **two-week iteration**.

The two-week cadence is a planning target, not a reason to ship incomplete or insufficiently validated work. If the release milestone is not ready, reduce or defer scope rather than weakening acceptance criteria.

The following changes are not held for the normal cadence and should be released **as soon as practical after validation**:

- security fixes;
- dependency patches, especially security-relevant dependency updates;
- production hotfixes for released behavior.

Urgent patch releases still require review, tests, version/changelog updates, and a release pull request. They shorten the waiting period; they do not bypass release controls.

## Release status

### `main`

`main` represents released/stable code.

- Release tags such as `v1.4.0` point to commits on `main`.
- Feature development must not start from `main`.
- Direct pushes to `main` are not part of the normal workflow.
- Every pull request merged into `main` is a **release pull request** and therefore represents a versioned release.
- A merge to `main` must be followed by the matching tag and GitHub Release after final verification.

The normal release PR uses:

```text
base: main
compare: develop
```

An urgent patch may use a dedicated `hotfix/`, `security/`, or `deps/` branch based on current `main` when releasing from `develop` would include unrelated prerelease work. This is the only normal exception to the `develop -> main` source-branch rule. The PR is still a versioned patch release, and the same fix must be propagated back to `develop` immediately through a pull request.

### `develop`

`develop` is the prerelease integration branch for the next normal release.

- `develop` is **prerelease state**, not a stable release.
- Normal feature, fix, refactor, documentation, and dependency branches start from current `develop`.
- Completed topic branches return to `develop` through pull requests.
- Direct feature or maintenance commits to `develop` should be avoided; use a topic branch even for small changes so review and CI history remain explicit.
- Release preparation, including version and changelog updates, is finalized on `develop` before the normal release PR.
- Stable release tags must not point to `develop`.

If a GitHub Release or test artifact is ever intentionally published from `develop`, it must be clearly marked as **prerelease** and must not reuse a final stable `vX.Y.Z` tag.

## Topic branches

Use short-lived branches with focused scope, for example:

```text
feature/dns-evidence-layer
feature/cli-entry-points
fix/dns-timeout-handling
docs/release-workflow
deps/update-dnspython
```

Create a normal topic branch from an up-to-date `develop`:

```bash
git checkout develop
git pull --ff-only origin develop
git checkout -b feature/<topic>
git push -u origin feature/<topic>
```

Keep unrelated changes out of the branch. Add tests and documentation with the behavior they describe rather than deferring them to an unrelated later PR.

CI is expected to run automatically for pull requests targeting `develop` or `main`, and for direct updates to those long-lived branches. Topic branches can use the manual GitHub Actions workflow when CI is needed before opening a pull request.

## Issues and milestones

Create issues from the active release milestone once the release boundary is clear.

A useful implementation issue should normally contain:

- the problem or capability being addressed;
- the intended scope;
- relevant RFCs or technical references;
- acceptance criteria;
- important non-goals;
- test expectations;
- report/JSON compatibility considerations when applicable.

Keep issue size large enough to represent meaningful work. If an issue becomes too broad to review safely, split it by capability rather than by individual functions or files.

When implementation starts, use a topic branch whose name reflects the issue scope. Reference the issue from the pull request and close it only when its acceptance criteria are satisfied or intentionally revised.

If work is intentionally deferred, move the issue to the appropriate future milestone rather than leaving the current release milestone ambiguous.

## Topic pull requests

Open normal topic pull requests with:

```text
base: develop
compare: feature/<topic>   # or fix/<topic>, docs/<topic>, deps/<topic>
```

Before merging:

- confirm the linked issue acceptance criteria are satisfied or updated;
- confirm the issue is assigned to the intended release milestone;
- run the unit tests;
- run compile checks when Python code changed;
- review generated PDF output when report layout changed;
- confirm uncertainty is handled conservatively for externally unavailable evidence;
- confirm the change remains within the documented low-impact scope;
- update relevant roadmap/release-plan wording if the implementation materially changed the planned boundary.

The repository uses **Squash and merge** for pull requests. Delete finished topic branches after their work is safely present in `develop`.

## Normal release flow

When the active milestone and `develop` are ready for release:

1. review the target milestone and ensure intended issues are closed or explicitly deferred;
2. finalize the semantic version, README version, and `CHANGELOG.md` on `develop`;
3. run the complete release validation and authorized smoke tests;
4. push the finalized `develop` branch;
5. open a pull request with **base `main`** and **compare `develop`**;
6. use a release title such as `Release vX.Y.Z`;
7. review CI, security/code-scanning results, and the complete release diff;
8. squash-merge the release pull request;
9. pull the new `main` locally and rerun the version check and unit tests;
10. create an annotated `vX.Y.Z` tag on `main` and push the tag;
11. publish the GitHub Release from that tag;
12. close the corresponding GitHub Milestone;
13. realign `develop` with the released `main` before the next normal development cycle.

A pull request to `main` is never a routine development PR. Its merge is a release event.

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for the detailed release checklist.

## Urgent patch flow

Security fixes, dependency patches, and hotfixes should not wait for the normal two-week release cadence.

If `develop` can be released safely without unrelated work, use the normal release flow immediately.

If `develop` contains unrelated prerelease work:

1. branch from current `main` using `hotfix/<topic>`, `security/<topic>`, or `deps/<topic>`;
2. make the smallest safe patch;
3. update the patch version and changelog;
4. run the focused and full regression checks required by the change;
5. open a pull request to `main`;
6. treat that PR as a patch release and publish the matching tag/GitHub Release;
7. propagate the same fix back to `develop` through a follow-up pull request before continuing normal release work.

Do not silently leave a released hotfix absent from `develop`.

## Realigning `develop` after a squash release

Squash merging the normal `develop -> main` release PR creates a new commit on `main` instead of preserving the individual `develop` commit ancestry. Even when the file contents are equivalent, the branch histories therefore need to be realigned before the next development cycle.

Only perform the reset after confirming that no new work has been added to `develop` since the release PR was finalized.

```bash
git fetch origin
git checkout develop
git reset --hard origin/main
git push --force-with-lease origin develop
```

Never replace `--force-with-lease` with an unconditional force push. If the lease fails, inspect the new remote commits before doing anything else.

After realignment, `main` and `develop` should point at the same released commit. New topic branches can then start from `develop`.

Do not use this reset procedure after an urgent patch release if `develop` contains unrelated prerelease work. In that case, propagate the released patch back to `develop` through a dedicated pull request.

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
