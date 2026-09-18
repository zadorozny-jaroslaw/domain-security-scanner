# Release checklist

Use semantic version tags such as `v1.0.0`, `v1.0.1`, and `v1.1.0`.

Releases are prepared on `develop`, promoted to `main` through a release pull request, and tagged only after the release PR is merged.

## Prepare the release on `develop`

- [ ] Decide whether the change is patch, minor, or major.
- [ ] Confirm `develop` contains only work intended for the release.
- [ ] Update `__version__` in `domain_security_scanner/version.py`.
- [ ] Confirm `python domain_security_scan.py --version` reports the same version; `USER_AGENT` is derived from `__version__`.
- [ ] Update `CHANGELOG.md`.
- [ ] Update the README version when the release version changes.
- [ ] Run the test suite on a clean virtual environment.
- [ ] Run `python domain_security_scan.py --version`.
- [ ] Run `python -m py_compile domain_security_scan.py` and `python -m compileall domain_security_scanner`.
- [ ] Run at least one authorized real-world smoke test.
- [ ] If the report layout changed, regenerate `docs/example-report.pdf` and its preview.
- [ ] Review generated reports for secrets or data that should not be committed.
- [ ] Confirm README usage remains accurate.
- [ ] Confirm `LICENSE` and copyright text are unchanged unless intentionally revised.
- [ ] Commit and push the release-preparation changes to `develop`.

## Release pull request

- [ ] Open a pull request with **base `main`** and **compare `develop`**.
- [ ] Use a release title such as `Release vX.Y.Z`.
- [ ] Confirm CI and security/code-scanning checks are complete.
- [ ] Review the final diff for accidental reports, secrets, generated files, or unrelated changes.
- [ ] Squash-merge the release pull request.

Do not tag `develop`. The release tag must point at the final commit on `main` after the release pull request has been merged.

## Verify `main` and create the tag

```bash
git checkout main
git pull --ff-only origin main
python domain_security_scan.py --version
python -m unittest discover -s tests -v
git status
```

Confirm the working tree is clean and the reported version is the intended release version. Then create and push the annotated tag:

```bash
git tag -a vX.Y.Z -m "Domain Security Scanner vX.Y.Z"
git show --stat vX.Y.Z
git push origin vX.Y.Z
```

Create a GitHub Release from that tag. With GitHub CLI:

```bash
gh release create vX.Y.Z --title "Domain Security Scanner vX.Y.Z" --generate-notes --verify-tag
```

Use the matching `CHANGELOG.md` entry as the curated release summary when editing the generated GitHub Release notes.

## Realign `develop` after a squash release

Because the release pull request is squash-merged, `main` receives a new squash commit. Before starting the next development cycle, realign `develop` with that released commit.

First verify that nobody has added new work to `develop` after the release pull request was created or merged. If `develop` has unpublished/new commits, do not reset it; reconcile those changes first.

When it is safe to realign:

```bash
git fetch origin
git checkout develop
git reset --hard origin/main
git push --force-with-lease origin develop
```

`--force-with-lease` is required here so the push fails rather than overwriting an unexpected newer remote `develop` state.

## After release checks

- [ ] Verify the GitHub Actions workflow is green.
- [ ] Verify the GitHub Release points to the expected `vX.Y.Z` tag.
- [ ] Download the source archive once and verify the expected files are present.
- [ ] Check `Insights -> Community Standards` for accidental regressions in community-health files.
- [ ] Confirm `main` and `develop` are aligned before creating the next feature branch.
