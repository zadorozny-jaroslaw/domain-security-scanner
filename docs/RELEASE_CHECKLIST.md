# Release checklist

Use semantic version tags such as `v1.0.0`, `v1.0.1`, and `v1.1.0`.

## Before tagging

- [ ] Decide whether the change is patch, minor, or major.
- [ ] Update `__version__` in `domain_security_scan.py`.
- [ ] Confirm the `USER_AGENT` reflects the same version.
- [ ] Update `CHANGELOG.md`.
- [ ] Run the test suite on a clean virtual environment.
- [ ] Run `python domain_security_scan.py --version`.
- [ ] Run at least one authorized real-world smoke test.
- [ ] If the report layout changed, regenerate `docs/example-report.pdf` and its preview.
- [ ] Review generated reports for secrets or data that should not be committed.
- [ ] Confirm README usage remains accurate.
- [ ] Confirm `LICENSE` and copyright text are unchanged unless intentionally revised.

## Tag and release

```bash
git status
git add .
git commit -m "Release vX.Y.Z"
git tag -a vX.Y.Z -m "Domain Security Scanner vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Then create a GitHub Release from the tag and use the matching `CHANGELOG.md` entry as the basis for the release notes.

## After release

- [ ] Verify the GitHub Actions workflow is green.
- [ ] Download the source archive once and verify the expected files are present.
- [ ] Check `Insights -> Community Standards` for accidental regressions in community-health files.
