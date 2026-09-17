## Summary

Describe the change and the problem it solves.

## Scope / safety

- [ ] The change remains within the low-impact external posture-check scope, or the scope change has been discussed first.
- [ ] The change does not add exploitation, credential attacks, broad port scanning, DoS/load testing, or non-public data access to the default scanner.
- [ ] New/changed findings handle uncertainty and false positives conservatively.

## Validation

- [ ] `python domain_security_scan.py --version`
- [ ] `python -m py_compile domain_security_scan.py`
- [ ] `python -m unittest discover -s tests -v`
- [ ] I tested any report-layout change and checked Unicode/Polish rendering.

## Documentation

- [ ] README/docs updated if user-visible behavior changed.
- [ ] CHANGELOG updated for release-worthy changes.

## Data hygiene

- [ ] No credentials, secrets, private customer reports, or sensitive target data are included in this pull request.
