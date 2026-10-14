# CLI exit status contract

This document describes the exit statuses of `domeval` on the v1.4 development
branch. It also applies to `domain-security-scan`,
`python -m domain_security_scanner` and `python domain_security_scan.py`,
which delegate to the same CLI implementation.

## Scan exit codes

| Code | Meaning | Examples |
| --- | --- | --- |
| `0` | Requested scan completed | Report contains `OK`, `REVIEW`, `ACTION`, or `VERIFY` findings |
| `2` | Incorrect usage, invalid target or scan options, or authorization not confirmed | Invalid group/limit, invalid domain, missing `--authorized` in non-interactive use |
| `3` | Scan could not complete | Scanner initialization, evidence orchestration, or report assembly failed |
| `4` | Output could not be produced | JSON serialization, JSON file/stdout writing, or PDF generation failed |
| `130` | Interrupted with Ctrl+C | User interrupted an active scan or output step |

The status describes whether **the command ran successfully**, not whether the
target is secure. A completed scan with an `ACTION` finding still returns `0`.
An unobservable DNS/TLS/HTTP check that is represented in the report as `VERIFY`
or `UNKNOWN` is not by itself a process error. Only an unrecoverable failure that
prevents the scan from completing is code `3`.

The scanner reports expected execution and output failures on **stderr** without
an uncontrolled Python traceback. Progress also goes to stderr, while
`--json-stdout` emits report JSON to stdout. `--quiet` suppresses normal
progress, not errors. The detailed diagnostics supplied by `-vv` do not change
any of these exit codes or security-evidence semantics.

If writing the PDF fails after JSON has already been saved, code `4` is returned
and the existing JSON file may remain. A failed file or stream write can also
leave partial output; automation should only accept artifacts when the exit
status indicates success.

An expected closed consumer pipe in `--json-stdout` mode terminates cleanly
without a Python traceback (status `0`). Other stream write failures return `4`.

## Diff exit codes (intentionally different)

`domeval diff OLD_JSON NEW_JSON` compares local reports and performs no scan.
Its existing exit-code contract is preserved:

| Code | Meaning |
| --- | --- |
| `0` | Reports are semantically equivalent |
| `1` | Meaningful differences were found (not an execution failure) |
| `2` | Invalid arguments, missing files, unreadable or malformed report JSON (including invalid UTF-8) |
| `130` | Interrupted with Ctrl+C |

Do not treat exit `1` from `diff` as a runtime error or as a security finding.

## Automation example

```sh
domeval scan example.com --authorized --json-stdout > report.json
status=$?
if [ "$status" -ne 0 ]; then
  echo "Scanner did not complete: $status" >&2
  exit "$status"
fi
```

For PowerShell, inspect `$LASTEXITCODE` after invoking a scanner command.
Only run scans against domains you own or are explicitly authorized to assess.
