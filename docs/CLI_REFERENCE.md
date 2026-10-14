# Command-line interface reference

This document describes the supported CLI interface for version 1.4.0.
The command examples use `domeval`, the preferred installed executable. The
[README](../README.md) is the getting-started guide, and
[CLI_EXIT_CODES.md](CLI_EXIT_CODES.md) is the authoritative process-exit-status
contract. Built-in help (`domeval --help`, `domeval scan --help`, and
`domeval diff --help`) reflects the available arguments.

**Authorization and scope:** Run scans only against domains you own or are
explicitly authorized to assess. Replace `example.com` in the examples with an
authorized target. The scanner performs low-impact external posture checks, not
exploitation, credential testing, broad port scanning, or denial-of-service testing.

## Install and select an entry point

Install Python 3.11 or newer, then in a virtual environment or other suitable
Python environment:

```sh
python -m pip install .
domeval --version
```

When working from a source checkout, `python -m pip install -e .` installs an
editable development copy instead. The four supported entry points are:

| Invocation | Purpose |
| --- | --- |
| `domeval` | Preferred installed console command |
| `domain-security-scan` | Installed compatibility alias |
| `python -m domain_security_scanner` | Package module entry point |
| `python domain_security_scan.py` | Source-tree compatibility script (run from the checkout) |

Each delegates to the same CLI code and supports the same commands, options, and
exit codes. Run `COMMAND --version` or `COMMAND --help`, replacing `COMMAND` with
one of the entry points above.

**Compatibility is for the executable names, not the old argument syntax.**
Every invocation now requires the `scan` or `diff` subcommand for those operations.
The older flat forms `python domain_security_scan.py example.com` and
`python domain_security_scan.py --diff old.json new.json` are intentionally not
supported.

## Commands

```text
domeval [--help] [--version] {scan,diff} ...
domeval scan DOMAIN [OPTIONS]
domeval diff OLD_JSON NEW_JSON
```

`scan` gathers external domain-posture evidence and creates a report, subject to
scan authorization. `diff` compares two existing local JSON reports and performs
no network scan or authorization confirmation. Scan-specific flags do not apply
to `diff`.

### Scan arguments

| Argument | Meaning and default |
| --- | --- |
| `DOMAIN` | Required target domain or subdomain; for example `shop.example.com` |
| `--authorized` | Confirm authorization and skip the interactive prompt; required for non-interactive scans |
| `--scan GROUPS` | Run only specified comma-separated scan groups; default is all six |
| `--skip GROUPS` | Exclude specified comma-separated scan groups; overrides `--scan` for overlaps |
| `--max-pages N` | Maximum pages to crawl, integer `1`–`100`, default `20` |
| `--max-hosts N` | Maximum discovered hosts to assess, integer `1`–`100`, default `25` |
| `--out PREFIX` | Output path/name prefix; default `security-report-<domain>` |
| `--json-only` | Write the JSON file but do not generate a PDF |
| `--json-stdout` | Write JSON to standard output only; generate no files |
| `-v`, `--verbose` | Additional operational progress; repeat as `-vv` for diagnostics |
| `-q`, `--quiet` | Suppress routine progress/completion and warnings, but not errors |
| `-h`, `--help` | Show scan-specific help and exit |

The `--json-only` and `--json-stdout` modes are mutually exclusive.
`--json-stdout` also cannot be combined with `--out`. `-q` cannot be used with
`-v`/`-vv`. Invalid combinations or argument values fail during validation
rather than initiating a scan.

#### Authorization

```sh
# Interactive terminal: prompts with a default of No.
domeval scan example.com

# Non-interactive (for a domain you are authorized to scan):
domeval scan example.com --authorized
```

In an interactive terminal, omitting `--authorized` displays the target and
requires an explicit `y` or `yes` before scan activity. Enter, `n`, or no input
cancels the scan. In non-interactive environments, `--authorized` is mandatory;
otherwise the scan stops with exit `2`. The flag is an explicit assertion of
permission, not a way to acquire permission.

#### Select scan groups

Valid group names are `domain`, `discovery`, `mail`, `tls`, `web`, and `cms`.
Names are comma-separated, case-insensitive, and deduplicated. There is no
`all` group or other alias.

```sh
# Only Mail and Web findings:
domeval scan example.com --authorized --scan mail,web

# All groups except Discovery and CMS:
domeval scan example.com --authorized --skip discovery,cms

# Skip takes precedence; the effective selected group here is Web:
domeval scan example.com --authorized --scan mail,web --skip mail
```

With neither selection flag, all six groups run. When both flags are present,
`--skip` removes groups from the selected set; the CLI warns when the selection
is redundant or overlaps. Selected groups may gather limited prerequisite
context needed for their checks without enabling unrelated findings or scores.
The report records the effective selection. See [SCAN_GROUPS.md](SCAN_GROUPS.md)
for the orchestration model. Scores from differently scoped scans are not
directly comparable.

#### Output destinations and file naming

| Mode | JSON | PDF | Stdout |
| --- | --- | --- | --- |
| Default `scan DOMAIN` | `<PREFIX>.json` | `<PREFIX>.pdf` | No report JSON |
| `--json-only` | `<PREFIX>.json` | None | No report JSON |
| `--json-stdout` | No file | No file | One UTF-8 JSON report |

With no `--out`, `<PREFIX>` is `security-report-<domain>` (using the normalized
web target). For example, scanning `example.com` writes
`security-report-example.com.json` and `security-report-example.com.pdf` in
the current working directory. `--out customer-example` instead writes
`customer-example.json` and `customer-example.pdf`. Existing output paths may
be overwritten. An output failure can leave a partial artifact; only trust
file outputs after a successful scan exit status.

```sh
domeval scan example.com --authorized --out customer-example
domeval scan example.com --authorized --json-only
domeval scan example.com --authorized --json-stdout
```

Output selection changes the destination, not the scan evidence, scoring, or
security interpretation.

### Diff arguments

```sh
domeval diff previous.json current.json
```

`OLD_JSON` and `NEW_JSON` are required paths to existing scanner JSON reports.
The comparison ignores volatile fields such as generation timestamps and treats
known set-like report collections as unordered. It reports meaningful additions,
removals, and changes. No authorization flag or network scan is needed.

For `diff`, exit `0` means semantically equivalent, `1` means changed, and `2`
means invalid input (including missing, unreadable, malformed, or invalid-UTF-8
files). Ctrl+C returns `130`. Exit `1` signals a difference, **not** a process
failure or a security-finding verdict.

## Logging and output streams

| Mode | Human-oriented stderr | Report JSON on stdout |
| --- | --- | --- |
| Default | Concise progress, warnings, completion summary, and errors | Only with `--json-stdout` |
| `-v` | More scan-group/check-level operational detail | Unchanged |
| `-vv` | Detailed diagnostic logging | Unchanged |
| `-q` | Errors remain; routine progress/completion and warnings are suppressed | Unchanged |

`stdout` is reserved for explicitly requested machine-readable JSON
(`--json-stdout`) and the human-readable result of `diff`. Scan progress,
warnings, diagnostics, and errors go to `stderr`. The `--json-stdout` output
contains no human prefixes, so it can be parsed by `jq` or another JSON tool.

```sh
# jq is optional and must be installed separately.
domeval scan example.com --authorized --json-stdout | jq '.score.score'

# Quiet does not suppress JSON output.
domeval scan example.com --authorized --json-stdout --quiet

# Verbose/quiet apply to scan, not diff.
domeval scan example.com --authorized -vv --json-only
```

For reliable automation, prefer capturing the CLI process status before
processing generated data, rather than relying solely on a pipeline's last
command status.

## Process exit codes

The exact contract is in [CLI_EXIT_CODES.md](CLI_EXIT_CODES.md).

| Scan exit | Interpretation |
| --- | --- |
| `0` | Scan completed; findings may include `ACTION`, `REVIEW`, or `VERIFY` |
| `2` | Usage, invalid target/group/limit, or authorization not confirmed |
| `3` | Scanner initialization, execution, or report assembly failed |
| `4` | JSON serialization/write, stdout write, or PDF generation failed |
| `130` | Interrupted by Ctrl+C |

A successfully completed scan with an `ACTION` finding still exits `0`.
`VERIFY`/`UNKNOWN` describe inconclusive evidence, not a CLI failure. The CLI
does not implement a score threshold or `--fail-on` policy. A PDF failure can
leave behind the successfully written JSON; do not treat it as a complete
successful run if the process returned `4`. An expected downstream closed pipe
in `--json-stdout` mode terminates without a traceback and returns `0`.

## Automation examples

These examples deliberately use `--authorized` and assume the operator already
has permission to scan the target.

### POSIX shell: save JSON and verify success

```sh
# Replace example.com with your authorized target.
domeval scan example.com --authorized --json-stdout > report.json
status=$?
if [ "$status" -ne 0 ]; then
  echo "Scan failed with exit code $status" >&2
  rm -f report.json  # May contain incomplete output
  exit "$status"
fi

# Only interpret the JSON after exit 0 (jq is optional).
jq '.score.score' report.json
```

For direct piping into a consumer, use your shell's `pipefail` support or
capture the scanner's exit status explicitly. Without that, a downstream
command's success might conceal an upstream scanner failure.

### PowerShell: save UTF-8 JSON and verify success

```powershell
# Replace example.com with your authorized target.
# Works in Windows PowerShell 5.1 and PowerShell 7+.
domeval scan example.com --authorized --json-only --out report
$status = $LASTEXITCODE
if ($status -ne 0) {
    Remove-Item report.json -ErrorAction SilentlyContinue
    throw "Scan failed with exit code $status"
}

$report = Get-Content report.json -Raw -Encoding UTF8 | ConvertFrom-Json
$report.score.score
```

Read `$LASTEXITCODE` immediately after the native scanner command, before
calling other native commands. This uses the scanner's JSON file writer, so the
report stays UTF-8 across PowerShell versions. Avoid redirecting native stdout
with `--json-stdout > report.json` in Windows PowerShell 5.1: `>` writes
UTF-16LE by default, which may surprise UTF-8 JSON consumers. PowerShell 7
uses UTF-8 redirection; for cross-version file automation, prefer `--json-only`
with `--out` as above. For direct stdout consumers, `--json-stdout` is still
available; check the scanner's process exit status before trusting its output.

### CI: distinguish report differences from errors

```sh
domeval diff baseline.json current.json
status=$?
case "$status" in
  0) echo "Reports equivalent" ;;
  1) echo "Reports changed" ;;
  2) echo "Invalid comparison input" >&2; exit 2 ;;
  130) echo "Comparison interrupted" >&2; exit 130 ;;
  *) echo "Unexpected comparison failure: $status" >&2; exit "$status" ;;
esac
```

A script may choose to treat differences as a CI-policy failure, but that is a
caller decision; the CLI does not equate differences with security risk.

## Related documentation

- [README](../README.md) — installation, quick start, scan groups, and security scope.
- [CLI_EXIT_CODES.md](CLI_EXIT_CODES.md) — complete exit-code and partial-artifact semantics.
- [SCAN_GROUPS.md](SCAN_GROUPS.md) — selection, prerequisites, and scoped findings.
- [DATA_SOURCES.md](DATA_SOURCES.md) — external services contacted by checks.
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) — release validation and version updates.
