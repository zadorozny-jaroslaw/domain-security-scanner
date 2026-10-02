# v1.4.0 CLI implementation plan

## Release theme

**CLI Readiness & Automation**

v1.4.0 should turn the existing command-line entry point into a predictable, discoverable, automation-friendly interface.

The scanner already has a functional CLI, selectable scan groups, version reporting, authorization enforcement, JSON/PDF report generation, and JSON-only output.

This release should strengthen the interface around those capabilities rather than expand the scanner's security-assessment scope.

Target cadence: **the two-week release iteration following v1.3.0**. The cadence is a planning target; acceptance criteria and release quality take precedence over a fixed date.

## Design principles

### Keep scanner semantics separate from CLI presentation

CLI behavior must not alter the meaning of collected security evidence.

Changing verbosity, output destination, command entry point, or presentation mode must not change:

- which checks run for the same effective scan scope;
- JSON security evidence;
- PDF findings;
- scoring;
- UNKNOWN/VERIFY handling;
- authorization requirements.

The CLI should control invocation, presentation, and process behavior. Security interpretation remains owned by the scanner.

### Separate human and machine output

Human-oriented progress, warnings, and diagnostics must not corrupt machine-readable output.

The target contract is:

```text
stdout
    explicitly requested machine-readable/report output

stderr
    progress
    warnings
    diagnostics
    execution errors
```

This should make workflows such as JSON pipelines reliable.

### Prefer explicit operations over parser special cases

Scanning a domain and comparing two existing reports are different operations.

The CLI should model them explicitly rather than accumulating mutually exclusive top-level flags.

The preferred installed command shape is broadly:

```text
domeval scan DOMAIN [options]
domeval diff OLD_REPORT NEW_REPORT [options]
```

The longer `domain-security-scan` executable remains a compatibility alias, while `python -m domain_security_scanner` and `python domain_security_scan.py` provide equivalent module and source-tree entry points.

The v1.4 command contract intentionally makes a hard cut from the earlier flat operation syntax. The script entry point remains available, but scan and diff operations must be selected explicitly rather than inferred from a positional domain or top-level `--diff` flag.

### Keep automation behavior stable

Automation needs predictable:

- exit status;
- stdout;
- stderr;
- machine-readable output;
- argument validation.

Normal security findings must remain distinct from command execution failures.

A successful scan that discovers ACTION or REVIEW findings is still a successfully executed scan unless a future explicit CI-policy option says otherwise.

## Existing foundations

### JSON-only output

`--json-only` already provides an output mode that skips PDF generation while preserving the normal JSON report.

v1.4.0 should build on that behavior rather than replacing it unnecessarily.

### Semantic report comparison

Semantic comparison of existing JSON reports is already implemented as a report-aware local operation.

The v1.4 command structure should expose that capability cleanly through the `diff` command rather than duplicating its comparison engine.

## Workstream 1 - Command structure

Introduce explicit command handlers for logically distinct operations.

Primary target:

```bash
domeval scan example.com --authorized
domeval diff previous.json current.json
```

Requirements:

- scan-only arguments belong to `scan`;
- comparison-only arguments belong to `diff`;
- global `--help` and `--version` remain discoverable;
- `diff` does not require scanning authorization;
- parser validation completes before scanner network activity begins;
- the earlier flat `DOMAIN ...` and top-level `--diff` forms are rejected rather than silently reinterpreted;
- interactive scan invocations may confirm authorization at a prompt when `--authorized` is omitted;
- non-interactive scan invocations must provide `--authorized` and fail before scanner activity if it is missing.

Prefer a CLI structure such as:

```python
def build_parser():
    ...

def run_scan(args):
    ...

def run_diff(args):
    ...

def main(argv=None):
    ...
```

rather than growing one monolithic `main()` implementation.

## Workstream 2 - Help and discoverability

Improve built-in help so users can understand the scanner without reading source code.

Required:

- clear top-level help;
- command-specific help;
- concise command descriptions;
- representative examples;
- argument grouping by purpose;
- visible defaults where useful;
- concise numeric range descriptions;
- supported scan-group names;
- consistent public CLI language.

Public CLI messages should use English consistently.

Avoid dumping large argparse `choices` enumerations such as every integer from 1 through 100 when a range description is clearer.

## Workstream 3 - Verbose and quiet modes

Add controlled execution visibility.

Target interface:

```text
-v, --verbose
-vv
-q, --quiet
```

Expected semantics:

```text
default
    concise normal progress and completion summary

-v
    scan-group/check-level operational progress

-vv
    detailed diagnostics useful when investigating evidence collection

-q
    suppress normal status output while retaining fatal errors
    and explicitly requested machine-readable output
```

Use centralized logging or an equivalent abstraction.

Do not implement verbose behavior as unrelated `if verbose: print(...)` statements distributed throughout scanner modules.

Diagnostic output belongs on stderr.

Verbosity must never change scan findings or evidence interpretation.

## Workstream 4 - stdout, stderr, and machine-readable output

Establish a stable stream contract.

Add a supported way to emit scanner JSON directly to stdout without human-oriented prefixes.

A target workflow should be possible:

```bash
domeval scan example.com --authorized --json-stdout \
  | jq '.score'
```

The exact relationship between JSON stdout and file generation must be explicit and documented.

Requirements:

- stdout contains valid JSON when JSON stdout is requested;
- progress and warnings remain on stderr;
- quiet mode does not suppress explicitly requested JSON;
- broken pipes terminate cleanly;
- changing output destination does not alter report content or scoring.

## Workstream 5 - Exit codes and runtime errors

Define a small documented process-status contract.

Initial target:

```text
0     command completed successfully
2     invalid command usage, invalid input, or authorization not confirmed
3     scan could not complete
4     report/output generation failed
130   interrupted by the user
```

Expected operational failures should produce concise errors rather than uncontrolled tracebacks.

Handle at least:

- invalid arguments;
- invalid domain input;
- authorization declined or unavailable in non-interactive mode without `--authorized`;
- scanner initialization failure;
- unrecoverable scan execution failure;
- JSON write/serialization failure;
- PDF generation failure;
- invalid report-comparison input;
- filesystem permission/path failures;
- KeyboardInterrupt.

UNKNOWN/VERIFY security evidence must remain separate from process failure.

If a network observation fails but the scanner can represent that condition conservatively, the CLI should not convert it into a command failure merely because evidence was unavailable.

## Workstream 6 - Installation and entry points

Provide normal Python CLI entry points.

Preferred installed invocations:

```bash
domeval --version
domeval scan example.com --authorized
```

Supported compatibility console alias:

```bash
domain-security-scan --version
domain-security-scan scan example.com --authorized
```

Also support:

```bash
python -m domain_security_scanner --version
python -m domain_security_scanner scan example.com --authorized
```

Keep the existing source-tree wrapper available:

```bash
python domain_security_scan.py --version
python domain_security_scan.py scan example.com --authorized
```

Add project metadata, console-script configuration, and `domain_security_scanner/__main__.py` as appropriate.

`domeval` is the preferred human-facing executable name. `domain-security-scan` remains available for legacy references and compatibility, while the repository name, Python package name, and source filenames retain their existing naming conventions.

All entry points must delegate to the same CLI implementation and return equivalent exit statuses for equivalent commands.

Avoid creating competing version sources. Package metadata must derive its version from the existing project version source.

CI should install the project as a package and smoke-test the installed console scripts plus the module entry point on supported Windows and Linux runners.

## Workstream 7 - CLI regression contract

Add focused tests covering the public command-line interface.

At minimum test:

- top-level help;
- command help;
- version;
- scan command;
- diff command;
- rejection of the removed flat scan and top-level `--diff` syntax;
- invalid/missing domain;
- interactive authorization confirmation and cancellation;
- non-interactive authorization enforcement;
- `--authorized` prompt bypass;
- scan-group validation;
- `--scan` / `--skip` interaction;
- scan-limit validation;
- JSON-only mode;
- JSON stdout;
- verbose levels;
- quiet mode;
- stdout/stderr separation;
- documented exit codes;
- output failures;
- invalid comparison inputs;
- Ctrl+C behavior;
- alternate supported entry points where practical.

Refactor `main()` to accept an optional argument sequence so most parser tests do not need to patch global `sys.argv`.

Use subprocess tests where the actual process boundary is part of the behavior under test.

CLI regression tests should mock scanner/network behavior unless they are explicitly separate authorized smoke tests.

## Workstream 8 - User documentation

Update user-facing documentation after the CLI contract is implemented.

Document:

- `domeval` as the preferred installed command;
- `domain-security-scan` as the compatibility console alias;
- `python -m domain_security_scanner` and `domain_security_scan.py` as supported alternate entry points;
- `scan` command;
- `diff` command;
- the intentional removal of the old flat operation syntax;
- interactive authorization confirmation;
- `--authorized` for non-interactive use and prompt bypass;
- scan-group selection;
- scan limits;
- JSON-only mode;
- JSON stdout;
- verbosity levels;
- quiet mode;
- stdout/stderr behavior;
- output naming;
- exit codes;
- interactive examples;
- automation and shell-pipeline examples.

Do not document flags as available before their implementation is merged.

## Release boundaries

### In scope

- CLI command organization;
- CLI help and discoverability;
- verbosity and quiet behavior;
- output-stream separation;
- JSON stdout;
- execution error handling;
- stable exit codes;
- installable/module entry points;
- CLI regression tests;
- CLI user documentation;
- integration of already-developed JSON-only and semantic-diff capabilities.

### Out of scope

- new DNS, TLS, Web, Mail, Discovery, or CMS security checks;
- changing the security scoring model;
- changing UNKNOWN/VERIFY semantics;
- configuration-file systems;
- general interactive/TUI interfaces beyond the bounded authorization confirmation prompt;
- shell-completion frameworks unless required by the chosen packaging mechanism;
- automatic CI policy decisions based on score or finding severity;
- broad API redesign;
- plugin architecture;
- replacing JSON/PDF report formats;
- platform-specific native launcher metadata beyond the standard Python packaging entry points.

Features such as `--fail-on` or score thresholds can be considered later once the basic CLI execution contract is stable.

## Compatibility requirements

v1.4.0 intentionally changes the operation syntax while retaining multiple supported entry paths.

Preferred installed forms:

```text
domeval scan DOMAIN [options]
domeval diff OLD_REPORT NEW_REPORT
```

Compatibility entry points remain:

```text
domain-security-scan scan DOMAIN [options]
domain-security-scan diff OLD_REPORT NEW_REPORT
python -m domain_security_scanner scan DOMAIN [options]
python -m domain_security_scanner diff OLD_REPORT NEW_REPORT
python domain_security_scan.py scan DOMAIN [options]
python domain_security_scan.py diff OLD_REPORT NEW_REPORT
```

The earlier flat `python domain_security_scan.py DOMAIN ...` and `python domain_security_scan.py --diff ...` forms are not compatibility requirements and must not be silently reinterpreted as valid commands.

Security report schemas should not change merely because of CLI refactoring or packaging.

## v1.4.0 completion criteria

v1.4.0 is ready when:

- built-in help clearly exposes supported operations and their options;
- scanning and report comparison have explicit command paths;
- scan authorization is explicitly confirmed either interactively or through `--authorized`, while local report comparison requires no scan authorization;
- non-interactive scans without `--authorized` fail before scanner activity begins;
- verbose and quiet modes behave predictably;
- machine-readable JSON can be consumed without progress output contaminating stdout;
- documented exit codes distinguish usage, execution, and output failures;
- expected operational failures do not produce uncontrolled tracebacks;
- `domeval` is available as the preferred installed executable;
- `domain-security-scan` remains available as a compatibility console alias;
- `python -m domain_security_scanner` and `domain_security_scan.py` invoke the same CLI behavior;
- CLI behavior has dedicated regression coverage;
- README/help documentation matches the implemented interface.

The release must preserve the project's core evidence rule: externally unavailable evidence is not proof of failure, and CLI presentation must not change the security meaning of collected evidence.
