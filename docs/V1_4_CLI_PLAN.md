# v1.4.0 CLI implementation plan

## Release theme

**CLI Readiness & Automation**

v1.4.0 should turn the existing command-line entry point into a predictable, discoverable, automation-friendly interface.

The scanner already has a functional CLI, selectable scan groups, version reporting, authorization enforcement, JSON/PDF report generation, and JSON-only output.

This release should strengthen the interface around those capabilities rather than expand the scanner's security-assessment scope.

Target completion: **before 8 October 2026**.

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

The target command shape is broadly:

```text
domain-security-scan scan DOMAIN [options]
domain-security-scan diff OLD_REPORT NEW_REPORT [options]
```

Backward compatibility with the current script-style scan invocation should be retained during the transition where practical.

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

Semantic comparison of existing JSON reports is being developed separately before the main CLI-readiness work.

The v1.4 command structure should expose that capability cleanly as a report operation rather than duplicating its comparison engine.

## Workstream 1 - Command structure

Introduce explicit command handlers for logically distinct operations.

Primary target:

```bash
domain-security-scan scan example.com --authorized
domain-security-scan diff previous.json current.json
```

Requirements:

- scan-only arguments belong to `scan`;
- comparison-only arguments belong to `diff`;
- global `--help` and `--version` remain discoverable;
- `diff` does not require scanning authorization;
- parser validation completes before scanner network activity begins;
- existing scan invocation remains supported during the compatibility period where practical.

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
domain-security-scan scan example.com --authorized --json-stdout \
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
2     invalid command usage, invalid input, or authorization missing
3     scan could not complete
4     report/output generation failed
130   interrupted by the user
```

Expected operational failures should produce concise errors rather than uncontrolled tracebacks.

Handle at least:

- invalid arguments;
- invalid domain input;
- missing authorization;
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

Target supported invocations:

```bash
domain-security-scan --version
domain-security-scan scan example.com --authorized
```

and:

```bash
python -m domain_security_scanner --version
python -m domain_security_scanner scan example.com --authorized
```

Add project metadata, console-script configuration, and `domain_security_scanner/__main__.py` as appropriate.

Keep `domain_security_scan.py` as a compatibility entry point.

All entry points must delegate to the same CLI implementation and return equivalent exit statuses for equivalent commands.

Avoid creating competing version sources.

## Workstream 7 - CLI regression contract

Add focused tests covering the public command-line interface.

At minimum test:

- top-level help;
- command help;
- version;
- scan command;
- diff command;
- backward-compatible scan invocation;
- invalid/missing domain;
- authorization enforcement;
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

- supported entry points;
- `scan` command;
- `diff` command;
- backward-compatible invocation;
- authorization behavior;
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
- interactive/TUI interfaces;
- shell-completion frameworks unless required by the chosen packaging mechanism;
- automatic CI policy decisions based on score or finding severity;
- broad API redesign;
- plugin architecture;
- replacing JSON/PDF report formats.

Features such as `--fail-on` or score thresholds can be considered later once the basic CLI execution contract is stable.

## Compatibility requirements

v1.4.0 should avoid unnecessary breaking changes.

The current script entry point should remain available.

Where the introduction of subcommands changes the preferred syntax, provide a reasonable compatibility path for existing scan commands rather than silently changing their meaning.

Security report schemas should not change merely because of CLI refactoring.

## v1.4.0 completion criteria

v1.4.0 is ready when:

- built-in help clearly exposes supported operations and their options;
- scanning and report comparison have explicit command paths;
- authorization remains mandatory for scans and irrelevant to local report comparison;
- verbose and quiet modes behave predictably;
- machine-readable JSON can be consumed without progress output contaminating stdout;
- documented exit codes distinguish usage, execution, and output failures;
- expected operational failures do not produce uncontrolled tracebacks;
- the scanner has supported executable and `python -m` entry points;
- the compatibility script still works;
- CLI behavior has dedicated regression coverage;
- README/help documentation matches the implemented interface.

The release must preserve the project's core evidence rule: externally unavailable evidence is not proof of failure, and CLI presentation must not change the security meaning of collected evidence.
