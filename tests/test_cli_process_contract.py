"""Process-level CLI contract tests that never contact external services.

The subprocess shim mocks Scanner *inside* a separate Python process, so these
checks exercise actual shell exit codes and stdout/stderr without live scanning.
The module entry point is used directly for commands that do not start a scan.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 30

# The separate interpreter must install the scanner stub before calling main().
# Passing the scenario as argv[1] avoids modifying the parent's environment.
SCANNER_SHIM = textwrap.dedent(r"""
    import io
    import logging
    import sys
    from contextlib import ExitStack
    from unittest.mock import patch

    from domain_security_scanner import cli
    from domain_security_scanner.utils import normalize_domain

    # The process-contract test intentionally exercises the non-interactive
    # path. Force a non-TTY stdin even on Windows test runners.
    sys.stdin = io.StringIO('')
    scenario, *arguments = sys.argv[1:]

    class StubScanner:
        def __init__(self, domain, *, max_pages=20, max_hosts=25, scan_groups=None):
            self.target_domain = normalize_domain(domain)
            self.root_domain = 'example.com'
            self.scan_groups = tuple(scan_groups or ())

        def set_scan_selection_context(self, **kwargs):
            pass

        def run(self):
            logging.getLogger('domain_security_scanner.cli').debug('stub debug progress')
            logging.getLogger('domain_security_scanner.cli').log(5, 'stub trace detail')
            if scenario == 'scan_failure':
                raise RuntimeError('simulated scan failure')
            if scenario == 'interrupt':
                raise KeyboardInterrupt

        def to_dict(self):
            report = {
                'target_domain': self.target_domain,
                'scan_groups': list(self.scan_groups),
                'checks': [{'status': 'ACTION'}, {'status': 'VERIFY'}],
                'score': {'score': 92, 'label': 'Strong'},
                'unicode_note': 'Zażółć gęślą jaźń',
            }
            if scenario == 'serialize_failure':
                report['invalid_value'] = object()
            return report

    class UnwritableStdout:
        def write(self, value):
            raise OSError('simulated stdout failure')

        def flush(self):
            pass

    with ExitStack() as patches:
        if scenario == 'init_failure':
            patches.enter_context(patch.object(
                cli, 'Scanner', side_effect=OSError('simulated initialization failure')))
        else:
            patches.enter_context(patch.object(cli, 'Scanner', StubScanner))
        if scenario == 'write_failure':
            patches.enter_context(patch.object(
                cli.Path, 'write_text', side_effect=PermissionError('simulated permission error')))
        if scenario == 'pdf_failure':
            patches.enter_context(patch.object(
                cli, 'generate_pdf', side_effect=OSError('simulated PDF failure')))
        if scenario == 'stdout_failure':
            patches.enter_context(patch.object(cli.sys, 'stdout', UnwritableStdout()))
        result = cli.main(arguments)
    raise SystemExit(result)
""")


def run_process(*args: str, scanner_scenario: str | None = None) -> subprocess.CompletedProcess[str]:
    """Execute the real Python interpreter, optionally replacing scanner IO."""
    if scanner_scenario is None:
        command = [sys.executable, '-m', 'domain_security_scanner', *args]
    else:
        command = [sys.executable, '-c', SCANNER_SHIM, scanner_scenario, *args]
    env = dict(os.environ)
    env['PYTHONIOENCODING'] = 'utf-8'
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,  # Always exercise non-interactive authorization.
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        check=False,
        timeout=TIMEOUT,
    )


def report(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        'target_domain': 'example.com',
        'generated_at': '2026-10-01T10:00:00Z',
        'checks': [],
        'score': {'score': 100, 'label': 'Strong'},
    }
    result.update(overrides)
    return result


class CliProcessContractTest(unittest.TestCase):
    def assert_clean_error(self, completed: subprocess.CompletedProcess[str], code: int):
        self.assertEqual(completed.returncode, code, completed.stderr)
        self.assertEqual(completed.stdout, '')
        self.assertNotIn('Traceback (most recent call last)', completed.stderr)

    def test_real_module_help_and_version_exit_zero(self):
        for arguments in (('--help',), ('-h',), ('scan', '--help'), ('diff', '--help'), ('--version',)):
            with self.subTest(arguments=arguments):
                result = run_process(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout)
                self.assertEqual(result.stderr, '')

    def test_real_module_rejects_missing_or_legacy_commands(self):
        for arguments in ((), ('scan',), ('example.com', '--authorized'), ('--diff', 'a.json', 'b.json')):
            with self.subTest(arguments=arguments):
                result = run_process(*arguments)
                self.assert_clean_error(result, 2)
                self.assertIn('error:', result.stderr)

    def test_noninteractive_scan_requires_authorization(self):
        result = run_process('scan', 'example.com', '--json-stdout', scanner_scenario='success')
        self.assert_clean_error(result, 2)
        self.assertIn('--authorized', result.stderr)

    def test_invalid_target_returns_usage_error(self):
        result = run_process('scan', 'not a domain', '--authorized', '--json-stdout', scanner_scenario='success')
        self.assert_clean_error(result, 2)
        # Language wording belongs to the focused #26 tests; here we verify
        # the CLI process contract even on checkouts predating that merge.
        self.assertIn('Invalid scan target:', result.stderr)
        self.assertIn('not a domain', result.stderr)

    def test_scan_options_are_validated_before_scanning(self):
        cases = (
            (('--scan', 'not-a-group'), 'unknown scan group'),
            (('--max-pages', '0'), 'must be between 1 and 100'),
            (('--max-hosts', '101'), 'must be between 1 and 100'),
            (('--json-only', '--json-stdout'), 'not allowed with argument'),
            (('--json-stdout', '--out', 'bad'), 'cannot be used with --out'),
            (('-q', '-vv'), 'not allowed with argument'),
        )
        for options, expected in cases:
            with self.subTest(options=options):
                result = run_process('scan', 'example.com', '--authorized', *options, scanner_scenario='success')
                self.assert_clean_error(result, 2)
                self.assertIn(expected, result.stderr)

    def test_stdout_is_machine_readable_and_stderr_is_human_readable(self):
        result = run_process('scan', 'example.com', '--authorized', '--json-stdout', scanner_scenario='success')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['score']['score'], 92)
        self.assertEqual(data['unicode_note'], 'Zażółć gęślą jaźń')
        self.assertEqual({c['status'] for c in data['checks']}, {'ACTION', 'VERIFY'})
        self.assertIn('Score: 92/100', result.stderr)
        self.assertNotIn('"checks"', result.stderr)
        self.assertNotIn('[+] Score:', result.stdout)

    def test_scan_and_skip_interaction_in_process(self):
        result = run_process(
            'scan', 'example.com', '--authorized', '--json-stdout',
            '--scan', 'mail,web', '--skip', 'mail', scanner_scenario='success',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['scan_groups'], ['web'])
        self.assertIn('Warning:', result.stderr)

    def test_quiet_mode_keeps_json_and_suppresses_progress(self):
        plain = run_process('scan', 'example.com', '--authorized', '--json-stdout', scanner_scenario='success')
        quiet = run_process('scan', 'example.com', '--authorized', '--json-stdout', '-q', scanner_scenario='success')
        self.assertEqual((plain.returncode, quiet.returncode), (0, 0))
        self.assertEqual(json.loads(plain.stdout), json.loads(quiet.stdout))
        self.assertEqual(quiet.stderr, '')

    def test_verbose_modes_change_diagnostics_not_report_json(self):
        outputs = []
        for verbosity in ((), ('-v',), ('-vv',)):
            with self.subTest(verbosity=verbosity):
                result = run_process('scan', 'example.com', '--authorized', '--json-stdout', *verbosity, scanner_scenario='success')
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(json.loads(result.stdout))
                self.assertEqual('stub debug progress' in result.stderr, bool(verbosity))
                self.assertEqual('stub trace detail' in result.stderr, verbosity == ('-vv',))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])

    def test_json_only_generates_file_not_pdf(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / 'customer-report'
            result = run_process('scan', 'example.com', '--authorized', '--out', str(prefix), '--json-only', scanner_scenario='success')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(json.loads(prefix.with_suffix('.json').read_text(encoding='utf-8'))['score']['score'], 92)
            self.assertFalse(prefix.with_suffix('.pdf').exists())

    def test_scan_and_initialization_failures_return_three(self):
        for scenario, expected in (
            ('scan_failure', 'Scan could not complete'),
            ('init_failure', 'Cannot initialize scan'),
        ):
            with self.subTest(scenario=scenario):
                result = run_process('scan', 'example.com', '--authorized', '--json-stdout', scanner_scenario=scenario)
                self.assert_clean_error(result, 3)
                self.assertIn(expected, result.stderr)

    def test_json_serialization_and_file_write_failures_return_four(self):
        with tempfile.TemporaryDirectory() as temp:
            for scenario, expected in (
                ('serialize_failure', 'Could not serialize JSON report'),
                ('write_failure', 'Could not write JSON report'),
            ):
                with self.subTest(scenario=scenario):
                    prefix = Path(temp) / scenario
                    result = run_process('scan', 'example.com', '--authorized', '--out', str(prefix), '--json-only', scanner_scenario=scenario)
                    self.assert_clean_error(result, 4)
                    self.assertIn(expected, result.stderr)
                    self.assertFalse(prefix.with_suffix('.json').exists())

    def test_pdf_write_failure_returns_four_but_keeps_json(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / 'report'
            result = run_process('scan', 'example.com', '--authorized', '--out', str(prefix), scanner_scenario='pdf_failure')
            self.assert_clean_error(result, 4)
            self.assertIn('Could not generate PDF report', result.stderr)
            self.assertEqual(json.loads(prefix.with_suffix('.json').read_text(encoding='utf-8'))['score']['score'], 92)

    def test_stdout_write_failure_returns_four(self):
        result = run_process('scan', 'example.com', '--authorized', '--json-stdout', scanner_scenario='stdout_failure')
        self.assert_clean_error(result, 4)
        self.assertIn('Could not write JSON to stdout', result.stderr)

    def test_interrupted_scan_process_returns_130(self):
        result = run_process('scan', 'example.com', '--authorized', '--json-stdout', scanner_scenario='interrupt')
        self.assert_clean_error(result, 130)
        self.assertIn('Interrupted by user.', result.stderr)

    def test_diff_process_codes_zero_one_and_two(self):
        with tempfile.TemporaryDirectory() as temp:
            old = Path(temp) / 'old.json'
            new = Path(temp) / 'new.json'
            old.write_text(json.dumps(report()), encoding='utf-8')
            new.write_text(json.dumps(report(generated_at='2026-10-02T10:00:00Z')), encoding='utf-8')

            equal = run_process('diff', str(old), str(new))
            self.assertEqual(equal.returncode, 0, equal.stderr)
            self.assertIn('No meaningful differences', equal.stdout)
            self.assertEqual(equal.stderr, '')

            new.write_text(json.dumps(report(score={'score': 82, 'label': 'Good'})), encoding='utf-8')
            changed = run_process('diff', str(old), str(new))
            self.assertEqual(changed.returncode, 1, changed.stderr)
            self.assertIn('CHANGED', changed.stdout)
            self.assertEqual(changed.stderr, '')

            old.write_text('{broken', encoding='utf-8')
            bad = run_process('diff', str(old), str(new))
            self.assert_clean_error(bad, 2)
            self.assertIn('Diff error:', bad.stderr)

    def test_diff_missing_and_invalid_utf8_files_return_two(self):
        with tempfile.TemporaryDirectory() as temp:
            old = Path(temp) / 'old.json'
            new = Path(temp) / 'new.json'
            new.write_text(json.dumps(report()), encoding='utf-8')
            missing = run_process('diff', str(old), str(new))
            self.assert_clean_error(missing, 2)
            self.assertIn('Diff error:', missing.stderr)

            old.write_bytes(b'\xff\xfe\xfa')
            invalid_utf8 = run_process('diff', str(old), str(new))
            self.assert_clean_error(invalid_utf8, 2)
            self.assertIn('cannot decode', invalid_utf8.stderr)


if __name__ == '__main__':
    unittest.main()
