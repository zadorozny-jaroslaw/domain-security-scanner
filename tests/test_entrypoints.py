from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_python(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class EntryPointTest(unittest.TestCase):
    def test_project_declares_primary_and_compatibility_console_scripts(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        scripts = config["project"]["scripts"]
        self.assertEqual(scripts["domeval"], "domain_security_scanner.cli:main")
        self.assertEqual(
            scripts["domain-security-scan"],
            "domain_security_scanner.cli:main",
        )

    def test_packaging_reuses_existing_version_and_dependency_sources(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertIn("version", config["project"]["dynamic"])
        self.assertIn("dependencies", config["project"]["dynamic"])
        self.assertEqual(
            config["tool"]["setuptools"]["dynamic"]["version"]["attr"],
            "domain_security_scanner.version.__version__",
        )
        self.assertEqual(
            config["tool"]["setuptools"]["dynamic"]["dependencies"]["file"],
            ["requirements.txt"],
        )

    def test_module_and_compatibility_script_report_same_version(self):
        module = _run_python("-m", "domain_security_scanner", "--version")
        script = _run_python("domain_security_scan.py", "--version")

        self.assertEqual(module.returncode, 0, module.stderr)
        self.assertEqual(script.returncode, 0, script.stderr)
        self.assertEqual(module.stdout, script.stdout)

    def test_module_and_compatibility_script_have_equivalent_help(self):
        module = _run_python("-m", "domain_security_scanner", "--help")
        script = _run_python("domain_security_scan.py", "--help")

        self.assertEqual(module.returncode, 0, module.stderr)
        self.assertEqual(script.returncode, 0, script.stderr)
        for expected in ("{scan,diff}", "domeval scan", "domeval diff"):
            self.assertIn(expected, module.stdout)
            self.assertIn(expected, script.stdout)

    def test_module_and_compatibility_script_return_same_usage_error(self):
        module = _run_python("-m", "domain_security_scanner", "not-a-command")
        script = _run_python("domain_security_scan.py", "not-a-command")

        self.assertEqual(module.returncode, 2)
        self.assertEqual(script.returncode, 2)

    def _installed_commands(self) -> dict[str, str]:
        """Use installed launchers when present; source-tree runs need not install them."""
        names = ("domeval", "domain-security-scan")
        available = {name: shutil.which(name) for name in names}
        if not any(available.values()):
            self.skipTest("Install the package with 'python -m pip install -e .' to test console scripts")
        for name, path in available.items():
            self.assertIsNotNone(path, f"Missing installed CLI alias: {name}")
        return {name: path for name, path in available.items() if path is not None}

    def test_installed_console_scripts_have_equivalent_help_and_version(self):
        launchers = self._installed_commands()
        for arguments in (("--version",), ("--help",), ("scan", "--help"), ("diff", "--help")):
            with self.subTest(arguments=arguments):
                results = {}
                for name, executable in launchers.items():
                    result = subprocess.run(
                        [executable, *arguments],
                        cwd=ROOT,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")
                    self.assertEqual(result.stderr, "", name)
                    results[name] = result.stdout
                if arguments == ("--version",):
                    self.assertEqual(results["domeval"], results["domain-security-scan"])
                else:
                    # argparse uses the invoked executable's name in the
                    # "usage:" block. On Windows these differ (domeval.EXE
                    # vs domain-security-scan.EXE), and the longer name may
                    # also wrap the synopsis onto additional lines. Compare
                    # the meaningful help body, ignoring whitespace wrapping.
                    def help_body(output: str) -> str:
                        self.assertTrue(output.startswith("usage: "), output)
                        self.assertIn("\n\n", output, output)
                        return re.sub(r"\s+", " ", output.split("\n\n", 1)[1]).strip()

                    self.assertEqual(
                        help_body(results["domeval"]),
                        help_body(results["domain-security-scan"]),
                    )

    def test_installed_console_scripts_preserve_usage_error_exit_two(self):
        launchers = self._installed_commands()
        for arguments in (("unknown-command",), ("scan",), ("scan", "example.com", "--max-pages", "0")):
            for name, executable in launchers.items():
                with self.subTest(launcher=name, arguments=arguments):
                    result = subprocess.run(
                        [executable, *arguments],
                        cwd=ROOT,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 2, f"{name}: {result.stderr}")
                    self.assertEqual(result.stdout, "", name)
                    self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
