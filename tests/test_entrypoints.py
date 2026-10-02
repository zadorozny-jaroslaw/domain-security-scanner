from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
