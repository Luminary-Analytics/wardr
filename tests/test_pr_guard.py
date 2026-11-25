"""Unit tests for scripts/pr_guard.py security invariants and PR triage."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "pr_guard.py"

_SPEC = importlib.util.spec_from_file_location("pr_guard", SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
pr_guard = importlib.util.module_from_spec(_SPEC)
sys.modules["pr_guard"] = pr_guard
_SPEC.loader.exec_module(pr_guard)


class TestPRGuard(unittest.TestCase):
    def test_repo_baseline_passes(self) -> None:
        report = pr_guard.run_repo_scan(ROOT)
        self.assertEqual(
            report.errors,
            [],
            f"Expected zero blocking errors on repository baseline, got: {report.errors}",
        )

    def test_unicode_trojan_source_detected(self) -> None:
        poisoned = "def ok():\n    # hidden \u202e bidi override\n    return True\n"
        findings = pr_guard.check_unicode_text("wardr/demo.py", poisoned)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "hidden-unicode")
        self.assertEqual(findings[0].line, 2)

    def test_unicode_tag_characters_detected(self) -> None:
        poisoned = "comment \U000e0041 hidden tag"
        findings = pr_guard.check_unicode_text("docs/readme.md", poisoned)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "hidden-unicode")

    def test_html_csp_catches_inline_script_style_and_handlers(self) -> None:
        bad_html = (
            "<html><head><style>body{}</style></head>"
            "<body><div style='color:red' onclick='alert(1)'></div>"
            "<script>alert(1)</script>"
            "<script src='/static/wardr.js'></script></body></html>"
        )
        findings = pr_guard.check_html_csp("wardr/static/index.html", bad_html)
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(f.category == "csp-violation" for f in findings))

    def test_workflow_pinning_and_pull_request_target(self) -> None:
        bad_yml = (
            "on:\n"
            "  pull_request_target:\n"
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0\n"
            "  - uses: ./.github/workflows/local.yml\n"
        )
        findings = pr_guard.check_workflow_security(".github/workflows/bad.yml", bad_yml)
        categories = {f.category for f in findings}
        self.assertEqual(categories, {"workflow-security", "workflow-pinning"})
        self.assertEqual(len(findings), 2)

    def test_pyproject_dependency_lock(self) -> None:
        clean = '[project]\nname = "wardr"\ndependencies = ["cryptography>=50.0.2"]\n'
        self.assertEqual(pr_guard.check_pyproject_dependencies("pyproject.toml", clean), [])

        extra = '[project]\nname = "wardr"\ndependencies = ["cryptography>=50.0.2", "requests>=2.0"]\n'
        blocked = pr_guard.check_pyproject_dependencies("pyproject.toml", extra)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0].severity, "error")

        allowed = pr_guard.check_pyproject_dependencies(
            "pyproject.toml", extra, allow_dependency_change=True
        )
        self.assertEqual(len(allowed), 1)
        self.assertEqual(allowed[0].severity, "warning")

    def test_python_ast_blocks_dangerous_primitives_but_allows_re_compile(self) -> None:
        safe = "import re\nPAT = re.compile(r'abc')\n"
        self.assertEqual(pr_guard.check_python_ast("wardr/safe.py", safe), [])

        bad = (
            "import os, subprocess\n"
            "from pickle import loads as decode_obj\n"
            "eval('1+1')\n"
            "os.system('id')\n"
            "decode_obj(b'abc')\n"
            "subprocess.run('ls', shell=True)\n"
        )
        findings = pr_guard.check_python_ast("wardr/bad.py", bad)
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(f.severity == "error" for f in findings))

    def test_risk_tier_classification(self) -> None:
        tier, t0, t1 = pr_guard.classify_paths(["wardr/keys/release.pem", "docs/ARCHITECTURE.md"])
        self.assertIn("Tier 0", tier)
        self.assertEqual(t0, ["wardr/keys/release.pem"])
        self.assertEqual(t1, [])

        tier, t0, t1 = pr_guard.classify_paths(["wardr/remediation.py", "tests/test_remediation.py"])
        self.assertIn("Tier 1", tier)
        self.assertEqual(t0, [])
        self.assertEqual(t1, ["wardr/remediation.py"])

        tier, t0, t1 = pr_guard.classify_paths(["docs/DEVELOPMENT.md", "tests/test_checks.py"])
        self.assertIn("Tier 2", tier)
        self.assertEqual(t0, [])
        self.assertEqual(t1, [])


if __name__ == "__main__":
    unittest.main()
