#!/usr/bin/env python3
"""Deterministic PR & repository security guard for Wardr.

Checks Wardr's core security invariants and produces a fast maintainer triage
summary for pull requests:

1. Trojan Source / hidden Unicode detection (bidi overrides, zero-width chars,
   Unicode tag characters used for stealth code or prompt injection).
2. Strict CSP hygiene for ``wardr/static/*.html`` (no inline ``<script>``,
   ``<style>``, ``style=`` attributes, or ``on*=`` event handlers).
3. GitHub Actions workflow hardening (full 40-char SHA pinning on external
   ``uses:`` references and prohibition of ``pull_request_target``).
4. Python runtime dependency lock in ``pyproject.toml`` (single dependency
   ``cryptography`` unless explicitly approved by a maintainer).
5. High-risk Python primitive checks via AST in ``wardr/``, ``packaging/``,
   and ``scripts/`` (``eval``, ``exec``, builtin ``compile``, ``__import__``,
   ``pickle.load(s)``, ``marshal.load(s)``, ``os.system``, ``os.popen``,
   ``subprocess.*(..., shell=True)``).
6. PR risk-tier classification (Tier 0 Lockdown / Tier 1 Security Core /
   Tier 2 Fast Lane), binary file alerts, newly added network/process
   primitive alerts, and large-diff alerts.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import html.parser
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Risk-tier path rules (kept in sync with .github/CODEOWNERS)
# ---------------------------------------------------------------------------
TIER_0_PATTERNS = (
    ".github/*",
    ".github/**",
    "scripts/*",
    "scripts/**",
    "wardr/keys/*",
    "wardr/keys/**",
    "packaging/*",
    "packaging/**",
    "deploy/*",
    "deploy/**",
    "render.yaml",
    "pyproject.toml",
    "MANIFEST.in",
    "desktop/Cargo.toml",
    "desktop/Cargo.lock",
    "desktop/build.rs",
    "wardr/updater.py",
    "wardr/update_session.py",
    "wardr/release.py",
)

TIER_1_PATTERNS = (
    "wardr/server.py",
    "wardr/oauth_broker.py",
    "wardr/account.py",
    "wardr/remediation.py",
    "wardr/actions.py",
    "wardr/fleet.py",
    "wardr/fleet_agent.py",
    "wardr/pentest.py",
    "wardr/service.py",
    "wardr/threat_network.py",
    "wardr/local_ai.py",
    "wardr/supply_chain.py",
    "desktop/src/*",
    "desktop/src/**",
    "SECURITY.md",
    "PRIVACY.md",
    "TERMS.md",
    "CONTRIBUTING.md",
    "LICENSE",
)

# Directories scanned for text / code invariants in repo mode
REPO_SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".html",
    ".css",
    ".rs",
    ".toml",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".md",
    ".json",
    ".txt",
}

SKIP_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "build",
    "target",
    "wardr.egg-info",
    ".wardr-ci",
}

# Invisible / bidirectional / tag Unicode codepoints associated with
# Trojan Source (CVE-2021-42574) or hidden prompt injection.
DANGEROUS_CODEPOINTS: set[int] = (
    set(range(0x202A, 0x202F))  # LRE, RLE, PDF, LRO, RLO
    | set(range(0x2066, 0x206A))  # LRI, RLI, FSI, PDI
    | {0x200E, 0x200F, 0x061C}  # LRM, RLM, ALM
    | {0x200B, 0x200C, 0x200D, 0x2060}  # ZWSP, ZWNJ, ZWJ, WORD JOINER
    | set(range(0xE0000, 0xE0080))  # Unicode Tag characters
)

ALLOWED_RUNTIME_DEPENDENCY_NAMES = {"cryptography"}

ACTION_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"#\s]+)['\"]?")
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")
DEP_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")

# Patterns flagged as review alerts (non-blocking) when newly added in diffs
DIFF_ALERT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("subprocess usage", re.compile(r"\bsubprocess\.")),
    ("network client", re.compile(r"\b(?:urllib\.request|http\.client|socket\.create_connection|socket\.socket)\b")),
    ("ctypes FFI", re.compile(r"\bctypes\b")),
    ("dynamic base64 decode", re.compile(r"\bbase64\.b64decode\b")),
    ("webbrowser launch", re.compile(r"\bwebbrowser\.open\b")),
)


@dataclass
class Finding:
    severity: str  # "error" or "warning"
    category: str
    path: str
    message: str
    line: int | None = None

    def format_line(self) -> str:
        loc = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"- **{self.category}** (`{loc}`): {self.message}"


@dataclass
class GuardReport:
    mode: str
    risk_tier: str = "Tier 2 (Fast Lane)"
    changed_files: list[str] = field(default_factory=list)
    tier0_files: list[str] = field(default_factory=list)
    tier1_files: list[str] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)
    added_lines: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    def to_markdown(self) -> str:
        status = "FAILED" if self.errors else ("REVIEW ALERTS" if self.warnings else "PASSED")
        lines = [
            f"## Wardr PR Security Guard — {status}",
            "",
            f"- **Mode:** `{self.mode}`",
            f"- **Risk Tier:** **{self.risk_tier}**",
        ]
        if self.mode == "diff":
            lines.append(
                f"- **Changed Files:** {len(self.changed_files)} (+{self.added_lines} added lines)"
            )
            if self.tier0_files:
                lines.append(
                    "- **Tier 0 (Lockdown) paths touched:** "
                    + ", ".join(f"`{p}`" for p in self.tier0_files)
                )
            if self.tier1_files:
                lines.append(
                    "- **Tier 1 (Security Core) paths touched:** "
                    + ", ".join(f"`{p}`" for p in self.tier1_files)
                )
            if self.binary_files:
                lines.append(
                    "- **Binary files touched:** "
                    + ", ".join(f"`{p}`" for p in self.binary_files)
                )

        lines.append("")
        if self.errors:
            lines.append(f"### Blocking Findings ({len(self.errors)})")
            lines.extend(f.format_line() for f in self.errors)
            lines.append("")
        else:
            lines.append("### Blocking Findings (0)")
            lines.append("- None.")
            lines.append("")

        if self.warnings:
            lines.append(f"### Reviewer Alerts ({len(self.warnings)})")
            lines.extend(f.format_line() for f in self.warnings)
            lines.append("")

        return "\n".join(lines)


def _matches_any(rel_path: str, patterns: tuple[str, ...]) -> bool:
    norm = rel_path.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, pat) for pat in patterns)


def classify_paths(paths: list[str]) -> tuple[str, list[str], list[str]]:
    tier0 = sorted(p for p in paths if _matches_any(p, TIER_0_PATTERNS))
    tier1 = sorted(
        p for p in paths if p not in tier0 and _matches_any(p, TIER_1_PATTERNS)
    )
    if tier0:
        tier = "Tier 0 (Lockdown — Maintainer Deep Audit Required)"
    elif tier1:
        tier = "Tier 1 (Security Core — Security Invariant Review Required)"
    else:
        tier = "Tier 2 (Fast Lane)"
    return tier, tier0, tier1


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------
def check_unicode_text(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line, start=1):
            cp = ord(ch)
            # Allow UTF-8 BOM only at very start of line 1
            if cp == 0xFEFF and (lineno > 1 or col > 1):
                findings.append(
                    Finding(
                        severity="error",
                        category="hidden-unicode",
                        path=rel_path,
                        line=lineno,
                        message=f"Unexpected BOM/zero-width char U+{cp:04X} at column {col}",
                    )
                )
            elif cp in DANGEROUS_CODEPOINTS:
                findings.append(
                    Finding(
                        severity="error",
                        category="hidden-unicode",
                        path=rel_path,
                        line=lineno,
                        message=f"Forbidden invisible/bidi/tag Unicode character U+{cp:04X} at column {col}",
                    )
                )
    return findings


class _CSPHtmlScanner(html.parser.HTMLParser):
    def __init__(self, rel_path: str) -> None:
        super().__init__(convert_charrefs=False)
        self.rel_path = rel_path
        self.findings: list[Finding] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        line, _ = self.getpos()
        attr_map = {k.lower(): v for k, v in attrs}

        if tag_l == "script" and "src" not in attr_map:
            self.findings.append(
                Finding(
                    severity="error",
                    category="csp-violation",
                    path=self.rel_path,
                    line=line,
                    message="Inline <script> tag without `src` attribute violates strict CSP.",
                )
            )
        if tag_l == "style":
            self.findings.append(
                Finding(
                    severity="error",
                    category="csp-violation",
                    path=self.rel_path,
                    line=line,
                    message="Inline <style> tag violates strict CSP.",
                )
            )
        for name in attr_map:
            if name == "style":
                self.findings.append(
                    Finding(
                        severity="error",
                        category="csp-violation",
                        path=self.rel_path,
                        line=line,
                        message="Inline `style=` attribute violates strict CSP.",
                    )
                )
            elif name.startswith("on") and len(name) > 2:
                self.findings.append(
                    Finding(
                        severity="error",
                        category="csp-violation",
                        path=self.rel_path,
                        line=line,
                        message=f"Inline event handler `{name}=` violates strict CSP.",
                    )
                )


def check_html_csp(rel_path: str, text: str) -> list[Finding]:
    parser = _CSPHtmlScanner(rel_path)
    parser.feed(text)
    parser.close()
    return parser.findings


def check_workflow_security(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0]
        if re.search(r"\bpull_request_target\b", stripped):
            findings.append(
                Finding(
                    severity="error",
                    category="workflow-security",
                    path=rel_path,
                    line=lineno,
                    message="`pull_request_target` is prohibited; use `pull_request` with least-privilege permissions.",
                )
            )
        match = ACTION_USES_RE.match(line)
        if match:
            ref = match.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if "@" not in ref:
                findings.append(
                    Finding(
                        severity="error",
                        category="workflow-pinning",
                        path=rel_path,
                        line=lineno,
                        message=f"Action `{ref}` is missing a commit SHA pin.",
                    )
                )
                continue
            _, version = ref.rsplit("@", 1)
            if not SHA_PIN_RE.match(version):
                findings.append(
                    Finding(
                        severity="error",
                        category="workflow-pinning",
                        path=rel_path,
                        line=lineno,
                        message=f"Action `{ref}` must be pinned to a full 40-character commit SHA.",
                    )
                )
    return findings


def check_pyproject_dependencies(
    rel_path: str, text: str, allow_dependency_change: bool = False
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [
            Finding(
                severity="error",
                category="pyproject-parse",
                path=rel_path,
                message=f"Invalid TOML in pyproject.toml: {exc}",
            )
        ]

    deps = data.get("project", {}).get("dependencies", [])
    dep_names: set[str] = set()
    for spec in deps:
        match = DEP_NAME_RE.match(str(spec))
        if match:
            dep_names.add(match.group(1).lower())

    extra = sorted(dep_names - ALLOWED_RUNTIME_DEPENDENCY_NAMES)
    if extra and not allow_dependency_change:
        findings.append(
            Finding(
                severity="error",
                category="dependency-policy",
                path=rel_path,
                message=(
                    f"Unauthorized Python runtime dependency added: {', '.join(extra)}. "
                    "Wardr requires maintainer pre-approval (`approved-dependency` label) "
                    "before expanding beyond `cryptography`."
                ),
            )
        )
    elif extra and allow_dependency_change:
        findings.append(
            Finding(
                severity="warning",
                category="dependency-policy",
                path=rel_path,
                message=(
                    f"Extra Python runtime dependency present ({', '.join(extra)}); "
                    "allowed via maintainer override."
                ),
            )
        )
    return findings


def check_python_ast(rel_path: str, text: str) -> list[Finding]:
    """Check Python source for high-risk execution/deserialization primitives."""
    findings: list[Finding] = []
    try:
        tree = ast.parse(text, filename=rel_path)
    except SyntaxError as exc:
        return [
            Finding(
                severity="error",
                category="python-syntax",
                path=rel_path,
                line=exc.lineno,
                message=f"SyntaxError: {exc.msg}",
            )
        ]

    # Track aliases for dangerous modules/functions (e.g. `from pickle import loads as p`)
    module_aliases: dict[str, str] = {}
    func_aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                module_aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                func_aliases[local] = f"{node.module}.{alias.name}"

    forbidden_builtins = {"eval", "exec", "compile", "__import__"}
    forbidden_qualified = {
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
        "builtins.__import__",
        "os.system",
        "os.popen",
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        resolved: str | None = None
        if isinstance(fn, ast.Name):
            if fn.id in func_aliases:
                resolved = func_aliases[fn.id]
            elif fn.id in forbidden_builtins:
                resolved = f"builtins.{fn.id}"
        elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            base_mod = module_aliases.get(fn.value.id, fn.value.id)
            resolved = f"{base_mod}.{fn.attr}"

        if resolved in forbidden_qualified:
            findings.append(
                Finding(
                    severity="error",
                    category="forbidden-primitive",
                    path=rel_path,
                    line=node.lineno,
                    message=f"Forbidden high-risk Python call `{resolved}(...)`.",
                )
            )

        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                findings.append(
                    Finding(
                        severity="error",
                        category="shell-injection-risk",
                        path=rel_path,
                        line=node.lineno,
                        message="Found `shell=True` in call; pass an explicit argument list instead.",
                    )
                )

    return findings


def _is_binary_bytes(raw: bytes) -> bool:
    return b"\x00" in raw[:8192]


def _should_ast_check(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    if not norm.endswith(".py"):
        return False
    return (
        norm.startswith("wardr/")
        or norm.startswith("packaging/")
        or norm.startswith("scripts/")
    )


def scan_file(
    repo_root: Path, rel_path: str, *, allow_dependency_change: bool = False
) -> tuple[list[Finding], bool]:
    """Scan a single file on disk. Returns (findings, is_binary)."""
    full_path = repo_root / rel_path
    if not full_path.is_file():
        return [], False

    raw = full_path.read_bytes()
    if _is_binary_bytes(raw):
        return [], True

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], True

    findings: list[Finding] = []
    norm = rel_path.replace("\\", "/")

    findings.extend(check_unicode_text(norm, text))

    if norm.startswith("wardr/static/") and norm.endswith(".html"):
        findings.extend(check_html_csp(norm, text))

    if norm.startswith(".github/workflows/") and norm.endswith((".yml", ".yaml")):
        findings.extend(check_workflow_security(norm, text))

    if norm == "pyproject.toml":
        findings.extend(
            check_pyproject_dependencies(
                norm, text, allow_dependency_change=allow_dependency_change
            )
        )

    if _should_ast_check(norm):
        findings.extend(check_python_ast(norm, text))

    return findings, False


# ---------------------------------------------------------------------------
# Repo & Diff runners
# ---------------------------------------------------------------------------
def _iter_repo_files(repo_root: Path) -> list[str]:
    result: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(repo_root).as_posix()
            if full.suffix.lower() in REPO_SCAN_EXTENSIONS or rel == "pyproject.toml":
                result.append(rel)
    return result


def run_repo_scan(
    repo_root: Path, *, allow_dependency_change: bool = False
) -> GuardReport:
    report = GuardReport(mode="repo")
    for rel_path in _iter_repo_files(repo_root):
        findings, _ = scan_file(
            repo_root, rel_path, allow_dependency_change=allow_dependency_change
        )
        report.findings.extend(findings)
    return report


def _git_output(repo_root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _scan_added_diff_lines(diff_text: str) -> tuple[int, list[Finding]]:
    added_count = 0
    findings: list[Finding] = []
    current_file: str | None = None
    current_line = 0
    seen_alerts: set[tuple[str, str]] = set()

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        if raw_line.startswith("@@ "):
            match = re.search(r"\+(\d+)", raw_line)
            current_line = int(match.group(1)) if match else 0
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_count += 1
            code = raw_line[1:]
            if current_file and current_file.startswith("wardr/") and current_file.endswith(".py"):
                for label, pattern in DIFF_ALERT_PATTERNS:
                    if pattern.search(code):
                        key = (current_file, label)
                        if key not in seen_alerts:
                            seen_alerts.add(key)
                            findings.append(
                                Finding(
                                    severity="warning",
                                    category="sensitive-api-added",
                                    path=current_file,
                                    line=current_line or None,
                                    message=f"Newly added {label} in core package — verify offline/Zero-RCE invariants.",
                                )
                            )
            current_line += 1
        elif not raw_line.startswith("-"):
            current_line += 1

    return added_count, findings


def run_diff_scan(
    repo_root: Path,
    base: str,
    head: str,
    *,
    allow_dependency_change: bool = False,
) -> GuardReport:
    report = GuardReport(mode="diff")
    diff_range = f"{base}...{head}"

    changed_raw = _git_output(
        repo_root, ["diff", "--name-only", "--diff-filter=ACMR", diff_range]
    )
    changed_files = [line.strip() for line in changed_raw.splitlines() if line.strip()]
    report.changed_files = changed_files
    report.risk_tier, report.tier0_files, report.tier1_files = classify_paths(changed_files)

    for rel_path in changed_files:
        findings, is_binary = scan_file(
            repo_root, rel_path, allow_dependency_change=allow_dependency_change
        )
        report.findings.extend(findings)
        if is_binary:
            report.binary_files.append(rel_path)
            report.findings.append(
                Finding(
                    severity="warning",
                    category="binary-file-changed",
                    path=rel_path,
                    message="Binary file added or modified; inspect provenance carefully (XZ-style payload check).",
                )
            )

    if report.tier0_files:
        report.findings.append(
            Finding(
                severity="warning",
                category="tier-0-touched",
                path=report.tier0_files[0],
                message=(
                    f"Touches {len(report.tier0_files)} Tier 0 Lockdown file(s). "
                    "Requires line-by-line maintainer audit."
                ),
            )
        )

    diff_text = _git_output(repo_root, ["diff", "--unified=0", diff_range])
    added_lines, diff_warnings = _scan_added_diff_lines(diff_text)
    report.added_lines = added_lines
    report.findings.extend(diff_warnings)

    if added_lines > 800 or len(changed_files) > 15:
        report.findings.append(
            Finding(
                severity="warning",
                category="large-pr",
                path=".",
                message=(
                    f"Large diff ({len(changed_files)} files, +{added_lines} lines). "
                    "Consider splitting into smaller, focused PRs for faster review."
                ),
            )
        )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Wardr PR & repo security guard")
    parser.add_argument(
        "--mode",
        choices=("repo", "diff"),
        default="repo",
        help="Scan the whole repository or a git diff range.",
    )
    parser.add_argument("--base", help="Base git ref/SHA (required for --mode diff).")
    parser.add_argument(
        "--head", default="HEAD", help="Head git ref/SHA (for --mode diff)."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Repository root directory.",
    )
    parser.add_argument(
        "--allow-dependency-change",
        action="store_true",
        help="Allow extra runtime dependencies in pyproject.toml (maintainer label override).",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        help="Optional path to append the Markdown triage summary (e.g. $GITHUB_STEP_SUMMARY).",
    )
    args = parser.parse_args(argv)

    if args.mode == "diff":
        if not args.base:
            parser.error("--base is required when --mode diff is used.")
        report = run_diff_scan(
            args.repo_root,
            args.base,
            args.head,
            allow_dependency_change=args.allow_dependency_change,
        )
    else:
        report = run_repo_scan(
            args.repo_root,
            allow_dependency_change=args.allow_dependency_change,
        )

    markdown = report.to_markdown()
    print(markdown)

    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        with args.summary_out.open("a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")

    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
