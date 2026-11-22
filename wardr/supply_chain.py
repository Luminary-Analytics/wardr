"""Local supply-chain, compromised npm package, and high-impact exploit (React2Shell, PHP2Shell, Log4Shell) scanner."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time


_MAX_MANIFESTS = 250
_MAX_DEPTH = 4
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_PHP_FILES = 120
_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".nuxt", ".svelte-kit", "out", "target",
    "vendor", "Pods", ".gradle", ".idea", ".cache", "Library", "Applications",
})

# Known compromised npm packages: name -> (set of compromised versions or None for ALL versions, severity, advisory/title, remediation)
COMPROMISED_NPM_PACKAGES: dict[str, tuple[frozenset[str] | None, str, str, str]] = {
    "flatmap-stream": (None, "critical", "Compromised npm package (event-stream trojan)", "Remove flatmap-stream immediately, rotate credentials/wallets, and upgrade event-stream."),
    "peacenotwar": (None, "critical", "Sabotage payload package (node-ipc supply-chain incident)", "Remove peacenotwar immediately and pin node-ipc to a safe version."),
    "event-stream": (frozenset({"3.3.6"}), "critical", "Compromised event-stream@3.3.6 backdoor", "Upgrade or replace event-stream and audit lockfiles."),
    "ua-parser-js": (frozenset({"0.7.29", "0.8.0", "1.0.0"}), "critical", "Compromised ua-parser-js (cryptominer & password stealer)", "Upgrade ua-parser-js to >=0.7.30 / >=0.8.1 / >=1.0.1 and rotate local credentials."),
    "coa": (frozenset({"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"}), "critical", "Compromised coa npm release (credential stealer)", "Downgrade/pin coa to 2.0.2 and rotate secrets."),
    "rc": (frozenset({"1.2.9", "1.3.9", "2.3.9"}), "critical", "Compromised rc npm release (credential stealer)", "Pin rc to 1.2.8 and rotate secrets."),
    "node-ipc": (frozenset({"10.1.1", "10.1.2", "10.1.3", "11.0.0"}), "critical", "Sabotaged node-ipc release (destructive file overwrite payload)", "Pin node-ipc to 9.2.1 or >=10.1.4."),
    "colors": (frozenset({"1.4.1", "1.4.2", "1.4.44-liberty-2"}), "high", "Sabotaged colors release (infinite-loop DoS)", "Pin colors to 1.4.0 or migrate to picocolors."),
    "faker": (frozenset({"6.6.6"}), "high", "Sabotaged faker@6.6.6 release", "Migrate to @faker-js/faker."),
    "@lottiefiles/lottie-player": (frozenset({"2.0.5", "2.0.6", "2.0.7"}), "critical", "Compromised @lottiefiles/lottie-player (drainer injection)", "Upgrade immediately to >=2.0.8 and clear CDN/browser caches."),
    "eslint-config-prettier": (frozenset({"8.10.1", "9.1.1", "10.1.6", "10.1.7"}), "critical", "Compromised eslint-config-prettier (2025 npm supply-chain attack)", "Update eslint-config-prettier to a clean release and rotate npm/GitHub/cloud tokens."),
    "eslint-plugin-prettier": (frozenset({"4.2.2", "4.2.3"}), "critical", "Compromised eslint-plugin-prettier (2025 npm supply-chain attack)", "Update eslint-plugin-prettier and rotate tokens."),
    "synckit": (frozenset({"0.11.9"}), "critical", "Compromised synckit@0.11.9 (2025 npm supply-chain attack)", "Upgrade synckit to >=0.11.11 and rotate tokens."),
    "nx": (frozenset({"20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"}), "critical", "Compromised Nx release (s1ngularity AI/credential stealer)", "Upgrade Nx to a clean patched version immediately and rotate all GitHub/npm/AI/SSH credentials."),
    "chalk": (frozenset({"5.6.1"}), "critical", "Compromised chalk@5.6.1 (Sept 2025 npm phishing compromise)", "Pin chalk to 5.6.0 or >=5.6.2 and rebuild lockfiles."),
    "debug": (frozenset({"4.4.2"}), "critical", "Compromised debug@4.4.2 (Sept 2025 npm phishing compromise)", "Pin debug to 4.4.1 or >=4.4.3 and rebuild lockfiles."),
    "ansi-styles": (frozenset({"6.2.2"}), "critical", "Compromised ansi-styles@6.2.2 (Sept 2025 npm compromise)", "Pin ansi-styles to 6.2.1 or >=6.2.3."),
    "strip-ansi": (frozenset({"7.1.1"}), "critical", "Compromised strip-ansi@7.1.1 (Sept 2025 npm compromise)", "Pin strip-ansi to 7.1.0 or >=7.1.2."),
    "color-convert": (frozenset({"3.1.1"}), "critical", "Compromised color-convert@3.1.1 (Sept 2025 npm compromise)", "Pin color-convert to 3.1.0 or >=3.1.2."),
    "color-name": (frozenset({"2.0.1"}), "critical", "Compromised color-name@2.0.1 (Sept 2025 npm compromise)", "Pin color-name to 2.0.0 or >=2.0.2."),
    "supports-color": (frozenset({"10.2.1"}), "critical", "Compromised supports-color@10.2.1 (Sept 2025 npm compromise)", "Pin supports-color to 10.2.0 or >=10.2.2."),
    "wrap-ansi": (frozenset({"9.0.1"}), "critical", "Compromised wrap-ansi@9.0.1 (Sept 2025 npm compromise)", "Pin wrap-ansi to 9.0.0 or >=9.0.2."),
    "ansi-regex": (frozenset({"6.2.1"}), "critical", "Compromised ansi-regex@6.2.1 (Sept 2025 npm compromise)", "Pin ansi-regex to 6.2.0 or >=6.2.2."),
    "slice-ansi": (frozenset({"7.1.1"}), "critical", "Compromised slice-ansi@7.1.1 (Sept 2025 npm compromise)", "Pin slice-ansi to 7.1.0 or >=7.1.2."),
    "error-ex": (frozenset({"1.3.3"}), "critical", "Compromised error-ex@1.3.3 (Sept 2025 npm compromise)", "Pin error-ex to 1.3.2 or >=1.3.4."),
    "simple-swizzle": (frozenset({"0.2.3"}), "critical", "Compromised simple-swizzle@0.2.3 (Sept 2025 npm compromise)", "Pin simple-swizzle to 0.2.2 or >=0.2.4."),
    "has-ansi": (frozenset({"6.0.1"}), "critical", "Compromised has-ansi@6.0.1 (Sept 2025 npm compromise)", "Pin has-ansi to 6.0.0 or >=6.0.2."),
    "backslash": (frozenset({"0.2.1"}), "critical", "Compromised backslash@0.2.1 (Sept 2025 npm compromise)", "Pin backslash to 0.2.0 or >=0.2.2."),
    "chalk-template": (frozenset({"1.1.1"}), "critical", "Compromised chalk-template@1.1.1 (Sept 2025 npm compromise)", "Pin chalk-template to 1.1.0 or >=1.1.2."),
    "is-arrayish": (frozenset({"0.3.3"}), "critical", "Compromised is-arrayish@0.3.3 (Sept 2025 npm compromise)", "Pin is-arrayish to 0.3.2 or >=0.3.4."),
    "@ctrl/tinycolor": (frozenset({"4.1.1", "4.1.2"}), "critical", "Compromised @ctrl/tinycolor (Shai-Hulud npm worm)", "Pin @ctrl/tinycolor to 4.1.0 or clean release and rotate all tokens."),
    "angulartics2": (frozenset({"14.1.2"}), "critical", "Compromised angulartics2@14.1.2 (Shai-Hulud npm worm)", "Pin angulartics2 to a clean version and rotate tokens."),
    "ngx-toastr": (frozenset({"19.0.2"}), "critical", "Compromised ngx-toastr@19.0.2 (Shai-Hulud npm worm)", "Pin ngx-toastr to a clean version and rotate tokens."),
}

_REACT2SHELL_PACKAGES = frozenset({
    "react-server-dom-webpack",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
})
_REACT2SHELL_VERSIONS = frozenset({"19.0.0", "19.1.0", "19.1.1", "19.2.0"})

_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")
_SUSPICIOUS_SCRIPT_PATTERNS = (
    (re.compile(r"\b(?:curl|wget)\b[^\n|]{0,180}\|\s*(?:ba|z|da)?sh\b", re.I), "Remote script piped directly to shell in npm lifecycle hook"),
    (re.compile(r"\beval\s*\(\s*Buffer\.from\s*\(", re.I), "Obfuscated base64 Buffer.from eval payload in npm lifecycle hook"),
    (re.compile(r"\bpowershell(?:\.exe)?\b[^\n]{0,120}-(?:e|enc|encodedcommand)\b", re.I), "Encoded PowerShell execution in npm lifecycle hook"),
    (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|]{0,120}\|\s*(?:ba|z|da)?sh\b", re.I), "Base64-decoded shell payload in npm lifecycle hook"),
    (re.compile(r"/dev/tcp/[0-9a-zA-Z.-]+/[0-9]+", re.I), "Reverse shell connection attempt in npm lifecycle hook"),
)

_PHP_WEBSHELL_PATTERNS = (
    (re.compile(r"\b(?:eval|assert)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\b", re.I), "PHP remote code execution webshell pattern (eval/assert on user input)"),
    (re.compile(r"\b(?:system|shell_exec|passthru|exec|popen)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\b", re.I), "PHP command-injection webshell pattern (OS shell on user input)"),
    (re.compile(r"\beval\s*\(\s*(?:gzinflate|gzuncompress|str_rot13)?\s*\(?\s*base64_decode\s*\(", re.I), "Obfuscated PHP base64/eval backdoor payload"),
)

_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_LOG4J_POM_RE = re.compile(r"<artifactId>\s*log4j-core\s*</artifactId>.*?<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>", re.S)
_LOG4J_GRADLE_RE = re.compile(r"org\.apache\.logging\.log4j:log4j-core:([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
_POLYFILL_RE = re.compile(r"https?://cdn\.polyfill\.io/", re.I)


def _tilde(path: Path) -> str:
    try:
        return f"~/{path.relative_to(Path.home()).as_posix()}"
    except ValueError:
        return str(path)


def _read_safe_text(path: Path, limit: int = _MAX_FILE_BYTES) -> str | None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read(limit).decode("utf-8", errors="ignore")
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _parse_semver(raw: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.search(str(raw or ""))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _is_next_react2shell_vulnerable(ver: tuple[int, int, int]) -> bool:
    major, minor, patch = ver
    if major == 15:
        if minor == 0:
            return patch <= 4
        if minor == 1:
            return patch <= 8
        if minor == 2:
            return patch <= 5
        if minor == 3:
            return patch <= 5
        if minor == 4:
            return patch <= 7
        if minor == 5:
            return patch <= 6
    if major == 16 and minor == 0:
        return patch <= 6
    return False


def _is_next_middleware_bypass_vulnerable(ver: tuple[int, int, int]) -> bool:
    major, minor, patch = ver
    if 11 <= major <= 13:
        return True
    if major == 14:
        return (minor, patch) < (2, 25)
    if major == 15:
        return (minor, patch) < (2, 3)
    return False


def _is_php_cve_2024_4577_vulnerable(ver: tuple[int, int, int]) -> bool:
    major, minor, patch = ver
    if major < 8 or (major == 8 and minor == 0):
        return True
    if major == 8 and minor == 1:
        return patch < 29
    if major == 8 and minor == 2:
        return patch < 20
    if major == 8 and minor == 3:
        return patch < 8
    return False


def _evaluate_npm_package(name: str, raw_version: str, location: str, findings: list[dict], seen: set[tuple[str, str, str]]) -> None:
    clean_name = name.strip()
    ver_tuple = _parse_semver(raw_version)
    exact_ver = f"{ver_tuple[0]}.{ver_tuple[1]}.{ver_tuple[2]}" if ver_tuple else str(raw_version or "").lstrip("^~>=< ")

    # 1. Known compromised npm packages
    spec = COMPROMISED_NPM_PACKAGES.get(clean_name)
    if spec is not None:
        bad_versions, severity, title, remediation = spec
        if bad_versions is None or exact_ver in bad_versions or str(raw_version).strip() in bad_versions:
            key = ("compromised-npm", f"{clean_name}@{exact_ver}", location)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "id": f"npm-{clean_name}-{exact_ver}",
                    "kind": "compromised_npm",
                    "severity": severity,
                    "title": f"{title}: {clean_name}@{exact_ver}",
                    "package": clean_name,
                    "version": exact_ver,
                    "location": location,
                    "cve": "SUPPLY-CHAIN",
                    "mitre": "T1195.002",
                    "plain_summary": f"A known malicious or hijacked npm package ({clean_name}@{exact_ver}) was found in {location}.",
                    "remediation": remediation,
                })

    # 2. React2Shell (CVE-2025-55182 / CVE-2025-66478)
    if clean_name in _REACT2SHELL_PACKAGES and exact_ver in _REACT2SHELL_VERSIONS:
        key = ("react2shell", f"{clean_name}@{exact_ver}", location)
        if key not in seen:
            seen.add(key)
            findings.append({
                "id": f"react2shell-{clean_name}-{exact_ver}",
                "kind": "framework_rce",
                "severity": "critical",
                "title": f"React2Shell RCE (CVE-2025-55182): {clean_name}@{exact_ver}",
                "package": clean_name,
                "version": exact_ver,
                "location": location,
                "cve": "CVE-2025-55182",
                "mitre": "T1190",
                "plain_summary": f"Critical unauthenticated remote code execution vulnerability (React2Shell) in {clean_name}@{exact_ver} at {location}.",
                "remediation": "Upgrade React Server DOM packages immediately to 19.0.1, 19.1.2, or 19.2.1+ and redeploy.",
            })

    if clean_name == "next" and ver_tuple is not None:
        if _is_next_react2shell_vulnerable(ver_tuple):
            key = ("react2shell-next", f"next@{exact_ver}", location)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "id": f"react2shell-next-{exact_ver}",
                    "kind": "framework_rce",
                    "severity": "critical",
                    "title": f"Next.js React2Shell RCE (CVE-2025-55182 / CVE-2025-66478): next@{exact_ver}",
                    "package": "next",
                    "version": exact_ver,
                    "location": location,
                    "cve": "CVE-2025-55182",
                    "mitre": "T1190",
                    "plain_summary": f"Next.js {exact_ver} in {location} is vulnerable to React2Shell unauthenticated remote code execution.",
                    "remediation": "Upgrade Next.js immediately to the latest patched 15.x / 16.0.7+ release and rotate runtime secrets.",
                })
        elif _is_next_middleware_bypass_vulnerable(ver_tuple):
            key = ("next-middleware", f"next@{exact_ver}", location)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "id": f"next-mw-{exact_ver}",
                    "kind": "framework_rce",
                    "severity": "high",
                    "title": f"Next.js Middleware Auth Bypass (CVE-2025-29927): next@{exact_ver}",
                    "package": "next",
                    "version": exact_ver,
                    "location": location,
                    "cve": "CVE-2025-29927",
                    "mitre": "T1190",
                    "plain_summary": f"Next.js {exact_ver} in {location} allows attackers to bypass middleware authorization checks.",
                    "remediation": "Upgrade Next.js to >=14.2.25 or >=15.2.3.",
                })


def _scan_package_json(path: Path, findings: list[dict], seen: set[tuple[str, str, str]]) -> int:
    text = _read_safe_text(path)
    if not text:
        return 0
    try:
        doc = json.loads(text)
    except ValueError:
        return 0
    if not isinstance(doc, dict):
        return 0
    loc = _tilde(path)
    pkg_count = 0
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if isinstance(name, str) and isinstance(ver, str):
                pkg_count += 1
                _evaluate_npm_package(name, ver, loc, findings, seen)

    scripts = doc.get("scripts")
    if isinstance(scripts, dict):
        for hook in _LIFECYCLE_HOOKS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            for pattern, desc in _SUSPICIOUS_SCRIPT_PATTERNS:
                if pattern.search(cmd):
                    key = ("npm-hook", hook, loc)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "id": f"npm-hook-{hook}-{abs(hash(loc)) % 100000}",
                            "kind": "malicious_script",
                            "severity": "critical",
                            "title": f"Suspicious npm `{hook}` lifecycle script in {loc}",
                            "package": str(doc.get("name") or path.parent.name),
                            "version": str(doc.get("version") or "local"),
                            "location": loc,
                            "cve": "SUPPLY-CHAIN",
                            "mitre": "T1059",
                            "plain_summary": f"{desc}. Command snippet: {cmd[:140]}",
                            "remediation": f"Inspect {loc} immediately before running npm install, and run with --ignore-scripts if untrusted.",
                        })
                    break
    return pkg_count


def _scan_package_lock(path: Path, findings: list[dict], seen: set[tuple[str, str, str]]) -> int:
    text = _read_safe_text(path)
    if not text:
        return 0
    try:
        doc = json.loads(text)
    except ValueError:
        return 0
    if not isinstance(doc, dict):
        return 0
    loc = _tilde(path)
    count = 0
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if not isinstance(ver, str):
                continue
            name = meta.get("name")
            if not isinstance(name, str) and "node_modules/" in pkg_path:
                name = pkg_path.rsplit("node_modules/", 1)[-1]
            if isinstance(name, str) and name:
                count += 1
                _evaluate_npm_package(name, ver, loc, findings, seen)
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if isinstance(name, str) and isinstance(meta, dict) and isinstance(meta.get("version"), str):
                count += 1
                _evaluate_npm_package(name, meta["version"], loc, findings, seen)
    return count


def _scan_php_runtime(findings: list[dict], seen: set[tuple[str, str, str]]) -> dict:
    php_bin = shutil.which("php")
    if not php_bin:
        return {"installed": False, "version": None}
    try:
        proc = subprocess.run([php_bin, "-v"], capture_output=True, text=True, timeout=3, check=False)
        first = (proc.stdout or proc.stderr or "").splitlines()[0] if (proc.stdout or proc.stderr) else ""
    except (OSError, subprocess.SubprocessError):
        return {"installed": True, "version": "unknown"}
    ver = _parse_semver(first)
    ver_str = f"{ver[0]}.{ver[1]}.{ver[2]}" if ver else first[:40]
    if ver and _is_php_cve_2024_4577_vulnerable(ver):
        key = ("php2shell", ver_str, php_bin)
        if key not in seen:
            seen.add(key)
            findings.append({
                "id": f"php2shell-{ver_str}",
                "kind": "framework_rce",
                "severity": "critical",
                "title": f"PHP-CGI / PHP2Shell Vulnerable Runtime (CVE-2024-4577): PHP {ver_str}",
                "package": "php",
                "version": ver_str,
                "location": php_bin,
                "cve": "CVE-2024-4577",
                "mitre": "T1190",
                "plain_summary": f"Installed PHP runtime ({ver_str}) is older than the security fix for PHP-CGI argument injection / PHP2Shell (CVE-2024-4577).",
                "remediation": "Upgrade PHP immediately to >=8.1.29, >=8.2.20, or >=8.3.8+ (or uninstall PHP if unused).",
            })
    return {"installed": True, "version": ver_str}


def _scan_php_file(path: Path, findings: list[dict], seen: set[tuple[str, str, str]]) -> None:
    text = _read_safe_text(path, limit=256 * 1024)
    if not text:
        return
    loc = _tilde(path)
    for pattern, desc in _PHP_WEBSHELL_PATTERNS:
        if pattern.search(text):
            key = ("php-webshell", desc, loc)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "id": f"php-shell-{abs(hash(loc)) % 100000}",
                    "kind": "php_webshell",
                    "severity": "critical",
                    "title": f"Potential PHP webshell / remote code execution in {loc}",
                    "package": path.parent.name,
                    "version": "local",
                    "location": loc,
                    "cve": "PHP-WEBSHELL",
                    "mitre": "T1505.003",
                    "plain_summary": f"{desc} detected in {loc}.",
                    "remediation": f"Inspect {loc} immediately; remove unauthorized webshell code and rotate server credentials.",
                })
            break


def _scan_java_manifest(path: Path, findings: list[dict], seen: set[tuple[str, str, str]]) -> None:
    text = _read_safe_text(path, limit=512 * 1024)
    if not text:
        return
    loc = _tilde(path)
    matches = _LOG4J_POM_RE.findall(text) if path.name == "pom.xml" else _LOG4J_GRADLE_RE.findall(text)
    for raw_ver in matches:
        ver = _parse_semver(raw_ver)
        if ver and ver[0] == 2 and (ver[1], ver[2]) < (15, 0):
            key = ("log4shell", raw_ver, loc)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "id": f"log4shell-{raw_ver}",
                    "kind": "framework_rce",
                    "severity": "critical",
                    "title": f"Log4Shell RCE (CVE-2021-44228): log4j-core {raw_ver}",
                    "package": "log4j-core",
                    "version": raw_ver,
                    "location": loc,
                    "cve": "CVE-2021-44228",
                    "mitre": "T1190",
                    "plain_summary": f"Vulnerable Apache Log4j ({raw_ver}) detected in {loc}.",
                    "remediation": "Upgrade log4j-core immediately to >=2.17.1.",
                })


def _scan_polyfill_reference(path: Path, findings: list[dict], seen: set[tuple[str, str, str]]) -> None:
    text = _read_safe_text(path, limit=256 * 1024)
    if not text or "polyfill.io" not in text.lower():
        return
    if _POLYFILL_RE.search(text):
        loc = _tilde(path)
        key = ("polyfill-io", loc, loc)
        if key not in seen:
            seen.add(key)
            findings.append({
                "id": f"polyfill-{abs(hash(loc)) % 100000}",
                "kind": "compromised_cdn",
                "severity": "high",
                "title": f"Compromised cdn.polyfill.io reference in {loc}",
                "package": "polyfill.io",
                "version": "cdn",
                "location": loc,
                "cve": "SUPPLY-CHAIN",
                "mitre": "T1195.002",
                "plain_summary": f"{loc} loads JavaScript from cdn.polyfill.io, a hijacked supply-chain domain known to inject malware.",
                "remediation": "Remove cdn.polyfill.io immediately or replace with Cloudflare's cdnjs.cloudflare.com/polyfill/.",
            })


def default_scan_roots() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Repos",
        home / "Projects",
        home / "Code",
        home / "Developer",
        home / "src",
        home / "workspace",
        Path.cwd(),
    ]
    roots: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            roots.append(resolved)
    return roots


def scan_supply_chain(roots: list[Path] | None = None) -> dict:
    """Scan local repositories, lockfiles, and runtimes for compromised packages and critical RCEs."""
    started = time.monotonic()
    target_roots = [Path(p).expanduser().resolve() for p in roots] if roots else default_scan_roots()
    target_roots = [p for p in target_roots if p.is_dir()]

    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    manifests_scanned = 0
    packages_checked = 0
    repos_detected = 0
    php_files_checked = 0
    scanned_root_labels = [_tilde(r) for r in target_roots]

    php_runtime = _scan_php_runtime(findings, seen)

    for root in target_roots:
        root_depth = len(root.parts)
        for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            cur_path = Path(current)
            depth = len(cur_path.parts) - root_depth
            if ".git" in dirnames:
                repos_detected += 1
            dirnames[:] = [
                d for d in dirnames
                if d not in _SKIP_DIRS and not d.startswith(".") and depth < _MAX_DEPTH
            ]
            if manifests_scanned >= _MAX_MANIFESTS:
                break
            for fname in filenames:
                if manifests_scanned >= _MAX_MANIFESTS:
                    break
                fpath = cur_path / fname
                if fname == "package.json":
                    manifests_scanned += 1
                    packages_checked += _scan_package_json(fpath, findings, seen)
                elif fname == "package-lock.json":
                    manifests_scanned += 1
                    packages_checked += _scan_package_lock(fpath, findings, seen)
                elif fname in ("pom.xml", "build.gradle", "build.gradle.kts"):
                    manifests_scanned += 1
                    _scan_java_manifest(fpath, findings, seen)
                elif fname in ("index.html", "layout.tsx", "layout.jsx", "_document.tsx", "_document.js"):
                    _scan_polyfill_reference(fpath, findings, seen)
                elif fname.endswith(".php") and php_files_checked < _MAX_PHP_FILES:
                    php_files_checked += 1
                    _scan_php_file(fpath, findings, seen)

    # Also check global npm modules if installed
    for global_npm in (Path("/opt/homebrew/lib/node_modules"), Path("/usr/local/lib/node_modules")):
        if not global_npm.is_dir():
            continue
        try:
            for entry in list(global_npm.iterdir())[:80]:
                pkg_json = entry / "package.json"
                if pkg_json.is_file():
                    manifests_scanned += 1
                    text = _read_safe_text(pkg_json, limit=256 * 1024)
                    if text:
                        try:
                            meta = json.loads(text)
                            if isinstance(meta, dict) and isinstance(meta.get("name"), str) and isinstance(meta.get("version"), str):
                                packages_checked += 1
                                _evaluate_npm_package(meta["name"], meta["version"], _tilde(pkg_json), findings, seen)
                        except ValueError:
                            pass
        except OSError:
            pass

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_rank.get(f["severity"], 4), f["title"]))
    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "roots": scanned_root_labels,
        "repos_detected": repos_detected,
        "manifests_scanned": manifests_scanned,
        "packages_checked": packages_checked,
        "php_runtime": php_runtime,
        "signatures_count": len(COMPROMISED_NPM_PACKAGES) + 5,
        "status": "exposed" if (critical or high) else ("warning" if findings else "clean"),
        "critical_count": critical,
        "high_count": high,
        "total_findings": len(findings),
        "findings": findings[:100],
    }
