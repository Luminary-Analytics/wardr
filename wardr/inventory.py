"""Fast, incremental local software inventory (CycloneDX) and AI/credential surface checks."""

from datetime import datetime, timezone
import hashlib
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import tempfile
from urllib.parse import quote


_MAX_COMPONENTS = 15_000
_MAX_DPKG_BYTES = 32 * 1024 * 1024
_MAX_APK_BYTES = 16 * 1024 * 1024
_MAX_CONFIG_BYTES = 512 * 1024
_CACHE_FILE = "inventory-cache.json"

_AI_PORTS = {
    11434: ("Ollama", True),
    1234: ("LM Studio", True),
    8188: ("ComfyUI", True),
    7860: ("Gradio / local AI UI", False),
    8000: ("vLLM / local API", False),
}
_AI_PROCESS_HINTS = ("ollama", "lmstudio", "vllm", "llama", "comfy", "open-webui", "mcp")

_SECRET_PATTERNS = (
    ("OpenAI / API key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{15,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
)
_PINNED_NPM = re.compile(r"^(@[^/]+/)?[^@]+@[0-9]")
_PINNED_PY = re.compile(r"^[A-Za-z0-9._-]+==[0-9]")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _purl_quote(segment: str) -> str:
    return quote(segment, safe="._-")


def _distro_id() -> str:
    try:
        release = platform.freedesktop_os_release()
        distro = str(release.get("ID") or "").strip().lower()
        if distro in ("debian", "ubuntu", "alpine"):
            return distro
    except OSError:
        pass
    return "debian"


def _collect_python_packages() -> tuple[list[dict], str]:
    items = []
    seen = set()
    try:
        for dist in importlib_metadata.distributions():
            name = (dist.metadata.get("Name") or "").strip()
            version = (dist.version or "").strip()
            if not name or not version:
                continue
            normalized = re.sub(r"[-_.]+", "-", name).lower()
            key = (normalized, version)
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "type": "library",
                "name": normalized,
                "version": version,
                "purl": f"pkg:pypi/{_purl_quote(normalized)}@{_purl_quote(version)}",
            })
            if len(items) >= _MAX_COMPONENTS:
                break
    except Exception:
        return [], "unavailable"
    return items, f"python ({len(items)})"


def _collect_homebrew_packages(cellars: tuple[Path, ...] | None = None) -> tuple[list[dict], str, str]:
    roots = cellars or (Path("/opt/homebrew/Cellar"), Path("/usr/local/Cellar"))
    items = []
    fingerprints = []
    for root in roots:
        try:
            root_stat = root.stat()
            if not stat.S_ISDIR(root_stat.st_mode):
                continue
            fingerprints.append(f"{root}:{root_stat.st_mtime_ns}")
            with os.scandir(root) as packages:
                for entry in packages:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        with os.scandir(entry.path) as versions:
                            for ver in versions:
                                if ver.is_dir(follow_symlinks=False) and not ver.name.startswith("."):
                                    name = entry.name
                                    version = ver.name
                                    items.append({
                                        "type": "application",
                                        "name": name,
                                        "version": version,
                                        "purl": f"pkg:brew/{_purl_quote(name)}@{_purl_quote(version)}",
                                    })
                    except OSError:
                        continue
                    if len(items) >= _MAX_COMPONENTS:
                        break
        except OSError:
            continue
    return items, (f"homebrew ({len(items)})" if items else ""), "|".join(fingerprints)


def _collect_dpkg_packages(status_path: Path = Path("/var/lib/dpkg/status")) -> tuple[list[dict], str, str]:
    try:
        info = status_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_DPKG_BYTES:
            return [], "", ""
        raw = status_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "", ""

    distro = _distro_id()
    items = []
    pkg = version = status_val = None
    for line in (*raw.splitlines(), ""):
        if not line.strip():
            if pkg and version and status_val == "install ok installed":
                items.append({
                    "type": "library",
                    "name": pkg,
                    "version": version,
                    "purl": f"pkg:deb/{distro}/{_purl_quote(pkg)}@{_purl_quote(version)}",
                })
                if len(items) >= _MAX_COMPONENTS:
                    break
            pkg = version = status_val = None
        elif line.startswith("Package:"):
            pkg = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Status:"):
            status_val = line.split(":", 1)[1].strip()
    fp = f"dpkg:{info.st_mtime_ns}:{info.st_size}"
    return items, (f"dpkg ({len(items)})" if items else ""), fp


def _collect_apk_packages(db_path: Path = Path("/lib/apk/db/installed")) -> tuple[list[dict], str, str]:
    try:
        info = db_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_APK_BYTES:
            return [], "", ""
        raw = db_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "", ""

    items = []
    pkg = version = None
    for line in (*raw.splitlines(), ""):
        if not line.strip():
            if pkg and version:
                items.append({
                    "type": "library",
                    "name": pkg,
                    "version": version,
                    "purl": f"pkg:apk/alpine/{_purl_quote(pkg)}@{_purl_quote(version)}",
                })
                if len(items) >= _MAX_COMPONENTS:
                    break
            pkg = version = None
        elif line.startswith("P:"):
            pkg = line[2:].strip()
        elif line.startswith("V:"):
            version = line[2:].strip()
    fp = f"apk:{info.st_mtime_ns}:{info.st_size}"
    return items, (f"apk ({len(items)})" if items else ""), fp


def _source_fingerprint(cellars: tuple[Path, ...] | None = None, dpkg_path: Path | None = None, apk_path: Path | None = None) -> str:
    parts = [platform.system(), platform.python_version()]
    for root in (cellars or (Path("/opt/homebrew/Cellar"), Path("/usr/local/Cellar"))):
        try:
            st = root.stat()
            parts.append(f"{root}:{st.st_mtime_ns}")
        except OSError:
            pass
    for path in (dpkg_path or Path("/var/lib/dpkg/status"), apk_path or Path("/lib/apk/db/installed")):
        try:
            st = path.stat()
            parts.append(f"{path}:{st.st_mtime_ns}:{st.st_size}")
        except OSError:
            pass
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def collect_inventory(
    state_dir: Path | None = None,
    *,
    include_python: bool = True,
    force: bool = False,
    cellars: tuple[Path, ...] | None = None,
    dpkg_path: Path | None = None,
    apk_path: Path | None = None,
) -> dict:
    """Fast, incremental local software inventory returning a CycloneDX 1.5 SBOM + summary."""
    fingerprint = _source_fingerprint(cellars=cellars, dpkg_path=dpkg_path, apk_path=apk_path)
    cache_path = Path(state_dir) / _CACHE_FILE if state_dir is not None else None
    if cache_path is not None and not force:
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if (
                isinstance(cached, dict)
                and cached.get("fingerprint") == fingerprint
                and isinstance(cached.get("sbom"), dict)
                and isinstance(cached.get("sources"), list)
            ):
                return {**cached, "cached": True}
        except (OSError, ValueError):
            pass

    components = []
    sources = []
    if include_python:
        py_items, py_label = _collect_python_packages()
        components.extend(py_items)
        if py_label:
            sources.append(py_label)

    brew_items, brew_label, _ = _collect_homebrew_packages(cellars=cellars)
    components.extend(brew_items)
    if brew_label:
        sources.append(brew_label)

    dpkg_items, dpkg_label, _ = _collect_dpkg_packages(dpkg_path or Path("/var/lib/dpkg/status"))
    components.extend(dpkg_items)
    if dpkg_label:
        sources.append(dpkg_label)

    apk_items, apk_label, _ = _collect_apk_packages(apk_path or Path("/lib/apk/db/installed"))
    components.extend(apk_items)
    if apk_label:
        sources.append(apk_label)

    # Deduplicate by purl while keeping deterministic ordering.
    unique = {}
    for item in components:
        unique.setdefault(item["purl"], item)
    deduped = [unique[key] for key in sorted(unique)][:_MAX_COMPONENTS]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _utc_now(),
            "tools": [{"vendor": "Wardr", "name": "wardr-inventory"}],
        },
        "components": deduped,
    }
    result = {
        "collected_at": _utc_now(),
        "fingerprint": fingerprint,
        "cached": False,
        "component_count": len(deduped),
        "sources": sources,
        "sbom": sbom,
    }
    if cache_path is not None:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, tmp_name = tempfile.mkstemp(dir=cache_path.parent, prefix=".inv-", suffix=".json")
            tmp_path = Path(tmp_name)
            try:
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(result, handle, ensure_ascii=False)
                tmp_path.replace(cache_path)
            finally:
                tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return result


def _user_home(home: Path | None = None) -> Path | None:
    if home is not None:
        return Path(home)
    if os.name == "posix":
        import pwd
        try:
            resolved = Path(pwd.getpwuid(os.geteuid()).pw_dir)
            return resolved if resolved.is_absolute() and resolved != Path("/") else None
        except KeyError:
            return None
    return Path.home()


def _safe_read_user_json(path: Path) -> dict | None:
    try:
        flags = os.O_RDONLY
        if os.name == "posix":
            flags |= os.O_NOFOLLOW | os.O_NONBLOCK
        else:
            flags |= os.O_BINARY
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            if os.name == "posix" and info.st_uid != os.geteuid():
                return None
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return None
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except (OSError, ValueError, RecursionError):
        return None


def _mcp_config_candidates(home: Path) -> list[tuple[str, Path]]:
    candidates = [
        ("~/.claude.json", home / ".claude.json"),
        ("~/.cursor/mcp.json", home / ".cursor" / "mcp.json"),
        ("~/.codeium/windsurf/mcp_config.json", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("~/.gemini/antigravity/mcp_config.json", home / ".gemini" / "antigravity" / "mcp_config.json"),
    ]
    if platform.system() == "Darwin":
        candidates.append((
            "Claude Desktop config",
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ))
    else:
        candidates.append((
            "~/.config/Claude/claude_desktop_config.json",
            home / ".config" / "Claude" / "claude_desktop_config.json",
        ))
    return candidates


def _walk_strings(value, prefix: str = "", depth: int = 0):
    if depth > 10:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            key_name = str(key)[:64]
            next_prefix = f"{prefix}.{key_name}" if prefix else key_name
            yield from _walk_strings(item, next_prefix, depth + 1)
    elif isinstance(value, list):
        for idx, item in enumerate(value[:64]):
            yield from _walk_strings(item, f"{prefix}[{idx}]", depth + 1)
    elif isinstance(value, str):
        yield prefix, value


def _check_mcp_servers(label: str, doc: dict) -> list[str]:
    unpinned = []
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        return unpinned
    for server_name, cfg in list(servers.items())[:64]:
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command") or "").strip().lower()
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        str_args = [str(a).strip() for a in args[:16]]
        if cmd in ("npx", "npx.cmd"):
            pkg_args = [a for a in str_args if a and not a.startswith("-")]
            if pkg_args and not _PINNED_NPM.match(pkg_args[0]):
                unpinned.append(f"{label}:{server_name} (npx {pkg_args[0]})")
        elif cmd in ("uvx", "uvx.exe"):
            pkg_args = [a for a in str_args if a and not a.startswith("-")]
            if pkg_args and not _PINNED_PY.match(pkg_args[0]):
                unpinned.append(f"{label}:{server_name} (uvx {pkg_args[0]})")
    return unpinned


def check_exposed_ai_endpoints(exposure_result: dict) -> dict:
    """Inspect a local exposure snapshot for non-loopback AI inference/agent listeners."""
    exposed_ai = []
    for row in exposure_result.get("listeners", ()):
        if row.get("scope") not in ("wildcard", "interface"):
            continue
        port = row.get("port")
        proc = str(row.get("process") or "").lower()
        port_info = _AI_PORTS.get(port)
        is_ai_proc = any(hint in proc for hint in _AI_PROCESS_HINTS)
        if (port_info and (port_info[1] or is_ai_proc)) or is_ai_proc:
            service = port_info[0] if port_info else (row.get("process") or "Local AI service")
            exposed_ai.append(f"{service} on {row.get('address')}:{port} ({row.get('scope')})")
    if exposed_ai:
        return {
            "id": "ai-exposed-endpoints",
            "title": "Local AI inference & agent port exposure",
            "category": "AI Security",
            "severity": "high",
            "status": "fail",
            "evidence": f"Detected {len(exposed_ai)} non-loopback local AI service binding(s): {', '.join(exposed_ai[:4])}.",
            "risk": "Local AI servers such as Ollama or LM Studio typically lack authentication; network exposure allows remote abuse or data theft.",
            "remediation": "Bind local AI services strictly to 127.0.0.1 (for example OLLAMA_HOST=127.0.0.1:11434) and block the port in your host firewall.",
            "can_fix": False,
            "references": [],
        }
    return {
        "id": "ai-exposed-endpoints",
        "title": "Local AI inference & agent port exposure",
        "category": "AI Security",
        "severity": "high",
        "status": "pass",
        "evidence": "No local AI inference servers were observed listening on non-loopback network interfaces.",
        "risk": "Local AI servers such as Ollama or LM Studio typically lack authentication; network exposure allows remote abuse or data theft.",
        "remediation": "Keep local AI services bound to 127.0.0.1.",
        "can_fix": False,
        "references": [],
    }


def scan_ai_surface(*, home: Path | None = None, exposure_result: dict | None = None) -> list[dict]:
    """Audit local AI/MCP configurations and exposed local AI inference sockets."""
    findings = []
    resolved_home = _user_home(home)
    secret_hits = []
    unpinned_hits = []
    configs_found = 0

    if resolved_home is not None:
        for label, path in _mcp_config_candidates(resolved_home):
            doc = _safe_read_user_json(path)
            if doc is None:
                continue
            configs_found += 1
            for field_path, text in _walk_strings(doc):
                for kind, pattern in _SECRET_PATTERNS:
                    if pattern.search(text):
                        secret_hits.append(f"{label} ({field_path}: {kind})")
                        break
            unpinned_hits.extend(_check_mcp_servers(label, doc))

    if configs_found == 0:
        findings.append({
            "id": "ai-mcp-secrets",
            "title": "Local AI & MCP credential hygiene",
            "category": "AI Security",
            "severity": "high",
            "status": "not_applicable",
            "evidence": "No local MCP or AI assistant JSON configurations were found in standard user paths.",
            "risk": "Plaintext API keys in local AI tool configs can be exfiltrated by local malware or prompt-injected agents.",
            "remediation": "Store AI and tool API keys in your OS keychain or short-lived environment brokers rather than static JSON files.",
            "can_fix": False,
            "references": [],
        })
        findings.append({
            "id": "ai-mcp-unpinned",
            "title": "MCP server package pinning",
            "category": "AI Security",
            "severity": "medium",
            "status": "not_applicable",
            "evidence": "No local MCP server configurations were found in standard user paths.",
            "risk": "Unpinned npx or uvx MCP servers fetch mutable remote packages on launch, creating a silent supply-chain execution risk.",
            "remediation": "Pin every MCP server package to an exact audited version (for example pkg@1.2.3 or pkg==1.2.3).",
            "can_fix": False,
            "references": [],
        })
    else:
        if secret_hits:
            summary = ", ".join(secret_hits[:4])
            if len(secret_hits) > 4:
                summary += f", and {len(secret_hits) - 4} more"
            findings.append({
                "id": "ai-mcp-secrets",
                "title": "Local AI & MCP credential hygiene",
                "category": "AI Security",
                "severity": "high",
                "status": "fail",
                "evidence": f"Detected {len(secret_hits)} plaintext credential pattern(s) in local AI/MCP configs: {summary}.",
                "risk": "Plaintext API keys in local AI tool configs can be exfiltrated by local malware or prompt-injected agents.",
                "remediation": "Move these keys into your OS keychain or a secrets manager, rotate exposed keys, and restrict config file permissions.",
                "can_fix": False,
                "references": [],
            })
        else:
            findings.append({
                "id": "ai-mcp-secrets",
                "title": "Local AI & MCP credential hygiene",
                "category": "AI Security",
                "severity": "high",
                "status": "pass",
                "evidence": f"Inspected {configs_found} local AI/MCP configuration file(s); no known plaintext API key patterns were detected.",
                "risk": "Plaintext API keys in local AI tool configs can be exfiltrated by local malware or prompt-injected agents.",
                "remediation": "Continue storing credentials in your OS keychain instead of static JSON configs.",
                "can_fix": False,
                "references": [],
            })

        if unpinned_hits:
            summary = ", ".join(unpinned_hits[:4])
            if len(unpinned_hits) > 4:
                summary += f", and {len(unpinned_hits) - 4} more"
            findings.append({
                "id": "ai-mcp-unpinned",
                "title": "MCP server package pinning",
                "category": "AI Security",
                "severity": "medium",
                "status": "fail",
                "evidence": f"Found {len(unpinned_hits)} unpinned dynamic MCP package invocation(s): {summary}.",
                "risk": "Unpinned npx or uvx MCP servers fetch mutable remote packages on launch, creating a silent supply-chain execution risk.",
                "remediation": "Pin each MCP server command to an exact audited version (for example @scope/server@1.2.3).",
                "can_fix": False,
                "references": [],
            })
        else:
            findings.append({
                "id": "ai-mcp-unpinned",
                "title": "MCP server package pinning",
                "category": "AI Security",
                "severity": "medium",
                "status": "pass",
                "evidence": f"Inspected {configs_found} local AI/MCP configuration file(s); no unpinned npx/uvx server launchers were found.",
                "risk": "Unpinned npx or uvx MCP servers fetch mutable remote packages on launch, creating a silent supply-chain execution risk.",
                "remediation": "Keep MCP server dependencies pinned to explicit versions.",
                "can_fix": False,
                "references": [],
            })

    # Optional exposed AI server port check when exposure data is available.
    if exposure_result is not None:
        findings.append(check_exposed_ai_endpoints(exposure_result))

    return findings
