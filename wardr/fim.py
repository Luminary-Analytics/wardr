"""Lightweight, bounded File Integrity Monitoring (FIM) for critical security configs."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import tempfile


_BASELINE_FILE = "fim-baseline.json"
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TARGETS = 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_targets(home: Path | None = None) -> list[tuple[str, Path]]:
    """Return high-value security configuration paths for the current platform."""
    resolved_home = Path(home) if home is not None else Path.home()
    if platform.system() == "Windows":
        sys_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
        return [
            ("Windows hosts file", sys_root / "System32" / "drivers" / "etc" / "hosts"),
            ("~/.cursor/mcp.json", resolved_home / ".cursor" / "mcp.json"),
            ("~/.claude.json", resolved_home / ".claude.json"),
        ]
    return [
        ("/etc/ssh/sshd_config", Path("/etc/ssh/sshd_config")),
        ("/etc/hosts", Path("/etc/hosts")),
        ("~/.ssh/authorized_keys", resolved_home / ".ssh" / "authorized_keys"),
        ("~/.ssh/config", resolved_home / ".ssh" / "config"),
        ("~/.zshrc", resolved_home / ".zshrc"),
        ("~/.bashrc", resolved_home / ".bashrc"),
        ("~/.profile", resolved_home / ".profile"),
        ("~/.cursor/mcp.json", resolved_home / ".cursor" / "mcp.json"),
        ("~/.claude.json", resolved_home / ".claude.json"),
    ]


def _hash_regular_file(path: Path) -> dict | None:
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
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_FILE_BYTES:
                return None
            digest = hashlib.sha256()
            remaining = _MAX_FILE_BYTES
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            return {
                "sha256": digest.hexdigest(),
                "size": info.st_size,
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            }
    except OSError:
        return None


def _snapshot(targets: list[tuple[str, Path]]) -> dict[str, dict]:
    records = {}
    for label, path in targets[:_MAX_TARGETS]:
        hashed = _hash_regular_file(path)
        if hashed is not None:
            records[label] = {"path": str(path), **hashed}
    return records


def _save_baseline(state_dir: Path, doc: dict) -> None:
    path = Path(state_dir) / _BASELINE_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".fim-", suffix=".json")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_baseline(state_dir: Path) -> dict | None:
    path = Path(state_dir) / _BASELINE_FILE
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict) and parsed.get("schema_version") == 1 and isinstance(parsed.get("files"), dict):
            return parsed
    except (OSError, ValueError):
        pass
    return None


def init_baseline(state_dir: Path, *, targets: list[tuple[str, Path]] | None = None) -> dict:
    """Capture and save a fresh SHA-256 baseline of critical local security configs."""
    resolved_targets = default_targets() if targets is None else targets
    files = _snapshot(resolved_targets)
    doc = {
        "schema_version": 1,
        "initialized_at": _utc_now(),
        "files": files,
    }
    _save_baseline(state_dir, doc)
    return {
        "status": "initialized",
        "initialized_at": doc["initialized_at"],
        "tracked_count": len(files),
        "tracked": sorted(files.keys()),
    }


def check_integrity(
    state_dir: Path,
    *,
    targets: list[tuple[str, Path]] | None = None,
    auto_init: bool = True,
) -> dict:
    """Compare critical security config files against the saved SHA-256 baseline."""
    resolved_targets = default_targets() if targets is None else targets
    baseline = _load_baseline(state_dir)
    now = _utc_now()
    if baseline is None:
        if not auto_init:
            return {
                "status": "uninitialized",
                "checked_at": now,
                "tracked_count": 0,
                "changes": [],
            }
        init_result = init_baseline(state_dir, targets=resolved_targets)
        return {
            "status": "pass",
            "initialized_at": init_result["initialized_at"],
            "checked_at": now,
            "tracked_count": init_result["tracked_count"],
            "changes": [],
            "note": f"Initialized integrity baseline for {init_result['tracked_count']} security configuration file(s).",
        }

    expected_files = baseline["files"]
    current_files = _snapshot(resolved_targets)
    changes = []

    for label, expected in sorted(expected_files.items()):
        observed = current_files.get(label)
        if observed is None:
            changes.append({
                "label": label,
                "change": "removed_or_unreadable",
                "previous_sha256": expected["sha256"][:16],
                "current_sha256": None,
            })
        elif observed["sha256"] != expected["sha256"]:
            changes.append({
                "label": label,
                "change": "modified",
                "previous_sha256": expected["sha256"][:16],
                "current_sha256": observed["sha256"][:16],
            })
        elif observed["mode"] != expected.get("mode"):
            changes.append({
                "label": label,
                "change": "permissions_changed",
                "previous_mode": expected.get("mode"),
                "current_mode": observed["mode"],
            })

    for label, observed in sorted(current_files.items()):
        if label not in expected_files:
            changes.append({
                "label": label,
                "change": "added",
                "previous_sha256": None,
                "current_sha256": observed["sha256"][:16],
            })

    return {
        "status": "fail" if changes else "pass",
        "initialized_at": baseline.get("initialized_at"),
        "checked_at": now,
        "tracked_count": len(expected_files),
        "changes": changes,
        "note": (
            f"Detected {len(changes)} unexpected integrity change(s) since {baseline.get('initialized_at')}."
            if changes else f"All {len(expected_files)} tracked security configuration file(s) match the saved SHA-256 baseline."
        ),
    }
