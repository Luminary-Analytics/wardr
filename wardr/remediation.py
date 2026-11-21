"""Transactional, allowlisted one-click remediation with dry-run preview and rollback."""

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import platform
import stat
import tempfile
import uuid


_HISTORY_FILE = "remediation-history.json"
_MAX_HISTORY = 50
_MAX_HISTORY_BYTES = 256 * 1024

# Allowlisted POSIX credential-permission rules (directory or files under user's home).
_CREDENTIAL_SPECS = {
    "aws-credentials-permissions": {
        "kind": "files",
        "dir": ".aws",
        "files": ("credentials", "config"),
        "mask": 0o077,
        "title": "AWS CLI credential file permissions",
        "category": "Credentials",
        "severity": "high",
        "risk": "Readable AWS credentials or config files can let other local accounts hijack cloud access.",
        "remediation": "Remove group and other permissions from ~/.aws/credentials and ~/.aws/config.",
        "effect": "Remove group and other permissions from affected ~/.aws credential files.",
    },
    "kube-config-permissions": {
        "kind": "files",
        "dir": ".kube",
        "files": ("config",),
        "mask": 0o077,
        "title": "Kubernetes config permissions",
        "category": "Credentials",
        "severity": "high",
        "risk": "Group- or world-readable ~/.kube/config files can expose cluster bearer tokens and client keys.",
        "remediation": "Remove group and other permissions from ~/.kube/config.",
        "effect": "Remove group and other permissions from ~/.kube/config.",
    },
    "gnupg-directory-permissions": {
        "kind": "dir",
        "dir": ".gnupg",
        "files": (),
        "mask": 0o077,
        "title": "GnuPG directory permissions",
        "category": "Credentials",
        "severity": "medium",
        "risk": "Broad permissions on ~/.gnupg can expose private GPG keyrings or let other local accounts tamper with trust settings.",
        "remediation": "Remove group and other permissions from ~/.gnupg.",
        "effect": "Remove group and other permissions from ~/.gnupg.",
    },
    "docker-config-permissions": {
        "kind": "files",
        "dir": ".docker",
        "files": ("config.json",),
        "mask": 0o077,
        "title": "Docker registry credential permissions",
        "category": "Credentials",
        "severity": "medium",
        "risk": "Readable ~/.docker/config.json files can expose registry authentication tokens to other local accounts.",
        "remediation": "Remove group and other permissions from ~/.docker/config.json.",
        "effect": "Remove group and other permissions from ~/.docker/config.json.",
    },
}

_SSH_SPECS = {
    "ssh-directory-permissions": {"kind": "dir", "dir": ".ssh", "files": (), "mask": 0o077},
    "ssh-identity-permissions": {
        "kind": "files",
        "dir": ".ssh",
        "files": ("id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_mldsa44_ed25519"),
        "mask": 0o077,
    },
    "ssh-authorized-keys-permissions": {
        "kind": "files",
        "dir": ".ssh",
        "files": ("authorized_keys", "authorized_keys2"),
        "mask": 0o022,
    },
}

ALL_FIX_IDS = frozenset((*_SSH_SPECS.keys(), *_CREDENTIAL_SPECS.keys()))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _can_repair_posix() -> bool:
    return os.name == "posix" and platform.system() in ("Darwin", "Linux") and os.geteuid() != 0 and os.geteuid() == os.getuid()


def _account_home() -> Path:
    import pwd
    uid = os.geteuid()
    home = Path(pwd.getpwuid(uid).pw_dir)
    if not home.is_absolute() or home == Path("/"):
        raise PermissionError("Account home is unavailable")
    return home


def _acl_absent(fd: int) -> bool:
    if platform.system() == "Linux":
        try:
            os.getxattr(fd, "system.posix_acl_access")
        except AttributeError:
            return False
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                return False
        else:
            return False
        try:
            return not any("acl" in name or name == "system.cifs_ntsd" for name in os.listxattr(fd))
        except (AttributeError, OSError):
            return False
    if platform.system() == "Darwin":
        import ctypes
        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.acl_get_fd.argtypes = [ctypes.c_int]
            libc.acl_get_fd.restype = ctypes.c_void_p
            libc.acl_free.argtypes = [ctypes.c_void_p]
            ctypes.set_errno(0)
            acl = libc.acl_get_fd(fd)
            if not acl:
                return ctypes.get_errno() == errno.ENOENT
            libc.acl_free(acl)
        except (AttributeError, OSError):
            pass
    return False


@contextmanager
def _open_owned_dir(rel_dir: str):
    uid = os.geteuid()
    target = _account_home() / rel_dir
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(target, flags)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid:
            raise PermissionError("Directory ownership does not match the process user")
        yield fd, info
    finally:
        os.close(fd)


def _require_reg_file(info, reference):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or (info.st_dev, info.st_ino) != (reference.st_dev, reference.st_ino)
    ):
        raise PermissionError("Target file is unsupported or changed")


@contextmanager
def _open_owned_files(rel_dir: str, names: tuple[str, ...]):
    with _open_owned_dir(rel_dir) as (dir_fd, dir_info), ExitStack() as stack:
        files, skipped = [], []
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        for name in names:
            try:
                expected = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                skipped.append(name)
                continue
            try:
                _require_reg_file(expected, expected)
                fd = os.open(name, flags, dir_fd=dir_fd)
                stack.callback(os.close, fd)
                observed = os.fstat(fd)
                _require_reg_file(observed, expected)
            except OSError:
                skipped.append(name)
            else:
                files.append((name, fd, observed))
        yield dir_fd, dir_info, files, skipped


def _credential_check(check_id: str) -> dict:
    spec = _CREDENTIAL_SPECS[check_id]
    mask = spec["mask"]
    rel_dir = spec["dir"]
    status, evidence, can_fix = "unknown", f"Wardr could not safely inspect ~/{rel_dir}.", False
    try:
        if spec["kind"] == "dir":
            with _open_owned_dir(rel_dir) as (fd, info):
                mode = stat.S_IMODE(info.st_mode)
                no_acl = _acl_absent(fd)
                evidence = f"The current account's ~/{rel_dir} directory has POSIX mode {mode:04o}."
                if mode & mask:
                    status = "fail"
                    can_fix = no_acl and _can_repair_posix()
                else:
                    status = "pass" if no_acl else "unknown"
                if not no_acl:
                    evidence += " Review extended directory permissions manually."
        else:
            with _open_owned_files(rel_dir, spec["files"]) as (dir_fd, dir_info, files, skipped):
                dir_mode = stat.S_IMODE(dir_info.st_mode)
                weak = [f"~/{rel_dir}/{name} ({stat.S_IMODE(info.st_mode):04o})" for name, _, info in files if info.st_mode & mask]
                unverified = sorted(skipped + [name for name, fd, _ in files if not _acl_absent(fd)])
                if weak:
                    status = "fail"
                    evidence = f"Permissions require attention on {', '.join(weak)}."
                    can_fix = (not unverified and not (dir_mode & 0o022) and _can_repair_posix() and _acl_absent(dir_fd))
                    if not can_fix:
                        evidence += " Automatic repair requires a private directory owned by you and files without extended ACLs."
                elif files:
                    status = "pass"
                    evidence = f"The inspected files in ~/{rel_dir} use private POSIX permissions."
                if unverified:
                    if not weak:
                        status = "unknown"
                        evidence = f"Permissions could not be fully verified for ~/{rel_dir}."
                    evidence += f" Review {', '.join(unverified)} manually."
                elif not files:
                    status = "not_applicable"
                    evidence = f"No target credential files were found in ~/{rel_dir}."
    except FileNotFoundError:
        status = "not_applicable"
        evidence = f"No ~/{rel_dir} directory was found for the process account."
    except (OSError, KeyError):
        pass

    finding = {
        "id": check_id,
        "title": spec["title"],
        "category": spec["category"],
        "severity": spec["severity"],
        "status": status,
        "evidence": evidence,
        "risk": spec["risk"],
        "remediation": spec["remediation"],
        "can_fix": can_fix,
        "references": [],
    }
    if can_fix:
        finding["fix_description"] = spec["effect"]
    return finding


def credential_checks() -> list[dict]:
    """Return read-only posture findings for sensitive user credential locations."""
    if os.name != "posix" or platform.system() not in ("Darwin", "Linux"):
        return []
    return [_credential_check(check_id) for check_id in _CREDENTIAL_SPECS]


def _spec_for(check_id: str) -> dict | None:
    if check_id in _SSH_SPECS:
        return _SSH_SPECS[check_id]
    if check_id in _CREDENTIAL_SPECS:
        return _CREDENTIAL_SPECS[check_id]
    return None


def preview_fix(check_id: str) -> dict:
    """Return a read-only dry-run diff preview of the exact permission changes Wardr would make."""
    spec = _spec_for(check_id)
    if spec is None or not _can_repair_posix():
        return {
            "id": check_id,
            "eligible": False,
            "reversible": False,
            "changes": [],
            "message": "No automatic fix preview is available for this check on this account.",
        }
    mask = spec["mask"]
    rel_dir = spec["dir"]
    changes = []
    try:
        if spec["kind"] == "dir":
            with _open_owned_dir(rel_dir) as (fd, info):
                if not _acl_absent(fd):
                    return {
                        "id": check_id,
                        "eligible": False,
                        "reversible": False,
                        "changes": [],
                        "message": f"~/{rel_dir} has extended ACLs and requires manual review.",
                    }
                mode = stat.S_IMODE(info.st_mode)
                target_mode = mode & ~mask
                if mode != target_mode:
                    changes.append({
                        "target": f"~/{rel_dir}",
                        "current_mode": f"{mode:04o}",
                        "target_mode": f"{target_mode:04o}",
                    })
        else:
            with _open_owned_files(rel_dir, spec["files"]) as (dir_fd, dir_info, files, skipped):
                if skipped or (stat.S_IMODE(dir_info.st_mode) & 0o022) or not _acl_absent(dir_fd):
                    return {
                        "id": check_id,
                        "eligible": False,
                        "reversible": False,
                        "changes": [],
                        "message": f"~/{rel_dir} or one of its files requires manual review before automatic repair.",
                    }
                for name, fd, info in files:
                    if not _acl_absent(fd):
                        return {
                            "id": check_id,
                            "eligible": False,
                            "reversible": False,
                            "changes": [],
                            "message": f"~/{rel_dir}/{name} has extended ACLs and requires manual review.",
                        }
                    mode = stat.S_IMODE(info.st_mode)
                    target_mode = mode & ~mask
                    if mode != target_mode:
                        changes.append({
                            "target": f"~/{rel_dir}/{name}",
                            "current_mode": f"{mode:04o}",
                            "target_mode": f"{target_mode:04o}",
                        })
    except (OSError, KeyError):
        return {
            "id": check_id,
            "eligible": False,
            "reversible": False,
            "changes": [],
            "message": f"Wardr could not inspect ~/{rel_dir} safely.",
        }

    return {
        "id": check_id,
        "eligible": bool(changes),
        "reversible": bool(changes),
        "changes": changes,
        "message": (
            f"Will tighten POSIX permissions on {len(changes)} target(s) with automatic rollback snapshot."
            if changes else "Permissions already satisfy this check."
        ),
    }


def _load_history(state_dir: Path | None) -> list[dict]:
    if state_dir is None:
        return []
    path = Path(state_dir) / _HISTORY_FILE
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_HISTORY_BYTES:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [row for row in parsed if isinstance(row, dict)][:_MAX_HISTORY]
    except (OSError, ValueError):
        pass
    return []


def _save_history(state_dir: Path | None, entries: list[dict]) -> None:
    if state_dir is None:
        return
    path = Path(state_dir) / _HISTORY_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".rem-", suffix=".json")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(entries[:_MAX_HISTORY], handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def list_history(state_dir: Path) -> list[dict]:
    """Return recent remediation records with rollback eligibility."""
    return [
        {
            "rollback_id": row.get("rollback_id"),
            "check_id": row.get("check_id"),
            "applied_at": row.get("applied_at"),
            "restored_at": row.get("restored_at"),
            "can_undo": row.get("restored_at") is None and bool(row.get("targets")),
            "changes": [
                {
                    "target": t.get("label"),
                    "previous_mode": f"{t['old_mode']:04o}",
                    "applied_mode": f"{t['new_mode']:04o}",
                }
                for t in row.get("targets", ())
                if isinstance(t, dict) and isinstance(t.get("old_mode"), int) and isinstance(t.get("new_mode"), int)
            ],
        }
        for row in _load_history(state_dir)
    ]


def _recheck(check_id: str) -> dict | None:
    if check_id in _CREDENTIAL_SPECS:
        return _credential_check(check_id)
    from . import checks
    if check_id == "ssh-directory-permissions":
        return checks._ssh_check()
    if check_id in checks._SSH_FILE_CHECKS:
        return checks._ssh_file_check(check_id)
    return None


def apply_fix(check_id: str, state_dir: Path | None = None) -> dict:
    """Apply an allowlisted remediation transactionally, saving a rollback snapshot."""
    spec = _spec_for(check_id)
    if spec is None or not _can_repair_posix():
        return {"ok": False, "message": "No automatic fix is available for this check and account."}

    mask = spec["mask"]
    rel_dir = spec["dir"]
    recorded_targets = []
    try:
        if spec["kind"] == "dir":
            with _open_owned_dir(rel_dir) as (fd, info):
                if not _acl_absent(fd):
                    raise PermissionError("Directory ACL requires manual review")
                old_mode = stat.S_IMODE(info.st_mode)
                new_mode = old_mode & ~mask
                if old_mode != new_mode:
                    os.fchmod(fd, new_mode)
                    observed = os.fstat(fd)
                    if observed.st_uid != os.geteuid() or (observed.st_mode & mask) or not _acl_absent(fd):
                        raise PermissionError("Could not verify updated directory permissions")
                    recorded_targets.append({
                        "kind": "dir",
                        "dir": rel_dir,
                        "name": None,
                        "label": f"~/{rel_dir}",
                        "dev": observed.st_dev,
                        "ino": observed.st_ino,
                        "old_mode": old_mode,
                        "new_mode": new_mode,
                    })
        else:
            with _open_owned_files(rel_dir, spec["files"]) as (dir_fd, dir_info, files, skipped):
                if skipped or (stat.S_IMODE(dir_info.st_mode) & 0o022) or not _acl_absent(dir_fd):
                    raise PermissionError("Directory or file requires manual review")
                if any(not _acl_absent(fd) for _, fd, _ in files):
                    raise PermissionError("Target file has an extended ACL")
                for name, fd, expected in files:
                    current = os.fstat(fd)
                    _require_reg_file(current, expected)
                    old_mode = stat.S_IMODE(current.st_mode)
                    new_mode = old_mode & ~mask
                    if old_mode != new_mode:
                        current_path = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                        _require_reg_file(current_path, current)
                        if not _acl_absent(fd):
                            raise PermissionError("File ACL changed")
                        os.fchmod(fd, new_mode)
                        updated = os.fstat(fd)
                        _require_reg_file(updated, current)
                        if (updated.st_mode & mask) or not _acl_absent(fd):
                            raise PermissionError("Could not verify updated file permissions")
                        recorded_targets.append({
                            "kind": "file",
                            "dir": rel_dir,
                            "name": name,
                            "label": f"~/{rel_dir}/{name}",
                            "dev": updated.st_dev,
                            "ino": updated.st_ino,
                            "old_mode": old_mode,
                            "new_mode": new_mode,
                        })
    except (OSError, KeyError):
        return {
            "ok": False,
            "message": f"Wardr could not verify a safe permission change for ~/{rel_dir}. Review manually.",
            "check": _recheck(check_id),
        }

    check = _recheck(check_id)
    if check is None or check["status"] != "pass":
        return {
            "ok": False,
            "message": f"The ~/{rel_dir} state changed during verification. Rescan before retrying.",
            "check": check,
        }

    rollback_id = None
    if recorded_targets and state_dir is not None:
        rollback_id = uuid.uuid4().hex[:16]
        record = {
            "rollback_id": rollback_id,
            "check_id": check_id,
            "applied_at": _utc_now(),
            "restored_at": None,
            "targets": recorded_targets,
        }
        history = _load_history(state_dir)
        history.insert(0, record)
        try:
            _save_history(state_dir, history)
        except OSError:
            rollback_id = None

    message = (
        f"Tightened permissions on {len(recorded_targets)} target(s) in ~/{rel_dir}."
        if recorded_targets else f"~/{rel_dir} permissions already meet this check."
    )
    return {
        "ok": True,
        "message": message,
        "check": check,
        "rollback_id": rollback_id,
        "changes": [
            {"target": t["label"], "previous_mode": f"{t['old_mode']:04o}", "applied_mode": f"{t['new_mode']:04o}"}
            for t in recorded_targets
        ],
    }


def undo_fix(rollback_id: str, state_dir: Path) -> dict:
    """Safely restore exact prior permissions for a recorded remediation transaction."""
    if not isinstance(rollback_id, str) or not rollback_id.strip():
        return {"ok": False, "message": "Provide a valid rollback ID."}
    if not _can_repair_posix():
        return {"ok": False, "message": "Rollback is not supported for this account or platform."}

    history = _load_history(state_dir)
    match_idx = next((i for i, row in enumerate(history) if row.get("rollback_id") == rollback_id), None)
    if match_idx is None:
        return {"ok": False, "message": "No matching remediation record was found."}
    record = history[match_idx]
    if record.get("restored_at") is not None:
        return {"ok": False, "message": "This remediation was already rolled back."}

    targets = record.get("targets", [])
    restored = 0
    try:
        for item in targets:
            rel_dir = item["dir"]
            old_mode = int(item["old_mode"]) & 0o7777
            expected_dev, expected_ino = int(item["dev"]), int(item["ino"])
            if item["kind"] == "dir":
                with _open_owned_dir(rel_dir) as (fd, info):
                    if (info.st_dev, info.st_ino) != (expected_dev, expected_ino) or not _acl_absent(fd):
                        raise PermissionError("Directory identity or ACL changed since remediation")
                    os.fchmod(fd, old_mode)
                    restored += 1
            elif item["kind"] == "file":
                name = item["name"]
                with _open_owned_dir(rel_dir) as (dir_fd, _):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
                    try:
                        info = os.fstat(fd)
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or (info.st_dev, info.st_ino) != (expected_dev, expected_ino)
                            or not _acl_absent(fd)
                        ):
                            raise PermissionError("File identity or ACL changed since remediation")
                        os.fchmod(fd, old_mode)
                        restored += 1
                    finally:
                        os.close(fd)
    except (OSError, KeyError, ValueError):
        return {
            "ok": False,
            "message": "Wardr refused rollback because a target file or directory changed since the fix ran.",
        }

    record["restored_at"] = _utc_now()
    history[match_idx] = record
    try:
        _save_history(state_dir, history)
    except OSError:
        pass
    check_id = record.get("check_id")
    return {
        "ok": True,
        "message": f"Restored prior permissions on {restored} target(s).",
        "check": _recheck(check_id) if isinstance(check_id, str) else None,
        "rollback_id": rollback_id,
    }
