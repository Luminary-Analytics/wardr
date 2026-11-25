"""MIT-licensed self-hosted Wardr Fleet control plane for small security teams.

Provides RBAC (admin, responder, viewer), short-lived enrollment tokens,
per-host cryptographic device tokens, cross-host zero-day/posture correlation,
strictly allowlisted zero-RCE command dispatch, an immutable audit log,
executive HTML/JSON compliance reports, and a bundled web console.
"""

from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlsplit

from . import remediation
from .report import REPORT_CSS


STATIC = Path(__file__).with_name("static")
_FLEET_ASSETS = {
    "/static/fleet.css": ("fleet.css", "text/css; charset=utf-8"),
    "/static/fleet.js": ("fleet.js", "text/javascript; charset=utf-8"),
    "/static/wardr-mark.png": ("wardr-mark.png", "image/png"),
}
_REPORT_STYLE_HASH = hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()
_PAGE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)
_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"

_ROLES = ("admin", "responder", "viewer")
_HOST_ROLES = ("server", "workstation")
_ALLOWED_COMMANDS = frozenset({"scan", "exposure", "inventory", "fim_check", "apply_fix", "undo_fix"})
_USERNAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{1,47}\Z")
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")
_PBKDF2_ITERATIONS = 200_000
_SESSION_TTL_HOURS = 12
_STALE_AFTER_SECONDS = 300
_MAX_HEARTBEAT_BYTES = 512 * 1024
_MAX_API_BYTES = 64 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operators (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    pw_salt TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    default_role TEXT NOT NULL,
    default_tags TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    os_version TEXT NOT NULL,
    arch TEXT NOT NULL,
    wardr_version TEXT NOT NULL,
    role TEXT NOT NULL,
    tags TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    posture_score INTEGER NOT NULL DEFAULT 100,
    open_critical INTEGER NOT NULL DEFAULT 0,
    open_high INTEGER NOT NULL DEFAULT 0,
    open_medium INTEGER NOT NULL DEFAULT 0,
    open_low INTEGER NOT NULL DEFAULT 0,
    active_alerts INTEGER NOT NULL DEFAULT 0,
    risky_services INTEGER NOT NULL DEFAULT 0,
    fim_status TEXT NOT NULL DEFAULT 'unknown',
    snapshot_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    command_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    result_json TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commands_host_status ON commands(host_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
"""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def _sha256_hex(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return salt.hex(), derived.hex()


def _normalize_tags(raw) -> list[str]:
    if isinstance(raw, str):
        items = [part.strip().lower() for part in raw.split(",") if part.strip()]
    elif isinstance(raw, list):
        items = [str(part).strip().lower() for part in raw if str(part).strip()]
    else:
        items = []
    valid = []
    for tag in items:
        if _TAG_RE.fullmatch(tag) and tag not in valid:
            valid.append(tag)
        if len(valid) >= 16:
            break
    return valid


def _clean_text(value, limit: int = 200) -> str:
    if value is None:
        return ""
    return "".join(ch if ch.isprintable() else " " for ch in str(value)[:limit]).strip()


def _validate_command(action: str, params: dict | None) -> tuple[str, dict]:
    """Enforce zero-RCE allowlist for all fleet-dispatched commands."""
    if action not in _ALLOWED_COMMANDS:
        raise ValueError(f"Unsupported or disallowed fleet command: {action}")
    clean_params = {}
    params = params if isinstance(params, dict) else {}
    if action == "apply_fix":
        fix_id = params.get("id")
        if not isinstance(fix_id, str) or fix_id not in remediation.ALL_FIX_IDS:
            raise ValueError("apply_fix requires a locally allowlisted Wardr fix ID.")
        clean_params["id"] = fix_id
    elif action == "undo_fix":
        rollback_id = params.get("rollback_id")
        if not isinstance(rollback_id, str) or not 4 <= len(rollback_id) <= 64 or not rollback_id.isalnum():
            raise ValueError("undo_fix requires a valid rollback_id.")
        clean_params["rollback_id"] = rollback_id
    return action, clean_params


class FleetStore:
    """SQLite-backed fleet state, RBAC, correlation engine, and zero-RCE command queue."""

    def __init__(self, data_dir: Path, *, stale_after_seconds: int = _STALE_AFTER_SECONDS):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = self.data_dir / "fleet.sqlite3"
        self.stale_after_seconds = max(30, stale_after_seconds)
        self._lock = threading.Lock()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=5)

    def _audit(self, conn: sqlite3.Connection, actor: str, role: str, action: str, target: str, detail: str) -> None:
        conn.execute(
            "INSERT INTO audit_log (at, actor, role, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (_iso(), _clean_text(actor, 64), _clean_text(role, 24), _clean_text(action, 64),
             _clean_text(target, 128), _clean_text(detail, 500)),
        )

    # --- Operator & RBAC management ---

    def ensure_bootstrap_admin(self, username: str = "admin", password: str | None = None) -> tuple[str, str] | None:
        """Create an initial admin account if no operators exist yet. Returns (user, password) if created."""
        with self._lock, closing(self._connect()) as conn, conn:
            count = conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
            if count > 0:
                return None
            pw = password or secrets.token_urlsafe(18)
            salt, pw_hash = _hash_password(pw)
            conn.execute(
                "INSERT INTO operators (username, role, pw_salt, pw_hash, created_at, disabled) "
                "VALUES (?, 'admin', ?, ?, ?, 0)",
                (username, salt, pw_hash, _iso()),
            )
            self._audit(conn, "system", "system", "bootstrap_admin", username, "Created initial Fleet administrator.")
            return username, pw

    def create_operator(self, username: str, password: str, role: str, *, actor: str, actor_role: str) -> dict:
        if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
            raise ValueError("Username must be 2-48 alphanumeric characters (._- allowed).")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        if role not in _ROLES:
            raise ValueError(f"Role must be one of: {', '.join(_ROLES)}.")
        salt, pw_hash = _hash_password(password)
        now = _iso()
        with self._lock, closing(self._connect()) as conn, conn:
            existing = conn.execute("SELECT 1 FROM operators WHERE username = ?", (username,)).fetchone()
            if existing:
                raise ValueError(f"Operator '{username}' already exists.")
            conn.execute(
                "INSERT INTO operators (username, role, pw_salt, pw_hash, created_at, disabled) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (username, role, salt, pw_hash, now),
            )
            self._audit(conn, actor, actor_role, "create_operator", username, f"Added {role} operator.")
        return {"username": username, "role": role, "created_at": now}

    def list_operators(self) -> list[dict]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT username, role, created_at, disabled FROM operators ORDER BY username ASC"
            ).fetchall()
        return [
            {"username": r[0], "role": r[1], "created_at": r[2], "disabled": bool(r[3])}
            for r in rows
        ]

    def authenticate_operator(self, username: str, password: str) -> dict | None:
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT role, pw_salt, pw_hash, disabled FROM operators WHERE username = ?",
                (username,),
            ).fetchone()
        # Run PBKDF2 outside the global lock and execute a constant-work dummy derivation
        # when the account does not exist or is disabled to eliminate lock DoS and timing oracles.
        if row is None or row[3]:
            _hash_password(password, "0" * 32)
            return None
        role, salt, expected_hash, _ = row
        _, computed = _hash_password(password, salt)
        if not hmac.compare_digest(computed, expected_hash):
            return None
        raw_token = secrets.token_urlsafe(32)
        now = _utc_now()
        expires = now + timedelta(hours=_SESSION_TTL_HOURS)
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(now),))
            conn.execute(
                "INSERT INTO sessions (token_hash, username, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (_sha256_hex(raw_token), username, role, _iso(now), _iso(expires)),
            )
            self._audit(conn, username, role, "operator_login", username, "Signed into Wardr Fleet console.")
        return {"token": raw_token, "username": username, "role": role, "expires_at": _iso(expires)}

    def verify_session(self, raw_token: str) -> dict | None:
        if not isinstance(raw_token, str) or len(raw_token) < 20:
            return None
        now_iso = _iso()
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT s.username, o.role, s.expires_at, o.disabled FROM sessions s "
                "JOIN operators o ON o.username = s.username WHERE s.token_hash = ?",
                (_sha256_hex(raw_token),),
            ).fetchone()
            if row is None or row[3] or row[2] < now_iso:
                return None
            return {"username": row[0], "role": row[1], "expires_at": row[2]}

    def revoke_session(self, raw_token: str) -> None:
        if not isinstance(raw_token, str):
            return
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_sha256_hex(raw_token),))

    # --- Enrollment & Host Lifecycle ---

    def create_enrollment_token(
        self,
        *,
        label: str,
        default_role: str = "workstation",
        default_tags: list[str] | str = (),
        ttl_hours: int = 24,
        max_uses: int = 25,
        actor: str,
        actor_role: str,
    ) -> dict:
        if default_role not in _HOST_ROLES:
            raise ValueError("default_role must be 'server' or 'workstation'.")
        if not 1 <= int(ttl_hours) <= 720:
            raise ValueError("ttl_hours must be between 1 and 720.")
        if not 1 <= int(max_uses) <= 10000:
            raise ValueError("max_uses must be between 1 and 10000.")
        clean_label = _clean_text(label, 80) or f"{default_role}-enrollment"
        tags = _normalize_tags(default_tags)
        token_id = f"ET-{secrets.token_hex(4).upper()}"
        raw_token = f"wf_enroll_{secrets.token_urlsafe(24)}"
        now = _utc_now()
        expires = now + timedelta(hours=int(ttl_hours))
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO enrollment_tokens (token_id, token_hash, label, default_role, default_tags, "
                "created_by, created_at, expires_at, max_uses, uses, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)",
                (token_id, _sha256_hex(raw_token), clean_label, default_role, json.dumps(tags),
                 actor, _iso(now), _iso(expires), int(max_uses)),
            )
            self._audit(
                conn, actor, actor_role, "create_enrollment_token", token_id,
                f"Created enrollment token '{clean_label}' ({default_role}, max_uses={max_uses}, tags={tags}).",
            )
        return {
            "token_id": token_id,
            "enrollment_token": raw_token,
            "label": clean_label,
            "default_role": default_role,
            "default_tags": tags,
            "expires_at": _iso(expires),
            "max_uses": int(max_uses),
        }

    def list_enrollment_tokens(self) -> list[dict]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT token_id, label, default_role, default_tags, created_by, created_at, "
                "expires_at, max_uses, uses, revoked FROM enrollment_tokens ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        now_iso = _iso()
        return [
            {
                "token_id": r[0],
                "label": r[1],
                "default_role": r[2],
                "default_tags": json.loads(r[3]),
                "created_by": r[4],
                "created_at": r[5],
                "expires_at": r[6],
                "max_uses": r[7],
                "uses": r[8],
                "revoked": bool(r[9]),
                "active": not r[9] and r[6] >= now_iso and r[8] < r[7],
            }
            for r in rows
        ]

    def revoke_enrollment_token(self, token_id: str, *, actor: str, actor_role: str) -> dict:
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute("UPDATE enrollment_tokens SET revoked = 1 WHERE token_id = ?", (token_id,))
            if cur.rowcount == 0:
                raise KeyError("Enrollment token not found.")
            self._audit(conn, actor, actor_role, "revoke_enrollment_token", token_id, "Revoked enrollment token.")
        return {"revoked": True, "token_id": token_id}

    def enroll_host(self, payload: dict) -> dict:
        raw_enroll = payload.get("enrollment_token")
        if not isinstance(raw_enroll, str) or not raw_enroll.startswith("wf_enroll_"):
            raise PermissionError("Invalid enrollment token.")
        hostname = _clean_text(payload.get("hostname"), 128)
        os_name = _clean_text(payload.get("os"), 64)
        os_version = _clean_text(payload.get("os_version"), 128)
        arch = _clean_text(payload.get("arch"), 32) or "unknown"
        wardr_version = _clean_text(payload.get("wardr_version"), 32) or "0.3.0"
        if not hostname or not os_name:
            raise ValueError("Host enrollment requires hostname and os.")

        now_iso = _iso()
        with self._lock, closing(self._connect()) as conn, conn:
            tok = conn.execute(
                "SELECT token_id, default_role, default_tags, expires_at, max_uses, uses, revoked "
                "FROM enrollment_tokens WHERE token_hash = ?",
                (_sha256_hex(raw_enroll),),
            ).fetchone()
            if tok is None or tok[6] or tok[3] < now_iso or tok[5] >= tok[4]:
                raise PermissionError("Enrollment token is expired, exhausted, or revoked.")

            token_id, default_role, default_tags_json = tok[0], tok[1], tok[2]
            role = payload.get("role") if payload.get("role") in _HOST_ROLES else default_role
            tags = sorted(set(json.loads(default_tags_json)) | set(_normalize_tags(payload.get("tags"))))[:16]
            host_id = f"host-{secrets.token_hex(6)}"
            device_token = f"wf_dev_{secrets.token_urlsafe(32)}"

            conn.execute("UPDATE enrollment_tokens SET uses = uses + 1 WHERE token_id = ?", (token_id,))
            conn.execute(
                "INSERT INTO hosts (host_id, token_hash, hostname, os, os_version, arch, wardr_version, "
                "role, tags, enrolled_at, last_seen, revoked, snapshot_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '{}')",
                (host_id, _sha256_hex(device_token), hostname, os_name, os_version, arch, wardr_version,
                 role, json.dumps(tags), now_iso, now_iso),
            )
            self._audit(
                conn, host_id, "device", "enroll_host", hostname,
                f"Enrolled {role} ({os_name} {arch}) using {token_id} with tags {tags}.",
            )
        return {
            "enrolled": True,
            "host_id": host_id,
            "device_token": device_token,
            "role": role,
            "tags": tags,
        }

    def authenticate_device(self, device_token: str) -> str | None:
        if not isinstance(device_token, str) or not device_token.startswith("wf_dev_"):
            return None
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT host_id, revoked FROM hosts WHERE token_hash = ?",
                (_sha256_hex(device_token),),
            ).fetchone()
            if row is None or row[1]:
                return None
            return row[0]

    def process_heartbeat(self, host_id: str, payload: dict) -> dict:
        """Record a host's latest defensive snapshot and return pending allowlisted commands."""
        if not isinstance(payload, dict):
            raise ValueError("Heartbeat payload must be a JSON object.")
        checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
        alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
        risky_services = payload.get("risky_services") if isinstance(payload.get("risky_services"), list) else []
        software_findings = payload.get("software_findings") if isinstance(payload.get("software_findings"), list) else []
        fim_info = payload.get("fim") if isinstance(payload.get("fim"), dict) else {}
        fim_status = str(fim_info.get("status") or "unknown")
        if fim_status not in ("pass", "fail", "unknown", "uninitialized"):
            fim_status = "unknown"

        # Compute deterministic host security score (0-100).
        sev_counts = Counter()
        passed = failed = 0
        compact_checks = []
        for c in checks[:120]:
            if not isinstance(c, dict) or not isinstance(c.get("id"), str):
                continue
            status = str(c.get("status") or "unknown")
            sev = str(c.get("severity") or "low")
            if status == "pass":
                passed += 1
            elif status == "fail":
                failed += 1
                sev_counts[sev] += 1
            compact_checks.append({
                "id": _clean_text(c.get("id"), 80),
                "title": _clean_text(c.get("title"), 160),
                "category": _clean_text(c.get("category"), 48),
                "severity": sev,
                "status": status,
                "can_fix": bool(c.get("can_fix")),
                "evidence": _clean_text(c.get("evidence"), 400),
            })

        compact_alerts = [
            {
                "id": _clean_text(a.get("id"), 80),
                "rule_id": _clean_text(a.get("rule_id"), 80),
                "title": _clean_text(a.get("title"), 180),
                "severity": str(a.get("severity") or "medium"),
                "last_seen": _clean_text(a.get("last_seen"), 48),
                "summary": _clean_text(a.get("summary"), 360),
            }
            for a in alerts[:50]
            if isinstance(a, dict)
        ]
        compact_services = [
            {
                "id": _clean_text(s.get("id"), 80),
                "service": _clean_text(s.get("service"), 120),
                "port": int(s["port"]) if isinstance(s.get("port"), int) else 0,
                "scope": _clean_text(s.get("scope"), 32),
                "severity": str(s.get("severity") or "medium"),
                "process": _clean_text(s.get("process"), 80),
            }
            for s in risky_services[:32]
            if isinstance(s, dict)
        ]
        compact_software = [
            {
                "advisory_id": _clean_text(f.get("advisory_id"), 80),
                "package": _clean_text(f.get("package"), 120),
                "version": _clean_text(f.get("version"), 64),
                "severity": str(f.get("severity") or "unknown"),
                "known_exploited": bool(f.get("known_exploited")),
            }
            for f in software_findings[:50]
            if isinstance(f, dict)
        ]

        # Weighted posture score (starts at 100, deducts for real failures/alerts/exposed services).
        deduction = (
            sev_counts["critical"] * 25
            + sev_counts["high"] * 12
            + sev_counts["medium"] * 5
            + sev_counts["low"] * 2
            + len(compact_alerts) * 10
            + len(compact_services) * 8
            + (15 if fim_status == "fail" else 0)
        )
        posture_score = max(0, min(100, 100 - deduction))
        now_iso = _iso()

        snapshot = {
            "reported_at": now_iso,
            "checks": compact_checks,
            "alerts": compact_alerts,
            "risky_services": compact_services,
            "software_findings": compact_software,
            "inventory_count": int(payload.get("inventory_count") or 0),
            "fim": {"status": fim_status, "changes": fim_info.get("changes", [])[:16]},
            "passed": passed,
            "failed": failed,
        }

        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "UPDATE hosts SET last_seen = ?, wardr_version = COALESCE(?, wardr_version), "
                "os_version = COALESCE(?, os_version), posture_score = ?, "
                "open_critical = ?, open_high = ?, open_medium = ?, open_low = ?, "
                "active_alerts = ?, risky_services = ?, fim_status = ?, snapshot_json = ? "
                "WHERE host_id = ? AND revoked = 0",
                (
                    now_iso,
                    _clean_text(payload.get("wardr_version"), 32) or None,
                    _clean_text(payload.get("os_version"), 128) or None,
                    posture_score,
                    sev_counts["critical"], sev_counts["high"], sev_counts["medium"], sev_counts["low"],
                    len(compact_alerts), len(compact_services), fim_status,
                    json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")),
                    host_id,
                ),
            )
            pending_rows = conn.execute(
                "SELECT command_id, action, params_json FROM commands "
                "WHERE host_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 16",
                (host_id,),
            ).fetchall()
            commands = [
                {"command_id": r[0], "action": r[1], "params": json.loads(r[2])}
                for r in pending_rows
            ]
            if commands:
                conn.executemany(
                    "UPDATE commands SET status = 'dispatched' WHERE command_id = ?",
                    [(cmd["command_id"],) for cmd in commands],
                )
        return {"ok": True, "server_time": now_iso, "posture_score": posture_score, "commands": commands}

    def record_command_result(self, host_id: str, command_id: str, *, ok: bool, result: dict) -> dict:
        now_iso = _iso()
        status = "completed" if ok else "failed"
        raw_json = json.dumps(result if isinstance(result, dict) else {"message": str(result)}, ensure_ascii=True)
        if len(raw_json) > 16384:
            safe_result = json.dumps({"truncated": True, "preview": raw_json[:15500]}, ensure_ascii=True)
        else:
            safe_result = raw_json
        with self._lock, closing(self._connect()) as conn, conn:
            row = conn.execute(
                "SELECT action, params_json FROM commands WHERE command_id = ? AND host_id = ?",
                (command_id, host_id),
            ).fetchone()
            if row is None:
                raise KeyError("Command not found for this host.")
            conn.execute(
                "UPDATE commands SET status = ?, completed_at = ?, result_json = ? WHERE command_id = ?",
                (status, now_iso, safe_result, command_id),
            )
            self._audit(
                conn, host_id, "device", f"command_{status}", command_id,
                f"Host completed {row[0]} ({row[1]}): {status}.",
            )
        return {"recorded": True, "command_id": command_id, "status": status}

    def queue_commands(
        self,
        *,
        action: str,
        params: dict | None = None,
        host_ids: list[str] | None = None,
        tag: str | None = None,
        actor: str,
        actor_role: str,
    ) -> dict:
        """Queue a strictly allowlisted zero-RCE command across one host, a tag group, or selected hosts."""
        valid_action, valid_params = _validate_command(action, params)
        now_iso = _iso()
        params_json = json.dumps(valid_params, ensure_ascii=True, separators=(",", ":"))

        with self._lock, closing(self._connect()) as conn, conn:
            if host_ids:
                if not isinstance(host_ids, list) or len(host_ids) > 500 or not all(isinstance(h, str) and len(h) <= 64 for h in host_ids):
                    raise ValueError("Provide up to 500 valid string host IDs.")
                placeholders = ",".join("?" for _ in host_ids)
                rows = conn.execute(
                    f"SELECT host_id, hostname FROM hosts WHERE revoked = 0 AND host_id IN ({placeholders})",
                    host_ids,
                ).fetchall()
            elif tag:
                norm_tag = tag.strip().lower()
                all_rows = conn.execute("SELECT host_id, hostname, tags FROM hosts WHERE revoked = 0").fetchall()
                rows = [(r[0], r[1]) for r in all_rows if norm_tag in json.loads(r[2])]
            else:
                rows = conn.execute("SELECT host_id, hostname FROM hosts WHERE revoked = 0").fetchall()

            if not rows:
                raise ValueError("No active enrolled hosts matched the selected target.")

            queued = []
            for h_id, hostname in rows:
                cmd_id = f"CMD-{secrets.token_hex(5).upper()}"
                conn.execute(
                    "INSERT INTO commands (command_id, host_id, action, params_json, status, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, 'queued', ?, ?)",
                    (cmd_id, h_id, valid_action, params_json, actor, now_iso),
                )
                queued.append({"command_id": cmd_id, "host_id": h_id, "hostname": hostname})
            self._audit(
                conn, actor, actor_role, f"queue_{valid_action}",
                f"{len(queued)} host(s)", f"params={params_json} tag={tag or 'selected'}",
            )
        return {"queued": len(queued), "action": valid_action, "params": valid_params, "commands": queued}

    def revoke_host(self, host_id: str, *, actor: str, actor_role: str) -> dict:
        with self._lock, closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE host_id = ?", (host_id,)).fetchone()
            if row is None:
                raise KeyError("Host not found.")
            conn.execute("UPDATE hosts SET revoked = 1 WHERE host_id = ?", (host_id,))
            conn.execute("UPDATE commands SET status = 'cancelled' WHERE host_id = ? AND status = 'queued'", (host_id,))
            self._audit(conn, actor, actor_role, "revoke_host", host_id, f"Revoked device credentials for {row[0]}.")
        return {"revoked": True, "host_id": host_id}

    # --- Fleet Views, Cross-Host Correlation & Compliance Export ---

    def _host_status(self, last_seen_iso: str, revoked: bool, now: datetime) -> str:
        if revoked:
            return "revoked"
        try:
            seen = datetime.fromisoformat(last_seen_iso)
            age = (now - seen).total_seconds()
            if age <= self.stale_after_seconds:
                return "online"
            if age <= self.stale_after_seconds * 6:
                return "stale"
        except ValueError:
            pass
        return "offline"

    def overview(self, *, tag: str | None = None, os_filter: str | None = None, status_filter: str | None = None) -> dict:
        now = _utc_now()
        with self._lock, closing(self._connect()) as conn:
            host_rows = conn.execute(
                "SELECT host_id, hostname, os, os_version, arch, wardr_version, role, tags, enrolled_at, last_seen, "
                "revoked, posture_score, open_critical, open_high, open_medium, open_low, active_alerts, "
                "risky_services, fim_status, snapshot_json FROM hosts ORDER BY revoked ASC, posture_score ASC, hostname ASC"
            ).fetchall()
            recent_cmds = conn.execute(
                "SELECT command_id, host_id, action, params_json, status, created_by, created_at, completed_at, result_json "
                "FROM commands ORDER BY created_at DESC LIMIT 40"
            ).fetchall()

        all_hosts = []
        all_tags = set()
        # Cross-host correlation maps:
        check_hosts: dict[str, dict] = {}
        alert_hosts: dict[str, dict] = {}
        service_hosts: dict[str, dict] = {}
        cve_hosts: dict[str, dict] = {}

        for row in host_rows:
            tags = json.loads(row[7])
            all_tags.update(tags)
            status = self._host_status(row[9], bool(row[10]), now)
            snap = json.loads(row[19]) if row[19] else {}
            host_obj = {
                "host_id": row[0],
                "hostname": row[1],
                "os": row[2],
                "os_version": row[3],
                "arch": row[4],
                "wardr_version": row[5],
                "role": row[6],
                "tags": tags,
                "enrolled_at": row[8],
                "last_seen": row[9],
                "status": status,
                "posture_score": row[11],
                "open_critical": row[12],
                "open_high": row[13],
                "open_medium": row[14],
                "open_low": row[15],
                "active_alerts": row[16],
                "risky_services": row[17],
                "fim_status": row[18],
                "inventory_count": snap.get("inventory_count", 0),
            }
            all_hosts.append(host_obj)

            if status == "revoked":
                continue

            for c in snap.get("checks", ()):
                if c.get("status") != "fail":
                    continue
                cid = c["id"]
                bucket = check_hosts.setdefault(cid, {
                    "kind": "posture", "id": cid, "title": c.get("title", cid),
                    "severity": c.get("severity", "medium"),
                    "can_bulk_fix": cid in remediation.ALL_FIX_IDS and bool(c.get("can_fix")),
                    "host_ids": [], "hostnames": [],
                })
                bucket["host_ids"].append(row[0])
                bucket["hostnames"].append(row[1])
                if cid in remediation.ALL_FIX_IDS and c.get("can_fix"):
                    bucket["can_bulk_fix"] = True

            for a in snap.get("alerts", ()):
                key = a.get("rule_id") or a.get("title") or "alert"
                bucket = alert_hosts.setdefault(key, {
                    "kind": "alert", "id": key, "title": a.get("title", key),
                    "severity": a.get("severity", "high"), "can_bulk_fix": False,
                    "host_ids": [], "hostnames": [],
                })
                if row[0] not in bucket["host_ids"]:
                    bucket["host_ids"].append(row[0])
                    bucket["hostnames"].append(row[1])

            for s in snap.get("risky_services", ()):
                key = s.get("id") or f"port-{s.get('port')}"
                bucket = service_hosts.setdefault(key, {
                    "kind": "surface", "id": key,
                    "title": f"Exposed {s.get('service', key)} (:{s.get('port')})",
                    "severity": s.get("severity", "high"), "can_bulk_fix": False,
                    "host_ids": [], "hostnames": [],
                })
                if row[0] not in bucket["host_ids"]:
                    bucket["host_ids"].append(row[0])
                    bucket["hostnames"].append(row[1])

            for f in snap.get("software_findings", ()):
                key = f.get("advisory_id") or "advisory"
                bucket = cve_hosts.setdefault(key, {
                    "kind": "software", "id": key,
                    "title": f"{f.get('package', '')} · {key}" + (" (CISA KEV)" if f.get("known_exploited") else ""),
                    "severity": "critical" if f.get("known_exploited") else f.get("severity", "high"),
                    "can_bulk_fix": False, "host_ids": [], "hostnames": [],
                })
                if row[0] not in bucket["host_ids"]:
                    bucket["host_ids"].append(row[0])
                    bucket["hostnames"].append(row[1])

        active_hosts = [h for h in all_hosts if h["status"] != "revoked"]
        avg_score = round(sum(h["posture_score"] for h in active_hosts) / len(active_hosts)) if active_hosts else 100

        # Apply optional UI filters cleanly.
        filtered = all_hosts
        if tag:
            norm_tag = tag.strip().lower()
            filtered = [h for h in filtered if norm_tag in h["tags"]]
        if os_filter:
            filtered = [h for h in filtered if h["os"].lower() == os_filter.strip().lower()]
        if status_filter:
            filtered = [h for h in filtered if h["status"] == status_filter.strip().lower()]

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        correlations = [
            {**entry, "host_count": len(entry["host_ids"])}
            for entry in (*alert_hosts.values(), *service_hosts.values(), *cve_hosts.values(), *check_hosts.values())
        ]
        correlations.sort(key=lambda e: (sev_rank.get(e["severity"], 4), -e["host_count"], e["title"]))

        def _safe_parse(val):
            if not val:
                return None
            try:
                return json.loads(val)
            except ValueError:
                return {"raw": str(val)[:200]}

        commands = [
            {
                "command_id": r[0], "host_id": r[1], "action": r[2],
                "params": _safe_parse(r[3]) or {}, "status": r[4], "created_by": r[5],
                "created_at": r[6], "completed_at": r[7],
                "result": _safe_parse(r[8]),
            }
            for r in recent_cmds
        ]

        return {
            "generated_at": _iso(now),
            "summary": {
                "total_hosts": len(active_hosts),
                "online": sum(1 for h in active_hosts if h["status"] == "online"),
                "stale": sum(1 for h in active_hosts if h["status"] == "stale"),
                "offline": sum(1 for h in active_hosts if h["status"] == "offline"),
                "revoked": sum(1 for h in all_hosts if h["status"] == "revoked"),
                "fleet_score": avg_score,
                "open_critical": sum(h["open_critical"] for h in active_hosts),
                "open_high": sum(h["open_high"] for h in active_hosts),
                "active_alerts": sum(h["active_alerts"] for h in active_hosts),
                "risky_services": sum(h["risky_services"] for h in active_hosts),
                "fim_failures": sum(1 for h in active_hosts if h["fim_status"] == "fail"),
            },
            "tags": sorted(all_tags),
            "correlations": correlations[:30],
            "hosts": filtered,
            "recent_commands": commands,
        }

    def host_detail(self, host_id: str) -> dict:
        now = _utc_now()
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT host_id, hostname, os, os_version, arch, wardr_version, role, tags, enrolled_at, last_seen, "
                "revoked, posture_score, fim_status, snapshot_json FROM hosts WHERE host_id = ?",
                (host_id,),
            ).fetchone()
            if row is None:
                raise KeyError("Host not found.")
            cmds = conn.execute(
                "SELECT command_id, action, params_json, status, created_by, created_at, completed_at, result_json "
                "FROM commands WHERE host_id = ? ORDER BY created_at DESC LIMIT 25",
                (host_id,),
            ).fetchall()
        snap = json.loads(row[13]) if row[13] else {}
        def _safe_parse_cmd(val):
            if not val:
                return None
            try:
                return json.loads(val)
            except ValueError:
                return {"raw": str(val)[:200]}

        return {
            "host_id": row[0],
            "hostname": row[1],
            "os": row[2],
            "os_version": row[3],
            "arch": row[4],
            "wardr_version": row[5],
            "role": row[6],
            "tags": json.loads(row[7]),
            "enrolled_at": row[8],
            "last_seen": row[9],
            "status": self._host_status(row[9], bool(row[10]), now),
            "posture_score": row[11],
            "fim_status": row[12],
            "snapshot": snap,
            "commands": [
                {
                    "command_id": c[0], "action": c[1], "params": _safe_parse_cmd(c[2]) or {}, "status": c[3],
                    "created_by": c[4], "created_at": c[5], "completed_at": c[6],
                    "result": _safe_parse_cmd(c[7]),
                }
                for c in cmds
            ],
        }

    def audit_entries(self, *, limit: int = 100) -> list[dict]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, at, actor, role, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [
            {"id": r[0], "at": r[1], "actor": r[2], "role": r[3], "action": r[4], "target": r[5], "detail": r[6]}
            for r in rows
        ]

    def compliance_report_html(self) -> str:
        data = self.overview()
        s = data["summary"]
        audit = self.audit_entries(limit=30)
        host_rows = "".join(
            f"<tr><td>{escape(h['hostname'])}</td><td>{escape(h['role'])}</td>"
            f"<td>{escape(h['os'])}</td><td>{escape(h['status'])}</td>"
            f"<td><strong>{h['posture_score']}%</strong></td>"
            f"<td>{h['open_critical']}/{h['open_high']}</td>"
            f"<td>{h['active_alerts']}</td><td>{escape(h['fim_status'])}</td></tr>"
            for h in data["hosts"]
        ) or "<tr><td colspan='8'>No enrolled hosts yet.</td></tr>"
        corr_rows = "".join(
            f"<li><strong>[{escape(c['severity'].upper())}]</strong> {escape(c['title'])} "
            f"— affects <strong>{c['host_count']}</strong> host(s) ({escape(', '.join(c['hostnames'][:6]))})</li>"
            for c in data["correlations"][:20]
        ) or "<li>No open cross-host findings.</li>"
        audit_rows = "".join(
            f"<li><code>{escape(a['at'])}</code> · <strong>{escape(a['actor'])}</strong> ({escape(a['role'])}) "
            f"· {escape(a['action'])} · {escape(a['target'])} — {escape(a['detail'])}</li>"
            for a in audit
        ) or "<li>No audit entries recorded.</li>"
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardr Fleet Compliance Report</title><style>{REPORT_CSS}
table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:.9rem}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #d7e0d2}}
</style></head><body><main>
<header><span class="brand">WARDR FLEET</span><h1>Executive Security &amp; Compliance Report</h1>
<p class="muted">Generated {escape(data['generated_at'])} (UTC)</p>
<div class="risks">
  <span><strong>{s['total_hosts']}</strong> Active Hosts</span>
  <span><strong>{s['fleet_score']}%</strong> Fleet Score</span>
  <span><strong>{s['open_critical']}</strong> Critical</span>
  <span><strong>{s['open_high']}</strong> High</span>
  <span><strong>{s['active_alerts']}</strong> Alerts</span>
  <span><strong>{s['risky_services']}</strong> Exposed Services</span>
</div></header>
<section><h2>Cross-Host Findings &amp; Correlation</h2><ul>{corr_rows}</ul></section>
<section><h2>Enrolled Fleet Inventory</h2>
<table><thead><tr><th>Hostname</th><th>Role</th><th>OS</th><th>Status</th><th>Score</th><th>Crit/High</th><th>Alerts</th><th>FIM</th></tr></thead>
<tbody>{host_rows}</tbody></table></section>
<section><h2>Recent Remediation &amp; Security Audit Log</h2><ul>{audit_rows}</ul></section>
</main></body></html>
"""


class _AuthRateLimiter:
    def __init__(self, limit: int = 12, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(bucket) >= self.limit:
                self._hits[key] = bucket
                return False
            bucket.append(now)
            self._hits[key] = bucket
            return True


class FleetServer(ThreadingHTTPServer):
    allow_reuse_address = os.name == "posix"
    daemon_threads = True

    def __init__(self, bind_address: tuple[str, int], store: FleetStore):
        self.store = store
        self.auth_limiter = _AuthRateLimiter(limit=12, window=60.0)
        self.page = (STATIC / "fleet.html").read_bytes()
        self.assets = {url: ((STATIC / name).read_bytes(), kind) for url, (name, kind) in _FLEET_ASSETS.items()}
        super().__init__(bind_address, _FleetHandler)


class _FleetHandler(BaseHTTPRequestHandler):
    server: FleetServer
    server_version = "WardrFleet"
    sys_version = ""

    def setup(self) -> None:
        self.request.settimeout(30)
        super().setup()

    def log_message(self, format, *args):
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str, *, csp: str = _PAGE_CSP, download: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8")

    def _bearer_token(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        if header.startswith("Bearer "):
            return header[7:].strip()
        return self.headers.get("X-Wardr-Fleet-Token")

    def _require_operator(self, allowed_roles: tuple[str, ...] = _ROLES) -> dict | None:
        token = self._bearer_token()
        session = self.server.store.verify_session(token or "")
        if session is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Sign in to access Wardr Fleet."})
            return None
        if session["role"] not in allowed_roles:
            self._json(HTTPStatus.FORBIDDEN, {"error": f"Requires role: {' or '.join(allowed_roles)}."})
            return None
        return session

    def _read_json(self, limit: int) -> dict:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Send application/json.")
        lengths = self.headers.get_all("Content-Length") or []
        if (
            len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()
            or len(lengths[0]) > len(str(limit)) or "Transfer-Encoding" in self.headers
        ):
            raise ValueError("Invalid Content-Length.")
        size = int(lengths[0])
        if not 0 < size <= limit:
            raise OverflowError("Request payload exceeds limit.")
        try:
            parsed = json.loads(self.rfile.read(size))
        except (ValueError, RecursionError, OSError) as exc:
            raise ValueError("Invalid JSON payload.") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object.")
        return parsed

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._send(HTTPStatus.OK, self.server.page, "text/html; charset=utf-8")
            return
        if path in self.server.assets:
            content, kind = self.server.assets[path]
            self._send(HTTPStatus.OK, content, kind)
            return
        if path == "/api/fleet/health":
            self._json(HTTPStatus.OK, {"ok": True})
            return

        if path == "/api/fleet/me":
            op = self._require_operator()
            if op:
                self._json(HTTPStatus.OK, op)
            return
        if path == "/api/fleet/overview":
            if not self._require_operator():
                return
            self._json(HTTPStatus.OK, self.server.store.overview(
                tag=(query.get("tag") or [None])[0],
                os_filter=(query.get("os") or [None])[0],
                status_filter=(query.get("status") or [None])[0],
            ))
            return
        if path.startswith("/api/fleet/hosts/"):
            if not self._require_operator():
                return
            host_id = path[len("/api/fleet/hosts/"):]
            try:
                self._json(HTTPStatus.OK, self.server.store.host_detail(host_id))
            except KeyError as exc:
                self._json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            return
        if path == "/api/fleet/tokens":
            if not self._require_operator(("admin",)):
                return
            self._json(HTTPStatus.OK, {"tokens": self.server.store.list_enrollment_tokens()})
            return
        if path == "/api/fleet/operators":
            if not self._require_operator(("admin",)):
                return
            self._json(HTTPStatus.OK, {"operators": self.server.store.list_operators()})
            return
        if path == "/api/fleet/audit":
            if not self._require_operator():
                return
            self._json(HTTPStatus.OK, {"entries": self.server.store.audit_entries()})
            return
        if path == "/api/fleet/report.html":
            if not self._require_operator():
                return
            dl = "wardr-fleet-compliance.html" if (query.get("download") == ["1"]) else None
            self._send(HTTPStatus.OK, self.server.store.compliance_report_html().encode("utf-8"),
                       "text/html; charset=utf-8", csp=_REPORT_CSP, download=dl)
            return
        if path == "/api/fleet/report.json":
            if not self._require_operator():
                return
            dl = "wardr-fleet-compliance.json" if (query.get("download") == ["1"]) else None
            payload = {**self.server.store.overview(), "audit_log": self.server.store.audit_entries(limit=100)}
            self._send(HTTPStatus.OK, (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
                       "application/json; charset=utf-8", csp=_REPORT_CSP, download=dl)
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            # --- Public Auth & Device Enrollment / Agent Endpoints ---
            if path == "/api/fleet/login":
                client_ip = (self.client_address[0] if self.client_address else "unknown")
                if not self.server.auth_limiter.allow(f"login:{client_ip}"):
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many sign-in attempts. Wait a minute and try again."})
                    return
                body = self._read_json(4096)
                session = self.server.store.authenticate_operator(body.get("username"), body.get("password"))
                if session is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid username or password."})
                    return
                self._json(HTTPStatus.OK, session)
                return
            if path == "/api/fleet/logout":
                self.server.store.revoke_session(self._bearer_token() or "")
                self._json(HTTPStatus.OK, {"ok": True})
                return
            if path == "/api/fleet/enroll":
                client_ip = (self.client_address[0] if self.client_address else "unknown")
                if not self.server.auth_limiter.allow(f"enroll:{client_ip}"):
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many enrollment attempts. Wait a minute and try again."})
                    return
                body = self._read_json(16384)
                self._json(HTTPStatus.CREATED, self.server.store.enroll_host(body))
                return
            if path == "/api/fleet/heartbeat":
                host_id = self.server.store.authenticate_device(self._bearer_token() or "")
                if host_id is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid or revoked device token."})
                    return
                body = self._read_json(_MAX_HEARTBEAT_BYTES)
                self._json(HTTPStatus.OK, self.server.store.process_heartbeat(host_id, body))
                return
            if path.startswith("/api/fleet/commands/") and path.endswith("/result"):
                host_id = self.server.store.authenticate_device(self._bearer_token() or "")
                if host_id is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid or revoked device token."})
                    return
                cmd_id = path[len("/api/fleet/commands/"):-len("/result")]
                body = self._read_json(_MAX_API_BYTES)
                self._json(HTTPStatus.OK, self.server.store.record_command_result(
                    host_id, cmd_id, ok=bool(body.get("ok")), result=body.get("result") or {},
                ))
                return

            # --- Authenticated Operator Endpoints (RBAC Enforced) ---
            if path == "/api/fleet/commands":
                op = self._require_operator(("admin", "responder"))
                if not op:
                    return
                body = self._read_json(_MAX_API_BYTES)
                res = self.server.store.queue_commands(
                    action=str(body.get("action") or ""),
                    params=body.get("params"),
                    host_ids=body.get("host_ids") if isinstance(body.get("host_ids"), list) else None,
                    tag=body.get("tag") if isinstance(body.get("tag"), str) else None,
                    actor=op["username"], actor_role=op["role"],
                )
                self._json(HTTPStatus.ACCEPTED, res)
                return
            if path == "/api/fleet/tokens":
                op = self._require_operator(("admin",))
                if not op:
                    return
                body = self._read_json(8192)
                res = self.server.store.create_enrollment_token(
                    label=body.get("label") or "",
                    default_role=str(body.get("default_role") or "workstation"),
                    default_tags=body.get("default_tags") or [],
                    ttl_hours=int(body.get("ttl_hours") or 24),
                    max_uses=int(body.get("max_uses") or 25),
                    actor=op["username"], actor_role=op["role"],
                )
                self._json(HTTPStatus.CREATED, res)
                return
            if path.startswith("/api/fleet/tokens/") and path.endswith("/revoke"):
                op = self._require_operator(("admin",))
                if not op:
                    return
                token_id = path[len("/api/fleet/tokens/"):-len("/revoke")]
                self._json(HTTPStatus.OK, self.server.store.revoke_enrollment_token(
                    token_id, actor=op["username"], actor_role=op["role"],
                ))
                return
            if path.startswith("/api/fleet/hosts/") and path.endswith("/revoke"):
                op = self._require_operator(("admin",))
                if not op:
                    return
                host_id = path[len("/api/fleet/hosts/"):-len("/revoke")]
                self._json(HTTPStatus.OK, self.server.store.revoke_host(
                    host_id, actor=op["username"], actor_role=op["role"],
                ))
                return
            if path == "/api/fleet/operators":
                op = self._require_operator(("admin",))
                if not op:
                    return
                body = self._read_json(8192)
                res = self.server.store.create_operator(
                    body.get("username"), body.get("password"), body.get("role"),
                    actor=op["username"], actor_role=op["role"],
                )
                self._json(HTTPStatus.CREATED, res)
                return

            self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
        except PermissionError as exc:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except OverflowError as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(exc)})
        except KeyError as exc:
            self._json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
