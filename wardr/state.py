"""Local state and the dashboard's scan and advisory lifecycle."""

import hashlib
import json
import os
import platform
import socket
import stat
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import account, actions, ai_tiers, assessment, changelog, checks, exposure, feeds, fim, hunting, intel, inventory, legal, local_ai, pentest, remediation, reporting, supply_chain, surface
from .monitor import Monitor
from .plan import build_plan, prioritize_software
from .report import SEVERITIES, assess_posture


SCAN_PROFILES = {
    "light": {
        "id": "light",
        "label": "Light scan",
        "duration": "~2–5 sec",
        "cpu_level": "Minimal CPU",
        "recommended": False,
        "checks_included": [
            "OS firewall, encryption, and security update posture",
            "SSH, credential, and local AI tool permissions",
        ],
        "benefit": "Near-instant results with virtually zero CPU or battery impact — safe to run anytime.",
        "warning": "Skips live network port inspection, config file integrity hashing, and installed software CVE checks.",
    },
    "medium": {
        "id": "medium",
        "label": "Medium scan",
        "duration": "~10–25 sec",
        "cpu_level": "Moderate CPU",
        "recommended": True,
        "checks_included": [
            "All Light scan OS & credential posture checks",
            "Local network exposure (listening TCP/UDP sockets & owners)",
            "File Integrity Monitoring (SHA-256 baseline check)",
        ],
        "benefit": "Best everyday balance — verifies OS security, catches exposed ports, and detects tampered security configs.",
        "warning": "Brief moderate CPU and disk activity while inspecting sockets and hashing files; skips full package SBOM matching and AI deep review.",
    },
    "heavy": {
        "id": "heavy",
        "label": "Heavy / Deep scan",
        "duration": "~30–90+ sec",
        "cpu_level": "High CPU & RAM",
        "recommended": False,
        "checks_included": [
            "All Medium scan posture, socket & file-integrity checks",
            "Full installed software discovery (SBOM) & advisory matching",
            "Attack-surface & loopback TLS hygiene audit",
            "AI Threat & Posture Triage (via Tier 2 Cloud or Tier 3 Local AI if enabled)",
        ],
        "benefit": "Maximum depth — audits installed packages, risky exposed services, local TLS, and correlates findings with AI.",
        "warning": "Noticeably higher CPU, disk, and memory load (especially if Tier 3 Local AI is active); fans may spin up and battery drains faster.",
    },
}


class BusyError(Exception):
    """A different action already owns the applicable worker."""


def default_state_dir() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Wardr"
    elif sys.platform == "darwin":
        base = home / "Library" / "Application Support" / "Wardr"
    else:
        configured = Path(os.environ.get("XDG_STATE_HOME") or "")
        base = (configured if configured.is_absolute() else home / ".local" / "state") / "wardr"
    return base


def host_info() -> dict:
    operating_system = {"Darwin": "macOS"}.get(platform.system(), platform.system())
    version = {
        "Darwin": lambda: platform.mac_ver()[0],
        "Windows": platform.version,
        "Linux": lambda: platform.freedesktop_os_release().get("PRETTY_NAME", ""),
    }.get(platform.system(), platform.release)
    try:
        label = version() or platform.release()
    except OSError:
        label = platform.release()
    return {"name": socket.gethostname(), "os": operating_system, "version": label}


def prepare_state_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("Choose a Wardr state directory owned and accessible only by the current account.")


def read_local_json(path: Path, limit: int) -> dict | None:
    try:
        flags = os.O_RDONLY
        if os.name == "posix":
            flags |= os.O_NOFOLLOW | os.O_NONBLOCK
        else:
            flags |= os.O_BINARY
        with os.fdopen(os.open(path, flags), "rb") as handle:
            info = os.fstat(handle.fileno())
            if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                return None
            if not stat.S_ISREG(info.st_mode):
                return None
            contents = handle.read(limit + 1)
        if len(contents) > limit:
            return None
        snapshot = json.loads(contents)
    except (OSError, RecursionError, ValueError):
        return None
    return snapshot if isinstance(snapshot, dict) else None


def read_scan(path: Path, hostname: str) -> dict | None:
    snapshot = read_local_json(path, 2 * 1024 * 1024)
    statuses = ("pass", "fail", "unknown", "not_applicable")
    text_fields = ("id", "title", "category", "evidence", "remediation")
    if (
        isinstance(snapshot, dict)
        and snapshot.get("host") == hostname
        and isinstance(snapshot.get("scanned_at"), str)
        and isinstance(snapshot.get("checks"), list)
        and all(
            isinstance(item, dict)
            and all(isinstance(item.get(key), str) for key in text_fields)
            and item.get("status") in statuses
            and item.get("severity") in SEVERITIES
            for item in snapshot["checks"]
        )
    ):
        return snapshot
    return None


def save_local_json(path: Path, payload: dict) -> None:
    prepare_state_dir(path.parent)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".scan-", suffix=".json")
    staging = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        staging.replace(path)
    finally:
        staging.unlink(missing_ok=True)


def read_software(path: Path) -> dict | None:
    snapshot = read_local_json(path, 8 * 1024 * 1024)
    if not snapshot or not all(
        isinstance(snapshot.get(key), dict) for key in ("summary", "inventory", "advisories")
    ) or not isinstance(snapshot.get("findings"), list):
        return None
    if not all(
        isinstance(row, dict)
        and all(isinstance(row.get(key), str) for key in ("id", "advisory_id", "package", "version", "evidence", "remediation"))
        and row.get("severity") in (*SEVERITIES, "unknown")
        and isinstance(row.get("aliases"), list) and all(isinstance(alias, str) for alias in row["aliases"])
        for row in snapshot["findings"]
    ):
        return None
    return snapshot


def _evidence_hash(check: dict) -> str:
    raw = str(check.get("evidence") or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def read_dispositions(path: Path) -> dict[str, dict]:
    snapshot = read_local_json(path, 256 * 1024)
    if not snapshot or not isinstance(snapshot.get("items"), dict):
        return {}
    now = datetime.now(timezone.utc)
    valid: dict[str, dict] = {}
    for check_id, entry in snapshot["items"].items():
        if not isinstance(check_id, str) or len(check_id) > 120 or not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if kind not in ("queued", "acknowledged"):
            continue
        at = entry.get("at")
        evidence_hash = entry.get("evidence_hash")
        expires_at = entry.get("expires_at")
        note = entry.get("note", "")
        if not isinstance(at, str) or not isinstance(evidence_hash, str) or not isinstance(note, str):
            continue
        if expires_at is not None:
            if not isinstance(expires_at, str):
                continue
            try:
                if datetime.fromisoformat(expires_at) <= now:
                    continue
            except ValueError:
                continue
        valid[check_id] = {
            "kind": kind,
            "at": at,
            "expires_at": expires_at,
            "evidence_hash": evidence_hash,
            "note": note[:240],
        }
    return valid


class WardrState:
    def __init__(self, directory: Path, interval: int = 30, *, offline: bool = False):
        prepare_state_dir(directory)
        self.directory = directory
        self.scan_path = directory / "latest-scan.json"
        self.software_path = directory / "software-assessment.json"
        self.dispositions_path = directory / "check-dispositions.json"
        self.pentest_path = directory / "latest-pentest.json"
        self.pentest_dispositions_path = directory / "pentest-dispositions.json"
        self.supply_chain_path = directory / "latest-supply-chain.json"
        self.ui_state_path = directory / "ui-state.json"
        self.host = host_info()
        self.offline = offline
        self.accounts = account.AccountManager(directory, offline=offline)
        self.monitor = Monitor(interval=interval, state_dir=directory)
        self._lock = threading.Lock()
        self._scan_error = None
        self._scan_running = False
        self._scan_id = 0
        self._scan_profile = "medium"
        self._scan_duration_ms = None
        self._scan_modules = {}
        self._scan_steps: list[dict] = []
        self._scan_progress = 0
        self._fix_running = False
        self._fix_batch_id = 0
        self._fix_batch: dict | None = None
        self._pentest_running = False
        self._pentest_id = 0
        self._pentest_steps: list[dict] = []
        self._pentest_progress = 0
        self._pentest_error = None
        self._pentest_fix_running = False
        self._pentest_fix_id = 0
        self._pentest_fix_batch: dict | None = None
        self._supply_chain_running = False
        self._supply_chain_error = None
        self._advisory_running = False
        self._advisory_error = None
        self._exposure_running = False
        self._exposure_error = None
        self._exposure = None
        self._software_running = False
        self._ai_running = False
        self._ai_triage = None
        self._ai_triage_error = None
        self._ai_status_cache = None
        self._ai_status_cached_at = 0.0
        self._threats_cache_key = None
        self._threats_cache = None
        self._last_auto_telemetry_at = 0.0
        self._scan = read_scan(self.scan_path, self.host["name"])
        self._software = read_software(self.software_path)
        self._dispositions = read_dispositions(self.dispositions_path)
        self._pentest_dispositions = read_dispositions(self.pentest_dispositions_path)
        saved_pentest = read_local_json(self.pentest_path, 1024 * 1024)
        self._pentest = saved_pentest if isinstance(saved_pentest, dict) and isinstance(saved_pentest.get("tests"), list) else None
        saved_sc = read_local_json(self.supply_chain_path, 2 * 1024 * 1024)
        self._supply_chain = saved_sc if isinstance(saved_sc, dict) and isinstance(saved_sc.get("findings"), list) else None
        ui_state = read_local_json(self.ui_state_path, 32 * 1024) or {}
        self._last_seen_version = ui_state.get("last_seen_version") if isinstance(ui_state.get("last_seen_version"), str) else None
        self._advisories = intel.advisory_status(directory)

    def active_threats(self, monitoring_status: dict | None = None) -> dict:
        monitor_snapshot = monitoring_status if monitoring_status is not None else self.monitor.status()
        events = monitor_snapshot.get("events") or []
        cache_key = (
            monitor_snapshot.get("last_poll"),
            monitor_snapshot.get("poll_count", 0),
            len(events),
            events[0].get("id") if events else None,
        )
        with self._lock:
            if self._threats_cache is not None and self._threats_cache_key == cache_key:
                return dict(self._threats_cache)
        feed_rules = feeds.load_feed_rules(self.directory)
        analysis = hunting.analyze(monitor_snapshot, feed_rules=feed_rules)
        alerts = analysis["alerts"]
        critical_count = sum(1 for item in alerts if item.get("severity") == "critical")
        high_count = sum(1 for item in alerts if item.get("severity") == "high")
        medium_count = sum(1 for item in alerts if item.get("severity") == "medium")
        if critical_count > 0 or high_count > 0:
            threat_status = "threat"
        elif alerts:
            threat_status = "warning"
        else:
            threat_status = "clear"
        coverage = analysis["coverage"]
        sources_active = sum(1 for item in coverage if item.get("available") is True)
        result = {
            "status": threat_status,
            "count": len(alerts),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "alerts": alerts[:8],
            "checked_at": monitor_snapshot.get("last_poll"),
            "lookback_hours": analysis["lookback_hours"],
            "events_considered": analysis["events_considered"],
            "coverage_state": analysis["coverage_state"],
            "coverage_note": analysis["coverage_note"],
            "sources_active": sources_active,
            "sources_total": len(coverage),
        }
        with self._lock:
            self._threats_cache_key = cache_key
            self._threats_cache = result
        return dict(result)

    def _apply_dispositions_locked(self, items: list[dict]) -> tuple[list[dict], bool]:
        now = datetime.now(timezone.utc)
        changed = False
        enriched: list[dict] = []
        for item in items:
            check_id = item.get("id")
            entry = self._dispositions.get(check_id) if isinstance(check_id, str) else None
            if entry is None:
                enriched.append(item)
                continue
            expires_at = entry.get("expires_at")
            expired = False
            if isinstance(expires_at, str):
                try:
                    expired = datetime.fromisoformat(expires_at) <= now
                except ValueError:
                    expired = True
            if expired or item.get("status") == "pass":
                self._dispositions.pop(check_id, None)
                changed = True
                enriched.append(item)
                continue
            if item.get("status") in ("fail", "unknown"):
                if entry.get("evidence_hash") != _evidence_hash(item):
                    self._dispositions.pop(check_id, None)
                    changed = True
                    enriched.append(item)
                    continue
                enriched.append({
                    **item,
                    "disposition": {
                        "kind": entry["kind"],
                        "at": entry["at"],
                        "expires_at": expires_at,
                        "note": entry.get("note", ""),
                    },
                })
                continue
            enriched.append(item)
        return enriched, changed

    def _save_dispositions_payload(self, items_copy: dict[str, dict]) -> None:
        try:
            save_local_json(self.dispositions_path, {"version": 1, "items": items_copy})
        except OSError:
            pass

    def enriched_scan_snapshot(self) -> dict | None:
        save_copy = None
        with self._lock:
            if not self._scan:
                return None
            enriched_checks, changed = self._apply_dispositions_locked(actions.enrich_checks(self._scan.get("checks", [])))
            if changed:
                save_copy = dict(self._dispositions)
            result = {**self._scan, "checks": enriched_checks}
        if save_copy is not None:
            self._save_dispositions_payload(save_copy)
        return result

    def set_check_disposition(self, check_id: str, kind: str, note: str = "") -> dict:
        if kind not in ("queued", "acknowledged", "clear"):
            raise ValueError("Choose queued, acknowledged, or clear for check status.")
        if not isinstance(note, str) or len(note) > 240:
            raise ValueError("Disposition note must be 240 characters or fewer.")
        cleaned_note = note.strip()
        with self._lock:
            if kind == "clear":
                removed = self._dispositions.pop(check_id, None)
                save_copy = dict(self._dispositions) if removed is not None else None
                result = {"ok": True, "id": check_id, "disposition": None}
            else:
                snapshot = self._scan or {}
                items = snapshot.get("checks", [])
                target = next((item for item in items if item.get("id") == check_id), None)
                if not target or target.get("status") not in ("fail", "unknown"):
                    raise ValueError("Only an active failing or unverified check from the latest scan can be marked queued or handled.")
                if target.get("status") == "fail" and target.get("can_fix") is True:
                    raise ValueError("This check has a safe automatic fix. Apply the fix instead of acknowledging it.")
                if kind == "queued" and not check_id.endswith("-pending-updates"):
                    raise ValueError("Only pending OS update checks can be marked queued for restart.")
                now = datetime.now(timezone.utc)
                expires_at = (now + timedelta(days=7)).isoformat(timespec="seconds") if kind == "queued" else None
                entry = {
                    "kind": kind,
                    "at": now.isoformat(timespec="seconds"),
                    "expires_at": expires_at,
                    "evidence_hash": _evidence_hash(target),
                    "note": cleaned_note,
                }
                self._dispositions[check_id] = entry
                save_copy = dict(self._dispositions)
                result = {
                    "ok": True,
                    "id": check_id,
                    "disposition": {
                        "kind": entry["kind"],
                        "at": entry["at"],
                        "expires_at": entry["expires_at"],
                        "note": entry["note"],
                    },
                }
        if save_copy is not None:
            save_local_json(self.dispositions_path, {"version": 1, "items": save_copy})
        return result

    def set_check_dispositions_batch(self, check_ids: list[str], kind: str, note: str = "") -> dict:
        if kind not in ("queued", "acknowledged", "clear"):
            raise ValueError("Choose queued, acknowledged, or clear for check status.")
        if not isinstance(note, str) or len(note) > 240:
            raise ValueError("Disposition note must be 240 characters or fewer.")
        if not isinstance(check_ids, list) or not check_ids or len(check_ids) > 64:
            raise ValueError("Provide between 1 and 64 check IDs.")
        cleaned_note = note.strip()
        updated: list[str] = []
        skipped_autofix: list[str] = []
        save_copy = None
        with self._lock:
            snapshot = self._scan or {}
            by_id = {str(item.get("id") or ""): item for item in snapshot.get("checks", []) if item.get("id")}
            now = datetime.now(timezone.utc)
            for raw_id in check_ids:
                if not isinstance(raw_id, str) or not raw_id or len(raw_id) > 120:
                    raise ValueError("Provide valid check IDs.")
                if kind == "clear":
                    if self._dispositions.pop(raw_id, None) is not None:
                        updated.append(raw_id)
                else:
                    target = by_id.get(raw_id)
                    if not target or target.get("status") not in ("fail", "unknown"):
                        continue
                    if target.get("status") == "fail" and target.get("can_fix") is True:
                        skipped_autofix.append(raw_id)
                        continue
                    is_update_check = raw_id.endswith("-pending-updates")
                    if kind == "queued" and not is_update_check:
                        continue
                    effective_kind = "queued" if (is_update_check and kind in ("queued", "acknowledged")) else kind
                    expires_at = (now + timedelta(days=7)).isoformat(timespec="seconds") if effective_kind == "queued" else None
                    self._dispositions[raw_id] = {
                        "kind": effective_kind,
                        "at": now.isoformat(timespec="seconds"),
                        "expires_at": expires_at,
                        "evidence_hash": _evidence_hash(target),
                        "note": cleaned_note,
                    }
                    updated.append(raw_id)
            if updated:
                save_copy = dict(self._dispositions)
        if not updated and skipped_autofix:
            raise ValueError("Selected check(s) have automatic fixes — run Fix & Protect instead of acknowledging them.")
        if save_copy is not None:
            save_local_json(self.dispositions_path, {"version": 1, "items": save_copy})
        return {"ok": True, "updated": updated, "count": len(updated), "skipped_autofix": skipped_autofix}

    def status(self) -> dict:
        save_copy = None
        with self._lock:
            snapshot = self._scan or {}
            enriched_checks, changed = self._apply_dispositions_locked(actions.enrich_checks(snapshot.get("checks", [])))
            if changed:
                save_copy = dict(self._dispositions)
            scan = {
                "id": self._scan_id,
                "state": (
                    "running" if self._scan_running else
                    "error" if self._scan_error else
                    "complete" if self._scan is not None else "idle"
                ),
                "profile": self._scan_profile,
                "profile_label": SCAN_PROFILES.get(self._scan_profile, SCAN_PROFILES["medium"])["label"],
                "progress_pct": self._scan_progress,
                "steps": [dict(step) for step in self._scan_steps],
                "duration_ms": self._scan_duration_ms,
                "modules": dict(self._scan_modules),
                "updated_at": snapshot.get("scanned_at"),
                "error": self._scan_error,
                "checks": enriched_checks,
                "fix_running": self._fix_running,
            }
            fix_batch = (
                {**self._fix_batch, "steps": [dict(step) for step in self._fix_batch.get("steps", [])]}
                if isinstance(self._fix_batch, dict) else None
            )
            advisories = {
                **intel.public_status(self._advisories),
                "state": (
                    "running" if self._advisory_running else
                    "error" if self._advisory_error else
                    "ready" if self._advisories.get("available") else "idle"
                ),
                "error": self._advisory_error,
            }
            triage = dict(self._ai_triage) if isinstance(self._ai_triage, dict) else None
            triage_error = self._ai_triage_error
            ai_running = self._ai_running
        if save_copy is not None:
            self._save_dispositions_payload(save_copy)
        monitoring_status = self.monitor.status()
        threats = self.active_threats(monitoring_status)
        posture = assess_posture(scan, monitoring=monitoring_status, threats=threats)
        ai_info = self.ai_status(cached=True)
        ai_info["running"] = ai_running
        ai_info["triage"] = triage
        ai_info["triage_error"] = triage_error
        monitoring_payload = {**monitoring_status, "events": (monitoring_status.get("events") or [])[:100]}
        with self._lock:
            last_seen = self._last_seen_version
        return {
            "host": self.host,
            "account": self.accounts.status(),
            "whats_new": changelog.whats_new_payload(last_seen),
            "scan": scan,
            "scan_profiles": list(SCAN_PROFILES.values()),
            "fix_batch": fix_batch,
            "posture": posture,
            "threats": threats,
            "ai": ai_info,
            "monitoring": monitoring_payload,
            "intel": advisories,
            "offline": self.offline,
        }

    def mark_whats_new_seen(self) -> dict:
        version = changelog.current_release()["version"]
        with self._lock:
            self._last_seen_version = version
        save_local_json(self.ui_state_path, {"last_seen_version": version})
        return changelog.whats_new_payload(version)

    def telemetry_preview(self) -> dict:
        enriched_scan = self.enriched_scan_snapshot() or {}
        monitoring_status = self.monitor.status()
        threats = self.active_threats(monitoring_status)
        posture = assess_posture(
            {"updated_at": enriched_scan.get("scanned_at"), "checks": enriched_scan.get("checks", [])},
            monitoring=monitoring_status,
            threats=threats,
        )
        with self._lock:
            sc = self._supply_chain
            local_exp = self._exposure
            scan_meta = {
                "profile": self._scan_profile,
                "duration_ms": self._scan_duration_ms,
                "checks": enriched_scan.get("checks", []),
            }
            enriched_pt, _ = pentest.apply_pentest_dispositions(
                self._pentest,
                self._pentest_dispositions,
                scan_snapshot=enriched_scan or self._scan,
            )
        return self.accounts.build_telemetry_preview(
            host=self.host,
            posture=posture,
            threats=threats,
            scan=scan_meta,
            exposure_result=local_exp,
            supply_chain=sc,
            pentest_result=enriched_pt,
        )

    def sync_telemetry(self) -> dict:
        preview = self.telemetry_preview()
        return self.accounts.sync_telemetry(preview)

    def _maybe_auto_sync_telemetry(self, *, min_interval_seconds: float = 300.0) -> bool:
        if not self.accounts.should_auto_sync():
            return False
        now = time.monotonic()
        with self._lock:
            if self._last_auto_telemetry_at > 0 and (now - self._last_auto_telemetry_at) < min_interval_seconds:
                return False
            self._last_auto_telemetry_at = now

        def _worker() -> None:
            try:
                self.sync_telemetry()
            except Exception:
                pass

        threading.Thread(target=_worker, name="wardr-telemetry-sync", daemon=True).start()
        return True

    def run_supply_chain_scan(self, custom_path: str | None = None) -> dict:
        roots = None
        if custom_path is not None and custom_path.strip():
            candidate = Path(custom_path.strip()).expanduser()
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise ValueError("Choose an existing local folder to scan.") from exc
            if not resolved.is_dir():
                raise ValueError("The selected path is not a folder.")
            roots = [resolved]
        with self._lock:
            if self._supply_chain_running:
                raise BusyError("A supply-chain scan is already running.")
            self._supply_chain_running = True
            self._supply_chain_error = None
        try:
            result = supply_chain.scan_supply_chain(roots=roots)
            with self._lock:
                self._supply_chain = result
            try:
                save_local_json(self.supply_chain_path, result)
            except OSError:
                pass
            self._maybe_auto_sync_telemetry()
            return result
        except Exception as exc:
            with self._lock:
                self._supply_chain_error = "Supply-chain scan could not complete."
            raise ValueError(str(exc)) from exc
        finally:
            with self._lock:
                self._supply_chain_running = False

    def defense_status(self) -> dict:
        enriched_scan = self.enriched_scan_snapshot()
        save_pt_disp = None
        with self._lock:
            scan = enriched_scan or self._scan
            local_exposure = self._exposure
            collecting = self._exposure_running
            exposure_error = self._exposure_error
            software = self._software
            matching = self._software_running
            catalog = self._advisories
            enriched_pentest, pt_disp_changed = pentest.apply_pentest_dispositions(
                self._pentest,
                self._pentest_dispositions,
                scan_snapshot=scan,
            )
            if pt_disp_changed:
                save_pt_disp = dict(self._pentest_dispositions)
            pentest_fix_batch = (
                {**self._pentest_fix_batch, "steps": [dict(s) for s in self._pentest_fix_batch.get("steps", [])]}
                if isinstance(self._pentest_fix_batch, dict) else None
            )
            pentest_payload = {
                "id": self._pentest_id,
                "running": self._pentest_running,
                "fix_running": self._pentest_fix_running,
                "fix_batch": pentest_fix_batch,
                "progress_pct": self._pentest_progress,
                "steps": [dict(step) for step in self._pentest_steps],
                "error": self._pentest_error,
                "modules": [dict(m) for m in pentest.PENTEST_MODULES],
                "result": enriched_pentest,
            }
            fim_status = self._scan_modules.get("fim_status")
            sc_payload = {
                "running": self._supply_chain_running,
                "error": self._supply_chain_error,
                "result": self._supply_chain,
            }
        if save_pt_disp is not None:
            try:
                save_local_json(self.pentest_dispositions_path, {"version": 1, "items": save_pt_disp})
            except OSError:
                pass
        monitoring_status = self.monitor.status()
        threats = self.active_threats(monitoring_status)
        feed_rules = feeds.load_feed_rules(self.directory)
        hunting_result = hunting.analyze(monitoring_status, feed_rules=feed_rules)
        prioritized = prioritize_software(software, catalog)
        matrix = pentest.build_defense_matrix(
            scan=scan,
            monitoring=monitoring_status,
            threats=threats,
            exposure_result=local_exposure,
            software_result=prioritized,
            advisories=catalog,
            pentest_result=pentest_payload["result"],
            fim_status=fim_status,
        )
        return {
            "defense_matrix": matrix,
            "pentest": pentest_payload,
            "supply_chain": sc_payload,
            "exposure": {
                "running": collecting, "error": exposure_error, "result": local_exposure,
            },
            "hunting": hunting_result,
            "software": {
                "running": matching, "result": prioritized,
                "catalog_coverage": intel.exploited_index(catalog)[1],
            },
            "feed": feeds.feed_status(self.directory),
            "remediation_history": remediation.list_history(self.directory),
            "plan": build_plan(self.host, scan, local_exposure, hunting_result, prioritized),
        }

    def start_pentest(self, test_ids: list[str] | None = None) -> dict:
        if test_ids is None:
            chosen = list(pentest.PENTEST_MODULE_IDS)
        else:
            if not test_ids or any(tid not in pentest.PENTEST_MODULE_IDS for tid in test_ids):
                raise ValueError("Choose one or more valid self-pen-test modules.")
            chosen = list(dict.fromkeys(test_ids))
        meta_by_id = {m["id"]: m for m in pentest.PENTEST_MODULES}
        steps = [
            {
                "id": tid,
                "label": meta_by_id[tid]["short_title"],
                "title": meta_by_id[tid]["title"],
                "category": meta_by_id[tid]["category"],
                "status": "pending",
                "detail": "Waiting to run safe local probe…",
            }
            for tid in chosen
        ]
        with self._lock:
            if self._pentest_running:
                raise BusyError("A self-pen-test simulation is already running.")
            self._pentest_id += 1
            run_id = self._pentest_id
            self._pentest_running = True
            self._pentest_error = None
            self._pentest_steps = steps
            self._pentest_progress = 6
        threading.Thread(
            target=self._run_pentest,
            args=(chosen,),
            name="wardr-pentest",
            daemon=True,
        ).start()
        return {"ok": True, "pentest_id": run_id, "count": len(chosen)}

    def _run_pentest(self, module_ids: list[str]) -> None:
        started = time.monotonic()
        error = None
        results: list[dict] = []
        try:
            enriched_scan = self.enriched_scan_snapshot()
            monitoring_status = self.monitor.status()
            with self._lock:
                local_exp = self._exposure
            if local_exp is None and any(mid in ("unauth-services", "firewall-lan") for mid in module_ids):
                try:
                    local_exp = exposure.collect_exposure()
                    with self._lock:
                        self._exposure = local_exp
                except Exception:
                    local_exp = None

            total = len(module_ids) or 1
            for idx, mid in enumerate(module_ids):
                with self._lock:
                    for step in self._pentest_steps:
                        if step["id"] == mid:
                            step["status"] = "running"
                            step["detail"] = "Executing safe local probe…"
                            break
                    self._pentest_progress = min(95, max(10, round(100 * (idx + 0.35) / total)))

                res = pentest.run_single_test(
                    mid,
                    state_dir=self.directory,
                    scan_snapshot=enriched_scan,
                    exposure_result=local_exp,
                    monitoring_status=monitoring_status,
                )
                results.append(res)
                step_status = "done" if res["outcome"] == "defended" else ("warn" if res["outcome"] == "warning" else "exposed")
                with self._lock:
                    for step in self._pentest_steps:
                        if step["id"] == mid:
                            step["status"] = step_status
                            step["detail"] = res["plain_summary"]
                            break
                    self._pentest_progress = min(98, round(100 * (idx + 1) / total))

            elapsed_ms = int((time.monotonic() - started) * 1000)
            with self._lock:
                existing = (self._pentest or {}).get("tests") if len(module_ids) < len(pentest.PENTEST_MODULE_IDS) else None
            summary = pentest.summarize_pentest(
                results,
                duration_ms=elapsed_ms,
                scan_snapshot=enriched_scan,
                existing_tests=existing,
            )
            with self._lock:
                self._pentest = summary
            try:
                save_local_json(self.pentest_path, summary)
            except OSError:
                pass
        except Exception:
            error = "The self-pen-test stopped unexpectedly. Try running it again."
        finally:
            with self._lock:
                self._pentest_error = error
                self._pentest_progress = 100
                self._pentest_running = False
            if error is None:
                self._maybe_auto_sync_telemetry()

    def start_pentest_fix(self, fix_ids: list[str] | None = None) -> dict:
        requested = set(fix_ids) if fix_ids is not None else None
        with self._lock:
            if self._pentest_running or self._pentest_fix_running:
                raise BusyError("A self-pen-test or hardening fix is already running.")
            enriched_pt, _ = pentest.apply_pentest_dispositions(
                self._pentest, self._pentest_dispositions, scan_snapshot=self._scan,
            )
            tests = (enriched_pt or {}).get("tests") or []
            targets: list[dict] = []
            seen_ids: set[str] = set()
            for test in tests:
                if requested is None and pentest._is_pentest_handled(test):
                    continue
                for finding in test.get("findings") or []:
                    fid = finding.get("fix_id")
                    if not isinstance(fid, str) or finding.get("can_fix") is not True:
                        continue
                    if requested is not None and fid not in requested:
                        continue
                    if fid in seen_ids:
                        continue
                    seen_ids.add(fid)
                    targets.append({
                        "fix_id": fid,
                        "module_id": test["id"],
                        "title": finding.get("fix_label") or finding.get("title") or fid,
                        "detail": finding.get("title") or "",
                    })
            if not targets:
                raise ValueError("There are no automatic hardening fixes waiting in the latest self-pen-test.")
            self._pentest_fix_running = True
            self._pentest_fix_id += 1
            batch_id = self._pentest_fix_id
            steps = [
                {
                    "id": item["fix_id"],
                    "module_id": item["module_id"],
                    "label": item["title"],
                    "status": "pending",
                    "detail": "Queued for hardening & live re-verification…",
                }
                for item in targets
            ]
            self._pentest_fix_batch = {
                "id": batch_id,
                "state": "running",
                "progress_pct": 6,
                "total": len(steps),
                "completed": 0,
                "succeeded": 0,
                "failed": 0,
                "steps": steps,
            }
        threading.Thread(
            target=self._run_pentest_fix,
            args=(targets,),
            name="wardr-pentest-fix",
            daemon=True,
        ).start()
        return {"ok": True, "batch_id": batch_id, "count": len(targets)}

    def _run_pentest_fix(self, targets: list[dict]) -> None:
        try:
            total = len(targets) or 1
            affected_modules: list[str] = []
            for idx, target in enumerate(targets):
                fid = target["fix_id"]
                mid = target["module_id"]
                if mid not in affected_modules:
                    affected_modules.append(mid)
                with self._lock:
                    for step in self._pentest_fix_batch["steps"]:
                        if step["id"] == fid:
                            step["status"] = "running"
                            step["detail"] = "Applying hardening fix & re-testing…"
                            break
                    self._pentest_fix_batch["progress_pct"] = min(90, round(100 * (idx + 0.35) / total))

                try:
                    result = pentest.apply_pentest_fix(fid, state_dir=self.directory)
                except Exception:
                    result = {"ok": False, "fix_id": fid, "module_id": mid, "message": "Hardening fix could not complete safely."}

                ok = bool(result.get("ok"))
                with self._lock:
                    for step in self._pentest_fix_batch["steps"]:
                        if step["id"] == fid:
                            step["status"] = "fixed" if ok else "failed"
                            step["detail"] = result.get("message") or ("Hardened & verified." if ok else "Manual step required.")
                            break
                    self._pentest_fix_batch["completed"] += 1
                    if ok:
                        self._pentest_fix_batch["succeeded"] += 1
                    else:
                        self._pentest_fix_batch["failed"] += 1
                    self._pentest_fix_batch["progress_pct"] = min(94, round(100 * self._pentest_fix_batch["completed"] / total))

            # Re-run affected self-pen-test modules so live proof reflects the fixes immediately!
            enriched_scan = self.enriched_scan_snapshot()
            monitoring_status = self.monitor.status()
            local_exp = None
            if any(m in ("unauth-services", "firewall-lan") for m in affected_modules):
                try:
                    local_exp = exposure.collect_exposure()
                    with self._lock:
                        self._exposure = local_exp
                except Exception:
                    with self._lock:
                        local_exp = self._exposure
            else:
                with self._lock:
                    local_exp = self._exposure

            retested = [
                pentest.run_single_test(
                    mid,
                    state_dir=self.directory,
                    scan_snapshot=enriched_scan,
                    exposure_result=local_exp,
                    monitoring_status=monitoring_status,
                )
                for mid in affected_modules
            ]
            with self._lock:
                existing = (self._pentest or {}).get("tests") or []
                merged = pentest.summarize_pentest(
                    retested,
                    duration_ms=int((self._pentest or {}).get("duration_ms") or 0),
                    scan_snapshot=enriched_scan,
                    existing_tests=existing,
                )
                self._pentest = merged
            try:
                save_local_json(self.pentest_path, merged)
            except OSError:
                pass
            with self._lock:
                self._pentest_fix_batch["state"] = "complete"
                self._pentest_fix_batch["progress_pct"] = 100
        finally:
            with self._lock:
                self._pentest_fix_running = False

    def set_pentest_disposition(self, module_id: str, kind: str, note: str = "") -> dict:
        if module_id not in pentest.PENTEST_MODULE_IDS:
            raise ValueError("Unknown self-pen-test module.")
        if kind not in ("acknowledged", "clear"):
            raise ValueError("Choose acknowledged or clear for pen-test item status.")
        if not isinstance(note, str) or len(note) > 240:
            raise ValueError("Note must be 240 characters or fewer.")
        with self._lock:
            if kind == "clear":
                removed = self._pentest_dispositions.pop(module_id, None)
                save_copy = dict(self._pentest_dispositions) if removed is not None else None
                result = {"ok": True, "id": module_id, "disposition": None}
            else:
                tests = (self._pentest or {}).get("tests") or []
                target = next((t for t in tests if t.get("id") == module_id), None)
                if not target or target.get("outcome") not in ("warning", "exposed"):
                    raise ValueError("Only an active pen-test warning or exposure can be marked handled.")
                entry = {
                    "kind": "acknowledged",
                    "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "expires_at": None,
                    "evidence_hash": pentest.pentest_evidence_hash(target),
                    "note": note.strip(),
                }
                self._pentest_dispositions[module_id] = entry
                save_copy = dict(self._pentest_dispositions)
                result = {
                    "ok": True,
                    "id": module_id,
                    "disposition": {"kind": entry["kind"], "at": entry["at"], "note": entry["note"]},
                }
        if save_copy is not None:
            save_local_json(self.pentest_dispositions_path, {"version": 1, "items": save_copy})
        return result

    def start_exposure(self) -> None:
        with self._lock:
            if self._exposure_running:
                raise BusyError("Wardr is already collecting local exposure.")
            self._exposure_running = True
            self._exposure_error = None
        threading.Thread(target=self._run_exposure, name="wardr-exposure", daemon=True).start()

    def _run_exposure(self) -> None:
        try:
            result = exposure.collect_exposure()
            with self._lock:
                self._exposure = result
        except Exception:
            with self._lock:
                self._exposure_error = "Wardr could not collect the local socket tables. Try refreshing."
        finally:
            with self._lock:
                self._exposure_running = False

    def assess_software(self, sbom, advisories) -> dict:
        with self._lock:
            if self._software_running:
                raise BusyError("A software assessment is already running.")
            self._software_running = True
            index, _ = intel.exploited_index(self._advisories)
        try:
            result = assessment.assess_documents(sbom, advisories, exploited_ids=index)
            save_local_json(self.software_path, result)
            with self._lock:
                self._software = result
                catalog = self._advisories
            return prioritize_software(result, catalog)
        finally:
            with self._lock:
                self._software_running = False

    def review_plan(self) -> dict:
        with self._lock:
            if self._ai_running:
                raise BusyError("A local model review is already running.")
            self._ai_running = True
        try:
            return local_ai.review(self.defense_status()["plan"])
        finally:
            with self._lock:
                self._ai_running = False

    def scan_snapshot(self) -> dict | None:
        with self._lock:
            return self._scan

    def ai_status(self, *, cached: bool = False) -> dict:
        now = time.monotonic()
        with self._lock:
            if cached and self._ai_status_cache is not None and (now - self._ai_status_cached_at) < 60.0:
                return dict(self._ai_status_cache)
        fresh = ai_tiers.public_status(self.directory, offline=self.offline)
        with self._lock:
            self._ai_status_cache = fresh
            self._ai_status_cached_at = now
        return dict(fresh)

    def update_ai_config(self, payload: dict) -> dict:
        ai_tiers.save_config(self.directory, payload)
        with self._lock:
            self._ai_status_cache = None
            self._ai_triage_error = None
        return self.ai_status(cached=False)

    def run_ai_triage(self) -> dict:
        with self._lock:
            if self._ai_running:
                raise BusyError("An AI analysis is already running.")
            snapshot = self._scan or {}
            self._ai_running = True
            self._ai_triage_error = None
        try:
            monitoring_status = self.monitor.status()
            threats = self.active_threats(monitoring_status)
            scan_view = {"updated_at": snapshot.get("scanned_at"), "checks": snapshot.get("checks", [])}
            posture = assess_posture(scan_view, monitoring=monitoring_status, threats=threats)
            result = ai_tiers.run_triage(
                self.directory,
                host=self.host,
                posture=posture,
                checks=snapshot.get("checks", []),
                threats=threats,
                offline=self.offline,
            )
            with self._lock:
                self._ai_triage = result
                self._ai_triage_error = None
            return result
        except ai_tiers.AITierError as exc:
            with self._lock:
                self._ai_triage_error = str(exc)
            raise
        finally:
            with self._lock:
                self._ai_running = False

    @staticmethod
    def _build_scan_steps(profile: str) -> list[dict]:
        steps = [
            {"id": "posture", "label": "OS firewall, encryption & hardening", "status": "pending", "detail": "Waiting…"},
            {"id": "updates", "label": "Operating system security updates", "status": "pending", "detail": "Waiting…"},
            {"id": "credentials", "label": "SSH keys, credentials & AI tool configs", "status": "pending", "detail": "Waiting…"},
        ]
        if profile in ("medium", "heavy"):
            steps.extend([
                {"id": "exposure", "label": "Live network ports & listening services", "status": "pending", "detail": "Waiting…"},
                {"id": "fim", "label": "File integrity verification (SHA-256)", "status": "pending", "detail": "Waiting…"},
                {"id": "threats", "label": "Active threat-hunting correlation", "status": "pending", "detail": "Waiting…"},
            ])
        if profile == "heavy":
            steps.extend([
                {"id": "surface", "label": "Attack surface & loopback TLS audit", "status": "pending", "detail": "Waiting…"},
                {"id": "inventory", "label": "Installed software inventory (SBOM) & CVEs", "status": "pending", "detail": "Waiting…"},
                {"id": "ai", "label": "AI threat & posture triage", "status": "pending", "detail": "Waiting…"},
            ])
        steps.append({"id": "verdict", "label": "Red / Amber / Green protection verdict", "status": "pending", "detail": "Waiting…"})
        return steps

    def _update_scan_step(self, step_id: str, status: str, detail: str) -> None:
        with self._lock:
            total = len(self._scan_steps) or 1
            for step in self._scan_steps:
                if step["id"] == step_id:
                    step["status"] = status
                    step["detail"] = detail
                    break
            completed = sum(1 for step in self._scan_steps if step["status"] in ("done", "warn"))
            running = sum(1 for step in self._scan_steps if step["status"] == "running")
            self._scan_progress = min(99 if completed < total else 100, round(100 * (completed + 0.4 * running) / total))

    def start_scan(self, profile: str = "medium") -> dict:
        if profile not in SCAN_PROFILES:
            raise ValueError("Choose a valid scan depth: light, medium, or heavy.")
        with self._lock:
            if self._scan_running or self._fix_running:
                raise BusyError("A scan or fix is already running.")
            self._scan_id += 1
            scan_id = self._scan_id
            self._scan_running = True
            self._scan_profile = profile
            self._scan_error = None
            self._scan_steps = self._build_scan_steps(profile)
            self._scan_progress = 4
        threading.Thread(target=self._run_scan, args=(profile,), name="wardr-scan", daemon=True).start()
        return {"ok": True, "scan_id": scan_id, "profile": profile}

    def _run_scan(self, profile: str = "medium") -> None:
        started = time.monotonic()
        error = None
        modules: dict = {"profile": profile}
        expected_steps = self._build_scan_steps(profile)
        with self._lock:
            if [s["id"] for s in self._scan_steps] != [s["id"] for s in expected_steps] or self._scan_progress >= 100:
                self._scan_steps = expected_steps
                self._scan_progress = 4
        try:
            self._update_scan_step("posture", "running", "Inspecting OS firewall, disk encryption & hardening…")
            snapshot = checks.scan()
            all_checks = snapshot.get("checks", [])
            modules["posture_checks"] = len(all_checks)
            with self._lock:
                self._scan = snapshot
            try:
                save_local_json(self.scan_path, snapshot)
            except OSError:
                error = "The scan completed. Wardr could not save it to local storage."

            update_checks = [c for c in all_checks if (c.get("category") or "").lower() == "updates" or "update" in (c.get("id") or "")]
            cred_checks = [
                c for c in all_checks
                if c not in update_checks and (
                    (c.get("category") or "").lower() in ("access", "credentials", "ai security")
                    or "ssh" in (c.get("id") or "")
                )
            ]
            os_checks = [c for c in all_checks if c not in update_checks and c not in cred_checks]

            def summarize_group(items: list[dict], fallback_label: str) -> tuple[str, str]:
                applicable = [c for c in items if c.get("status") != "not_applicable"]
                failed = [c for c in applicable if c.get("status") == "fail"]
                passed = [c for c in applicable if c.get("status") == "pass"]
                if not applicable:
                    return "done", f"Checked {fallback_label}"
                if failed:
                    return "warn", f"{len(passed)} secured · {len(failed)} need attention"
                return "done", f"All {len(passed)} checks verified secure"

            self._update_scan_step("posture", *summarize_group(os_checks, "OS hardening"))
            self._update_scan_step("updates", "running", "Checking OS security update status…")
            self._update_scan_step("updates", *summarize_group(update_checks, "OS updates"))
            self._update_scan_step("credentials", "running", "Checking SSH keys, credentials & AI tool configs…")
            self._update_scan_step("credentials", *summarize_group(cred_checks, "credentials & AI tools"))

            if profile in ("medium", "heavy"):
                self._update_scan_step("exposure", "running", "Reading local TCP/UDP socket tables…")
                try:
                    exp = exposure.collect_exposure()
                    with self._lock:
                        self._exposure = exp
                    count = len(exp.get("listeners", []))
                    modules["sockets_inspected"] = count
                    self._update_scan_step("exposure", "done", f"Mapped {count} listening local socket(s)")
                except Exception:
                    modules["sockets_inspected"] = None
                    self._update_scan_step("exposure", "warn", "Socket tables partially unavailable")

                self._update_scan_step("fim", "running", "Hashing critical security configs (SHA-256)…")
                try:
                    fim_res = fim.check_integrity(self.directory, auto_init=True)
                    modules["fim_status"] = fim_res.get("status")
                    modules["fim_tracked"] = fim_res.get("tracked_count", 0)
                    changes = len(fim_res.get("changes", []))
                    modules["fim_changes"] = changes
                    if fim_res.get("status") == "fail":
                        self._update_scan_step("fim", "warn", f"Detected {changes} config integrity change(s)")
                    else:
                        self._update_scan_step("fim", "done", f"Verified {modules['fim_tracked']} security config file(s)")
                except Exception:
                    modules["fim_status"] = "unavailable"
                    self._update_scan_step("fim", "warn", "File integrity baseline unavailable")

                self._update_scan_step("threats", "running", "Evaluating live telemetry & threat-hunting rules…")
                threats = self.active_threats()
                if threats.get("count", 0) > 0:
                    self._update_scan_step("threats", "warn", f"Flagged {threats['count']} active threat pattern(s)")
                else:
                    self._update_scan_step("threats", "done", "0 active threats in live telemetry")

            if profile == "heavy":
                self._update_scan_step("surface", "running", "Auditing risky exposed ports & loopback TLS…")
                try:
                    with self._lock:
                        local_exp = self._exposure
                    if isinstance(local_exp, dict):
                        surf = surface.audit_exposure(local_exp, probe_local_tls=True)
                        risky_services = surf.get("risky_services", [])
                        tls_issues = [item for item in surf.get("local_tls", []) if item.get("status") == "fail"]
                        s_count = len(risky_services) + len(tls_issues)
                        modules["surface_findings"] = s_count
                        modules["risky_services"] = len(risky_services)
                        modules["tls_issues"] = len(tls_issues)
                        self._update_scan_step(
                            "surface",
                            "warn" if s_count else "done",
                            f"Found {s_count} risky exposed service/TLS issue(s)" if s_count else "No risky exposed local services detected",
                        )
                    else:
                        self._update_scan_step("surface", "warn", "Socket tables unavailable for attack-surface audit")
                except Exception:
                    modules["surface_findings"] = None
                    self._update_scan_step("surface", "warn", "Attack-surface audit incomplete")

                self._update_scan_step("inventory", "running", "Scanning installed packages & matching advisories…")
                try:
                    collected = inventory.collect_inventory(self.directory)
                    feed_advisories = feeds.load_feed_advisories(self.directory)
                    with self._lock:
                        index, _ = intel.exploited_index(self._advisories)
                    sw_result = assessment.assess_documents(collected["sbom"], feed_advisories, exploited_ids=index)
                    save_local_json(self.software_path, sw_result)
                    with self._lock:
                        self._software = sw_result
                    pkg_count = collected.get("component_count", 0)
                    matched = sw_result.get("summary", {}).get("matched_findings", 0)
                    modules["packages_discovered"] = pkg_count
                    modules["package_findings"] = matched
                    modules["feed_advisories_loaded"] = len(feed_advisories)
                    if not feed_advisories:
                        self._update_scan_step(
                            "inventory",
                            "done",
                            f"Cataloged {pkg_count} packages · No OSV/feed advisories loaded yet",
                        )
                    else:
                        self._update_scan_step(
                            "inventory",
                            "warn" if matched else "done",
                            f"Audited {pkg_count} packages against {len(feed_advisories)} advisories · {matched} match(es)",
                        )
                except Exception:
                    modules["packages_discovered"] = None
                    self._update_scan_step("inventory", "warn", "Software inventory partially unavailable")

                self._update_scan_step("ai", "running", "Checking active AI protection tier…")
                try:
                    ai_info = self.ai_status(cached=False)
                    active_tier = ai_info.get("active_tier")
                    tier_ready = (
                        (active_tier == "cloud" and ai_info["tier2"]["ready"])
                        or (active_tier == "local" and ai_info["tier3"]["ready"])
                    )
                    if tier_ready:
                        triage = self.run_ai_triage()
                        modules["ai_triage"] = triage.get("tier_label")
                        self._update_scan_step("ai", "done", f"Completed via {triage.get('tier_label')}")
                    else:
                        self._update_scan_step("ai", "done", "Skipped (Tier 1 deterministic radar active)")
                except (BusyError, ai_tiers.AITierError):
                    self._update_scan_step("ai", "warn", "AI tier unavailable; deterministic results complete")

            self._update_scan_step("verdict", "running", "Building Red / Amber / Green report…")
            save_copy = None
            with self._lock:
                verdict_checks, changed = self._apply_dispositions_locked(all_checks)
                if changed:
                    save_copy = dict(self._dispositions)
            if save_copy is not None:
                self._save_dispositions_payload(save_copy)
            posture = assess_posture(
                {"updated_at": snapshot.get("scanned_at"), "checks": verdict_checks},
                monitoring=self.monitor.status(),
                threats=self.active_threats(),
            )
            self._update_scan_step(
                "verdict",
                "done" if posture["level"] == "green" else "warn",
                f"{posture['label']} · {posture['addressed']} of {posture['securable_total']} securable items addressed",
            )
        except Exception:
            error = "The scan stopped unexpectedly. Try running it again."
        finally:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            with self._lock:
                self._scan_error = error
                self._scan_duration_ms = elapsed_ms
                self._scan_modules = modules
                self._scan_progress = 100
                self._scan_running = False
            if error is None:
                self._maybe_auto_sync_telemetry()

    def open_check_settings(self, check_id: str) -> dict:
        return actions.open_settings(check_id)

    def start_batch_fix(self, ids: list[str] | None = None, *, include_scripts: bool = False) -> dict:
        with self._lock:
            if self._scan_running or self._fix_running:
                raise BusyError("A scan or fix is already running.")
            snapshot = self._scan or {}
            items = snapshot.get("checks", [])
            requested = set(ids) if ids is not None else None
            targets: list[tuple[dict, str]] = []
            for item in items:
                if item.get("status") != "fail":
                    continue
                if requested is not None and item.get("id") not in requested:
                    continue
                if item.get("can_fix") is True:
                    targets.append((item, "auto"))
                elif include_scripts:
                    guide = actions.action_guide_for(str(item.get("id") or ""))
                    if guide and guide.get("can_script_fix"):
                        targets.append((item, "script"))
            if not targets:
                raise ValueError("There are no automatic or scripted fixes waiting in the latest scan.")
            self._fix_running = True
            self._fix_batch_id += 1
            batch_id = self._fix_batch_id
            steps = [
                {
                    "id": item["id"],
                    "title": item.get("title", item["id"]),
                    "category": item.get("category", "Security"),
                    "mode": mode,
                    "status": "pending",
                    "message": "Queued for scripted OS fix…" if mode == "script" else "Queued for automatic protection…",
                    "rollback_id": None,
                }
                for item, mode in targets
            ]
            self._fix_batch = {
                "id": batch_id,
                "state": "running",
                "progress_pct": 5,
                "total": len(steps),
                "completed": 0,
                "succeeded": 0,
                "failed": 0,
                "steps": steps,
            }
        threading.Thread(
            target=self._run_batch_fix,
            args=([(item["id"], mode) for item, mode in targets],),
            name="wardr-batch-fix",
            daemon=True,
        ).start()
        return {"ok": True, "batch_id": batch_id, "count": len(targets)}

    def _run_batch_fix(self, targets: list) -> None:
        try:
            normalized = [(t, "auto") if isinstance(t, str) else t for t in targets]
            total = len(normalized) or 1
            for index, (identifier, mode) in enumerate(normalized):
                with self._lock:
                    for step in self._fix_batch["steps"]:
                        if step["id"] == identifier:
                            step["status"] = "running"
                            step["message"] = (
                                "Awaiting administrator approval & running fix script…"
                                if mode == "script" else "Applying rollback-safe protection…"
                            )
                            break
                    self._fix_batch["progress_pct"] = min(95, round(100 * (index + 0.35) / total))

                try:
                    if mode == "script":
                        result = actions.run_script_fix(identifier)
                    elif identifier in remediation.ALL_FIX_IDS:
                        result = remediation.apply_fix(identifier, state_dir=self.directory)
                    else:
                        result = checks.apply_fix(identifier)
                except Exception:
                    result = {"ok": False, "message": "Fix could not complete safely."}

                verified = result.get("check")
                with self._lock:
                    snapshot = self._scan or {}
                    items = snapshot.get("checks", [])
                    if isinstance(verified, dict) and verified.get("id") == identifier:
                        verified = {**verified, "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                        updated = {**snapshot, "checks": [verified if item["id"] == identifier else item for item in items]}
                        self._scan = updated
                        try:
                            save_local_json(self.scan_path, updated)
                        except OSError:
                            pass
                    ok = bool(result.get("ok")) and (not isinstance(verified, dict) or verified.get("status") == "pass")
                    for step in self._fix_batch["steps"]:
                        if step["id"] == identifier:
                            step["status"] = "fixed" if ok else "failed"
                            step["message"] = result.get("message") or ("Protected and verified." if ok else "Manual review needed.")
                            step["rollback_id"] = result.get("rollback_id")
                            break
                    self._fix_batch["completed"] += 1
                    if ok:
                        self._fix_batch["succeeded"] += 1
                    else:
                        self._fix_batch["failed"] += 1
                    self._fix_batch["progress_pct"] = round(100 * self._fix_batch["completed"] / total)
            with self._lock:
                self._fix_batch["state"] = "complete"
                self._fix_batch["progress_pct"] = 100
        finally:
            with self._lock:
                self._fix_running = False

    def apply_fix(self, identifier: str) -> dict:
        with self._lock:
            if self._scan_running or self._fix_running:
                raise BusyError("A scan or fix is already running.")
            snapshot = self._scan or {}
            items = snapshot.get("checks", [])
            if not any(
                item["id"] == identifier and item.get("status") == "fail" and item.get("can_fix") is True
                for item in items
            ):
                raise ValueError("The latest scan has no applicable automatic fix for this check.")
            self._fix_running = True
        try:
            try:
                if identifier in remediation.ALL_FIX_IDS:
                    result = remediation.apply_fix(identifier, state_dir=self.directory)
                else:
                    result = checks.apply_fix(identifier)
            except Exception:
                return {"ok": False, "message": "The fix stopped unexpectedly. Run a new scan to verify the setting."}
            verified = result.get("check")
            if isinstance(verified, dict) and verified.get("id") == identifier:
                verified = {**verified, "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                updated = {**snapshot, "checks": [verified if item["id"] == identifier else item for item in items]}
                result = {**result, "check": verified}
                with self._lock:
                    self._scan = updated
                try:
                    save_local_json(self.scan_path, updated)
                except OSError:
                    result = {**result, "message": f"{result['message']} Wardr could not save the updated checklist to disk."}
            return result
        finally:
            with self._lock:
                self._fix_running = False

    def preview_fix(self, identifier: str) -> dict:
        return remediation.preview_fix(identifier)

    def undo_fix(self, rollback_id: str) -> dict:
        with self._lock:
            if self._scan_running or self._fix_running:
                raise BusyError("A scan or fix is already running.")
            snapshot = self._scan or {}
            items = snapshot.get("checks", [])
            self._fix_running = True
        try:
            result = remediation.undo_fix(rollback_id, self.directory)
            verified = result.get("check")
            if isinstance(verified, dict) and verified.get("id"):
                check_id = verified["id"]
                verified = {**verified, "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                updated = {**snapshot, "checks": [verified if item["id"] == check_id else item for item in items]}
                result = {**result, "check": verified}
                with self._lock:
                    self._scan = updated
                try:
                    save_local_json(self.scan_path, updated)
                except OSError:
                    pass
            return result
        finally:
            with self._lock:
                self._fix_running = False

    def remediation_history(self) -> list[dict]:
        return remediation.list_history(self.directory)

    def auto_assess_software(self) -> dict:
        with self._lock:
            if self._software_running:
                raise BusyError("A software assessment is already running.")
            self._software_running = True
            index, _ = intel.exploited_index(self._advisories)
        try:
            collected = inventory.collect_inventory(self.directory)
            feed_advisories = feeds.load_feed_advisories(self.directory)
            result = assessment.assess_documents(
                collected["sbom"],
                feed_advisories,
                exploited_ids=index,
            )
            save_local_json(self.software_path, result)
            with self._lock:
                self._software = result
                catalog = self._advisories
            return {
                "inventory": {
                    "collected_at": collected["collected_at"],
                    "cached": collected["cached"],
                    "component_count": collected["component_count"],
                    "sources": collected["sources"],
                    "feed_advisories_used": len(feed_advisories),
                },
                "assessment": prioritize_software(result, catalog),
            }
        finally:
            with self._lock:
                self._software_running = False

    def feed_status(self) -> dict:
        return feeds.feed_status(self.directory)

    def preview_report(self, kind: str, item_id: str, *, notes: str = "", suspected_zero_day: bool = False) -> dict:
        source_item = None
        if kind == "finding":
            snapshot = self.scan_snapshot() or {}
            source_item = next((c for c in snapshot.get("checks", ()) if c.get("id") == item_id), None)
        elif kind == "alert":
            defense = self.defense_status()
            source_item = next((a for a in defense["hunting"].get("alerts", ()) if a.get("id") == item_id), None)
        elif kind == "software":
            defense = self.defense_status()
            sw = (defense["software"].get("result") or {}).get("findings", ())
            source_item = next((f for f in sw if f.get("id") == item_id), None)
        elif kind == "custom":
            source_item = {"id": item_id or "custom", "title": item_id or "Suspected vulnerability"}
        if source_item is None:
            raise ValueError("The selected item is no longer present in the latest local state.")
        return reporting.build_report(
            kind, source_item, host=self.host, notes=notes, suspected_zero_day=suspected_zero_day,
        )

    def submit_report(self, payload: dict) -> dict:
        return reporting.submit_report(payload, state_dir=self.directory, offline=self.offline)

    def start_advisory_refresh(self) -> None:
        if self.offline:
            raise ValueError("Advisory downloads are disabled in offline mode.")
        with self._lock:
            if self._advisory_running:
                raise BusyError("An advisory refresh is already running.")
            self._advisory_running = True
            self._advisory_error = None
        threading.Thread(target=self._run_advisory_refresh, name="wardr-advisories", daemon=True).start()

    def _run_advisory_refresh(self) -> None:
        error = None
        try:
            updated = intel.refresh_advisories(self.directory)
            with self._lock:
                self._advisories = updated
        except intel.AdvisoryError as exc:
            error = str(exc)
        except Exception:
            error = "The CISA catalog could not be refreshed."
        finally:
            with self._lock:
                self._advisory_running = False
                self._advisory_error = error
