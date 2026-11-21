"""Local state and the dashboard's scan and advisory lifecycle."""

import json
import os
import platform
import socket
import stat
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import assessment, checks, exposure, feeds, hunting, intel, inventory, local_ai, remediation, reporting
from .monitor import Monitor
from .plan import build_plan, prioritize_software
from .report import SEVERITIES


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
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise PermissionError("Choose a Wardr state directory owned and writable only by the current account.")


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


class WardrState:
    def __init__(self, directory: Path, interval: int = 30, *, offline: bool = False):
        prepare_state_dir(directory)
        self.directory = directory
        self.scan_path = directory / "latest-scan.json"
        self.software_path = directory / "software-assessment.json"
        self.host = host_info()
        self.offline = offline
        self.monitor = Monitor(interval=interval, state_dir=directory)
        self._lock = threading.Lock()
        self._scan_error = None
        self._scan_running = False
        self._fix_running = False
        self._advisory_running = False
        self._advisory_error = None
        self._exposure_running = False
        self._exposure_error = None
        self._exposure = None
        self._software_running = False
        self._ai_running = False
        self._scan = read_scan(self.scan_path, self.host["name"])
        self._software = read_software(self.software_path)
        self._advisories = intel.advisory_status(directory)

    def status(self) -> dict:
        with self._lock:
            snapshot = self._scan or {}
            scan = {
                "state": (
                    "running" if self._scan_running else
                    "error" if self._scan_error else
                    "complete" if self._scan is not None else "idle"
                ),
                "updated_at": snapshot.get("scanned_at"),
                "error": self._scan_error,
                "checks": snapshot.get("checks", []),
                "fix_running": self._fix_running,
            }
            advisories = {
                **intel.public_status(self._advisories),
                "state": (
                    "running" if self._advisory_running else
                    "error" if self._advisory_error else
                    "ready" if self._advisories.get("available") else "idle"
                ),
                "error": self._advisory_error,
            }
        return {"host": self.host, "scan": scan, "monitoring": self.monitor.status(), "intel": advisories,
                "offline": self.offline}

    def defense_status(self) -> dict:
        with self._lock:
            scan = self._scan
            local_exposure = self._exposure
            collecting = self._exposure_running
            exposure_error = self._exposure_error
            software = self._software
            matching = self._software_running
            catalog = self._advisories
        feed_rules = feeds.load_feed_rules(self.directory)
        hunting_result = hunting.analyze(self.monitor.status(), feed_rules=feed_rules)
        prioritized = prioritize_software(software, catalog)
        return {
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

    def start_scan(self) -> None:
        with self._lock:
            if self._scan_running or self._fix_running:
                raise BusyError("A scan or fix is already running.")
            self._scan_running = True
            self._scan_error = None
        threading.Thread(target=self._run_scan, name="wardr-scan", daemon=True).start()

    def _run_scan(self) -> None:
        error = None
        try:
            snapshot = checks.scan()
            with self._lock:
                self._scan = snapshot
            try:
                save_local_json(self.scan_path, snapshot)
            except OSError:
                error = "The scan completed. Wardr could not save it to local storage."
        except Exception:
            error = "The scan stopped unexpectedly. Try running it again."
        finally:
            with self._lock:
                self._scan_error = error
                self._scan_running = False

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
