"""Lightweight Wardr Fleet enrollment and zero-RCE continuous check-in agent."""

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import platform
import ssl
import tempfile
import time
from urllib.parse import urlsplit

from . import (
    assessment, checks, exposure, feeds, fim, hunting, intel, inventory,
    remediation, surface, updater,
)
from .monitor import Monitor
from .state import host_info, read_software, save_local_json


_CRED_FILE = "fleet-credentials.json"
_IO_TIMEOUT = 15
_MAX_RESPONSE_BYTES = 256 * 1024


class FleetAgentError(RuntimeError):
    """Fleet enrollment or check-in could not complete."""


def _parse_server_url(server_url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(server_url.strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise FleetAgentError("Provide a valid Fleet server URL without embedded credentials.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise FleetAgentError("Remote Wardr Fleet servers must use HTTPS.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    prefix = parsed.path.rstrip("/")
    return parsed.scheme, parsed.hostname, port, prefix


def _http_post(server_url: str, path: str, body: dict, *, bearer: str | None = None) -> tuple[int, dict]:
    scheme, host, port, prefix = _parse_server_url(server_url)
    raw = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"Wardr/{updater.current_version()}",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=_IO_TIMEOUT, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=_IO_TIMEOUT)
    try:
        conn.request("POST", prefix + path, body=raw, headers=headers)
        resp = conn.getresponse()
        data = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(data) > _MAX_RESPONSE_BYTES:
            raise FleetAgentError("Fleet server response exceeded size limit.")
        try:
            parsed = json.loads(data) if data else {}
        except ValueError:
            parsed = {"raw": data.decode("utf-8", errors="replace")[:200]}
        return resp.status, parsed if isinstance(parsed, dict) else {}
    except OSError as exc:
        raise FleetAgentError(f"Could not reach Wardr Fleet server at {server_url}: {exc}") from exc
    finally:
        conn.close()


def _save_credentials(state_dir: Path, creds: dict) -> None:
    path = Path(state_dir) / _CRED_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".fleet-", suffix=".json")
    tmp = Path(name)
    try:
        os.chmod(name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(creds, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def load_credentials(state_dir: Path) -> dict | None:
    path = Path(state_dir) / _CRED_FILE
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if (
            isinstance(parsed, dict)
            and isinstance(parsed.get("server_url"), str)
            and isinstance(parsed.get("host_id"), str)
            and isinstance(parsed.get("device_token"), str)
        ):
            return parsed
    except (OSError, ValueError):
        pass
    return None


def enroll(
    state_dir: Path,
    server_url: str,
    enrollment_token: str,
    *,
    role: str | None = None,
    tags: list[str] | str = (),
) -> dict:
    """Enroll this host into a Wardr Fleet server and save its 0600 device credentials."""
    _parse_server_url(server_url)
    info = host_info()
    payload = {
        "enrollment_token": enrollment_token.strip(),
        "hostname": info["name"],
        "os": info["os"],
        "os_version": info["version"],
        "arch": platform.machine() or "unknown",
        "wardr_version": updater.current_version(),
        "tags": tags,
    }
    if role:
        payload["role"] = role
    status, resp = _http_post(server_url, "/api/fleet/enroll", payload)
    if status not in (200, 201) or not resp.get("device_token"):
        raise FleetAgentError(resp.get("error") or f"Enrollment rejected (HTTP {status}).")

    creds = {
        "server_url": server_url.rstrip("/"),
        "host_id": resp["host_id"],
        "device_token": resp["device_token"],
        "role": resp.get("role", role or "workstation"),
        "tags": resp.get("tags", []),
        "enrolled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _save_credentials(state_dir, creds)
    return {
        "enrolled": True,
        "server_url": creds["server_url"],
        "host_id": creds["host_id"],
        "role": creds["role"],
        "tags": creds["tags"],
    }


def collect_heartbeat(state_dir: Path, *, monitor: Monitor | None = None) -> dict:
    """Collect a fast, compact defensive snapshot from this host."""
    info = host_info()
    scan_result = checks.scan()
    save_local_json(state_dir / "latest-scan.json", scan_result)
    exp_result = exposure.collect_exposure()
    surf_result = surface.audit_exposure(exp_result, probe_local_tls=False)
    fim_result = fim.check_integrity(state_dir)
    mon = monitor or Monitor(state_dir=state_dir)
    mon_status = mon.poll()
    feed_rules = feeds.load_feed_rules(state_dir)
    hunt_result = hunting.analyze(mon_status, feed_rules=feed_rules)
    inv_result = inventory.collect_inventory(state_dir)
    sw = read_software(state_dir / "software-assessment.json") or {}

    return {
        "wardr_version": updater.current_version(),
        "os_version": info["version"],
        "checks": scan_result.get("checks", []),
        "alerts": hunt_result.get("alerts", []),
        "risky_services": surf_result.get("risky_services", []),
        "software_findings": sw.get("findings", []),
        "inventory_count": inv_result.get("component_count", 0),
        "fim": {"status": fim_result.get("status", "unknown"), "changes": fim_result.get("changes", [])},
    }


def _execute_allowlisted_command(state_dir: Path, command: dict) -> tuple[bool, dict]:
    """Execute ONLY locally compiled, allowlisted Wardr actions (zero remote code execution)."""
    action = command.get("action")
    params = command.get("params") if isinstance(command.get("params"), dict) else {}

    if action == "scan":
        res = checks.scan()
        save_local_json(state_dir / "latest-scan.json", res)
        return True, {"message": f"Completed posture scan ({len(res.get('checks', []))} checks)."}
    if action == "exposure":
        exp = exposure.collect_exposure()
        surf = surface.audit_exposure(exp, probe_local_tls=False)
        return True, {"listeners": len(exp.get("listeners", [])), "risky_services": surf["summary"]["risky_service_count"]}
    if action == "inventory":
        inv = inventory.collect_inventory(state_dir, force=True)
        catalog = intel.advisory_status(state_dir)
        index, _ = intel.exploited_index(catalog)
        advs = feeds.load_feed_advisories(state_dir)
        assessed = assessment.assess_documents(inv["sbom"], advs, exploited_ids=index)
        save_local_json(state_dir / "software-assessment.json", assessed)
        return True, {
            "component_count": inv["component_count"],
            "matched_findings": assessed["summary"]["matched_findings"],
        }
    if action == "fim_check":
        res = fim.check_integrity(state_dir)
        return True, {"status": res["status"], "changes": len(res.get("changes", []))}
    if action == "apply_fix":
        fix_id = params.get("id")
        if fix_id not in remediation.ALL_FIX_IDS:
            return False, {"message": "Rejected non-allowlisted fix ID."}
        res = remediation.apply_fix(fix_id, state_dir=state_dir)
        return bool(res.get("ok")), {
            "message": res.get("message", ""),
            "rollback_id": res.get("rollback_id"),
            "status": (res.get("check") or {}).get("status"),
        }
    if action == "undo_fix":
        rollback_id = params.get("rollback_id")
        res = remediation.undo_fix(str(rollback_id or ""), state_dir)
        return bool(res.get("ok")), {"message": res.get("message", "")}
    return False, {"message": f"Rejected unsupported fleet command: {action}"}


def checkin_once(state_dir: Path, *, monitor: Monitor | None = None) -> dict:
    """Send one fleet heartbeat, execute any queued allowlisted commands, and report verified outcomes."""
    creds = load_credentials(state_dir)
    if creds is None:
        raise FleetAgentError("This host is not enrolled in a Wardr Fleet. Run `wardr fleet enroll` first.")

    snapshot = collect_heartbeat(state_dir, monitor=monitor)
    status, resp = _http_post(
        creds["server_url"], "/api/fleet/heartbeat", snapshot, bearer=creds["device_token"],
    )
    if status != 200:
        raise FleetAgentError(resp.get("error") or f"Fleet heartbeat failed (HTTP {status}).")

    executed = []
    mutated = False
    for cmd in resp.get("commands", ()):
        cmd_id = cmd.get("command_id")
        ok, outcome = _execute_allowlisted_command(state_dir, cmd)
        if cmd.get("action") in ("apply_fix", "undo_fix", "inventory", "scan", "fim_check"):
            mutated = True
        _http_post(
            creds["server_url"], f"/api/fleet/commands/{cmd_id}/result",
            {"ok": ok, "result": outcome}, bearer=creds["device_token"],
        )
        executed.append({"command_id": cmd_id, "action": cmd.get("action"), "ok": ok, "result": outcome})

    # If a command updated host posture or software state, immediately push a fresh verified snapshot.
    if mutated:
        refreshed = collect_heartbeat(state_dir, monitor=monitor)
        _http_post(creds["server_url"], "/api/fleet/heartbeat", refreshed, bearer=creds["device_token"])

    return {
        "ok": True,
        "host_id": creds["host_id"],
        "posture_score": resp.get("posture_score"),
        "commands_executed": executed,
    }


def agent_status(state_dir: Path) -> dict:
    creds = load_credentials(state_dir)
    if creds is None:
        return {"enrolled": False, "detail": "Not enrolled in a Wardr Fleet."}
    return {
        "enrolled": True,
        "server_url": creds["server_url"],
        "host_id": creds["host_id"],
        "role": creds.get("role"),
        "tags": creds.get("tags", []),
        "enrolled_at": creds.get("enrolled_at"),
    }


def run_agent(state_dir: Path, interval: int = 60) -> None:
    """Continuously check in with the Fleet control plane at low overhead."""
    mon = Monitor(interval=max(15, min(interval, 300)), state_dir=state_dir)
    while True:
        started = time.monotonic()
        try:
            outcome = checkin_once(state_dir, monitor=mon)
            print(json.dumps(outcome, ensure_ascii=True), flush=True)
        except FleetAgentError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True), flush=True)
        elapsed = time.monotonic() - started
        time.sleep(max(5.0, interval - elapsed))
