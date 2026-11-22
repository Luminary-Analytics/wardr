"""Opt-in, client-redacted central vulnerability and zero-day reporting."""

from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import tempfile
import time
from urllib.parse import urlsplit


INTAKE_HOST = "intake.getwardr.com"
INTAKE_PATH = "/v1/reports"
_RECEIPTS_FILE = "submitted-reports.json"
_MAX_RECEIPTS = 100
_MAX_REPORT_BYTES = 32 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024
_IO_TIMEOUT = 10

_REDACT_PATTERNS = (
    ("secret", re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----")),
    ("secret", re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I)),
    ("secret", re.compile(r"://[^/\s:@]+:[^/\s@]+@")),
    ("secret", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("secret", re.compile(
        r"\b(?:"
        r"sk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{20,}|"
        r"gsk_[A-Za-z0-9]{20,}|"
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|"
        r"glpat-[A-Za-z0-9_-]{16,}|"
        r"npm_[A-Za-z0-9]{20,}|"
        r"pypi-[A-Za-z0-9_-]{20,}|"
        r"AIza[0-9A-Za-z_-]{20,}|"
        r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
        r"xox[baprs]-[0-9A-Za-z-]{15,}|"
        r"hf_[A-Za-z0-9]{20,}"
        r")\b"
    )),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("home_path", re.compile(r"(?:/Users/[^/\s\"']+|/home/[^/\s\"']+|/root(?=/|\b)|[A-Za-z]:[\\/]Users[\\/][^\\/\s\"']+)", re.I)),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"(?<![0-9a-fA-F:])(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{0,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::1)(?![0-9a-fA-F:])")),
)
_REPLACEMENTS = {
    "secret": "<REDACTED_SECRET>",
    "email": "<EMAIL>",
    "home_path": "<HOME>",
    "ipv4": "<IP>",
    "ipv6": "<IP>",
    "hostname": "<HOST>",
    "username": "<USER>",
}


class ReportingError(RuntimeError):
    """A sanitized report could not be built, exported, or submitted."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _local_identifiers(host: dict | None) -> list[tuple[str, str]]:
    pairs = []
    host_name = (host or {}).get("name") or socket.gethostname()
    if isinstance(host_name, str) and len(host_name.strip()) >= 2:
        pairs.append(("hostname", host_name.strip()))
        short_host = host_name.strip().split(".")[0]
        if len(short_host) >= 2 and short_host != host_name.strip():
            pairs.append(("hostname", short_host))

    usernames = set()
    for env_key in ("USER", "USERNAME", "LOGNAME"):
        val = os.environ.get(env_key, "").strip()
        if len(val) >= 2:
            usernames.add(val)
    if os.name == "posix":
        import pwd
        try:
            name = pwd.getpwuid(os.geteuid()).pw_name
            if len(name) >= 2:
                usernames.add(name)
        except KeyError:
            pass
    for name in sorted(usernames, key=len, reverse=True):
        pairs.append(("username", name))
    return pairs


def redact_text(text: str, *, host: dict | None = None) -> tuple[str, dict[str, int]]:
    """Strip PII, paths, IPs, hostnames, usernames, and secret patterns from text."""
    if not isinstance(text, str):
        return "", {}
    counts: dict[str, int] = {}
    cleaned = "".join(ch if ch.isprintable() or ch == "\n" else " " for ch in text)

    for category, pattern in _REDACT_PATTERNS:
        replacement = _REPLACEMENTS[category]
        cleaned, n = pattern.subn(replacement, cleaned)
        if n:
            counts[category] = counts.get(category, 0) + n

    for category, token in _local_identifiers(host):
        pattern = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(token) + r"(?![A-Za-z0-9_-])", re.I)
        cleaned, n = pattern.subn(_REPLACEMENTS[category], cleaned)
        if n:
            counts[category] = counts.get(category, 0) + n

    return cleaned.strip(), counts


def _merge_counts(target: dict[str, int], addition: dict[str, int]) -> None:
    for key, val in addition.items():
        target[key] = target.get(key, 0) + val


def build_report(
    kind: str,
    item: dict,
    *,
    host: dict | None = None,
    notes: str = "",
    suspected_zero_day: bool = False,
) -> dict:
    """Create a strictly redacted, reviewable Community Vulnerability / Zero-Day Report."""
    if kind not in ("finding", "alert", "software", "custom"):
        raise ReportingError("Report kind must be finding, alert, software, or custom.")
    if not isinstance(item, dict):
        raise ReportingError("Report source item must be a JSON object.")

    redactions: dict[str, int] = {}

    def clean(value, limit: int) -> str:
        if not value:
            return ""
        redacted, c = redact_text(str(value)[:limit], host=host)
        _merge_counts(redactions, c)
        return redacted

    item_id = clean(item.get("id") or "custom", 120)
    title = clean(item.get("title") or item.get("advisory_id") or "Security observation", 200)
    severity = str(item.get("severity") or "medium").lower()
    if severity not in ("critical", "high", "medium", "low", "unknown"):
        severity = "medium"

    raw_evidence = item.get("evidence")
    evidence_lines = []
    if isinstance(raw_evidence, str):
        evidence_lines.append(clean(raw_evidence, 1000))
    elif isinstance(raw_evidence, list):
        for entry in raw_evidence[:12]:
            if isinstance(entry, dict):
                line = f"{entry.get('source', '')} | {entry.get('title', '')} | {entry.get('detail', '')}"
                evidence_lines.append(clean(line, 600))
            else:
                evidence_lines.append(clean(entry, 600))
    evidence_lines = [line for line in evidence_lines if line]

    summary = clean(item.get("summary") or item.get("risk") or "", 1000)
    user_notes = clean(notes, 1000)

    package_info = None
    if item.get("package") or item.get("purl"):
        package_info = {
            "package": clean(item.get("package") or "", 160),
            "version": clean(item.get("version") or "", 120),
            "advisory_id": clean(item.get("advisory_id") or "", 120),
        }

    os_family = (host or {}).get("os") or {"Darwin": "macOS"}.get(platform.system(), platform.system())
    arch = platform.machine() or "unknown"

    fingerprint_input = json.dumps(
        {
            "kind": kind,
            "id": item_id,
            "title": title,
            "os": os_family,
            "package": package_info,
            "evidence_count": len(evidence_lines),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint = hashlib.sha256(fingerprint_input).hexdigest()[:32]

    payload = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "report_kind": kind,
        "suspected_zero_day": bool(suspected_zero_day),
        "fingerprint": fingerprint,
        "environment": {
            "os": clean(os_family, 64),
            "arch": clean(arch, 64),
        },
        "signal": {
            "id": item_id,
            "title": title,
            "severity": severity,
            "summary": summary,
            "evidence": evidence_lines,
            "package": package_info,
        },
        "operator_notes": user_notes,
    }
    encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    if len(encoded) > _MAX_REPORT_BYTES:
        raise ReportingError("The redacted report exceeds Wardr's maximum payload size.")

    return {
        "payload": payload,
        "redactions": redactions,
        "redaction_total": sum(redactions.values()),
        "bytes": len(encoded),
    }


def _validate_payload(payload: dict) -> bytes:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ReportingError("Invalid report payload schema.")
    if payload.get("report_kind") not in ("finding", "alert", "software", "custom"):
        raise ReportingError("Invalid report kind.")
    if not isinstance(payload.get("signal"), dict) or not isinstance(payload.get("fingerprint"), str):
        raise ReportingError("Incomplete report payload.")
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if not 0 < len(raw) <= _MAX_REPORT_BYTES:
        raise ReportingError("Report payload size is out of bounds.")
    return raw


def _save_receipt(state_dir: Path | None, receipt: dict) -> None:
    if state_dir is None:
        return
    path = Path(state_dir) / _RECEIPTS_FILE
    existing = list_receipts(state_dir)
    existing.insert(0, receipt)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".rep-", suffix=".json")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(existing[:_MAX_RECEIPTS], handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def list_receipts(state_dir: Path) -> list[dict]:
    path = Path(state_dir) / _RECEIPTS_FILE
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, list):
            return [row for row in parsed if isinstance(row, dict)][:_MAX_RECEIPTS]
    except (OSError, ValueError):
        pass
    return []


def export_report(payload: dict, destination: Path) -> dict:
    """Write a redacted report to a local JSON file (for air-gapped or manual CVD sharing)."""
    raw = _validate_payload(payload)
    target = Path(destination)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw + b"\n")
    except OSError as exc:
        raise ReportingError(f"Could not write report file: {target}") from exc
    return {
        "exported": True,
        "path": str(target),
        "fingerprint": payload["fingerprint"],
        "bytes": len(raw),
    }


def submit_report(
    payload: dict,
    *,
    state_dir: Path | None = None,
    offline: bool = False,
    endpoint: str | None = None,
) -> dict:
    """Submit a user-approved, redacted report over HTTPS to Wardr's central intake."""
    if offline:
        raise ReportingError("Central report submission is disabled in offline mode. Export the redacted report locally instead.")
    raw = _validate_payload(payload)
    host = INTAKE_HOST
    path = INTAKE_PATH
    port = 443
    if endpoint is not None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ReportingError("Central reporting requires an HTTPS endpoint without embedded credentials.")
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or INTAKE_PATH

    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=_IO_TIMEOUT, context=context)
    deadline = time.monotonic() + _IO_TIMEOUT
    try:
        conn.request(
            "POST",
            path,
            body=raw,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Wardr/1.0",
            },
        )
        response = conn.getresponse()
        body = bytearray()
        while time.monotonic() < deadline:
            chunk = response.read(4096)
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ReportingError("Intake server response exceeded limit.")
        if response.status not in (200, 201, 202):
            raise ReportingError(f"Central intake returned HTTP {response.status}.")
        try:
            ack = json.loads(body) if body else {}
        except ValueError:
            ack = {}
    except OSError as exc:
        raise ReportingError("Could not reach the Wardr central intake service. You can export the redacted report locally.") from exc
    finally:
        conn.close()

    receipt = {
        "submitted_at": _utc_now(),
        "fingerprint": payload["fingerprint"],
        "report_kind": payload["report_kind"],
        "suspected_zero_day": bool(payload.get("suspected_zero_day")),
        "title": payload["signal"].get("title", ""),
        "case_id": str(ack.get("case_id") or payload["fingerprint"][:12]),
    }
    _save_receipt(state_dir, receipt)
    return {"submitted": True, "receipt": receipt}
