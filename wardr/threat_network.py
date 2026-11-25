"""Self-hostable Wardr Threat Network intake, zero-day clustering, and Ed25519 feed server."""

from collections import deque
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import time
from urllib.parse import urlsplit

from . import feeds, oauth_broker


_MAX_REPORT_BYTES = 32 * 1024
_MAX_TELEMETRY_BYTES = 48 * 1024
_MAX_FEED_PUBLISH_BYTES = 2 * 1024 * 1024
_RATE_WINDOW_SECONDS = 60.0
_RATE_LIMIT_PER_IP = 30
_ALLOWED_TRIAGE_STATUS = ("open", "escalated", "vendor_notified", "cve_assigned", "mitigated", "closed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    case_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    report_kind TEXT NOT NULL,
    suspected_zero_day INTEGER NOT NULL,
    reporter_hash TEXT NOT NULL,
    os_family TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clusters (
    fingerprint TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    report_count INTEGER NOT NULL,
    unique_reporters INTEGER NOT NULL,
    zero_day_votes INTEGER NOT NULL,
    triage_status TEXT NOT NULL,
    sample_title TEXT NOT NULL,
    sample_kind TEXT NOT NULL,
    cve_id TEXT
);
CREATE TABLE IF NOT EXISTS telemetry_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    account_hash TEXT NOT NULL,
    reporter_hash TEXT NOT NULL,
    wardr_version TEXT NOT NULL,
    os_family TEXT NOT NULL,
    os_version TEXT NOT NULL,
    arch TEXT NOT NULL,
    posture_level TEXT NOT NULL,
    coverage_pct INTEGER,
    pentest_score_pct INTEGER,
    active_threat_count INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_fingerprint ON reports(fingerprint);
CREATE INDEX IF NOT EXISTS idx_telemetry_received_at ON telemetry_snapshots(received_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_account_hash ON telemetry_snapshots(account_hash);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_incoming_report(body: object) -> dict:
    if not isinstance(body, dict) or body.get("schema_version") != 1:
        raise ValueError("Unsupported report schema_version.")
    kind = body.get("report_kind")
    if kind not in ("finding", "alert", "software", "custom"):
        raise ValueError("Invalid report_kind.")
    fingerprint = body.get("fingerprint")
    if not isinstance(fingerprint, str) or not 16 <= len(fingerprint) <= 64 or not fingerprint.isalnum():
        raise ValueError("Invalid report fingerprint.")
    signal = body.get("signal")
    if not isinstance(signal, dict) or not isinstance(signal.get("title"), str) or not signal["title"].strip():
        raise ValueError("Report signal must include a non-empty title.")
    env = body.get("environment")
    if not isinstance(env, dict) or not isinstance(env.get("os"), str):
        raise ValueError("Report environment must include an os string.")
    if not isinstance(body.get("suspected_zero_day", False), bool):
        raise ValueError("suspected_zero_day must be a boolean.")
    return body


def _validate_incoming_telemetry(body: object) -> dict:
    if not isinstance(body, dict) or body.get("schema_version") != 1:
        raise ValueError("Unsupported telemetry schema_version.")
    account_hash = body.get("account_hash")
    if not isinstance(account_hash, str) or not 8 <= len(account_hash) <= 64 or not account_hash.isalnum():
        raise ValueError("Invalid telemetry account_hash.")
    wardr_version = body.get("wardr_version")
    if not isinstance(wardr_version, str) or not wardr_version.strip() or len(wardr_version) > 40:
        raise ValueError("Invalid wardr_version.")
    opt_in = body.get("opt_in")
    if not isinstance(opt_in, dict):
        raise ValueError("Telemetry payload must include an opt_in object.")
    opt_sys = opt_in.get("system_diagnostics", False)
    opt_thr = opt_in.get("threat_intelligence", False)
    if not isinstance(opt_sys, bool) or not isinstance(opt_thr, bool):
        raise ValueError("opt_in flags must be booleans.")
    if not opt_sys and not opt_thr:
        raise ValueError("At least one telemetry opt_in flag must be enabled.")
    sys_diag = body.get("system_diagnostics")
    if sys_diag is not None:
        if not isinstance(sys_diag, dict):
            raise ValueError("system_diagnostics must be an object.")
        checks_summary = sys_diag.get("checks_summary")
        if checks_summary is not None:
            if not isinstance(checks_summary, list) or len(checks_summary) > 100:
                raise ValueError("checks_summary must be a list of at most 100 items.")
            for item in checks_summary:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str) or len(item["id"]) > 120:
                    raise ValueError("Each checks_summary entry must include a valid string id.")
        pt_summary = sys_diag.get("pentest_summary")
        if pt_summary is not None:
            if not isinstance(pt_summary, dict):
                raise ValueError("pentest_summary must be an object.")
            probes = pt_summary.get("probes")
            if probes is not None:
                if not isinstance(probes, list) or len(probes) > 20:
                    raise ValueError("pentest_summary.probes must be a list of at most 20 items.")
                for probe in probes:
                    if not isinstance(probe, dict) or not isinstance(probe.get("id"), str) or len(probe["id"]) > 80:
                        raise ValueError("Each pentest probe entry must include a valid string id.")
    threat_intel = body.get("threat_intelligence")
    if threat_intel is not None:
        if not isinstance(threat_intel, dict):
            raise ValueError("threat_intelligence must be an object.")
        sc_matches = threat_intel.get("supply_chain_signatures_matched")
        if sc_matches is not None and (not isinstance(sc_matches, list) or len(sc_matches) > 50):
            raise ValueError("supply_chain_signatures_matched must be a list of at most 50 items.")
        risky_ports = threat_intel.get("exposed_risky_ports")
        if risky_ports is not None and (not isinstance(risky_ports, list) or len(risky_ports) > 32):
            raise ValueError("exposed_risky_ports must be a list of at most 32 items.")
    return body


class _RateLimiter:
    def __init__(self, limit: int = _RATE_LIMIT_PER_IP, window: float = _RATE_WINDOW_SECONDS):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            if len(self._buckets) > 4096:
                stale = [k for k, q in self._buckets.items() if not q or q[-1] < cutoff]
                for k in stale:
                    del self._buckets[k]
            return True


class ThreatNetworkStore:
    """SQLite-backed intake storage, automatic zero-day clustering, and signed feed archive."""

    def __init__(
        self,
        data_dir: Path,
        *,
        escalation_reporters: int = 3,
        zero_day_threshold: int = 2,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = self.data_dir / "threat-network.sqlite3"
        self.feed_path = self.data_dir / "defense-v1.json"
        self.sig_path = self.data_dir / "defense-v1.json.sig"
        self.escalation_reporters = max(1, escalation_reporters)
        self.zero_day_threshold = max(1, zero_day_threshold)
        self._lock = threading.Lock()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT value FROM meta WHERE key = 'reporter_salt'").fetchone()
            if row and isinstance(row[0], str) and len(row[0]) >= 16:
                self._salt = row[0]
            else:
                self._salt = secrets.token_hex(16)
                conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('reporter_salt', ?)", (self._salt,))
        if os.name == "posix" and self.db_path.exists():
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _reporter_hash(self, client_ip: str) -> str:
        return hashlib.sha256(f"{self._salt}:{client_ip}".encode("utf-8")).hexdigest()[:24]

    def ingest_report(self, payload: dict, *, client_ip: str = "unknown") -> dict:
        validated = _validate_incoming_report(payload)
        now = _utc_now()
        case_id = f"WR-{secrets.token_hex(6).upper()}"
        fp = validated["fingerprint"]
        kind = validated["report_kind"]
        zero_day = 1 if validated.get("suspected_zero_day") else 0
        reporter_hash = self._reporter_hash(client_ip)
        os_family = validated["environment"]["os"][:64]
        title = validated["signal"]["title"][:200]
        raw = json.dumps(validated, ensure_ascii=True, separators=(",", ":"))

        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            conn.execute(
                "INSERT INTO reports (case_id, received_at, fingerprint, report_kind, suspected_zero_day, "
                "reporter_hash, os_family, title, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, now, fp, kind, zero_day, reporter_hash, os_family, title, raw),
            )
            stats = conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT reporter_hash), "
                "COUNT(DISTINCT CASE WHEN suspected_zero_day = 1 THEN reporter_hash END) "
                "FROM reports WHERE fingerprint = ?",
                (fp,),
            ).fetchone()
            total_reports, unique_reporters, zero_day_votes = int(stats[0]), int(stats[1]), int(stats[2] or 0)
            existing = conn.execute(
                "SELECT first_seen, triage_status, cve_id FROM clusters WHERE fingerprint = ?", (fp,)
            ).fetchone()
            should_escalate = (
                unique_reporters >= self.escalation_reporters
                or zero_day_votes >= self.zero_day_threshold
            )
            if existing is None:
                triage_status = "escalated" if should_escalate else "open"
                conn.execute(
                    "INSERT INTO clusters (fingerprint, first_seen, last_seen, report_count, unique_reporters, "
                    "zero_day_votes, triage_status, sample_title, sample_kind, cve_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (fp, now, now, total_reports, unique_reporters, zero_day_votes, triage_status, title, kind),
                )
            else:
                current_status = existing[1]
                triage_status = (
                    "escalated" if current_status == "open" and should_escalate else current_status
                )
                conn.execute(
                    "UPDATE clusters SET last_seen = ?, report_count = ?, unique_reporters = ?, "
                    "zero_day_votes = ?, triage_status = ? WHERE fingerprint = ?",
                    (now, total_reports, unique_reporters, zero_day_votes, triage_status, fp),
                )

        return {
            "accepted": True,
            "case_id": case_id,
            "fingerprint": fp,
            "cluster_reports": total_reports,
            "unique_reporters": unique_reporters,
            "triage_status": triage_status,
        }

    def list_clusters(self, *, limit: int = 100) -> list[dict]:
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn:
            rows = conn.execute(
                "SELECT fingerprint, first_seen, last_seen, report_count, unique_reporters, zero_day_votes, "
                "triage_status, sample_title, sample_kind, cve_id FROM clusters "
                "ORDER BY (triage_status = 'escalated') DESC, zero_day_votes DESC, report_count DESC, last_seen DESC "
                "LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [
            {
                "fingerprint": row[0],
                "first_seen": row[1],
                "last_seen": row[2],
                "report_count": row[3],
                "unique_reporters": row[4],
                "zero_day_votes": row[5],
                "triage_status": row[6],
                "sample_title": row[7],
                "sample_kind": row[8],
                "cve_id": row[9],
            }
            for row in rows
        ]

    def update_cluster(self, fingerprint: str, *, triage_status: str, cve_id: str | None = None) -> dict:
        if triage_status not in _ALLOWED_TRIAGE_STATUS:
            raise ValueError(f"triage_status must be one of: {', '.join(_ALLOWED_TRIAGE_STATUS)}.")
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            cur = conn.execute(
                "UPDATE clusters SET triage_status = ?, cve_id = COALESCE(?, cve_id) WHERE fingerprint = ?",
                (triage_status, cve_id, fingerprint),
            )
            if cur.rowcount == 0:
                raise KeyError("Cluster fingerprint not found.")
        return {"updated": True, "fingerprint": fingerprint, "triage_status": triage_status, "cve_id": cve_id}

    def publish_feed(self, feed_document: dict, signing_key_pem: bytes) -> dict:
        """Validate, sign with Ed25519, and atomically publish the active Rapid-Defense Feed."""
        raw = json.dumps(feed_document, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        sig = feeds.sign_feed_bytes(raw, signing_key_pem)
        with self._lock:
            for target, content in ((self.feed_path, raw), (self.sig_path, sig)):
                fd, name = tempfile.mkstemp(dir=self.data_dir, prefix=".pub-")
                tmp = Path(name)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    tmp.replace(target)
                finally:
                    tmp.unlink(missing_ok=True)
        return {
            "published": True,
            "version": feed_document.get("version"),
            "rule_count": len(feed_document.get("rules", ())),
            "advisory_count": len(feed_document.get("advisories", ())),
            "bytes": len(raw),
        }

    def read_published_feed(self) -> tuple[bytes, bytes] | None:
        with self._lock:
            try:
                return self.feed_path.read_bytes(), self.sig_path.read_bytes()
            except OSError:
                return None

    def ingest_telemetry(self, payload: dict, *, client_ip: str = "unknown") -> dict:
        validated = _validate_incoming_telemetry(payload)
        now = _utc_now()
        snapshot_id = f"TEL-{secrets.token_hex(6).upper()}"
        account_hash = validated["account_hash"][:64]
        reporter_hash = self._reporter_hash(client_ip)
        wardr_version = validated["wardr_version"].strip()[:40]
        sys_diag = validated.get("system_diagnostics") if isinstance(validated.get("system_diagnostics"), dict) else {}
        threat_intel = validated.get("threat_intelligence") if isinstance(validated.get("threat_intelligence"), dict) else {}

        os_family = str(sys_diag.get("os") or "unknown").strip()[:64] or "unknown"
        os_version = str(sys_diag.get("os_version") or "").strip()[:120]
        arch = str(sys_diag.get("arch") or "").strip()[:32]
        posture_level = str(sys_diag.get("posture_level") or "unknown").strip()[:32] or "unknown"

        cov_raw = sys_diag.get("coverage_pct")
        coverage_pct = int(cov_raw) if isinstance(cov_raw, (int, float)) and not isinstance(cov_raw, bool) else None

        pt_raw = sys_diag.get("pentest_score_pct")
        if pt_raw is None and isinstance(sys_diag.get("pentest_summary"), dict):
            pt_raw = sys_diag["pentest_summary"].get("score_pct")
        pentest_score_pct = int(pt_raw) if isinstance(pt_raw, (int, float)) and not isinstance(pt_raw, bool) else None

        thr_raw = threat_intel.get("active_threat_count", 0)
        active_threat_count = int(thr_raw) if isinstance(thr_raw, int) and not isinstance(thr_raw, bool) and thr_raw >= 0 else 0

        raw = json.dumps(validated, ensure_ascii=True, separators=(",", ":"))
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            conn.execute(
                "INSERT INTO telemetry_snapshots "
                "(snapshot_id, received_at, account_hash, reporter_hash, wardr_version, os_family, os_version, "
                "arch, posture_level, coverage_pct, pentest_score_pct, active_threat_count, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot_id, now, account_hash, reporter_hash, wardr_version,
                    os_family, os_version, arch, posture_level,
                    coverage_pct, pentest_score_pct, active_threat_count, raw,
                ),
            )
        return {
            "accepted": True,
            "snapshot_id": snapshot_id,
            "received_at": now,
            "status": "accepted",
        }

    def telemetry_summary(self, *, limit: int = 5000) -> dict:
        capped = max(1, min(limit, 5000))
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn:
            totals = conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT account_hash), MAX(received_at) FROM telemetry_snapshots"
            ).fetchone()
            rows = conn.execute(
                "SELECT wardr_version, os_family, arch, posture_level, coverage_pct, pentest_score_pct, payload "
                "FROM telemetry_snapshots ORDER BY received_at DESC LIMIT ?",
                (capped,),
            ).fetchall()

        total_snapshots = int(totals[0] or 0)
        unique_accounts = int(totals[1] or 0)
        latest_received_at = totals[2]

        by_os: dict[str, int] = {}
        by_arch: dict[str, int] = {}
        by_version: dict[str, int] = {}
        by_posture: dict[str, int] = {}
        cov_values: list[int] = []
        pt_values: list[int] = []
        failing_checks: dict[str, dict] = {}
        pentest_exposures: dict[str, int] = {}
        risky_ports: dict[tuple[int, str], dict] = {}
        sc_matches: dict[tuple[str, str], dict] = {}

        for version, os_family, arch, posture_level, cov_pct, pt_pct, payload_raw in rows:
            by_version[version] = by_version.get(version, 0) + 1
            by_os[os_family] = by_os.get(os_family, 0) + 1
            if arch:
                by_arch[arch] = by_arch.get(arch, 0) + 1
            by_posture[posture_level] = by_posture.get(posture_level, 0) + 1
            if isinstance(cov_pct, int):
                cov_values.append(cov_pct)
            if isinstance(pt_pct, int):
                pt_values.append(pt_pct)
            try:
                doc = json.loads(payload_raw)
            except ValueError:
                continue
            sys_diag = doc.get("system_diagnostics") if isinstance(doc.get("system_diagnostics"), dict) else {}
            for chk in sys_diag.get("checks_summary") or []:
                if not isinstance(chk, dict):
                    continue
                if chk.get("status") == "fail":
                    cid = str(chk.get("id") or "")
                    if not cid:
                        continue
                    rec = failing_checks.setdefault(cid, {
                        "id": cid,
                        "category": str(chk.get("category") or "Security"),
                        "severity": str(chk.get("severity") or "medium"),
                        "fail_count": 0,
                        "handled_count": 0,
                    })
                    rec["fail_count"] += 1
                    if chk.get("handled"):
                        rec["handled_count"] += 1

            pt_sum = sys_diag.get("pentest_summary") if isinstance(sys_diag.get("pentest_summary"), dict) else {}
            for probe in pt_sum.get("probes") or []:
                if not isinstance(probe, dict):
                    continue
                if probe.get("outcome") in ("exposed", "warning"):
                    pid = str(probe.get("id") or "")
                    if pid:
                        pentest_exposures[pid] = pentest_exposures.get(pid, 0) + 1

            thr = doc.get("threat_intelligence") if isinstance(doc.get("threat_intelligence"), dict) else {}
            for port_row in thr.get("exposed_risky_ports") or []:
                if not isinstance(port_row, dict) or not isinstance(port_row.get("port"), int):
                    continue
                p_key = (port_row["port"], str(port_row.get("service") or ""))
                rec = risky_ports.setdefault(p_key, {
                    "port": port_row["port"],
                    "service": str(port_row.get("service") or ""),
                    "severity": str(port_row.get("severity") or "medium"),
                    "count": 0,
                })
                rec["count"] += 1

            for match in thr.get("supply_chain_signatures_matched") or []:
                if not isinstance(match, dict):
                    continue
                pkg = str(match.get("package") or "")
                cve = str(match.get("cve") or "")
                if not pkg and not cve:
                    continue
                m_key = (pkg, cve)
                rec = sc_matches.setdefault(m_key, {
                    "package": pkg,
                    "cve": cve,
                    "kind": str(match.get("kind") or ""),
                    "severity": str(match.get("severity") or "high"),
                    "count": 0,
                })
                rec["count"] += 1

        return {
            "total_snapshots": total_snapshots,
            "unique_accounts": unique_accounts,
            "latest_received_at": latest_received_at,
            "by_os": by_os,
            "by_arch": by_arch,
            "by_wardr_version": by_version,
            "by_posture_level": by_posture,
            "avg_coverage_pct": round(sum(cov_values) / len(cov_values), 1) if cov_values else None,
            "avg_pentest_score_pct": round(sum(pt_values) / len(pt_values), 1) if pt_values else None,
            "top_failing_checks": sorted(failing_checks.values(), key=lambda r: r["fail_count"], reverse=True)[:20],
            "top_pentest_exposures": [
                {"id": k, "count": v}
                for k, v in sorted(pentest_exposures.items(), key=lambda kv: kv[1], reverse=True)[:15]
            ],
            "top_exposed_risky_ports": sorted(risky_ports.values(), key=lambda r: r["count"], reverse=True)[:15],
            "top_supply_chain_matches": sorted(sc_matches.values(), key=lambda r: r["count"], reverse=True)[:20],
        }

    def health(self) -> dict:
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn:
            reports_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            clusters_count = conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
            escalated = conn.execute("SELECT COUNT(*) FROM clusters WHERE triage_status = 'escalated'").fetchone()[0]
            telemetry_count = conn.execute("SELECT COUNT(*) FROM telemetry_snapshots").fetchone()[0]
        feed_version = None
        published = self.read_published_feed()
        if published is not None:
            try:
                feed_version = json.loads(published[0]).get("version")
            except ValueError:
                pass
        return {
            "ok": True,
            "reports": reports_count,
            "clusters": clusters_count,
            "escalated_clusters": escalated,
            "telemetry_snapshots": telemetry_count,
            "active_feed_version": feed_version,
        }


class ThreatNetworkServer(ThreadingHTTPServer):
    allow_reuse_address = os.name == "posix"
    daemon_threads = True

    def __init__(
        self,
        bind_address: tuple[str, int],
        store: ThreatNetworkStore,
        *,
        admin_token: str | None = None,
        signing_key_pem: bytes | None = None,
        broker: oauth_broker.OAuthBroker | None = None,
    ):
        self.store = store
        self.admin_token = admin_token or secrets.token_urlsafe(32)
        self.signing_key_pem = signing_key_pem
        self.limiter = _RateLimiter()
        self.oauth_limiter = _RateLimiter(limit=60, window=60.0)
        self.oauth_broker = broker if broker is not None else oauth_broker.OAuthBroker()
        super().__init__(bind_address, _ThreatNetworkHandler)


class _ThreatNetworkHandler(BaseHTTPRequestHandler):
    server: ThreatNetworkServer
    server_version = "WardrThreatNetwork"
    sys_version = ""

    def setup(self) -> None:
        self.request.settimeout(30)
        super().setup()

    def log_message(self, format, *args):
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str, *, cache_control: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8")

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()

    def _local_fallback_origin(self) -> str | None:
        host = (self.headers.get("Host") or "").strip()
        if not host:
            return None
        parsed = urlsplit(f"http://{host}")
        if parsed.hostname in ("127.0.0.1", "localhost"):
            return f"http://{host}"
        return None

    def _is_admin(self) -> bool:
        auth = self.headers.get("Authorization") or ""
        expected = f"Bearer {self.server.admin_token}"
        return hmac.compare_digest(auth.encode("utf-8", errors="ignore"), expected.encode("utf-8"))

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
        client_ip = self.client_address[0] if self.client_address else "unknown"
        if path == "/v1/health":
            health = self.server.store.health()
            health["oauth_providers"] = [
                pid for pid, ready in self.server.oauth_broker.configured_providers().items() if ready
            ]
            self._json(HTTPStatus.OK, health)
        elif path == "/oauth/providers":
            self._json(HTTPStatus.OK, {"providers": self.server.oauth_broker.configured_providers()})
        elif path in ("/oauth/google", "/oauth/microsoft"):
            if not self.server.oauth_limiter.allow(client_ip):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many sign-in attempts. Try again shortly."})
                return
            provider_id = path.rsplit("/", 1)[-1]
            try:
                target = self.server.oauth_broker.start_authorization(
                    provider_id, parsed.query, fallback_origin=self._local_fallback_origin(),
                )
                self._redirect(target)
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except oauth_broker.BrokerError as exc:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
        elif path in ("/oauth/google/callback", "/oauth/microsoft/callback"):
            if not self.server.oauth_limiter.allow(client_ip):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many sign-in callbacks. Try again shortly."})
                return
            provider_id = path.split("/")[2]
            try:
                target = self.server.oauth_broker.handle_callback(provider_id, parsed.query)
                self._redirect(target)
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except oauth_broker.BrokerError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        elif path == "/feeds/defense-v1.json":
            published = self.server.store.read_published_feed()
            if published is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "No signed defense feed published yet."})
            else:
                self._send(HTTPStatus.OK, published[0], "application/json; charset=utf-8", cache_control="public, max-age=300")
        elif path == "/feeds/defense-v1.json.sig":
            published = self.server.store.read_published_feed()
            if published is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "No signed defense feed published yet."})
            else:
                self._send(HTTPStatus.OK, published[1], "application/octet-stream", cache_control="public, max-age=300")
        elif path == "/v1/clusters":
            if not self._is_admin():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Valid Bearer token required."})
                return
            self._json(HTTPStatus.OK, {"clusters": self.server.store.list_clusters()})
        elif path == "/api/v1/telemetry/summary":
            if not self._is_admin():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Valid Bearer token required."})
                return
            self._json(HTTPStatus.OK, self.server.store.telemetry_summary())
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        client_ip = self.client_address[0] if self.client_address else "unknown"
        try:
            if path == "/v1/reports":
                if not self.server.limiter.allow(client_ip):
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Rate limit exceeded. Try again shortly."})
                    return
                payload = self._read_json(_MAX_REPORT_BYTES)
                receipt = self.server.store.ingest_report(payload, client_ip=client_ip)
                self._json(HTTPStatus.ACCEPTED, receipt)
            elif path == "/api/v1/telemetry/ingest":
                if not self.server.limiter.allow(client_ip):
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Rate limit exceeded. Try again shortly."})
                    return
                payload = self._read_json(_MAX_TELEMETRY_BYTES)
                receipt = self.server.store.ingest_telemetry(payload, client_ip=client_ip)
                self._json(HTTPStatus.ACCEPTED, receipt)
            elif path == "/oauth/token":
                if not self.server.oauth_limiter.allow(client_ip):
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Rate limit exceeded. Try again shortly."})
                    return
                body = self._read_json(4096)
                result = self.server.oauth_broker.exchange_code(body)
                self._json(HTTPStatus.OK, result)
            elif path == "/v1/feeds/publish":
                if not self._is_admin():
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Valid Bearer token required."})
                    return
                if not self.server.signing_key_pem:
                    self._json(HTTPStatus.CONFLICT, {"error": "Server was started without an Ed25519 signing key."})
                    return
                feed_doc = self._read_json(_MAX_FEED_PUBLISH_BYTES)
                result = self.server.store.publish_feed(feed_doc, self.server.signing_key_pem)
                self._json(HTTPStatus.OK, result)
            elif path.startswith("/v1/clusters/") and path.endswith("/status"):
                if not self._is_admin():
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Valid Bearer token required."})
                    return
                fp = path[len("/v1/clusters/"):-len("/status")]
                body = self._read_json(4096)
                result = self.server.store.update_cluster(
                    fp,
                    triage_status=str(body.get("triage_status") or ""),
                    cve_id=body.get("cve_id") if isinstance(body.get("cve_id"), str) else None,
                )
                self._json(HTTPStatus.OK, result)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
        except OverflowError as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(exc)})
        except KeyError as exc:
            self._json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except (ValueError, feeds.FeedError, oauth_broker.BrokerError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
