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

from . import feeds


_MAX_REPORT_BYTES = 32 * 1024
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
CREATE INDEX IF NOT EXISTS idx_reports_fingerprint ON reports(fingerprint);
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
        self._salt = secrets.token_hex(16)
        self._lock = threading.Lock()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as conn, conn:
            conn.executescript(_SCHEMA)

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
                "SELECT COUNT(*), COUNT(DISTINCT reporter_hash), SUM(suspected_zero_day) "
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

    def health(self) -> dict:
        with self._lock, closing(sqlite3.connect(self.db_path, timeout=5)) as conn:
            reports_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            clusters_count = conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
            escalated = conn.execute("SELECT COUNT(*) FROM clusters WHERE triage_status = 'escalated'").fetchone()[0]
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
    ):
        self.store = store
        self.admin_token = admin_token or secrets.token_urlsafe(32)
        self.signing_key_pem = signing_key_pem
        self.limiter = _RateLimiter()
        super().__init__(bind_address, _ThreatNetworkHandler)


class _ThreatNetworkHandler(BaseHTTPRequestHandler):
    server: ThreatNetworkServer
    server_version = "WardrThreatNetwork"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str, *, cache_control: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8")

    def _is_admin(self) -> bool:
        auth = self.headers.get("Authorization") or ""
        expected = f"Bearer {self.server.admin_token}"
        return hmac.compare_digest(auth.encode("latin-1", errors="ignore"), expected.encode("ascii"))

    def _read_json(self, limit: int) -> dict:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Send application/json.")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not lengths[0].isdecimal():
            raise ValueError("Invalid Content-Length.")
        size = int(lengths[0])
        if not 0 < size <= limit:
            raise OverflowError("Request payload exceeds limit.")
        parsed = json.loads(self.rfile.read(size))
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object.")
        return parsed

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/v1/health":
            self._json(HTTPStatus.OK, self.server.store.health())
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
        except (ValueError, feeds.FeedError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
