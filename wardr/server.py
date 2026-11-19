"""A browser interface bound to this machine's IPv4 loopback address."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import local_ai, updater
from .plan import html_plan
from .report import REPORT_CSS, html_report, json_report, report_data
from .state import BusyError, WardrState
from .update_session import UpdateSession

STATIC = Path(__file__).with_name("static")
ASSETS = {
    "/static/wardr.css": ("wardr.css", "text/css; charset=utf-8"),
    "/static/wardr.js": ("wardr.js", "text/javascript; charset=utf-8"),
    "/static/wardr-mark.png": ("wardr-mark.png", "image/png"),
}
REPORT_STYLE_HASH = base64.b64encode(hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()).decode("ascii")
PAGE_POLICY = (
    f"default-src 'none'; script-src 'self'; style-src 'self' 'sha256-{REPORT_STYLE_HASH}'; img-src 'self'; connect-src 'self'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)
REPORT_POLICY = f"default-src 'none'; style-src 'sha256-{REPORT_STYLE_HASH}'; base-uri 'none'; frame-ancestors 'none'"
REPORTS = ("/report.html", "/report.json", "/plan.html", "/plan.json")
ASSESSMENT_UPLOAD_LIMIT = 12 * 1024 * 1024
RESTART_DASHBOARD = object()


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = os.name == "posix"
    daemon_threads = True

    def __init__(self, port: int, state: WardrState, update_blocker: str | None = None):
        self.page = (STATIC / "index.html").read_bytes()
        # Serve this process’s asset versions while the next wheel replaces files on disk.
        self.assets = {url: ((STATIC / name).read_bytes(), kind) for url, (name, kind) in ASSETS.items()}
        self.updates = UpdateSession(offline=state.offline, blocker=update_blocker)
        super().__init__(("127.0.0.1", port), DashboardRequest)
        self.address = "127.0.0.1" if self.server_port == 80 else f"127.0.0.1:{self.server_port}"
        self.url = f"http://{self.address}"
        self.token = secrets.token_urlsafe(32)
        self.launch_url = f"{self.url}/#access={self.token}"
        self.state = state


class DashboardRequest(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "Wardr"
    sys_version = ""

    def setup(self) -> None:
        self.request.settimeout(45)
        super().setup()

    def log_message(self, format, *args) -> None:
        pass

    def _respond(self, status, body, content_type, *, policy=PAGE_POLICY, download=None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", policy)
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
        self._respond(status, json.dumps(payload, ensure_ascii=True), "application/json; charset=utf-8")

    def _trusted_host(self) -> bool:
        return self.headers.get_all("Host") == [self.server.address]

    def _access_granted(self) -> bool:
        tokens = self.headers.get_all("X-Wardr-Token") or []
        return len(tokens) == 1 and hmac.compare_digest(
            tokens[0].encode("latin-1"), self.server.token.encode("ascii")
        )

    def do_GET(self) -> None:
        if not self._trusted_host():
            self._json(HTTPStatus.FORBIDDEN, {"error": "Open Wardr at its printed local address."})
            return
        try:
            url = urlsplit(self.path)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request path."})
            return
        path = url.path
        if path in ("/api/status", "/api/defense", "/api/local-ai", "/api/update", *REPORTS) and not self._access_granted():
            self._json(HTTPStatus.FORBIDDEN, {"error": "Open the launch link printed by Wardr to access this dashboard."})
            return
        if path == "/":
            self._respond(HTTPStatus.OK, self.server.page, "text/html; charset=utf-8")
        elif path == "/api/status":
            self._json(HTTPStatus.OK, self.server.state.status())
        elif path == "/api/defense":
            self._json(HTTPStatus.OK, self.server.state.defense_status())
        elif path == "/api/local-ai":
            self._json(HTTPStatus.OK, local_ai.status())
        elif path == "/api/update":
            self._json(HTTPStatus.OK, self.server.updates.status())
        elif path in REPORTS:
            self._report(path, url.query == "download=1")
        elif path in self.server.assets:
            content, kind = self.server.assets[path]
            self._respond(HTTPStatus.OK, content, kind)
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Page not found."})

    def _report(self, path: str, download: bool) -> None:
        plan = path.startswith("/plan.")
        if plan:
            data = self.server.state.defense_status()["plan"]
        else:
            snapshot = self.server.state.scan_snapshot()
            if not snapshot:
                self._json(HTTPStatus.CONFLICT, {"error": "Run a scan to generate a report."})
                return
            data = report_data(self.server.state.host, snapshot)
        extension = path.rsplit(".", 1)[-1]
        if extension == "html":
            body = html_plan(data) if plan else html_report(data)
            content_type = "text/html; charset=utf-8"
        else:
            body = json_report(data)
            content_type = "application/json; charset=utf-8"
        self._respond(
            HTTPStatus.OK, body, content_type, policy=REPORT_POLICY,
            download=f"wardr-{'plan' if plan else 'report'}.{extension}" if download else None,
        )

    def do_POST(self) -> None:
        if (
            not self._trusted_host()
            or self.headers.get_all("Origin") != [self.server.url]
            or not self._access_granted()
        ):
            self._json(HTTPStatus.FORBIDDEN, {"error": "Open Wardr locally and reload the page."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Send a JSON request."})
            return
        lengths = self.headers.get_all("Content-Length") or []
        maximum = ASSESSMENT_UPLOAD_LIMIT if self.path == "/api/software/assess" else 2048
        if (
            len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()
            or len(lengths[0]) > len(str(maximum)) or "Transfer-Encoding" in self.headers
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request length."})
            return
        length = int(lengths[0])
        if not 0 < length <= maximum:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "The input exceeds Wardr's upload limit."})
            return
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object.")
        except (ValueError, RecursionError, OSError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON request."})
            return
        try:
            if self.path == "/api/scan" and not body:
                self.server.state.start_scan()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/intel/refresh" and not body:
                self.server.state.start_advisory_refresh()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/exposure" and not body:
                self.server.state.start_exposure()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/software/assess":
                if body.keys() != {"sbom", "advisories"}:
                    raise ValueError("Choose a CycloneDX inventory and an OSV advisory export.")
                self._json(HTTPStatus.OK, self.server.state.assess_software(body["sbom"], body["advisories"]))
            elif self.path == "/api/local-ai/review" and not body:
                self._json(HTTPStatus.OK, self.server.state.review_plan())
            elif self.path == "/api/update/check" and not body:
                self.server.updates.start_check()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/update/install":
                if body.keys() != {"version"} or not isinstance(body["version"], str):
                    raise ValueError("Choose the verified update version.")
                self.server.updates.start_install(body["version"])
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/update/restart" and not body:
                self.server.updates.request_restart()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
                self.server.shutdown()
            elif self.path == "/api/fix":
                identifier = body.get("id")
                if not isinstance(identifier, str) or len(identifier) > 120 or body.keys() != {"id"}:
                    raise ValueError("Choose an applicable fix from the checklist.")
                self._json(HTTPStatus.OK, self.server.state.apply_fix(identifier))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Action not found."})
        except BusyError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except updater.UpdaterError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        except local_ai.LocalAIError as exc:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
        except OSError:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Wardr could not save the assessment in its state directory."})


def serve(state: WardrState, port: int, open_browser: bool, auto_advisories: bool, *, update_blocker: str | None = None):
    stopping = threading.Event()

    def repeat(action, seconds: int) -> None:
        while not stopping.wait(seconds):
            try:
                action()
            except BusyError:
                pass

    with DashboardServer(port, state, update_blocker=update_blocker) as server:
        state.monitor.start()
        state.start_scan()
        state.start_exposure()
        threading.Thread(target=repeat, args=(state.start_scan, 3600), name="wardr-scan-timer", daemon=True).start()
        if auto_advisories:
            state.start_advisory_refresh()
            threading.Thread(
                target=repeat, args=(state.start_advisory_refresh, 6 * 3600),
                name="wardr-advisory-timer", daemon=True,
            ).start()
        print(f"Wardr is running at {server.launch_url}", flush=True)
        if open_browser:
            threading.Thread(target=webbrowser.open, args=(server.launch_url,), daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stopping.set()
            state.monitor.stop()
    return RESTART_DASHBOARD if server.updates.restart_requested else 0
