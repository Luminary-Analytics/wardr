"""A browser interface bound to this machine's IPv4 loopback address."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import webbrowser
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import account, ai_tiers, feeds, legal, local_ai, reporting, updater
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
        self._auth_lock = threading.Lock()
        self._session_tokens: list[str] = [self.token]
        self._bootstrap_nonces: list[str] = []
        self.launch_url = self.issue_launch_url()
        self.state = state

    def issue_launch_url(self) -> str:
        """Issue a single-use launch URL whose #access nonce is exchanged once for a session token."""
        nonce = secrets.token_urlsafe(32)
        with self._auth_lock:
            self._bootstrap_nonces.append(nonce)
            if len(self._bootstrap_nonces) > 32:
                self._bootstrap_nonces = self._bootstrap_nonces[-32:]
        return f"{self.url}/#access={nonce}"

    def exchange_bootstrap_nonce(self, candidate: str) -> str | None:
        if not isinstance(candidate, str) or len(candidate) > 128:
            return None
        cand_bytes = candidate.encode("latin-1", errors="ignore")
        with self._auth_lock:
            for idx, nonce in enumerate(self._bootstrap_nonces):
                if hmac.compare_digest(cand_bytes, nonce.encode("ascii")):
                    self._bootstrap_nonces.pop(idx)
                    session_token = secrets.token_urlsafe(32)
                    self._session_tokens.append(session_token)
                    if len(self._session_tokens) > 32:
                        self._session_tokens = [self.token, *self._session_tokens[-31:]]
                    return session_token
            for existing in self._session_tokens:
                if hmac.compare_digest(cand_bytes, existing.encode("ascii")):
                    return existing
        return None

    def is_valid_session_token(self, candidate: str) -> bool:
        if not isinstance(candidate, str):
            return False
        cand_bytes = candidate.encode("latin-1", errors="ignore")
        with self._auth_lock:
            tokens = list(self._session_tokens)
        matched = False
        for valid in tokens:
            if hmac.compare_digest(cand_bytes, valid.encode("ascii")):
                matched = True
        return matched


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
        return len(tokens) == 1 and self.server.is_valid_session_token(tokens[0])

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
        if path in (
            "/api/status", "/api/defense", "/api/local-ai", "/api/ai", "/api/update",
            "/api/remediation", "/api/feed", "/api/legal", "/api/account/telemetry/preview", *REPORTS,
        ) and not self._access_granted():
            self._json(HTTPStatus.FORBIDDEN, {"error": "Open the launch link printed by Wardr to access this dashboard."})
            return
        if path == "/":
            self._respond(HTTPStatus.OK, self.server.page, "text/html; charset=utf-8")
        elif path == "/auth/callback":
            self._oauth_callback(url.query)
        elif path == "/api/status":
            self._json(HTTPStatus.OK, self.server.state.status())
        elif path == "/api/defense":
            self._json(HTTPStatus.OK, self.server.state.defense_status())
        elif path == "/api/legal":
            self._json(HTTPStatus.OK, legal.legal_payload())
        elif path == "/api/account/telemetry/preview":
            self._json(HTTPStatus.OK, self.server.state.telemetry_preview())
        elif path == "/api/local-ai":
            self._json(HTTPStatus.OK, local_ai.status())
        elif path == "/api/ai":
            self._json(HTTPStatus.OK, self.server.state.ai_status(cached=False))
        elif path == "/api/update":
            self._json(HTTPStatus.OK, self.server.updates.status())
        elif path == "/api/remediation":
            self._json(HTTPStatus.OK, {"history": self.server.state.remediation_history()})
        elif path == "/api/feed":
            self._json(HTTPStatus.OK, self.server.state.feed_status())
        elif path in REPORTS:
            self._report(path, url.query == "download=1")
        elif path in self.server.assets:
            content, kind = self.server.assets[path]
            self._respond(HTTPStatus.OK, content, kind)
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Page not found."})

    def _oauth_callback_page(self, *, ok: bool, title: str, subtitle: str, detail: str, launch_url: str | None = None) -> str:
        tone = "pass" if ok else "error"
        glyph = "✓" if ok else "!"
        cta = (
            f'<div class="oauth-actions"><a class="button button-primary" href="{escape(launch_url)}">Open Wardr Dashboard</a></div>'
            if ok and launch_url else ""
        )
        return (
            "<!doctype html><html lang='en' data-theme='dark'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Wardr Sign-In</title><link rel='icon' href='/static/wardr-mark.png'>"
            "<link rel='stylesheet' href='/static/wardr.css'></head>"
            "<body class='oauth-body'><main class='oauth-card' data-tone='" + tone + "'>"
            "<div class='oauth-head'>"
            "<div class='auth-brand'><span class='brand-mark' aria-hidden='true'><span></span></span>"
            "<span>wardr<span class='brand-period'>.</span></span></div>"
            f"<div class='oauth-shield' data-tone='{tone}' aria-hidden='true'>{glyph}</div>"
            f"<h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>"
            f"<div class='oauth-content'><p>{escape(detail)}</p>{cta}</div>"
            "</main></body></html>"
        )

    def _oauth_callback(self, query: str) -> None:
        params = parse_qs(query, keep_blank_values=False)
        state_val = (params.get("state") or [""])[0]
        code_val = (params.get("code") or [""])[0]
        err_val = (params.get("error") or [""])[0]
        if err_val:
            body = self._oauth_callback_page(
                ok=False,
                title="Sign-in cancelled",
                subtitle="Your authentication request was not completed.",
                detail=f"Provider response: {err_val[:120]}. You can close this tab and return to Wardr.",
            )
            self._respond(HTTPStatus.BAD_REQUEST, body, "text/html; charset=utf-8")
            return
        try:
            st = self.server.state.accounts.complete_sso_callback(state_token=state_val, code=code_val)
            acct = st.get("account") or {}
            who = acct.get("name") or acct.get("email") or "your account"
            email = acct.get("email") or ""
            provider = str(acct.get("provider") or "SSO").capitalize()
            desktop_shell = os.environ.get("WARDR_DESKTOP_SHELL") == "1"
            if desktop_shell:
                # Signal the native desktop shell to pop Wardr to the front and refresh immediately.
                print("WARDR_DESKTOP_EVENT focus", flush=True)
            body = self._oauth_callback_page(
                ok=True,
                title=f"Welcome, {who}!",
                subtitle=f"Verified with {provider} ({email})" if email else f"Verified with {provider}",
                detail=(
                    "You're signed in! The Wardr desktop app has unlocked automatically — you can close this browser tab."
                    if desktop_shell
                    else "Authentication succeeded. Return to Wardr (it unlocks automatically), or click below to open your dashboard."
                ),
                launch_url=None if desktop_shell else self.server.issue_launch_url(),
            )
            self._respond(HTTPStatus.OK, body, "text/html; charset=utf-8")
        except account.AccountError as exc:
            body = self._oauth_callback_page(
                ok=False,
                title="Sign-in could not complete",
                subtitle="Wardr could not verify the sign-in response.",
                detail=f"{str(exc)} Close this tab and try again from Wardr.",
            )
            self._respond(HTTPStatus.BAD_REQUEST, body, "text/html; charset=utf-8")

    def _report(self, path: str, download: bool) -> None:
        plan = path.startswith("/plan.")
        if plan:
            data = self.server.state.defense_status()["plan"]
        else:
            snapshot = self.server.state.enriched_scan_snapshot()
            if not snapshot:
                self._json(HTTPStatus.CONFLICT, {"error": "Run a scan to generate a report."})
                return
            monitoring_status = self.server.state.monitor.status()
            threats = self.server.state.active_threats(monitoring_status)
            data = report_data(self.server.state.host, snapshot, monitoring=monitoring_status, threats=threats)
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
        is_exchange = self.path == "/api/auth/exchange"
        if (
            not self._trusted_host()
            or self.headers.get_all("Origin") != [self.server.url]
            or (not is_exchange and not self._access_granted())
        ):
            self._json(HTTPStatus.FORBIDDEN, {"error": "Open Wardr locally and reload the page."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Send a JSON request."})
            return
        lengths = self.headers.get_all("Content-Length") or []
        maximum = (
            ASSESSMENT_UPLOAD_LIMIT if self.path == "/api/software/assess" else
            48 * 1024 if self.path == "/api/report/submit" else
            8192 if self.path == "/api/report/preview" else
            2048
        )
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
            if self.path == "/api/auth/exchange":
                nonce = body.get("nonce")
                if body.keys() != {"nonce"} or not isinstance(nonce, str) or len(nonce) > 128:
                    raise ValueError("Provide a valid launch nonce.")
                exchanged = self.server.exchange_bootstrap_nonce(nonce)
                if not exchanged:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "Launch link already used or expired. Open the fresh launch link printed by Wardr."})
                    return
                self._json(HTTPStatus.OK, {"token": exchanged})
            elif self.path == "/api/scan":
                if not body:
                    profile = "medium"
                elif body.keys() == {"profile"} and isinstance(body.get("profile"), str):
                    profile = body["profile"]
                else:
                    raise ValueError("Choose a valid scan depth: light, medium, or heavy.")
                result = self.server.state.start_scan(profile=profile)
                self._json(HTTPStatus.ACCEPTED, result)
            elif self.path == "/api/ai/config":
                allowed = {
                    "active_tier", "cloud_preset", "cloud_endpoint", "cloud_model",
                    "cloud_api_key", "clear_api_key", "local_profile",
                }
                if not body or not body.keys() <= allowed:
                    raise ValueError("Provide valid AI protection settings.")
                self._json(HTTPStatus.OK, self.server.state.update_ai_config(body))
            elif self.path == "/api/ai/triage" and not body:
                self._json(HTTPStatus.OK, self.server.state.run_ai_triage())
            elif self.path == "/api/intel/refresh" and not body:
                self.server.state.start_advisory_refresh()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/exposure" and not body:
                self.server.state.start_exposure()
                self._json(HTTPStatus.ACCEPTED, {"ok": True})
            elif self.path == "/api/pentest/run":
                if not body:
                    ids = None
                elif body.keys() == {"ids"} and isinstance(body.get("ids"), list) and len(body["ids"]) <= 16 and all(isinstance(x, str) and len(x) <= 64 for x in body["ids"]):
                    ids = body["ids"]
                else:
                    raise ValueError("Provide an optional list of valid self-pen-test module IDs.")
                self._json(HTTPStatus.ACCEPTED, self.server.state.start_pentest(test_ids=ids))
            elif self.path == "/api/pentest/fix":
                if not body:
                    fix_ids = None
                elif body.keys() == {"fix_ids"} and isinstance(body.get("fix_ids"), list) and len(body["fix_ids"]) <= 32 and all(isinstance(x, str) and len(x) <= 160 for x in body["fix_ids"]):
                    fix_ids = body["fix_ids"]
                else:
                    raise ValueError("Provide an optional list of valid pen-test fix IDs.")
                self._json(HTTPStatus.ACCEPTED, self.server.state.start_pentest_fix(fix_ids=fix_ids))
            elif self.path == "/api/pentest/disposition":
                identifier = body.get("id")
                kind = body.get("kind")
                note = body.get("note", "")
                if (
                    not body.keys() <= {"id", "kind", "note"}
                    or not isinstance(identifier, str) or not identifier or len(identifier) > 64
                    or not isinstance(kind, str)
                    or not isinstance(note, str) or len(note) > 240
                ):
                    raise ValueError("Provide a valid pen-test module ID and status (acknowledged or clear).")
                self._json(HTTPStatus.OK, self.server.state.set_pentest_disposition(identifier, kind, note=note))
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
                if os.environ.get("WARDR_DESKTOP_SHELL") == "1":
                    print("WARDR_DESKTOP_EVENT restart", flush=True)
                self.server.shutdown()
            elif self.path == "/api/action/open-settings":
                identifier = body.get("id")
                if not isinstance(identifier, str) or len(identifier) > 120 or body.keys() != {"id"}:
                    raise ValueError("Provide a valid check ID to open settings.")
                self._json(HTTPStatus.OK, self.server.state.open_check_settings(identifier))
            elif self.path == "/api/check/disposition":
                identifier = body.get("id")
                kind = body.get("kind")
                note = body.get("note", "")
                if (
                    not body.keys() <= {"id", "kind", "note"}
                    or not isinstance(identifier, str) or not identifier or len(identifier) > 120
                    or not isinstance(kind, str)
                    or not isinstance(note, str) or len(note) > 240
                ):
                    raise ValueError("Provide a valid check ID and status (queued, acknowledged, or clear).")
                self._json(HTTPStatus.OK, self.server.state.set_check_disposition(identifier, kind, note=note))
            elif self.path == "/api/check/disposition/batch":
                ids = body.get("ids")
                kind = body.get("kind")
                note = body.get("note", "")
                if (
                    not body.keys() <= {"ids", "kind", "note"}
                    or not isinstance(ids, list) or not 1 <= len(ids) <= 64
                    or not all(isinstance(item, str) and item and len(item) <= 120 for item in ids)
                    or not isinstance(kind, str)
                    or not isinstance(note, str) or len(note) > 240
                ):
                    raise ValueError("Provide valid check IDs and status (queued, acknowledged, or clear).")
                self._json(HTTPStatus.OK, self.server.state.set_check_dispositions_batch(ids, kind, note=note))
            elif self.path == "/api/fix/batch":
                if not body.keys() <= {"ids", "include_scripts"}:
                    raise ValueError("Provide valid batch fix parameters.")
                ids = body.get("ids")
                include_scripts = body.get("include_scripts", False)
                if ids is not None and (
                    not isinstance(ids, list)
                    or len(ids) > 64
                    or not all(isinstance(item, str) and len(item) <= 120 for item in ids)
                ):
                    raise ValueError("Provide a valid list of check IDs to fix.")
                if not isinstance(include_scripts, bool):
                    raise ValueError("include_scripts must be a boolean.")
                self._json(HTTPStatus.ACCEPTED, self.server.state.start_batch_fix(ids=ids, include_scripts=include_scripts))
            elif self.path == "/api/fix":
                identifier = body.get("id")
                if not isinstance(identifier, str) or len(identifier) > 120 or body.keys() != {"id"}:
                    raise ValueError("Choose an applicable fix from the checklist.")
                self._json(HTTPStatus.OK, self.server.state.apply_fix(identifier))
            elif self.path == "/api/fix/preview":
                identifier = body.get("id")
                if not isinstance(identifier, str) or len(identifier) > 120 or body.keys() != {"id"}:
                    raise ValueError("Choose an applicable fix to preview.")
                self._json(HTTPStatus.OK, self.server.state.preview_fix(identifier))
            elif self.path == "/api/fix/undo":
                rollback_id = body.get("rollback_id")
                if not isinstance(rollback_id, str) or len(rollback_id) > 64 or body.keys() != {"rollback_id"}:
                    raise ValueError("Provide a valid remediation rollback ID.")
                self._json(HTTPStatus.OK, self.server.state.undo_fix(rollback_id))
            elif self.path == "/api/inventory/scan" and not body:
                self._json(HTTPStatus.OK, self.server.state.auto_assess_software())
            elif self.path == "/api/report/preview":
                kind = body.get("kind")
                item_id = body.get("id")
                notes = body.get("notes", "")
                zero_day = body.get("suspected_zero_day", False)
                if (
                    not body.keys() <= {"kind", "id", "notes", "suspected_zero_day"}
                    or not isinstance(kind, str)
                    or not isinstance(item_id, str) or len(item_id) > 160
                    or not isinstance(notes, str) or len(notes) > 2000
                    or not isinstance(zero_day, bool)
                ):
                    raise ValueError("Provide a valid report kind and item ID.")
                self._json(
                    HTTPStatus.OK,
                    self.server.state.preview_report(kind, item_id, notes=notes, suspected_zero_day=zero_day),
                )
            elif self.path == "/api/whats-new/seen" and not body:
                self._json(HTTPStatus.OK, self.server.state.mark_whats_new_seen())
            elif self.path == "/api/account/register":
                allowed = {"email", "password", "name", "accepted_legal", "share_system_diagnostics", "share_threat_intelligence"}
                if not body.keys() <= allowed:
                    raise ValueError("Invalid registration fields.")
                self._json(HTTPStatus.OK, self.server.state.accounts.register_email(
                    email=str(body.get("email") or ""),
                    password=str(body.get("password") or ""),
                    name=str(body.get("name") or ""),
                    accepted_legal=body.get("accepted_legal") is True,
                    share_system_diagnostics=body.get("share_system_diagnostics") is True,
                    share_threat_intelligence=body.get("share_threat_intelligence") is True,
                ))
            elif self.path == "/api/account/login":
                if body.keys() != {"email", "password"}:
                    raise ValueError("Provide email and password.")
                self._json(HTTPStatus.OK, self.server.state.accounts.login_email(
                    email=str(body.get("email") or ""),
                    password=str(body.get("password") or ""),
                ))
            elif self.path == "/api/account/logout" and not body:
                self._json(HTTPStatus.OK, self.server.state.accounts.sign_out())
            elif self.path == "/api/account/sso/start":
                if not body.keys() <= {"provider", "accepted_legal"} or not isinstance(body.get("provider"), str):
                    raise ValueError("Choose a valid SSO provider.")
                callback_url = f"{self.server.url}/auth/callback"
                self._json(HTTPStatus.OK, self.server.state.accounts.start_sso(
                    body["provider"],
                    callback_url=callback_url,
                    accepted_legal=body.get("accepted_legal") is True,
                ))
            elif self.path == "/api/account/sso/config":
                allowed = {"server_url", "google_client_id", "google_client_secret", "microsoft_client_id", "microsoft_client_secret"}
                if not body or not body.keys() <= allowed:
                    raise ValueError("Provide valid SSO / account server settings.")
                self._json(HTTPStatus.OK, self.server.state.accounts.update_sso_config(body))
            elif self.path == "/api/account/preferences":
                allowed = {"share_system_diagnostics", "share_threat_intelligence", "auto_check_updates"}
                if not body or not body.keys() <= allowed:
                    raise ValueError("Provide valid telemetry or update preferences.")
                self._json(HTTPStatus.OK, self.server.state.accounts.update_preferences(body))
            elif self.path == "/api/account/telemetry/sync" and not body:
                self._json(HTTPStatus.OK, self.server.state.sync_telemetry())
            elif self.path == "/api/supply-chain/scan":
                if not body:
                    custom_path = None
                elif body.keys() == {"path"} and isinstance(body.get("path"), str) and len(body["path"]) <= 512:
                    custom_path = body["path"]
                else:
                    raise ValueError("Provide an optional local folder path to scan.")
                self._json(HTTPStatus.OK, self.server.state.run_supply_chain_scan(custom_path=custom_path))
            elif self.path == "/api/report/submit":
                if body.keys() != {"payload"} or not isinstance(body.get("payload"), dict):
                    raise ValueError("Provide the reviewed redacted report payload.")
                self._json(HTTPStatus.OK, self.server.state.submit_report(body["payload"]))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Action not found."})
        except BusyError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except (feeds.FeedError, reporting.ReportingError, account.AccountError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except updater.UpdaterError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        except (local_ai.LocalAIError, ai_tiers.AITierError) as exc:
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
        state.accounts.refresh_broker_providers_async()
        threading.Thread(target=repeat, args=(state.start_scan, 3600), name="wardr-scan-timer", daemon=True).start()
        if auto_advisories:
            state.start_advisory_refresh()
            threading.Thread(
                target=repeat, args=(state.start_advisory_refresh, 6 * 3600),
                name="wardr-advisory-timer", daemon=True,
            ).start()
        if os.environ.get("WARDR_DESKTOP_SHELL") == "1":
            def watch_desktop_parent() -> None:
                # Duplicate the raw OS fd so this daemon thread never holds Python's
                # sys.stdin BufferedReader lock (which aborts Py_FinalizeEx on Windows
                # with _enter_buffered_busy during in-app update restarts).
                try:
                    watch_fd = os.dup(sys.stdin.fileno())
                except (AttributeError, OSError, ValueError):
                    return
                try:
                    while os.read(watch_fd, 1):
                        pass
                except OSError:
                    pass
                finally:
                    try:
                        os.close(watch_fd)
                    except OSError:
                        pass
                if not stopping.is_set():
                    server.shutdown()

            threading.Thread(target=watch_desktop_parent, name="wardr-desktop-parent", daemon=True).start()
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
