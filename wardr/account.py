"""Wardr Account management, OAuth 2.0 + PKCE SSO (Google & Microsoft), and strictly opt-in redacted telemetry."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import ssl
import stat
import tempfile
import threading
import time
from urllib.parse import urlencode, urlsplit

from . import legal, reporting, surface, updater


_SESSION_FILE = "account-session.json"
_USERS_FILE = "account-users.json"
_SSO_CONFIG_FILE = "sso-config.json"
_TELEMETRY_LOG_FILE = "telemetry-receipts.json"
_DEFAULT_CLOUD_URL = "https://api.getwardr.com"
# Public PKCE (RFC 8252) Microsoft Entra App Registration ID for Wardr (not a secret; uses S256 PKCE + loopback redirect).
_DEFAULT_MICROSOFT_CLIENT_ID = "d88b005f-fc08-40cd-8037-873321f31433"
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_IO_TIMEOUT = 15
_MAX_RESPONSE_BYTES = 128 * 1024
_PKCE_TTL_SECONDS = 600

SSO_PROVIDERS: dict[str, dict] = {
    "google": {
        "id": "google",
        "label": "Google",
        "env_client_id": "WARDR_GOOGLE_CLIENT_ID",
        "env_client_secret": "WARDR_GOOGLE_CLIENT_SECRET",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": "openid email profile",
    },
    "microsoft": {
        "id": "microsoft",
        "label": "Microsoft",
        "env_client_id": "WARDR_MICROSOFT_CLIENT_ID",
        "env_client_secret": "WARDR_MICROSOFT_CLIENT_SECRET",
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
        "scopes": "openid email profile User.Read",
    },
}


class AccountError(RuntimeError):
    """Account authentication, SSO, or telemetry sync failed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _save_private_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".acct-", suffix=".json")
    staging = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        staging.replace(path)
    finally:
        staging.unlink(missing_ok=True)


def _read_private_json(path: Path, limit: int = 512 * 1024) -> dict | None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    actual_salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=actual_salt, n=16384, r=8, p=1, dklen=32)
    return base64.b64encode(actual_salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def _verify_password(password: str, salt_b64: str, digest_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
    except ValueError:
        return False
    actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(actual, expected)


def _validate_server_url(url: str) -> str:
    cleaned = url.strip().rstrip("/")
    if not cleaned:
        return _DEFAULT_CLOUD_URL
    parsed = urlsplit(cleaned)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise AccountError("Server URL must be a valid HTTPS URL without embedded credentials.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise AccountError("Remote Wardr account servers must use HTTPS.")
    return cleaned


def _https_request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise AccountError("Invalid remote endpoint URL.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise AccountError("Remote endpoints must use HTTPS.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    req_headers = {"User-Agent": f"Wardr/{updater.current_version()}", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=_IO_TIMEOUT, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=_IO_TIMEOUT)
    try:
        conn.request(method, target or "/", body=body, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(data) > _MAX_RESPONSE_BYTES:
            raise AccountError("Authentication server response exceeded size limit.")
        try:
            payload = json.loads(data) if data else {}
        except ValueError:
            payload = {}
        return resp.status, payload if isinstance(payload, dict) else {}
    except OSError as exc:
        raise AccountError(f"Could not reach authentication server: {exc}") from exc
    finally:
        conn.close()


def _decode_jwt_claims(id_token: str) -> dict:
    """Decode claims from an OIDC id_token received directly over verified TLS from the token endpoint."""
    if not isinstance(id_token, str):
        return {}
    parts = id_token.split(".")
    if len(parts) != 3:
        return {}
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        claims = json.loads(raw)
        return claims if isinstance(claims, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _default_preferences() -> dict:
    return {
        "share_system_diagnostics": False,
        "share_threat_intelligence": False,
        "auto_check_updates": True,
    }


class AccountManager:
    """Manages local/cloud Wardr account sessions, Google/Microsoft OIDC+PKCE SSO, and opt-in telemetry."""

    def __init__(self, state_dir: Path, *, offline: bool = False):
        self.state_dir = Path(state_dir)
        self.offline = offline
        self.session_path = self.state_dir / _SESSION_FILE
        self.users_path = self.state_dir / _USERS_FILE
        self.sso_config_path = self.state_dir / _SSO_CONFIG_FILE
        self.telemetry_log_path = self.state_dir / _TELEMETRY_LOG_FILE
        self._lock = threading.Lock()
        self._pending_oauth: dict[str, dict] = {}
        self._session: dict | None = self._load_session()
        self._sso_config: dict = self._load_sso_config()

    def _load_session(self) -> dict | None:
        raw = _read_private_json(self.session_path)
        if not raw or not isinstance(raw.get("account_id"), str) or not isinstance(raw.get("email"), str):
            return None
        prefs = _default_preferences()
        if isinstance(raw.get("preferences"), dict):
            for key in prefs:
                if isinstance(raw["preferences"].get(key), bool):
                    prefs[key] = raw["preferences"][key]
        return {
            "account_id": raw["account_id"],
            "email": raw["email"],
            "name": str(raw.get("name") or raw["email"].split("@")[0]),
            "provider": str(raw.get("provider") or "email"),
            "server_url": str(raw.get("server_url") or _DEFAULT_CLOUD_URL),
            "connection_mode": str(raw.get("connection_mode") or "local_account"),
            "signed_in_at": str(raw.get("signed_in_at") or _utc_now()),
            "policy_version": str(raw.get("policy_version") or legal.POLICY_VERSION),
            "accepted_legal_at": str(raw.get("accepted_legal_at") or _utc_now()),
            "preferences": prefs,
            "last_telemetry_sync": raw.get("last_telemetry_sync"),
            "last_telemetry_status": raw.get("last_telemetry_status"),
        }

    def _load_sso_config(self) -> dict:
        saved = _read_private_json(self.sso_config_path) or {}
        return {
            "server_url": str(saved.get("server_url") or os.environ.get("WARDR_ACCOUNT_SERVER") or _DEFAULT_CLOUD_URL),
            "google_client_id": str(saved.get("google_client_id") or os.environ.get("WARDR_GOOGLE_CLIENT_ID") or ""),
            "google_client_secret": str(saved.get("google_client_secret") or os.environ.get("WARDR_GOOGLE_CLIENT_SECRET") or ""),
            "microsoft_client_id": str(saved.get("microsoft_client_id") or os.environ.get("WARDR_MICROSOFT_CLIENT_ID") or _DEFAULT_MICROSOFT_CLIENT_ID),
            "microsoft_client_secret": str(saved.get("microsoft_client_secret") or os.environ.get("WARDR_MICROSOFT_CLIENT_SECRET") or ""),
        }

    def _provider_credentials(self, provider_id: str) -> tuple[str, str]:
        with self._lock:
            cfg = dict(self._sso_config)
        if provider_id == "google":
            return cfg.get("google_client_id", "").strip(), cfg.get("google_client_secret", "").strip()
        if provider_id == "microsoft":
            return cfg.get("microsoft_client_id", "").strip(), cfg.get("microsoft_client_secret", "").strip()
        return "", ""

    def status(self) -> dict:
        with self._lock:
            session = dict(self._session) if isinstance(self._session, dict) else None
            cfg = dict(self._sso_config)
        signed_in = session is not None
        providers = []
        for pid, spec in SSO_PROVIDERS.items():
            cid, _ = self._provider_credentials(pid)
            providers.append({
                "id": pid,
                "label": spec["label"],
                "configured": bool(cid),
            })
        return {
            "signed_in": signed_in,
            "auth_required": (not self.offline) and (not signed_in),
            "offline": self.offline,
            "account": session,
            "server_url": cfg.get("server_url") or _DEFAULT_CLOUD_URL,
            "sso_providers": providers,
            "policy_version": legal.POLICY_VERSION,
        }

    def update_sso_config(self, payload: dict) -> dict:
        with self._lock:
            cfg = dict(self._sso_config)
        if "server_url" in payload and isinstance(payload["server_url"], str):
            cfg["server_url"] = _validate_server_url(payload["server_url"])
        for field in ("google_client_id", "google_client_secret", "microsoft_client_id", "microsoft_client_secret"):
            if field in payload and isinstance(payload[field], str):
                val = payload[field].strip()
                if len(val) > 256:
                    raise AccountError(f"{field} exceeds maximum length.")
                cfg[field] = val
        _save_private_json(self.sso_config_path, cfg)
        with self._lock:
            self._sso_config = cfg
        return self.status()

    def register_email(
        self,
        *,
        email: str,
        password: str,
        name: str = "",
        accepted_legal: bool = False,
        share_system_diagnostics: bool = False,
        share_threat_intelligence: bool = False,
    ) -> dict:
        cleaned_email = email.strip().lower()
        if not _EMAIL_RE.match(cleaned_email):
            raise ValueError("Enter a valid email address.")
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
            raise ValueError("Choose a password between 10 and 128 characters.")
        if not accepted_legal:
            raise ValueError("Please review and accept the Privacy Policy and Terms of Use to create an account.")
        display_name = (name.strip() or cleaned_email.split("@")[0])[:80]

        with self._lock:
            users_doc = _read_private_json(self.users_path) or {"version": 1, "users": {}}
            users = users_doc.get("users") if isinstance(users_doc.get("users"), dict) else {}
            if cleaned_email in users:
                raise ValueError("An account with this email already exists. Sign in instead.")
            salt_b64, digest_b64 = _hash_password(password)
            account_id = "acct_" + secrets.token_hex(12)
            now = _utc_now()
            users[cleaned_email] = {
                "account_id": account_id,
                "email": cleaned_email,
                "name": display_name,
                "salt": salt_b64,
                "password_hash": digest_b64,
                "created_at": now,
                "policy_version": legal.POLICY_VERSION,
                "accepted_legal_at": now,
            }
            _save_private_json(self.users_path, {"version": 1, "users": users})
            server_url = self._sso_config.get("server_url") or _DEFAULT_CLOUD_URL
            session = {
                "account_id": account_id,
                "email": cleaned_email,
                "name": display_name,
                "provider": "email",
                "server_url": server_url,
                "connection_mode": "cloud_ready" if not self.offline else "offline",
                "signed_in_at": now,
                "policy_version": legal.POLICY_VERSION,
                "accepted_legal_at": now,
                "preferences": {
                    "share_system_diagnostics": bool(share_system_diagnostics),
                    "share_threat_intelligence": bool(share_threat_intelligence),
                    "auto_check_updates": True,
                },
                "last_telemetry_sync": None,
                "last_telemetry_status": None,
            }
            self._session = session
            _save_private_json(self.session_path, session)
        return self.status()

    def login_email(self, *, email: str, password: str) -> dict:
        cleaned_email = email.strip().lower()
        if not _EMAIL_RE.match(cleaned_email) or not isinstance(password, str) or not password:
            raise ValueError("Enter a valid email address and password.")
        with self._lock:
            users_doc = _read_private_json(self.users_path) or {"version": 1, "users": {}}
            users = users_doc.get("users") if isinstance(users_doc.get("users"), dict) else {}
            record = users.get(cleaned_email)
            if not isinstance(record, dict) or not _verify_password(
                password,
                str(record.get("salt") or ""),
                str(record.get("password_hash") or ""),
            ):
                raise ValueError("Incorrect email address or password.")
            now = _utc_now()
            server_url = self._sso_config.get("server_url") or _DEFAULT_CLOUD_URL
            prev_prefs = (self._session or {}).get("preferences") or _default_preferences()
            session = {
                "account_id": str(record["account_id"]),
                "email": cleaned_email,
                "name": str(record.get("name") or cleaned_email.split("@")[0]),
                "provider": "email",
                "server_url": server_url,
                "connection_mode": "cloud_ready" if not self.offline else "offline",
                "signed_in_at": now,
                "policy_version": str(record.get("policy_version") or legal.POLICY_VERSION),
                "accepted_legal_at": str(record.get("accepted_legal_at") or now),
                "preferences": dict(prev_prefs),
                "last_telemetry_sync": None,
                "last_telemetry_status": None,
            }
            self._session = session
            _save_private_json(self.session_path, session)
        return self.status()

    def start_sso(self, provider_id: str, *, callback_url: str, accepted_legal: bool = False) -> dict:
        if self.offline:
            raise AccountError("SSO sign-in is disabled in offline mode.")
        spec = SSO_PROVIDERS.get(provider_id)
        if not spec:
            raise ValueError("Choose a supported SSO provider: google or microsoft.")
        if not accepted_legal:
            raise ValueError("Please review and accept the Privacy Policy and Terms of Use before continuing.")
        client_id, _ = self._provider_credentials(provider_id)
        broker_url = os.environ.get("WARDR_AUTH_BROKER_URL", "").strip().rstrip("/")
        if not client_id and not broker_url:
            raise AccountError(
                f"{spec['label']} sign-in is not linked on this local development build yet "
                f"(configure {spec['env_client_id']} or WARDR_AUTH_BROKER_URL for Wardr Cloud auth). "
                "You can create or sign in with an Email & Password account below."
            )
        state_token = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        challenge = _pkce_challenge(verifier)
        with self._lock:
            now = time.monotonic()
            # Prune expired states
            self._pending_oauth = {
                k: v for k, v in self._pending_oauth.items()
                if (now - v["created_at"]) < _PKCE_TTL_SECONDS
            }
            self._pending_oauth[state_token] = {
                "provider": provider_id,
                "verifier": verifier,
                "nonce": nonce,
                "callback_url": callback_url,
                "created_at": now,
            }
        if broker_url and not client_id:
            broker_params = {
                "redirect_uri": callback_url,
                "state": state_token,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            return {
                "ok": True,
                "provider": provider_id,
                "authorize_url": f"{_validate_server_url(broker_url)}/oauth/{provider_id}?{urlencode(broker_params)}",
            }
        params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": spec["scopes"],
            "state": state_token,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return {
            "ok": True,
            "provider": provider_id,
            "authorize_url": f"{spec['authorize_url']}?{urlencode(params)}",
        }

    def complete_sso_callback(self, *, state_token: str, code: str) -> dict:
        if not state_token or not code:
            raise AccountError("Missing OAuth state or authorization code.")
        with self._lock:
            matched_key = None
            for key in list(self._pending_oauth.keys()):
                if hmac.compare_digest(key, state_token):
                    matched_key = key
                    break
            pending = self._pending_oauth.pop(matched_key, None) if matched_key else None
        if not pending or (time.monotonic() - pending["created_at"]) > _PKCE_TTL_SECONDS:
            raise AccountError("SSO sign-in session expired or state did not match. Start sign-in again.")

        provider_id = pending["provider"]
        spec = SSO_PROVIDERS[provider_id]
        client_id, client_secret = self._provider_credentials(provider_id)
        if not client_id:
            raise AccountError(f"{spec['label']} SSO client ID is no longer configured.")

        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": pending["callback_url"],
            "client_id": client_id,
            "code_verifier": pending["verifier"],
        }
        if client_secret:
            form["client_secret"] = client_secret

        status_code, token_data = _https_request(
            spec["token_url"],
            method="POST",
            body=urlencode(form).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        access_token = token_data.get("access_token") if status_code == 200 else None
        id_claims = _decode_jwt_claims(str(token_data.get("id_token") or "")) if status_code == 200 else {}
        if id_claims and id_claims.get("nonce") and not hmac.compare_digest(str(id_claims["nonce"]), pending["nonce"]):
            raise AccountError(f"{spec['label']} ID token nonce verification failed.")
        if not isinstance(access_token, str) or not access_token:
            err_desc = str(token_data.get("error_description") or token_data.get("error") or "").strip()
            suffix = f": {err_desc[:120]}" if err_desc else ""
            raise AccountError(f"{spec['label']} did not complete the OAuth token exchange (HTTP {status_code}{suffix}).")

        profile: dict = {}
        ui_status = 0
        try:
            ui_status, profile = _https_request(
                spec["userinfo_url"],
                method="GET",
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except AccountError:
            profile = {}
        email = str(
            profile.get("email")
            or profile.get("preferred_username")
            or id_claims.get("email")
            or id_claims.get("preferred_username")
            or id_claims.get("upn")
            or ""
        ).strip().lower()
        if not _EMAIL_RE.match(email):
            raise AccountError(f"Could not verify email identity from {spec['label']} (HTTP {ui_status}).")
        display_name = str(profile.get("name") or id_claims.get("name") or email.split("@")[0])[:80]
        sub = str(profile.get("sub") or id_claims.get("sub") or secrets.token_hex(12))
        account_id = f"sso_{provider_id}_{hashlib.sha256(sub.encode('utf-8')).hexdigest()[:16]}"
        now = _utc_now()
        with self._lock:
            server_url = self._sso_config.get("server_url") or _DEFAULT_CLOUD_URL
            prev_prefs = (self._session or {}).get("preferences") or _default_preferences()
            session = {
                "account_id": account_id,
                "email": email,
                "name": display_name,
                "provider": provider_id,
                "server_url": server_url,
                "connection_mode": "sso_verified",
                "signed_in_at": now,
                "policy_version": legal.POLICY_VERSION,
                "accepted_legal_at": now,
                "preferences": dict(prev_prefs),
                "last_telemetry_sync": None,
                "last_telemetry_status": None,
            }
            self._session = session
            _save_private_json(self.session_path, session)
        return self.status()

    def sign_out(self) -> dict:
        with self._lock:
            self._session = None
            try:
                self.session_path.unlink(missing_ok=True)
            except OSError:
                pass
        return self.status()

    def update_preferences(self, updates: dict) -> dict:
        with self._lock:
            if not isinstance(self._session, dict):
                raise AccountError("Sign in to update telemetry and privacy preferences.")
            prefs = dict(self._session.get("preferences") or _default_preferences())
            for key in ("share_system_diagnostics", "share_threat_intelligence", "auto_check_updates"):
                if key in updates:
                    if not isinstance(updates[key], bool):
                        raise ValueError(f"{key} must be a boolean.")
                    prefs[key] = updates[key]
            self._session["preferences"] = prefs
            _save_private_json(self.session_path, self._session)
        return self.status()

    def should_auto_sync(self) -> bool:
        if self.offline:
            return False
        with self._lock:
            if not isinstance(self._session, dict):
                return False
            prefs = self._session.get("preferences") or _default_preferences()
            return bool(prefs.get("share_system_diagnostics") or prefs.get("share_threat_intelligence"))

    def build_telemetry_preview(
        self,
        *,
        host: dict,
        posture: dict,
        threats: dict,
        scan: dict | None = None,
        exposure_result: dict | None = None,
        supply_chain: dict | None = None,
        pentest_result: dict | None = None,
    ) -> dict:
        with self._lock:
            session = dict(self._session) if isinstance(self._session, dict) else None
        prefs = (session or {}).get("preferences") or _default_preferences()
        redactions = 0

        def _redact(text: str) -> str:
            nonlocal redactions
            cleaned, counts = reporting.redact_text(text)
            redactions += sum(counts.values())
            return cleaned

        raw_payload: dict = {
            "schema_version": 1,
            "generated_at": _utc_now(),
            "wardr_version": updater.current_version(),
            "account_hash": hashlib.sha256(str((session or {}).get("account_id") or "anonymous").encode("utf-8")).hexdigest()[:20],
            "opt_in": {
                "system_diagnostics": bool(prefs.get("share_system_diagnostics")),
                "threat_intelligence": bool(prefs.get("share_threat_intelligence")),
            },
        }
        if prefs.get("share_system_diagnostics") or not session:
            scan_checks = (scan or {}).get("checks") or []
            checks_summary = [
                {
                    "id": str(c.get("id") or "")[:120],
                    "category": str(c.get("category") or "Security")[:64],
                    "status": str(c.get("status") or "unknown")[:32],
                    "severity": str(c.get("severity") or "medium")[:32],
                    "handled": bool((c.get("disposition") or {}).get("kind") in ("queued", "acknowledged")),
                }
                for c in scan_checks[:100]
                if isinstance(c, dict) and c.get("id")
            ]
            pt_summary = None
            if isinstance(pentest_result, dict):
                pt_summary = {
                    "score_pct": pentest_result.get("score_pct"),
                    "verdict": pentest_result.get("verdict"),
                    "probes": [
                        {
                            "id": str(t.get("id") or "")[:80],
                            "outcome": str(t.get("outcome") or "unknown")[:32],
                            "finding_count": len(t.get("findings") or []),
                            "handled": bool((t.get("disposition") or {}).get("kind") == "acknowledged"),
                        }
                        for t in (pentest_result.get("tests") or [])[:20]
                        if isinstance(t, dict) and t.get("id")
                    ],
                }
            raw_payload["system_diagnostics"] = {
                "os": str(host.get("os") or ""),
                "os_version": _redact(str(host.get("version") or "")),
                "arch": platform.machine(),
                "python_version": platform.python_version(),
                "scan_profile": str((scan or {}).get("profile") or ""),
                "scan_duration_ms": (scan or {}).get("duration_ms"),
                "posture_level": posture.get("level"),
                "coverage_pct": posture.get("coverage_pct"),
                "secured_count": posture.get("secured", 0),
                "handled_count": posture.get("handled", 0),
                "failed_count": posture.get("failed", 0),
                "unverified_count": posture.get("unverified", 0),
                "checks_summary": checks_summary,
                "pentest_score_pct": (pentest_result or {}).get("score_pct"),
                "pentest_summary": pt_summary,
            }
        if prefs.get("share_threat_intelligence") or not session:
            sc_findings = (supply_chain or {}).get("findings") or []
            sc_summary = None
            if isinstance(supply_chain, dict):
                s_counts = supply_chain.get("summary") if isinstance(supply_chain.get("summary"), dict) else {}
                sc_summary = {
                    "status": supply_chain.get("status"),
                    "repos_detected": s_counts.get("repos_detected", 0),
                    "manifests_scanned": s_counts.get("manifests_scanned", 0),
                    "packages_checked": s_counts.get("packages_checked", 0),
                    "findings_count": len(sc_findings),
                }
            risky_ports: list[dict] = []
            if isinstance(exposure_result, dict):
                audited = surface.audit_exposure(exposure_result, probe_local_tls=False)
                for svc in (audited.get("risky_services") or [])[:32]:
                    risky_ports.append({
                        "port": svc.get("port"),
                        "service": str(svc.get("service") or "")[:120],
                        "severity": svc.get("severity"),
                        "scope": svc.get("scope"),
                    })
            raw_payload["threat_intelligence"] = {
                "active_threat_count": threats.get("count", 0),
                "threat_status": threats.get("status", "clear"),
                "exposed_risky_ports": risky_ports,
                "supply_chain_summary": sc_summary,
                "supply_chain_signatures_matched": [
                    {
                        "kind": f.get("kind"),
                        "cve": f.get("cve"),
                        "package": _redact(str(f.get("package") or "")),
                        "version": _redact(str(f.get("version") or "")),
                        "severity": f.get("severity"),
                    }
                    for f in sc_findings[:50]
                ],
            }
        return {
            "payload": raw_payload,
            "redactions_applied": redactions,
            "pii_excluded": ["usernames", "hostnames", "home_paths", "ip_addresses", "email_addresses", "api_keys_and_secrets"],
        }

    def sync_telemetry(self, preview_bundle: dict) -> dict:
        if self.offline:
            raise AccountError("Telemetry sync is disabled in offline mode.")
        with self._lock:
            if not isinstance(self._session, dict):
                raise AccountError("Sign in to your Wardr account before syncing telemetry.")
            prefs = self._session.get("preferences") or _default_preferences()
            if not prefs.get("share_system_diagnostics") and not prefs.get("share_threat_intelligence"):
                raise AccountError("Opt in to System Diagnostics or Threat Intelligence first before syncing.")
            server_url = self._session.get("server_url") or self._sso_config.get("server_url") or _DEFAULT_CLOUD_URL

        payload = preview_bundle.get("payload")
        if not isinstance(payload, dict):
            raise AccountError("Invalid telemetry bundle.")

        endpoint = f"{server_url.rstrip('/')}/api/v1/telemetry/ingest"
        raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        synced_at = _utc_now()
        try:
            code, resp = _https_request(
                endpoint,
                method="POST",
                body=raw,
                headers={"Content-Type": "application/json"},
            )
            if 200 <= code < 300:
                status_text = f"Synced redacted diagnostics to {urlsplit(server_url).hostname} (HTTP {code})."
                delivered = True
            else:
                status_text = f"Server returned HTTP {code}; redacted bundle queued locally."
                delivered = False
        except AccountError:
            status_text = f"Saved redacted bundle locally (server {urlsplit(server_url).hostname} not reachable yet)."
            delivered = False

        with self._lock:
            if isinstance(self._session, dict):
                self._session["last_telemetry_sync"] = synced_at
                self._session["last_telemetry_status"] = status_text
                _save_private_json(self.session_path, self._session)
        return {
            "ok": True,
            "delivered": delivered,
            "synced_at": synced_at,
            "message": status_text,
            "redactions_applied": preview_bundle.get("redactions_applied", 0),
        }
