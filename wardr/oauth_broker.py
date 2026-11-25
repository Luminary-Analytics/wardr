"""Stateless, zero-retention PKCE (S256) OAuth 2.0 broker for Wardr desktop clients.

Keeps OAuth client secrets strictly server-side (for example on api.getwardr.com)
so desktop builds never ship embedded Google/Microsoft OAuth secrets. Provider
access tokens and ID tokens are verified and immediately discarded—only a
short-lived, single-use, PKCE-bound authorization code carrying the verified
email/name/subject is returned to the user's local 127.0.0.1 Wardr callback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import threading
import time
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlsplit


_STATE_TTL_SECONDS = 300
_CODE_TTL_SECONDS = 120
_MAX_PENDING = 2048
_IO_TIMEOUT = 15
_MAX_RESPONSE_BYTES = 128 * 1024

_PKCE_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_TOKEN_PARAM_RE = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")

BROKER_PROVIDERS: dict[str, dict] = {
    "google": {
        "id": "google",
        "label": "Google",
        "env_client_id": "WARDR_GOOGLE_CLIENT_ID",
        "env_client_secret": "WARDR_GOOGLE_CLIENT_SECRET",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": "openid email profile",
        "valid_issuers": ("https://accounts.google.com", "accounts.google.com"),
        "require_email_verified": True,
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
        "valid_issuers": (),
        "require_email_verified": False,
    },
}


class BrokerError(RuntimeError):
    """Raised when an OAuth broker request fails validation or upstream exchange."""


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_jwt_claims(id_token: str) -> dict:
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


def validate_loopback_redirect_uri(redirect_uri: str) -> str:
    """Only permit Wardr's ephemeral IPv4 loopback callback URL (no open redirects)."""
    if not isinstance(redirect_uri, str) or len(redirect_uri) > 128:
        raise ValueError("Invalid loopback redirect_uri.")
    parsed = urlsplit(redirect_uri)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/auth/callback"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("redirect_uri must be http://127.0.0.1:<port>/auth/callback.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid loopback port in redirect_uri.") from exc
    if port is None or not 1024 <= port <= 65535:
        raise ValueError("redirect_uri port must be between 1024 and 65535.")
    return f"http://127.0.0.1:{port}/auth/callback"


def _default_http_exchange(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise BrokerError("Upstream OAuth endpoint must use HTTPS.")
    port = parsed.port or 443
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    req_headers = {"User-Agent": "WardrOAuthBroker/1", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    conn = http.client.HTTPSConnection(
        parsed.hostname, port, timeout=_IO_TIMEOUT, context=ssl.create_default_context()
    )
    try:
        conn.request(method, target or "/", body=body, headers=req_headers)
        resp = conn.getresponse()
        raw = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise BrokerError("Upstream OAuth response exceeded size limit.")
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        return resp.status, payload if isinstance(payload, dict) else {}
    except OSError as exc:
        raise BrokerError(f"Could not contact upstream OAuth provider: {exc}") from exc
    finally:
        conn.close()


class OAuthBroker:
    """In-memory, zero-retention PKCE OAuth broker for desktop Wardr clients."""

    def __init__(
        self,
        *,
        public_url: str | None = None,
        providers: dict[str, tuple[str, str]] | None = None,
        http_exchange: Callable[..., tuple[int, dict]] | None = None,
    ):
        raw_public = (
            public_url
            if public_url is not None
            else (os.environ.get("WARDR_PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "")
        )
        self.public_url = raw_public.strip().rstrip("/")
        self._explicit_providers = dict(providers) if providers is not None else None
        self._http_exchange = http_exchange or _default_http_exchange
        self._lock = threading.Lock()
        self._pending_states: dict[str, dict] = {}
        self._pending_codes: dict[str, dict] = {}

    def _credentials(self, provider_id: str) -> tuple[str, str]:
        if self._explicit_providers is not None:
            pair = self._explicit_providers.get(provider_id)
            if pair:
                return pair[0].strip(), pair[1].strip()
            return "", ""
        spec = BROKER_PROVIDERS.get(provider_id)
        if not spec:
            return "", ""
        cid = os.environ.get(spec["env_client_id"], "").strip()
        secret = os.environ.get(spec["env_client_secret"], "").strip()
        return cid, secret

    def configured_providers(self) -> dict[str, bool]:
        result: dict[str, bool] = {}
        for pid in BROKER_PROVIDERS:
            cid, secret = self._credentials(pid)
            # Require both client_id and client_secret on the confidential broker
            result[pid] = bool(cid and secret)
        return result

    def _broker_callback_url(self, provider_id: str, fallback_origin: str | None = None) -> str:
        base = self.public_url or (fallback_origin or "").strip().rstrip("/")
        if not base:
            raise BrokerError("WARDR_PUBLIC_URL is not configured on the OAuth broker.")
        parsed = urlsplit(base)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise BrokerError("Invalid broker public URL.")
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise BrokerError("Public OAuth broker URL must use HTTPS.")
        return f"{base}/oauth/{provider_id}/callback"

    def _prune_locked(self, now: float) -> None:
        self._pending_states = {
            k: v for k, v in self._pending_states.items() if (now - v["created_at"]) < _STATE_TTL_SECONDS
        }
        self._pending_codes = {
            k: v for k, v in self._pending_codes.items() if (now - v["created_at"]) < _CODE_TTL_SECONDS
        }
        if len(self._pending_states) > _MAX_PENDING:
            oldest = sorted(self._pending_states.items(), key=lambda kv: kv[1]["created_at"])
            for key, _ in oldest[: len(self._pending_states) - _MAX_PENDING]:
                self._pending_states.pop(key, None)
        if len(self._pending_codes) > _MAX_PENDING:
            oldest = sorted(self._pending_codes.items(), key=lambda kv: kv[1]["created_at"])
            for key, _ in oldest[: len(self._pending_codes) - _MAX_PENDING]:
                self._pending_codes.pop(key, None)

    def start_authorization(self, provider_id: str, query: str, *, fallback_origin: str | None = None) -> str:
        spec = BROKER_PROVIDERS.get(provider_id)
        if not spec:
            raise ValueError("Unsupported OAuth provider.")
        cid, secret = self._credentials(provider_id)
        if not cid or not secret:
            raise BrokerError(f"{spec['label']} sign-in is not configured on this Wardr auth broker.")

        params = parse_qs(query, keep_blank_values=False)
        redirect_uri = validate_loopback_redirect_uri((params.get("redirect_uri") or [""])[0])
        client_state = (params.get("state") or [""])[0]
        nonce = (params.get("nonce") or [""])[0]
        code_challenge = (params.get("code_challenge") or [""])[0]
        code_challenge_method = (params.get("code_challenge_method") or [""])[0]

        if not _TOKEN_PARAM_RE.fullmatch(client_state):
            raise ValueError("Invalid OAuth state parameter.")
        if not _TOKEN_PARAM_RE.fullmatch(nonce):
            raise ValueError("Invalid OAuth nonce parameter.")
        if code_challenge_method != "S256" or not _PKCE_CHALLENGE_RE.fullmatch(code_challenge):
            raise ValueError("PKCE S256 code_challenge is required.")

        broker_callback = self._broker_callback_url(provider_id, fallback_origin=fallback_origin)
        broker_state = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            self._pending_states[broker_state] = {
                "provider": provider_id,
                "redirect_uri": redirect_uri,
                "client_state": client_state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "broker_callback": broker_callback,
                "created_at": now,
            }

        upstream_params = {
            "client_id": cid,
            "redirect_uri": broker_callback,
            "response_type": "code",
            "scope": spec["scopes"],
            "state": broker_state,
            "nonce": nonce,
            "prompt": "select_account",
        }
        return f"{spec['authorize_url']}?{urlencode(upstream_params)}"

    def handle_callback(self, provider_id: str, query: str) -> str:
        spec = BROKER_PROVIDERS.get(provider_id)
        if not spec:
            raise ValueError("Unsupported OAuth provider.")

        params = parse_qs(query, keep_blank_values=False)
        broker_state = (params.get("state") or [""])[0]
        upstream_code = (params.get("code") or [""])[0]
        upstream_error = (params.get("error") or [""])[0]

        if not broker_state:
            raise ValueError("Missing OAuth state.")

        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            matched_key = None
            for key in list(self._pending_states.keys()):
                if hmac.compare_digest(key, broker_state):
                    matched_key = key
                    break
            pending = self._pending_states.pop(matched_key, None) if matched_key else None

        if not pending or pending["provider"] != provider_id or (now - pending["created_at"]) > _STATE_TTL_SECONDS:
            raise BrokerError("Sign-in session expired or state did not match. Start sign-in again from Wardr.")

        client_redirect = pending["redirect_uri"]
        client_state = pending["client_state"]

        if upstream_error:
            safe_err = re.sub(r"[^A-Za-z0-9_.-]", "_", upstream_error)[:64] or "access_denied"
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': safe_err})}"

        if not upstream_code or len(upstream_code) > 2048:
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'missing_code'})}"

        cid, secret = self._credentials(provider_id)
        if not cid or not secret:
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'provider_not_configured'})}"

        form = {
            "grant_type": "authorization_code",
            "code": upstream_code,
            "redirect_uri": pending["broker_callback"],
            "client_id": cid,
            "client_secret": secret,
        }
        status_code, token_data = self._http_exchange(
            spec["token_url"],
            method="POST",
            body=urlencode(form).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if status_code != 200 or not isinstance(token_data.get("access_token"), str):
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'token_exchange_failed'})}"

        access_token = token_data["access_token"]
        id_claims = _decode_jwt_claims(str(token_data.get("id_token") or ""))
        if id_claims:
            valid_issuers = spec["valid_issuers"]
            if valid_issuers and id_claims.get("iss") not in valid_issuers:
                return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'invalid_issuer'})}"
            aud = id_claims.get("aud")
            aud_ok = (aud == cid) if isinstance(aud, str) else (isinstance(aud, list) and cid in aud)
            if aud is not None and not aud_ok:
                return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'invalid_audience'})}"
            exp = id_claims.get("exp")
            if isinstance(exp, (int, float)) and exp < (time.time() - 30):
                return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'token_expired'})}"
            claim_nonce = id_claims.get("nonce")
            if claim_nonce and not hmac.compare_digest(str(claim_nonce), pending["nonce"]):
                return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'nonce_mismatch'})}"

        profile: dict = {}
        try:
            ui_status, ui_data = self._http_exchange(
                spec["userinfo_url"],
                method="GET",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if ui_status == 200:
                profile = ui_data
        except BrokerError:
            profile = {}
        finally:
            # Discard upstream provider tokens immediately (zero retention).
            access_token = ""
            token_data.clear()

        if spec["require_email_verified"]:
            verified = profile.get("email_verified")
            if verified is None:
                verified = id_claims.get("email_verified")
            if verified is not True:
                return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'email_not_verified'})}"

        email = str(
            profile.get("email")
            or profile.get("preferred_username")
            or id_claims.get("email")
            or id_claims.get("preferred_username")
            or id_claims.get("upn")
            or ""
        ).strip().lower()
        if not _EMAIL_RE.fullmatch(email):
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'invalid_email'})}"

        sub = str(profile.get("sub") or id_claims.get("sub") or "").strip()[:128]
        if not sub:
            return f"{client_redirect}?{urlencode({'state': client_state, 'error': 'missing_subject'})}"
        name = str(profile.get("name") or id_claims.get("name") or email.split("@")[0]).strip()[:80]

        broker_code = secrets.token_urlsafe(32)
        with self._lock:
            now_code = time.monotonic()
            self._prune_locked(now_code)
            self._pending_codes[broker_code] = {
                "provider": provider_id,
                "redirect_uri": client_redirect,
                "code_challenge": pending["code_challenge"],
                "nonce": pending["nonce"],
                "sub": sub,
                "email": email,
                "name": name,
                "created_at": now_code,
            }

        return f"{client_redirect}?{urlencode({'state': client_state, 'code': broker_code})}"

    def exchange_code(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Invalid token exchange payload.")
        if payload.get("grant_type") != "authorization_code":
            raise ValueError("Unsupported grant_type.")
        provider_id = str(payload.get("provider") or "")
        code = str(payload.get("code") or "")
        code_verifier = str(payload.get("code_verifier") or "")
        redirect_uri = validate_loopback_redirect_uri(str(payload.get("redirect_uri") or ""))

        if provider_id not in BROKER_PROVIDERS:
            raise ValueError("Unsupported provider.")
        if not code or len(code) > 256:
            raise ValueError("Invalid authorization code.")
        if not _PKCE_VERIFIER_RE.fullmatch(code_verifier):
            raise ValueError("Invalid PKCE code_verifier.")

        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            matched_key = None
            for key in list(self._pending_codes.keys()):
                if hmac.compare_digest(key, code):
                    matched_key = key
                    break
            record = self._pending_codes.pop(matched_key, None) if matched_key else None

        if not record or (now - record["created_at"]) > _CODE_TTL_SECONDS:
            raise BrokerError("Authorization code expired or already used.")
        if record["provider"] != provider_id or record["redirect_uri"] != redirect_uri:
            raise BrokerError("Authorization code binding mismatch.")

        expected_challenge = _pkce_s256(code_verifier)
        if not hmac.compare_digest(expected_challenge, record["code_challenge"]):
            raise BrokerError("PKCE code_verifier verification failed.")

        return {
            "ok": True,
            "provider": provider_id,
            "sub": record["sub"],
            "email": record["email"],
            "name": record["name"],
            "nonce": record["nonce"],
        }
