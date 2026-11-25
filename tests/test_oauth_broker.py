"""End-to-end and security regression tests for Wardr's stateless PKCE OAuth broker."""

from __future__ import annotations

import base64
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from wardr import account, oauth_broker, threat_network


def _fake_jwt(claims: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


class OAuthBrokerSecurityTests(unittest.TestCase):
    def test_rejects_open_redirects_and_non_loopback_callbacks(self):
        bad_uris = [
            "https://evil.example/auth/callback",
            "http://evil.example:8080/auth/callback",
            "http://localhost:8080/auth/callback",
            "http://127.0.0.1:80/auth/callback",
            "http://127.0.0.1:443/auth/callback",
            "http://127.0.0.1:8080/other",
            "http://127.0.0.1:8080/auth/callback?injected=1",
            "http://127.0.0.1:8080/auth/callback#frag",
            "http://user@127.0.0.1:8080/auth/callback",
            "javascript:alert(1)",
        ]
        for uri in bad_uris:
            with self.subTest(uri=uri):
                with self.assertRaises(ValueError):
                    oauth_broker.validate_loopback_redirect_uri(uri)
        self.assertEqual(
            oauth_broker.validate_loopback_redirect_uri("http://127.0.0.1:56507/auth/callback"),
            "http://127.0.0.1:56507/auth/callback",
        )

    def test_end_to_end_google_broker_pkce_flow_and_zero_token_retention(self):
        google_client_id = "wardr-web-client.apps.googleusercontent.com"
        google_client_secret = "GOCSPX-server-side-only-secret"
        seen_exchange_calls: list[dict] = []

        def fake_google(url: str, *, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
            seen_exchange_calls.append({"url": url, "method": method, "body": body})
            if url == oauth_broker.BROKER_PROVIDERS["google"]["token_url"]:
                form = parse_qs(body.decode("utf-8"))
                self.assertEqual(form["client_id"][0], google_client_id)
                self.assertEqual(form["client_secret"][0], google_client_secret)
                self.assertEqual(form["redirect_uri"][0], "https://api.getwardr.com/oauth/google/callback")
                return 200, {
                    "access_token": "ya29.ephemeral-google-token",
                    "refresh_token": "1//should-never-be-stored",
                    "id_token": _fake_jwt({
                        "iss": "https://accounts.google.com",
                        "aud": google_client_id,
                        "sub": "google-sub-12345",
                        "email": "Rich@Example.com",
                        "email_verified": True,
                        "name": "Rich Bellantoni",
                        "nonce": captured_nonce["value"],
                        "exp": int(time.time()) + 300,
                    }),
                }
            if url == oauth_broker.BROKER_PROVIDERS["google"]["userinfo_url"]:
                self.assertEqual((headers or {}).get("Authorization"), "Bearer ya29.ephemeral-google-token")
                return 200, {
                    "sub": "google-sub-12345",
                    "email": "Rich@Example.com",
                    "email_verified": True,
                    "name": "Rich Bellantoni",
                }
            raise AssertionError(f"Unexpected upstream URL: {url}")

        captured_nonce = {"value": ""}
        broker = oauth_broker.OAuthBroker(
            public_url="https://api.getwardr.com",
            providers={"google": (google_client_id, google_client_secret)},
            http_exchange=fake_google,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = threat_network.ThreatNetworkStore(root / "tn")
            srv = threat_network.ThreatNetworkServer(("127.0.0.1", 0), store, broker=broker)
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                broker_origin = f"http://127.0.0.1:{srv.server_port}"
                mgr = account.AccountManager(root / "client", offline=False)
                mgr.update_sso_config({"server_url": broker_origin})

                # Before discovery, Google is not yet marked configured
                before = {p["id"]: p["configured"] for p in mgr.status()["sso_providers"]}
                self.assertFalse(before["google"])
                self.assertTrue(before["microsoft"])

                # Discovery fetches GET /oauth/providers and enables Google automatically
                discovered = mgr.refresh_broker_providers()
                self.assertTrue(discovered["google"])
                after = {p["id"]: p["configured"] for p in mgr.status()["sso_providers"]}
                self.assertTrue(after["google"])

                # Step 1: Desktop starts Google SSO via broker (zero Google secrets on client)
                callback_url = "http://127.0.0.1:54321/auth/callback"
                started = mgr.start_sso("google", callback_url=callback_url, accepted_legal=True)
                self.assertTrue(started["authorize_url"].startswith(f"{broker_origin}/oauth/google?"))
                auth_split = urlsplit(started["authorize_url"])
                captured_nonce["value"] = parse_qs(auth_split.query)["nonce"][0]

                # Step 2: Browser visits broker /oauth/google -> 302 to Google
                conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
                conn.request("GET", f"{auth_split.path}?{auth_split.query}")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 302)
                google_loc = resp.getheader("Location")
                self.assertTrue(google_loc.startswith("https://accounts.google.com/o/oauth2/v2/auth?"))
                google_params = parse_qs(urlsplit(google_loc).query)
                self.assertEqual(google_params["client_id"][0], google_client_id)
                self.assertEqual(google_params["redirect_uri"][0], "https://api.getwardr.com/oauth/google/callback")
                broker_state = google_params["state"][0]

                # Step 3: Google redirects browser back to broker /oauth/google/callback -> 302 to 127.0.0.1
                conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
                conn.request("GET", f"/oauth/google/callback?state={broker_state}&code=mock-google-auth-code")
                cb_resp = conn.getresponse()
                cb_resp.read()
                conn.close()
                self.assertEqual(cb_resp.status, 302)
                local_loc = cb_resp.getheader("Location")
                self.assertTrue(local_loc.startswith(f"{callback_url}?"))
                local_params = parse_qs(urlsplit(local_loc).query)
                client_state = local_params["state"][0]
                broker_code = local_params["code"][0]

                # Verify ZERO upstream Google tokens are retained in broker memory
                broker_dump = json.dumps({"states": broker._pending_states, "codes": broker._pending_codes})
                self.assertNotIn("ya29.ephemeral-google-token", broker_dump)
                self.assertNotIn("should-never-be-stored", broker_dump)

                # Step 4: Desktop completes callback by exchanging broker_code + PKCE verifier at /oauth/token
                completed = mgr.complete_sso_callback(state_token=client_state, code=broker_code)
                self.assertTrue(completed["signed_in"])
                self.assertFalse(completed["auth_required"])
                self.assertEqual(completed["account"]["email"], "rich@example.com")
                self.assertEqual(completed["account"]["name"], "Rich Bellantoni")
                self.assertEqual(completed["account"]["provider"], "google")
                self.assertEqual(completed["account"]["connection_mode"], "sso_verified")

                # Verify single-use: replaying the same broker_code fails
                with self.assertRaises(oauth_broker.BrokerError):
                    broker.exchange_code({
                        "grant_type": "authorization_code",
                        "provider": "google",
                        "code": broker_code,
                        "code_verifier": "A" * 64,
                        "redirect_uri": callback_url,
                    })
            finally:
                srv.shutdown()
                srv.server_close()

    def test_broker_rejects_pkce_mismatch_and_unverified_email(self):
        google_client_id = "wardr-web-client.apps.googleusercontent.com"
        google_client_secret = "GOCSPX-secret"

        def make_broker(email_verified: bool, aud: str = google_client_id):
            def fake_google(url: str, *, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
                if "token" in url:
                    return 200, {
                        "access_token": "tok",
                        "id_token": _fake_jwt({
                            "iss": "https://accounts.google.com",
                            "aud": aud,
                            "sub": "sub-1",
                            "email": "user@example.com",
                            "email_verified": email_verified,
                            "nonce": "nonce_value_1234567890",
                            "exp": int(time.time()) + 300,
                        }),
                    }
                return 200, {"sub": "sub-1", "email": "user@example.com", "email_verified": email_verified}

            return oauth_broker.OAuthBroker(
                public_url="https://api.getwardr.com",
                providers={"google": (google_client_id, google_client_secret)},
                http_exchange=fake_google,
            )

        verifier = "verifier_" + "x" * 50
        challenge = oauth_broker._pkce_s256(verifier)
        query = (
            f"redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fauth%2Fcallback"
            f"&state=client_state_1234567890&nonce=nonce_value_1234567890"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        )

        # 1. Unverified email must redirect with error=email_not_verified and mint no code
        b_unverified = make_broker(email_verified=False)
        auth_url = b_unverified.start_authorization("google", query)
        b_state = parse_qs(urlsplit(auth_url).query)["state"][0]
        redir = b_unverified.handle_callback("google", f"state={b_state}&code=g1")
        self.assertIn("error=email_not_verified", redir)
        self.assertNotIn("code=", redir)

        # 2. Wrong audience must fail
        b_aud = make_broker(email_verified=True, aud="other-app.apps.googleusercontent.com")
        auth_url = b_aud.start_authorization("google", query)
        b_state = parse_qs(urlsplit(auth_url).query)["state"][0]
        redir = b_aud.handle_callback("google", f"state={b_state}&code=g2")
        self.assertIn("error=invalid_audience", redir)
        self.assertNotIn("code=", redir)

        # 3. Wrong PKCE code_verifier must be rejected (and burns the code)
        b_ok = make_broker(email_verified=True)
        auth_url = b_ok.start_authorization("google", query)
        b_state = parse_qs(urlsplit(auth_url).query)["state"][0]
        redir = b_ok.handle_callback("google", f"state={b_state}&code=g3")
        b_code = parse_qs(urlsplit(redir).query)["code"][0]
        with self.assertRaisesRegex(oauth_broker.BrokerError, "PKCE"):
            b_ok.exchange_code({
                "grant_type": "authorization_code",
                "provider": "google",
                "code": b_code,
                "code_verifier": "wrong_verifier_" + "y" * 50,
                "redirect_uri": "http://127.0.0.1:51234/auth/callback",
            })


if __name__ == "__main__":
    unittest.main()
