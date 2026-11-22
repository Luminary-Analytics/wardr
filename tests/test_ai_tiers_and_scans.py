"""Tests for 3-tier AI protection (Radar, Cloud Offload, Local Heavy AI) and scan depth profiles."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wardr import actions, ai_tiers
from wardr.state import SCAN_PROFILES, WardrState


HOST = {"name": "alice-workstation.local", "os": "macOS", "version": "15.2"}


class AITiersTests(unittest.TestCase):
    def test_ram_recommendations(self):
        self.assertEqual(ai_tiers.recommended_local_profile(4), "qwen2.5-1.5b")
        self.assertEqual(ai_tiers.recommended_local_profile(8), "qwen3-4b")
        self.assertEqual(ai_tiers.recommended_local_profile(16), "foundation-sec-8b")
        self.assertEqual(ai_tiers.recommended_local_profile(64), "foundation-sec-8b")

    def test_cloud_endpoint_rejects_non_https_and_private_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad_url in (
                "http://api.groq.com/openai/v1/chat/completions",
                "https://127.0.0.1:8080/v1/chat",
                "https://localhost/v1/chat",
                "https://192.168.1.5/v1/chat",
                "https://user:pass@api.groq.com/v1/chat",
            ):
                with self.subTest(bad_url=bad_url), self.assertRaises(ValueError):
                    ai_tiers.save_config(Path(tmp), {"active_tier": "cloud", "cloud_preset": "custom", "cloud_endpoint": bad_url})

    def test_config_persists_secret_with_0600_and_never_leaks_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            ai_tiers.save_config(state_dir, {
                "active_tier": "cloud",
                "cloud_preset": "groq",
                "cloud_api_key": "gsk_supersecretkey9876",
            })
            cfg_path = state_dir / "ai-tiers.json"
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(cfg_path.stat().st_mode), 0o600)
            with patch("wardr.ai_tiers._ollama_installed_models", return_value=(False, [])):
                pub = ai_tiers.public_status(state_dir, offline=False)
            self.assertEqual(pub["active_tier"], "cloud")
            self.assertTrue(pub["tier2"]["ready"])
            self.assertTrue(pub["tier2"]["has_api_key"])
            self.assertEqual(pub["tier2"]["key_hint"], "…9876")
            self.assertNotIn("gsk_supersecretkey9876", json.dumps(pub))

            # Offline mode pauses Tier 2 cloud readiness
            with patch("wardr.ai_tiers._ollama_installed_models", return_value=(False, [])):
                pub_offline = ai_tiers.public_status(state_dir, offline=True)
            self.assertFalse(pub_offline["tier2"]["ready"])

    def test_cloud_triage_redacts_pii_and_secrets_before_sending(self):
        captured = {}

        def fake_cloud(endpoint, api_key, model, user_content):
            captured["payload"] = user_content
            return json.dumps({
                "summary": "Firewall is off; enable it to close the main gap.",
                "threat_verdict": "No active threats detected right now.",
                "top_actions": ["Enable the macOS Application Firewall."],
            })

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            ai_tiers.save_config(state_dir, {
                "active_tier": "cloud",
                "cloud_preset": "huggingface",
                "cloud_api_key": "hf_testtoken1234567890abcd",
            })
            checks = [{
                "id": "ssh",
                "title": "SSH key permissions",
                "severity": "high",
                "category": "Access",
                "status": "fail",
                "can_fix": True,
                "evidence": "Found /Users/alice/.ssh/id_rsa on alice-workstation.local from 10.20.30.40 owned by alice@example.com",
            }]
            with patch("wardr.ai_tiers._call_cloud_api", side_effect=fake_cloud):
                result = ai_tiers.run_triage(
                    state_dir,
                    host=HOST,
                    posture={"level": "red", "secured": 4, "securable_total": 5},
                    checks=checks,
                    threats={"status": "clear", "count": 0, "alerts": []},
                    offline=False,
                )
            self.assertEqual(result["tier"], "cloud")
            self.assertGreater(result["redactions_applied"], 0)
            for sensitive in ("/Users/alice", "alice-workstation.local", "10.20.30.40", "alice@example.com"):
                self.assertNotIn(sensitive, captured["payload"])

    def test_local_triage_works_offline_with_installed_cyber_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            ai_tiers.save_config(state_dir, {"active_tier": "local", "local_profile": "foundation-sec-8b"})
            tag = ai_tiers.LOCAL_PROFILES["foundation-sec-8b"]["ollama_tag"]
            fake_reply = json.dumps({
                "summary": "All checked controls are secure.",
                "threat_verdict": "No active threats.",
                "top_actions": ["Keep continuous radar enabled."],
            })
            with (
                patch("wardr.ai_tiers._ollama_installed_models", return_value=(True, [tag])),
                patch("wardr.ai_tiers._call_local_ollama", return_value=fake_reply),
            ):
                result = ai_tiers.run_triage(
                    state_dir,
                    host=HOST,
                    posture={"level": "green", "secured": 5, "securable_total": 5},
                    checks=[],
                    threats={"status": "clear", "count": 0, "alerts": []},
                    offline=True,
                )
            self.assertEqual(result["tier"], "local")
            self.assertEqual(result["model"], "Cisco Foundation-Sec 1.1 (8B)")


class ScanDepthProfileTests(unittest.TestCase):
    def test_scan_profiles_reject_invalid_and_run_expected_modules(self):
        self.assertEqual(set(SCAN_PROFILES.keys()), {"light", "medium", "heavy"})
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp))
            with self.assertRaises(ValueError):
                state.start_scan(profile="extreme")

            fake_scan = {
                "host": state.host["name"],
                "scanned_at": "2026-11-22T10:00:00+00:00",
                "checks": [],
            }
            with (
                patch("wardr.state.checks.scan", return_value=fake_scan),
                patch("wardr.state.exposure.collect_exposure") as mock_exp,
                patch("wardr.state.fim.check_integrity") as mock_fim,
                patch("wardr.state.inventory.collect_inventory") as mock_inv,
            ):
                state._run_scan("light")
                mock_exp.assert_not_called()
                mock_fim.assert_not_called()
                mock_inv.assert_not_called()
                self.assertEqual(state._scan_modules["profile"], "light")

            with (
                patch("wardr.state.checks.scan", return_value=fake_scan),
                patch("wardr.state.exposure.collect_exposure", return_value={"listeners": [{"port": 80}]}) as mock_exp,
                patch("wardr.state.fim.check_integrity", return_value={"status": "pass", "tracked_count": 3, "changes": []}) as mock_fim,
                patch("wardr.state.inventory.collect_inventory") as mock_inv,
            ):
                state._run_scan("medium")
                mock_exp.assert_called_once()
                mock_fim.assert_called_once()
                mock_inv.assert_not_called()
                self.assertEqual(state._scan_modules["sockets_inspected"], 1)
                self.assertEqual(state._scan_modules["fim_status"], "pass")
                payload = state.status()
                self.assertEqual(payload["scan"]["progress_pct"], 100)
                self.assertGreaterEqual(len(payload["scan"]["steps"]), 6)

    def test_batch_fix_tracks_steps_and_updates_scan_to_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp))
            failing = {
                "id": "ssh-directory-permissions",
                "title": "SSH directory permissions",
                "category": "Access",
                "severity": "medium",
                "status": "fail",
                "can_fix": True,
                "evidence": "Observed 0755.",
                "remediation": "Restrict to 0700.",
            }
            fixed = {**failing, "status": "pass", "can_fix": False, "evidence": "Observed 0700."}
            state._scan = {
                "host": state.host["name"],
                "scanned_at": "2026-11-22T10:00:00+00:00",
                "checks": [failing],
            }
            with (
                patch("wardr.state.remediation.apply_fix", return_value={"ok": True, "message": "Hardened to 0700.", "check": fixed}),
                patch("wardr.state.checks.apply_fix", return_value={"ok": True, "message": "Hardened to 0700.", "check": fixed}),
            ):
                state._fix_running = True
                state._fix_batch = {
                    "id": 1,
                    "state": "running",
                    "progress_pct": 5,
                    "total": 1,
                    "completed": 0,
                    "succeeded": 0,
                    "failed": 0,
                    "steps": [{"id": failing["id"], "title": failing["title"], "category": "Access", "status": "pending", "message": "", "rollback_id": None}],
                }
                state._run_batch_fix([failing["id"]])
            payload = state.status()
            self.assertEqual(payload["fix_batch"]["state"], "complete")
            self.assertEqual(payload["fix_batch"]["succeeded"], 1)
            self.assertEqual(payload["fix_batch"]["steps"][0]["status"], "fixed")
            self.assertEqual(payload["scan"]["checks"][0]["status"], "pass")

    def test_allowlisted_action_guides_and_rejection(self):
        fw_mac = actions.action_guide_for("macos-firewall", system="Darwin")
        self.assertIsNotNone(fw_mac)
        self.assertTrue(fw_mac["can_open_settings"])
        self.assertTrue(fw_mac["can_script_fix"])
        self.assertIn("socketfilterfw", fw_mac["script_preview"])

        upd_mac = actions.action_guide_for("macos-pending-updates", system="Darwin")
        self.assertIsNotNone(upd_mac)
        self.assertEqual(upd_mac["settings_label"], "Open Software Update")

        self.assertIsNone(actions.action_guide_for("arbitrary-shell-cmd", system="Darwin"))
        with self.assertRaises(ValueError):
            actions.open_settings("arbitrary-shell-cmd")
        with self.assertRaises(ValueError):
            actions.run_script_fix("arbitrary-shell-cmd")


if __name__ == "__main__":
    unittest.main()
