"""Tests for Wardr's automated live feedback-to-release loop."""

from __future__ import annotations

import ast
import json
import tempfile
import threading
import unittest
from pathlib import Path

from wardr import feedback_loop, feeds
from wardr.threat_network import ThreatNetworkServer, ThreatNetworkStore


class FeedbackLoopTests(unittest.TestCase):
    def test_fetch_live_signals_and_build_triage_digest_end_to_end(self):
        with tempfile.TemporaryDirectory() as server_tmp, tempfile.TemporaryDirectory() as out_tmp:
            store = ThreatNetworkStore(Path(server_tmp), escalation_reporters=2, zero_day_threshold=2)
            admin_token = "feedback-loop-test-token-999"

            # Seed an escalated zero-day cluster (2 distinct reporters) with markdown-hostile title
            report_payload = {
                "schema_version": 1,
                "report_kind": "alert",
                "fingerprint": "deadbeef12345678abcd",
                "suspected_zero_day": True,
                "environment": {"os": "macOS"},
                "signal": {"title": "Novel [evil](https://x) `backdoor`\nport 31337"},
            }
            store.ingest_report(report_payload, client_ip="198.51.100.1")
            store.ingest_report(report_payload, client_ip="198.51.100.2")

            # Seed 3 telemetry snapshots with recurring failing check, pentest exposure, risky port, and supply-chain hit
            for idx in range(3):
                store.ingest_telemetry(
                    {
                        "schema_version": 1,
                        "wardr_version": "0.4.0",
                        "account_hash": f"accthash0000000{idx}",
                        "opt_in": {"system_diagnostics": True, "threat_intelligence": True},
                        "system_diagnostics": {
                            "os": "macOS",
                            "arch": "arm64",
                            "posture_level": "amber",
                            "coverage_pct": 80,
                            "pentest_score_pct": 83,
                            "checks_summary": [
                                {"id": "macos-firewall", "category": "Network", "status": "fail", "severity": "high", "handled": False},
                            ],
                            "pentest_summary": {
                                "score_pct": 83,
                                "verdict": "warn",
                                "probes": [{"id": "firewall-lan", "outcome": "exposed", "finding_count": 1}],
                            },
                        },
                        "threat_intelligence": {
                            "active_threat_count": 0,
                            "exposed_risky_ports": [
                                {"port": 11434, "service": "Ollama local AI server", "severity": "high", "scope": "wildcard"},
                            ],
                            "supply_chain_signatures_matched": [
                                {"kind": "compromised_npm", "cve": "CVE-2025-55182", "package": "chalk", "version": "5.6.1", "severity": "critical"},
                            ],
                        },
                    },
                    client_ip=f"198.51.100.{10 + idx}",
                )

            server = ThreatNetworkServer(("127.0.0.1", 0), store, admin_token=admin_token)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{port}"
                # Unauthorized token must fail cleanly
                with self.assertRaises(feedback_loop.FeedbackLoopError):
                    feedback_loop.fetch_live_signals(base_url, admin_token="wrong-token")

                signals = feedback_loop.fetch_live_signals(base_url, admin_token=admin_token)
                digest = feedback_loop.build_triage_digest(signals, current_version="0.4.0")

                self.assertTrue(digest["needs_attention"])
                self.assertEqual(digest["escalated_count"], 1)
                self.assertEqual(digest["recommended_version"], "0.4.1")
                self.assertEqual(digest["high_impact_checks"][0]["id"], "macos-firewall")
                self.assertEqual(digest["high_impact_pentest"][0]["id"], "firewall-lan")
                self.assertEqual(digest["risky_ports"][0]["port"], 11434)
                self.assertEqual(digest["supply_chain_matches"][0]["package"], "chalk")

                # Draft feed must pass Wardr's strict Zero-RCE feed validator
                validated_feed = feeds._parse_feed_document(json.dumps(digest["draft_feed"]).encode("utf-8"))
                self.assertEqual(validated_feed["advisories"][0]["id"], "CVE-2025-55182")

                # Markdown output must sanitize untrusted brackets/backticks/newlines
                self.assertNotIn("[evil]", digest["markdown"])
                self.assertNotIn("`backdoor`", digest["markdown"])
                self.assertIn("wardr feedback-loop prepare-release --version 0.4.1", digest["markdown"])

                # Artifacts write cleanly
                written = feedback_loop.write_digest_artifacts(digest, Path(out_tmp))
                self.assertTrue(Path(written["digest_md"]).is_file())
                self.assertTrue(Path(written["digest_json"]).is_file())
                draft_loaded = json.loads(Path(written["draft_feed"]).read_text(encoding="utf-8"))
                self.assertEqual(draft_loaded["schema_version"], 1)
            finally:
                server.shutdown()
                server.server_close()

    def test_prepare_release_bump_updates_files_and_validates_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wardr" / "static").mkdir(parents=True)
            (root / "pyproject.toml").write_text('[project]\nname = "wardr"\nversion = "0.4.0"\n', encoding="utf-8")
            (root / "wardr" / "changelog.py").write_text(
                'RELEASES: tuple[dict, ...] = (\n    {"version": "0.4.0", "date": "2026-11-22", "title": "Old", "summary": "Old", "highlights": []},\n)\n',
                encoding="utf-8",
            )
            (root / "wardr" / "static" / "index.html").write_text(
                '<span class="whats-new-pill" id="whats-new-version">Wardr v0.4.0</span>\n',
                encoding="utf-8",
            )

            # Reject downgrade or same version
            with self.assertRaises(feedback_loop.FeedbackLoopError):
                feedback_loop.prepare_release_bump(root, target_version="0.4.0")

            # Dry run leaves files untouched
            dry = feedback_loop.prepare_release_bump(root, bump="patch", dry_run=True)
            self.assertEqual(dry["target_version"], "0.4.1")
            self.assertIn('version = "0.4.0"', (root / "pyproject.toml").read_text(encoding="utf-8"))

            # Real bump writes valid Python changelog + updated version + updated pill
            applied = feedback_loop.prepare_release_bump(
                root,
                bump="patch",
                title="Rapid Security Update",
                highlights=[{"tag": "Security", "title": "Mitigated CVE", "detail": "Blocked exploit."}],
            )
            self.assertEqual(applied["target_version"], "0.4.1")
            self.assertIn('version = "0.4.1"', (root / "pyproject.toml").read_text(encoding="utf-8"))
            self.assertIn("Wardr v0.4.1", (root / "wardr" / "static" / "index.html").read_text(encoding="utf-8"))
            changelog_src = (root / "wardr" / "changelog.py").read_text(encoding="utf-8")
            ast.parse(changelog_src)
            self.assertIn('"version": "0.4.1"', changelog_src)
            self.assertIn('"version": "0.4.0"', changelog_src)


if __name__ == "__main__":
    unittest.main()
