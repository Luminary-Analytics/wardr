"""Tests for incremental auto-SBOM discovery and AI/MCP surface auditing."""

import json
from pathlib import Path
import tempfile
import unittest

from wardr import assessment, inventory


class InventoryAndAISurfaceTests(unittest.TestCase):
    def test_incremental_inventory_discovers_packages_and_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            cellar = root / "Cellar"
            (cellar / "openssl" / "3.3.2").mkdir(parents=True)
            dpkg = root / "dpkg-status"
            dpkg.write_text(
                "Package: curl\nStatus: install ok installed\nVersion: 8.5.0-2\n\n"
                "Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n",
                encoding="utf-8",
            )
            apk = root / "apk-installed"
            apk.write_text("P: busybox\nV: 1.36.1-r29\n\n", encoding="utf-8")

            first = inventory.collect_inventory(
                state_dir, include_python=False, cellars=(cellar,), dpkg_path=dpkg, apk_path=apk,
            )
            self.assertFalse(first["cached"])
            self.assertEqual(first["component_count"], 3)
            purls = {c["purl"] for c in first["sbom"]["components"]}
            self.assertIn("pkg:brew/openssl@3.3.2", purls)
            self.assertIn("pkg:apk/alpine/busybox@1.36.1-r29", purls)
            self.assertTrue(any(p.startswith("pkg:deb/") and "curl@8.5.0-2" in p for p in purls))

            # Second run should hit incremental cache.
            second = inventory.collect_inventory(
                state_dir, include_python=False, cellars=(cellar,), dpkg_path=dpkg, apk_path=apk,
            )
            self.assertTrue(second["cached"])
            self.assertEqual(second["component_count"], 3)

            # Auto-SBOM must be directly consumable by Wardr's assessment engine.
            osv = [
                {
                    "id": "OSV-BREW-1",
                    "modified": "2026-11-20T00:00:00Z",
                    "affected": [{"package": {"ecosystem": "Homebrew", "name": "openssl"}, "versions": ["3.3.2"]}],
                }
            ]
            matched = assessment.assess_documents(first["sbom"], osv)
            self.assertEqual(matched["summary"]["matched_findings"], 1)

    def test_ai_surface_detects_plaintext_secrets_unpinned_mcp_and_exposed_ollama(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            cursor_dir = fake_home / ".cursor"
            cursor_dir.mkdir(mode=0o700)
            secret_value = "sk-proj-1234567890abcdefghijklmnop"
            (cursor_dir / "mcp.json").write_text(
                json.dumps({
                    "mcpServers": {
                        "demo": {
                            "command": "npx",
                            "args": ["-y", "@example/mcp-server"],
                            "env": {"OPENAI_API_KEY": secret_value},
                        }
                    }
                }),
                encoding="utf-8",
            )
            exposure = {
                "listeners": [
                    {"protocol": "tcp", "address": "0.0.0.0", "port": 11434, "scope": "wildcard", "process": "ollama"},
                ]
            }
            findings = {item["id"]: item for item in inventory.scan_ai_surface(home=fake_home, exposure_result=exposure)}
            self.assertEqual(findings["ai-mcp-secrets"]["status"], "fail")
            # Raw secret must NEVER leak into the evidence string!
            self.assertNotIn(secret_value, findings["ai-mcp-secrets"]["evidence"])
            self.assertEqual(findings["ai-mcp-unpinned"]["status"], "fail")
            self.assertEqual(findings["ai-exposed-endpoints"]["status"], "fail")

            # Loopback-only Ollama should pass.
            safe_exposure = {
                "listeners": [
                    {"protocol": "tcp", "address": "127.0.0.1", "port": 11434, "scope": "loopback", "process": "ollama"},
                ]
            }
            safe_check = inventory.check_exposed_ai_endpoints(safe_exposure)
            self.assertEqual(safe_check["status"], "pass")


if __name__ == "__main__":
    unittest.main()
