"""Tests for attack-surface audit, hardened service templates, and persistent baseline drift."""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wardr import hunting, plan, service, surface
from wardr.monitor import Monitor


class SurfaceAndBaselineDriftTests(unittest.TestCase):
    def test_surface_audit_flags_risky_exposed_services_and_ignores_loopback(self):
        exposure = {
            "state": "complete",
            "listeners": [
                {"protocol": "tcp", "address": "0.0.0.0", "port": 2375, "scope": "wildcard", "process": "dockerd"},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 6379, "scope": "wildcard", "process": "redis-server"},
                {"protocol": "tcp", "address": "127.0.0.1", "port": 6379, "scope": "loopback", "process": "redis-server"},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 11434, "scope": "wildcard", "process": "ollama"},
            ],
        }
        result = surface.audit_exposure(exposure, probe_local_tls=False)
        self.assertEqual(result["summary"]["risky_service_count"], 3)
        self.assertEqual(result["risky_services"][0]["port"], 2375)
        self.assertEqual(result["risky_services"][0]["severity"], "critical")

        built = plan.build_plan({"name": "srv-1", "os": "Linux"}, None, exposure, {"alerts": []}, None)
        task_ids = {t["id"] for t in built["tasks"]}
        self.assertIn("surface/surface-port-2375", task_ids)
        self.assertIn("surface/surface-port-6379", task_ids)
        self.assertIn("surface/surface-port-11434", task_ids)

    def test_surface_audit_flags_exposed_vnc_rdp_and_smb(self):
        exposure = {
            "state": "complete",
            "listeners": [
                {"protocol": "tcp", "address": "*", "port": 5900, "scope": "wildcard", "process": "launchd"},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 3389, "scope": "wildcard", "process": "svchost"},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 445, "scope": "wildcard", "process": "smbd"},
                {"protocol": "tcp", "address": "127.0.0.1", "port": 5900, "scope": "loopback", "process": "vnc"},
            ],
        }
        result = surface.audit_exposure(exposure, probe_local_tls=False)
        ports = {item["port"]: item["severity"] for item in result["risky_services"]}
        self.assertEqual(ports, {5900: "high", 3389: "high", 445: "medium"})

    def test_heavy_scan_counts_risky_services_and_flags_unloaded_advisories(self):
        from wardr import checks, exposure as exp_mod, feeds, fim, inventory
        from wardr.state import WardrState

        fake_scan = {
            "platform": "macOS",
            "os_version": "26.5.1",
            "host": "test-host",
            "scanned_at": "2026-11-25T12:00:00+00:00",
            "checks": [
                {"id": "macos-firewall", "title": "Application firewall", "category": "Network", "severity": "medium", "status": "pass", "evidence": "enabled", "risk": "", "remediation": "", "can_fix": False, "references": []},
            ],
        }
        fake_exposure = {
            "state": "complete",
            "listeners": [
                {"protocol": "tcp", "address": "*", "port": 11434, "scope": "wildcard", "process": "ollama"},
                {"protocol": "tcp", "address": "*", "port": 5900, "scope": "wildcard", "process": "launchd"},
            ],
        }
        fake_inv = {
            "collected_at": "2026-11-25T12:00:00+00:00",
            "cached": False,
            "component_count": 42,
            "sources": ["homebrew (42)"],
            "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp), offline=True)
            with (
                patch.object(checks, "scan", return_value=fake_scan),
                patch.object(exp_mod, "collect_exposure", return_value=fake_exposure),
                patch.object(fim, "check_integrity", return_value={"status": "pass", "tracked_count": 3, "changes": []}),
                patch.object(inventory, "collect_inventory", return_value=fake_inv),
                patch.object(feeds, "load_feed_advisories", return_value=[]),
            ):
                state._run_scan("heavy")
            st = state.status()
            modules = st["scan"]["modules"]
            self.assertEqual(modules["surface_findings"], 2)
            self.assertEqual(modules["risky_services"], 2)
            self.assertEqual(modules["tls_issues"], 0)
            self.assertEqual(modules["feed_advisories_loaded"], 0)
            steps = {s["id"]: s for s in st["scan"]["steps"]}
            self.assertEqual(steps["surface"]["status"], "warn")
            self.assertIn("2 risky exposed", steps["surface"]["detail"])
            self.assertIn("No OSV/feed advisories loaded", steps["inventory"]["detail"])

    def test_service_templates_generate_hardened_configs(self):
        systemd = service.render_template("systemd", state_dir="/var/lib/wardr", interval=15)
        self.assertIn("NoNewPrivileges=yes", systemd)
        self.assertIn("MemoryMax=128M", systemd)
        self.assertIn("--interval 15", systemd)
        launchd = service.render_template("launchd", interval=20)
        self.assertIn("com.getwardr.watch", launchd)
        win = service.render_template("windows", interval=30)
        self.assertIn("Register-ScheduledTask", win)

    def test_persistent_baseline_drift_detects_novel_listener_across_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            # First monitor establishes baseline with port 443.
            m1 = Monitor(interval=30, state_dir=state_dir)
            with patch.object(m1, "_capture", return_value=({("0.0.0.0", 443)}, None, [], [])):
                s1 = m1.poll()
            self.assertEqual(s1["events"], [])

            # New monitor instance (simulating restart) sees novel port 4444 -> baseline drift!
            m2 = Monitor(interval=30, state_dir=state_dir)
            with patch.object(m2, "_capture", return_value=({("0.0.0.0", 443), ("0.0.0.0", 4444)}, None, [], [])):
                s2 = m2.poll()
            titles = [e["title"] for e in s2["events"]]
            self.assertIn("Novel non-loopback TCP listener (baseline drift)", titles)

            hunted = hunting.analyze(s2, now=datetime.now(timezone.utc))
            rule_ids = {a["rule_id"] for a in hunted["alerts"]}
            self.assertIn("baseline-drift-listener", rule_ids)


if __name__ == "__main__":
    unittest.main()
