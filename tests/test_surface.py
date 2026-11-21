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
