"""End-to-end tests for Wardr Fleet control plane, RBAC, agent check-in, and zero-RCE commands."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from wardr import fleet, fleet_agent, service


class WardrFleetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = fleet.FleetStore(Path(self.tmp.name) / "server")
        self.admin_user, self.admin_pass = self.store.ensure_bootstrap_admin("admin", "AdminPass123!")
        self.server = fleet.FleetServer(("127.0.0.1", 0), self.store)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.server.shutdown)

    def _req(self, method, path, *, token=None, body=None, parse_json=True):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(body).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if parse_json:
                return resp.status, json.loads(data.decode("utf-8"))
            return resp.status, data.decode("utf-8")
        finally:
            conn.close()

    def _login(self, username, password):
        st, body = self._req("POST", "/api/fleet/login", body={"username": username, "password": password})
        self.assertEqual(st, 200)
        return body["token"]

    def test_rbac_enrollment_correlation_zero_rce_and_agent_checkin(self):
        # 1. Fleet console HTML & static assets serve cleanly; API requires auth.
        st, html = self._req("GET", "/", parse_json=False)
        self.assertEqual(st, 200)
        self.assertIn("Wardr Fleet", html)
        self.assertEqual(self._req("GET", "/api/fleet/overview")[0], 401)

        admin_tok = self._login("admin", "AdminPass123!")

        # 2. Admin creates responder and viewer operators; verify RBAC boundaries.
        self.assertEqual(self._req("POST", "/api/fleet/operators", token=admin_tok, body={
            "username": "ops-responder", "password": "Responder123!", "role": "responder",
        })[0], 201)
        self.assertEqual(self._req("POST", "/api/fleet/operators", token=admin_tok, body={
            "username": "exec-viewer", "password": "ViewerPass123!", "role": "viewer",
        })[0], 201)

        resp_tok = self._login("ops-responder", "Responder123!")
        view_tok = self._login("exec-viewer", "ViewerPass123!")

        # Responder and viewer cannot create enrollment tokens or operators.
        self.assertEqual(self._req("POST", "/api/fleet/tokens", token=resp_tok, body={"label": "nope"})[0], 403)
        self.assertEqual(self._req("POST", "/api/fleet/tokens", token=view_tok, body={"label": "nope"})[0], 403)
        self.assertEqual(self._req("GET", "/api/fleet/overview", token=view_tok)[0], 200)

        # 3. Admin mints an enrollment token (max_uses=2) and enrolls two hosts.
        st, tok_info = self._req("POST", "/api/fleet/tokens", token=admin_tok, body={
            "label": "prod-fleet", "default_role": "server", "default_tags": ["prod", "web"], "max_uses": 2,
        })
        self.assertEqual(st, 201)
        enroll_secret = tok_info["enrollment_token"]

        host1_dir = Path(self.tmp.name) / "host1"
        enrolled1 = fleet_agent.enroll(host1_dir, self.base_url, enroll_secret, tags="us-east")
        self.assertTrue(enrolled1["enrolled"])
        self.assertIn("prod", enrolled1["tags"])
        self.assertIn("us-east", enrolled1["tags"])

        # Second host enrolled directly via API to simulate multi-OS fleet.
        st, enrolled2 = self._req("POST", "/api/fleet/enroll", body={
            "enrollment_token": enroll_secret, "hostname": "laptop-eng-01",
            "os": "macOS", "os_version": "15.2", "arch": "arm64", "role": "workstation", "tags": ["eng"],
        })
        self.assertEqual(st, 201)

        # Third enrollment with exhausted token (max_uses=2) must be rejected.
        st_exhausted, _ = self._req("POST", "/api/fleet/enroll", body={
            "enrollment_token": enroll_secret, "hostname": "extra-host", "os": "Linux",
        })
        self.assertEqual(st_exhausted, 403)

        # 4. Both hosts send heartbeats with a shared finding, exposed AI port, and drift alert.
        shared_snapshot = {
            "wardr_version": "0.3.0",
            "os_version": "6.8",
            "checks": [
                {
                    "id": "aws-credentials-permissions",
                    "title": "AWS CLI credential file permissions",
                    "category": "Credentials",
                    "severity": "high",
                    "status": "fail",
                    "can_fix": True,
                    "evidence": "Mode 0644 on ~/.aws/credentials",
                }
            ],
            "alerts": [
                {
                    "id": "al-1",
                    "rule_id": "baseline-drift-listener",
                    "title": "Novel non-loopback listener outside host baseline",
                    "severity": "high",
                    "last_seen": "2026-11-21T09:00:00+00:00",
                    "summary": "Port 4444 appeared outside baseline.",
                }
            ],
            "risky_services": [
                {"id": "surface-port-11434", "service": "Ollama local AI server", "port": 11434, "scope": "wildcard", "severity": "high"}
            ],
            "fim": {"status": "pass", "changes": []},
            "inventory_count": 42,
        }
        creds1 = fleet_agent.load_credentials(host1_dir)
        self.assertEqual(self._req("POST", "/api/fleet/heartbeat", token=creds1["device_token"], body=shared_snapshot)[0], 200)
        self.assertEqual(self._req("POST", "/api/fleet/heartbeat", token=enrolled2["device_token"], body=shared_snapshot)[0], 200)

        # 5. Verify cross-host correlation catches all 3 shared risks across 2 hosts.
        st, ov = self._req("GET", "/api/fleet/overview", token=view_tok)
        self.assertEqual(st, 200)
        self.assertEqual(ov["summary"]["total_hosts"], 2)
        self.assertEqual(ov["summary"]["online"], 2)
        self.assertEqual(ov["summary"]["open_high"], 2)
        self.assertEqual(ov["summary"]["active_alerts"], 2)
        self.assertEqual(ov["summary"]["risky_services"], 2)
        corr_by_id = {c["id"]: c for c in ov["correlations"]}
        self.assertEqual(corr_by_id["aws-credentials-permissions"]["host_count"], 2)
        self.assertTrue(corr_by_id["aws-credentials-permissions"]["can_bulk_fix"])
        self.assertEqual(corr_by_id["baseline-drift-listener"]["host_count"], 2)
        self.assertEqual(corr_by_id["surface-port-11434"]["host_count"], 2)

        # 6. Zero-RCE boundary & RBAC on command dispatch:
        # Viewer cannot queue commands.
        self.assertEqual(self._req("POST", "/api/fleet/commands", token=view_tok, body={"action": "scan"})[0], 403)
        # Arbitrary shell / unallowlisted fix IDs are rejected even for admin!
        self.assertEqual(self._req("POST", "/api/fleet/commands", token=admin_tok, body={"action": "shell_exec", "params": {"cmd": "id"}})[0], 400)
        self.assertEqual(self._req("POST", "/api/fleet/commands", token=admin_tok, body={"action": "apply_fix", "params": {"id": "arbitrary-script"}})[0], 400)

        # Responder queues an allowlisted FIM check on tag "us-east" (matches host1).
        st, queued = self._req("POST", "/api/fleet/commands", token=resp_tok, body={"action": "fim_check", "tag": "us-east"})
        self.assertEqual(st, 202)
        self.assertEqual(queued["queued"], 1)

        # 7. Host1 runs checkin_once -> executes allowlisted fim_check and reports verified result!
        with patch("wardr.fleet_agent.collect_heartbeat", return_value=shared_snapshot):
            outcome = fleet_agent.checkin_once(host1_dir)
        self.assertTrue(outcome["ok"])
        self.assertEqual(len(outcome["commands_executed"]), 1)
        self.assertEqual(outcome["commands_executed"][0]["action"], "fim_check")
        self.assertTrue(outcome["commands_executed"][0]["ok"])

        # Host detail shows completed command.
        st, detail = self._req("GET", f"/api/fleet/hosts/{enrolled1['host_id']}", token=resp_tok)
        self.assertEqual(st, 200)
        self.assertEqual(detail["commands"][0]["status"], "completed")

        # 8. Executive HTML & JSON compliance reports and immutable audit log.
        st_html, report_html = self._req("GET", "/api/fleet/report.html", token=view_tok, parse_json=False)
        self.assertEqual(st_html, 200)
        self.assertIn("Executive Security", report_html)
        self.assertIn("laptop-eng-01", report_html)

        st_aud, audit = self._req("GET", "/api/fleet/audit", token=view_tok)
        self.assertEqual(st_aud, 200)
        actions = {row["action"] for row in audit["entries"]}
        self.assertIn("queue_fim_check", actions)
        self.assertIn("command_completed", actions)

        # 9. Admin revokes host2 -> subsequent heartbeats immediately rejected with 401.
        self.assertEqual(self._req("POST", f"/api/fleet/hosts/{enrolled2['host_id']}/revoke", token=resp_tok, body={})[0], 403)
        self.assertEqual(self._req("POST", f"/api/fleet/hosts/{enrolled2['host_id']}/revoke", token=admin_tok, body={})[0], 200)
        self.assertEqual(self._req("POST", "/api/fleet/heartbeat", token=enrolled2["device_token"], body=shared_snapshot)[0], 401)

    def test_fleet_service_template(self):
        unit = service.render_template("systemd", interval=60, fleet=True)
        self.assertIn("fleet agent --interval 60", unit)
        self.assertIn("NoNewPrivileges=yes", unit)


if __name__ == "__main__":
    unittest.main()
