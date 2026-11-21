"""Tests for redacted central reporting and new Phase 1 dashboard endpoints."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from wardr import reporting
from wardr.server import DashboardServer
from wardr.state import WardrState


class SanitizedReportingTests(unittest.TestCase):
    def test_redaction_strips_secrets_paths_ips_emails_and_hostnames(self):
        host = {"name": "prod-web-01.internal.corp", "os": "Linux"}
        item = {
            "id": "alert-1",
            "title": "Suspicious activity on prod-web-01.internal.corp",
            "severity": "high",
            "summary": "Admin alice@example.com from 192.168.1.42 accessed /Users/alice/.aws/credentials",
            "evidence": [
                "Token sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234 found in /home/bob/app/.env for 10.0.0.5"
            ],
        }
        draft = reporting.build_report(
            "alert",
            item,
            host=host,
            notes="Contact alice@example.com; key AKIAIOSFODNN7EXAMPLE",
            suspected_zero_day=True,
        )
        serialized = json.dumps(draft["payload"])
        for sensitive in (
            "prod-web-01.internal.corp",
            "alice@example.com",
            "192.168.1.42",
            "10.0.0.5",
            "/Users/alice",
            "/home/bob",
            "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234",
            "AKIAIOSFODNN7EXAMPLE",
        ):
            self.assertNotIn(sensitive, serialized)
        self.assertGreaterEqual(draft["redaction_total"], 7)
        self.assertTrue(draft["payload"]["suspected_zero_day"])
        self.assertEqual(len(draft["payload"]["fingerprint"]), 32)

    def test_offline_mode_refuses_submission_and_export_works(self):
        draft = reporting.build_report("custom", {"id": "zd-1", "title": "Novel crash"}, suspected_zero_day=True)
        with self.assertRaises(reporting.ReportingError):
            reporting.submit_report(draft["payload"], offline=True)
        with self.assertRaises(reporting.ReportingError):
            reporting.submit_report(draft["payload"], endpoint="http://insecure.example/v1/reports")

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "redacted.json"
            exported = reporting.export_report(draft["payload"], out)
            self.assertTrue(exported["exported"])
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["fingerprint"], draft["payload"]["fingerprint"])


class Phase1DashboardEndpointsTests(unittest.TestCase):
    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.state = WardrState(Path(storage.name), offline=True)
        self.server = DashboardServer(0, self.state)
        worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.server.shutdown)

    def _req(self, method, path, *, auth=True, body=None):
        headers = {}
        if auth:
            headers["X-Wardr-Token"] = self.server.token
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Origin"] = self.server.url
            body = json.dumps(body)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def test_new_routes_require_auth_and_work_locally(self):
        self.assertEqual(self._req("GET", "/api/feed", auth=False)[0], 403)
        self.assertEqual(self._req("GET", "/api/remediation", auth=False)[0], 403)

        status, feed_data = self._req("GET", "/api/feed")
        self.assertEqual(status, 200)
        self.assertFalse(feed_data["available"])

        status, rem_data = self._req("GET", "/api/remediation")
        self.assertEqual(status, 200)
        self.assertEqual(rem_data["history"], [])

        status, preview = self._req("POST", "/api/report/preview", body={
            "kind": "custom", "id": "test-zd", "notes": "IP 10.1.2.3", "suspected_zero_day": True,
        })
        self.assertEqual(status, 200)
        self.assertNotIn("10.1.2.3", json.dumps(preview["payload"]))

        # Offline dashboard must refuse submitting externally.
        status, err = self._req("POST", "/api/report/submit", body={"payload": preview["payload"]})
        self.assertEqual(status, 400)
        self.assertIn("offline", err["error"].lower())

        # Auto-inventory scan works locally and returns component summary.
        status, inv = self._req("POST", "/api/inventory/scan", body={})
        self.assertEqual(status, 200)
        self.assertIn("inventory", inv)
        self.assertGreaterEqual(inv["inventory"]["component_count"], 1)


if __name__ == "__main__":
    unittest.main()
