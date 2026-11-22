"""Integration checks for local dashboard access and reports."""

import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from wardr.server import DashboardServer
from wardr.state import WardrState


CHECK = {
    "id": "test-check",
    "title": "<script>alert(1)</script>",
    "category": "Access",
    "severity": "high",
    "status": "fail",
    "can_fix": True,
    "risk": "Another user can see the setting.",
    "evidence": "Observed insecure mode.",
    "remediation": "Limit access.",
}
SCAN = {"scanned_at": "2026-11-19T12:00:00+00:00", "checks": [CHECK]}


class DashboardAccessTests(unittest.TestCase):
    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.state = WardrState(Path(storage.name))
        self.server = DashboardServer(0, self.state)
        worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, *, auth=False, origin=None, host=None, body=None):
        headers = {}
        if auth:
            headers["X-Wardr-Token"] = self.server.token
        if origin:
            headers["Origin"] = origin
        if host:
            headers["Host"] = host
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            connection.close()

    def test_local_access_and_origin(self):
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token, page)
        self.assertEqual(self.request("GET", "/api/status")[0], 403)
        self.assertEqual(self.request("GET", "/report.html")[0], 403)
        self.assertEqual(self.request("GET", "/api/status", auth=True)[0], 200)
        self.assertEqual(self.request("GET", "/api/status", auth=True, host="example.com")[0], 403)
        self.assertEqual(self.request("GET", "/report.html", auth=True)[0], 409)
        self.assertEqual(
            self.request("POST", "/api/scan", auth=True, origin="https://example.com", body={})[0], 403,
        )

    def test_scan_report_and_verified_fix(self):
        with (
            patch("wardr.state.checks.scan", return_value={**SCAN, "host": self.state.host["name"]}),
            patch("wardr.state.exposure.collect_exposure", return_value={"listeners": [], "coverage": []}),
            patch("wardr.state.fim.check_integrity", return_value={"status": "pass", "tracked_count": 0, "changes": []}),
        ):
            self.assertEqual(self.request("POST", "/api/scan", auth=True, origin=self.server.url, body={})[0], 202)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                _, status = self.request("GET", "/api/status", auth=True)
                if json.loads(status)["scan"]["state"] == "complete":
                    break
                time.sleep(0.01)
            self.assertEqual(json.loads(status)["scan"]["state"], "complete")

        _, markup = self.request("GET", "/report.html", auth=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", markup)
        self.assertNotIn("<script>alert(1)</script>", markup)
        _, result = self.request("GET", "/report.json", auth=True)
        self.assertEqual(json.loads(result)["summary"]["by_severity"]["high"], 1)
        invalid_status, _ = self.request("POST", "/api/fix", auth=True, origin=self.server.url, body={"id": "anything"})
        self.assertEqual(invalid_status, 400)

        verified = {**CHECK, "status": "pass", "can_fix": False, "evidence": "Observed private mode."}
        with patch("wardr.state.checks.apply_fix", return_value={"ok": True, "message": "Applied.", "check": verified}) as mutate:
            status, result = self.request("POST", "/api/fix", auth=True, origin=self.server.url, body={"id": CHECK["id"]})
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(result)["ok"])
            self.assertIn("verified_at", json.loads(result)["check"])
            mutate.assert_called_once_with(CHECK["id"])

        _, result = self.request("GET", "/report.json?download=1", auth=True)
        report = json.loads(result)
        self.assertEqual(report["summary"]["action_needed"], 0)
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(WardrState(self.state.directory).scan_snapshot()["checks"][0]["status"], "pass")
