"""Exercise the update API against an isolated local dashboard."""

from contextlib import nullcontext
from http import HTTPStatus
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from wardr.server import DashboardServer
from wardr.state import WardrState
from wardr.updater import ReleaseUpdate


RUNNING_VERSION = "1.2.3"
RELEASE = ReleaseUpdate(
    version="1.2.4",
    wheel_url="https://getwardr.com/releases/wardr-1.2.4-py3-none-any.whl",
    sha256="a" * 64,
    size=1,
)


class DashboardUpdateTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch("wardr.updater.current_version", return_value=RUNNING_VERSION))
        self.enterContext(patch("wardr.updater.installation_problem", return_value=None))
        self.enterContext(patch("wardr.update_session.installation_lock", side_effect=nullcontext))
        self.check_release = self.enterContext(patch("wardr.updater.check_for_update", return_value=RELEASE))
        self.install_release = self.enterContext(patch("wardr.updater.install_update", return_value=RELEASE.version))

    def start_dashboard(self, *, offline=False):
        self.server = DashboardServer(0, WardrState(self.directory, offline=offline))
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
        self.worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.worker.join, 3)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, *, body=None, token=None, origin=None, host=None):
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        if token is not None:
            headers["X-Wardr-Token"] = token
        if origin is not None:
            headers["Origin"] = origin
        if host is not None:
            headers["Host"] = host
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def post(self, action, body):
        return self.request("POST", "/api/update/" + action, body=body, token=self.server.token, origin=self.server.url)

    def update_status(self):
        code, payload = self.request("GET", "/api/update", token=self.server.token)
        self.assertEqual(code, HTTPStatus.OK)
        return payload

    def wait_for_state(self, expected):
        deadline = time.monotonic() + 3
        payload = self.update_status()
        while payload["state"] != expected and time.monotonic() < deadline:
            time.sleep(0.01)
            payload = self.update_status()
        self.assertEqual(payload["state"], expected, payload)
        return payload

    def test_update_routes_require_local_authentication(self):
        self.start_dashboard()
        self.assertEqual(self.request("GET", "/api/update")[0], HTTPStatus.FORBIDDEN)
        self.assertEqual(self.request("GET", "/api/update", token="invalid")[0], HTTPStatus.FORBIDDEN)
        self.assertEqual(
            self.request("GET", "/api/update", token=self.server.token, host="example.com")[0],
            HTTPStatus.FORBIDDEN,
        )
        disallowed_headers = (
            {"origin": self.server.url},
            {"token": "invalid", "origin": self.server.url},
            {"token": self.server.token},
            {"token": self.server.token, "origin": "https://example.com"},
            {"token": self.server.token, "origin": self.server.url, "host": "example.com"},
        )
        for action, body in (("check", {}), ("install", {"version": RELEASE.version}), ("restart", {})):
            for index, headers in enumerate(disallowed_headers):
                with self.subTest(action=action, header_case=index):
                    code, _ = self.request("POST", "/api/update/" + action, body=body, **headers)
                    self.assertEqual(code, HTTPStatus.FORBIDDEN)
        self.assertEqual(self.update_status()["state"], "idle")
        self.check_release.assert_not_called()
        self.install_release.assert_not_called()

    def test_offline_dashboard_refuses_update_checks_and_installs(self):
        self.start_dashboard(offline=True)
        status = self.update_status()
        self.assertEqual(status["state"], "unavailable")
        self.assertFalse(status["can_check"])
        self.assertFalse(status["can_update"])
        for action, body in (("check", {}), ("install", {"version": RELEASE.version})):
            with self.subTest(action=action):
                code, payload = self.post(action, body)
                self.assertEqual(code, HTTPStatus.CONFLICT)
                self.assertIn("offline mode", payload["error"])
        self.check_release.assert_not_called()
        self.install_release.assert_not_called()

    def test_install_rejects_an_unchecked_or_wrong_version(self):
        self.start_dashboard()
        self.assertEqual(self.post("install", {"version": RELEASE.version})[0], HTTPStatus.BAD_REQUEST)
        self.assertEqual(self.post("check", {})[0], HTTPStatus.ACCEPTED)
        status = self.wait_for_state("available")
        self.assertEqual(status["current_version"], RUNNING_VERSION)
        self.assertEqual(status["available_version"], RELEASE.version)
        self.assertTrue(status["can_update"])
        self.assertEqual(self.post("install", {"version": "1.2.5"})[0], HTTPStatus.BAD_REQUEST)
        self.assertEqual(self.update_status()["available_version"], RELEASE.version)
        self.install_release.assert_not_called()

    def test_restart_requires_an_installed_update(self):
        self.start_dashboard()
        finish_install = threading.Event()
        self.addCleanup(finish_install.set)

        def install_when_released(update):
            if not finish_install.wait(3):
                raise OSError("Timed out waiting for the test to release the mocked installer.")
            return update.version

        self.install_release.side_effect = install_when_released
        self.assertEqual(self.post("restart", {})[0], HTTPStatus.BAD_REQUEST)
        self.assertEqual(self.post("check", {})[0], HTTPStatus.ACCEPTED)
        self.wait_for_state("available")
        self.assertEqual(self.post("restart", {})[0], HTTPStatus.BAD_REQUEST)
        self.assertEqual(self.post("install", {"version": RELEASE.version})[0], HTTPStatus.ACCEPTED)
        self.assertEqual(self.update_status()["state"], "installing")
        self.assertEqual(self.post("restart", {})[0], HTTPStatus.BAD_REQUEST)

        finish_install.set()
        status = self.wait_for_state("installed")
        self.assertTrue(status["can_restart"])
        self.assertEqual(status["current_version"], RUNNING_VERSION)
        self.assertEqual(status["installed_version"], RELEASE.version)
        self.install_release.assert_called_once_with(RELEASE)
        self.assertEqual(self.post("restart", {})[0], HTTPStatus.ACCEPTED)
        self.worker.join(3)
        self.assertFalse(self.worker.is_alive())
        self.assertTrue(self.server.updates.restart_requested)
