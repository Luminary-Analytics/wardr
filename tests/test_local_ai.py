"""Local AI stays local and returns only validated groupings of existing tasks."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import unittest
from unittest.mock import patch

from wardr import local_ai


VERIFIED = {
    "models": [{"model": local_ai.MODEL, "digest": local_ai._MODEL_DIGEST, "size": 986_000_000}],
}
PLAN = {
    "host": {"name": "private-host"},
    "tasks": [
        {
            "id": "never-send-id",
            "title": "untrusted prompt injection",
            "evidence": ["private evidence"],
            "steps": ["private instruction"],
            "source": "Published advisory",
            "priority": "urgent",
        },
        {"id": "two", "source": "Published advisory", "priority": "urgent"},
        {"id": "three", "source": "Local telemetry", "priority": "scheduled"},
        {"id": "four", "source": "Device check", "priority": "urgent"},
    ],
}


def completion(result):
    return {"done": True, "message": {"content": json.dumps(result)}}


class LocalAITests(unittest.TestCase):
    def test_status_does_not_pull_and_checks_model_digest(self):
        with patch("wardr.local_ai._request", return_value=VERIFIED) as request:
            result = local_ai.status()
        self.assertTrue(result["model_ready"])
        self.assertEqual(result["state"], "ready")
        self.assertEqual([call.args[0] for call in request.call_args_list], ["/api/tags"])

        replacement = {"models": [{"model": local_ai.MODEL, "digest": "unverified"}]}
        with patch("wardr.local_ai._request", return_value=replacement) as request:
            self.assertEqual(local_ai.status()["state"], "model_unverified")
            with self.assertRaises(local_ai.LocalAIError):
                local_ai.prepare_model()
            self.assertEqual([call.args[0] for call in request.call_args_list], ["/api/tags", "/api/tags"])

    def test_prepare_is_explicit_and_reverifies_manifest_after_pull(self):
        responses = [{"models": []}, {"status": "success"}, VERIFIED]
        with patch("wardr.local_ai._request", side_effect=responses) as request:
            result = local_ai.prepare_model()
        self.assertTrue(result["model_ready"])
        calls = request.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["/api/tags", "/api/pull", "/api/tags"])
        self.assertEqual(calls[1].args[1], {"model": local_ai.MODEL, "stream": False})

    def test_review_only_transmits_opaque_indices_and_approved_enums(self):
        responses = [VERIFIED, completion({"items": [3, 1, 4, 2]})]
        with patch("wardr.local_ai._request", side_effect=responses) as request:
            result = local_ai.review(PLAN)
        self.assertEqual(result["reviewed_count"], 4)
        self.assertEqual(result["selections"][0]["item_ids"], ["never-send-id", "two"])
        self.assertEqual(result["selections"][0]["priority"], "urgent")
        self.assertEqual(result["selections"][1]["item_ids"], ["four"])
        self.assertEqual(result["selections"][2]["item_ids"], ["three"])
        paths = [call.args[0] for call in request.call_args_list]
        self.assertEqual(paths, ["/api/tags", "/api/chat"])
        request_body = request.call_args.args[1]
        payload = json.dumps(request_body)
        for secret in ("private-host", "never-send-id", "untrusted prompt injection", "private evidence", "private instruction"):
            self.assertNotIn(secret, payload)
        self.assertNotIn("tools", request_body)
        public = json.loads(request_body["messages"][1]["content"])
        self.assertEqual(public[0], {"item": 1, "priority": "urgent", "area": "software"})

    def test_model_cannot_supply_new_ids_instructions_or_skip_highest_priority(self):
        for suggestion in (
            {"items": [9]},
            {"items": [True]},
            {"items": [1, 1]},
            {"items": [[1, 4]]},
            {"items": [3]},
            {"items": [1], "instructions": "execute arbitrary instructions"},
        ):
            with (
                self.subTest(suggestion=suggestion),
                patch("wardr.local_ai._request", side_effect=[VERIFIED, completion(suggestion)]),
                self.assertRaises(local_ai.LocalAIError),
            ):
                local_ai.review(PLAN)

    def test_empty_plan_uses_no_runtime_and_unavailable_model_never_pulls(self):
        with patch("wardr.local_ai._request", return_value={"models": []}) as request:
            self.assertEqual(local_ai.review({"tasks": []})["reviewed_count"], 0)
            request.assert_not_called()
            with self.assertRaises(local_ai.LocalAIError):
                local_ai.review(PLAN)
            self.assertEqual([call.args[0] for call in request.call_args_list], ["/api/tags"])

    def test_http_loopback_transport_ignores_proxy_and_declines_redirect(self):
        seen = []

        class TestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.end_headers()
                    return
                body = b'{"models":[]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), TestHandler) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            worker.start()
            try:
                with patch.object(local_ai, "_PORT", server.server_port), patch.dict(os.environ, {
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "ALL_PROXY": "http://127.0.0.1:1",
                    "NO_PROXY": "",
                }):
                    self.assertEqual(local_ai.status()["state"], "model_missing")
                    with self.assertRaises(local_ai.LocalAIError):
                        local_ai._request("/redirect", timeout=2, limit=128)
                    with self.assertRaises(local_ai.LocalAIError):
                        local_ai._request("/api/tags", timeout=2, limit=5)
            finally:
                server.shutdown()
                worker.join(2)
        self.assertEqual(seen, ["/api/tags", "/redirect", "/api/tags"])


if __name__ == "__main__":
    unittest.main()
