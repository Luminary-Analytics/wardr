"""End-to-end tests for Wardr Threat Network intake, zero-day clustering, and signed feed publishing."""

from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from wardr import feeds, hunting, reporting, threat_network


class ThreatNetworkEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        private = Ed25519PrivateKey.generate()
        self.private_pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        self.public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.admin_token = "test-operator-secret-token"
        self.store = threat_network.ThreatNetworkStore(
            Path(self.tmp.name), escalation_reporters=2, zero_day_threshold=2,
        )
        self.server = threat_network.ThreatNetworkServer(
            ("127.0.0.1", 0), self.store, admin_token=self.admin_token, signing_key_pem=self.private_pem,
        )
        worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.server.shutdown)

    def _req(self, method, path, *, token=None, body=None):
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
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_report_cluster_escalate_publish_signed_feed_and_detect(self):
        # 1. Client redacts a suspected zero-day alert and submits twice (simulating escalation).
        draft = reporting.build_report(
            "alert",
            {
                "id": "zd-port-9999",
                "title": "Novel backdoor listener on port 9999",
                "severity": "high",
                "summary": "Host corp-1.internal saw unexpected listener from 10.20.30.40",
                "evidence": ["A local service began listening on 0.0.0.0:9999."],
            },
            host={"name": "corp-1.internal", "os": "Linux"},
            suspected_zero_day=True,
        )
        st1, r1 = self._req("POST", "/v1/reports", body=draft["payload"])
        self.assertEqual(st1, 202)
        self.assertEqual(json.loads(r1)["triage_status"], "open")

        st2, r2 = self._req("POST", "/v1/reports", body=draft["payload"])
        self.assertEqual(st2, 202)
        self.assertEqual(json.loads(r2)["triage_status"], "escalated")

        # 2. Unauthenticated cluster access is denied; operator token succeeds.
        self.assertEqual(self._req("GET", "/v1/clusters")[0], 401)
        st, raw_clusters = self._req("GET", "/v1/clusters", token=self.admin_token)
        self.assertEqual(st, 200)
        clusters = json.loads(raw_clusters)["clusters"]
        self.assertEqual(len(clusters), 1)
        fp = clusters[0]["fingerprint"]
        self.assertEqual(clusters[0]["triage_status"], "escalated")
        self.assertEqual(clusters[0]["zero_day_votes"], 2)

        # 3. Analyst updates CVD status with CVE ID.
        st, upd = self._req(
            "POST", f"/v1/clusters/{fp}/status", token=self.admin_token,
            body={"triage_status": "cve_assigned", "cve_id": "CVE-2026-99999"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(upd)["cve_id"], "CVE-2026-99999")

        # 4. Operator publishes an Ed25519-signed Rapid-Defense Feed with a rapid detection rule.
        feed_doc = {
            "schema_version": 1,
            "channel": "community",
            "version": "2026.11.21-rapid-1",
            "published_at": "2026-11-21T08:00:00+00:00",
            "rules": [
                {
                    "id": "rapid-cve-2026-99999",
                    "title": "Rapid response: CVE-2026-99999 listener indicator",
                    "severity": "critical",
                    "confidence": "high",
                    "summary": "Community-verified indicator for CVE-2026-99999.",
                    "actions": ["Block port 9999 immediately and update affected software."],
                    "match": {"kind": "event", "source": "TCP listeners", "detail_contains": [":9999"]},
                }
            ],
            "advisories": [],
        }
        st, pub = self._req("POST", "/v1/feeds/publish", token=self.admin_token, body=feed_doc)
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(pub)["published"])

        # 5. Any Wardr node fetches the signed feed + signature, verifies Ed25519, and detects immediately!
        st_f, feed_bytes = self._req("GET", "/feeds/defense-v1.json")
        st_s, sig_bytes = self._req("GET", "/feeds/defense-v1.json.sig")
        self.assertEqual(st_f, 200)
        self.assertEqual(st_s, 200)
        verified = feeds.verify_feed_bytes(feed_bytes, sig_bytes, self.public_pem)
        self.assertEqual(verified["version"], "2026.11.21-rapid-1")

        now = datetime(2026, 11, 21, 8, 5, 0, tzinfo=timezone.utc)
        hunted = hunting.analyze(
            {
                "last_poll": "2026-11-21T08:05:00+00:00",
                "coverage": [],
                "events": [
                    {
                        "id": "live-1",
                        "at": "2026-11-21T08:04:00+00:00",
                        "source": "TCP listeners",
                        "title": "New non-loopback TCP listener",
                        "detail": "A local service began listening on 0.0.0.0:9999.",
                    }
                ],
            },
            now=now,
            feed_rules=verified["rules"],
        )
        self.assertEqual(hunted["alerts"][0]["rule_id"], "feed/rapid-cve-2026-99999")
        self.assertEqual(hunted["alerts"][0]["severity"], "critical")

        # Health endpoint reflects reports, clusters, and active feed version.
        st_h, raw_h = self._req("GET", "/v1/health")
        self.assertEqual(st_h, 200)
        health = json.loads(raw_h)
        self.assertEqual(health["reports"], 2)
        self.assertEqual(health["active_feed_version"], "2026.11.21-rapid-1")


if __name__ == "__main__":
    unittest.main()
