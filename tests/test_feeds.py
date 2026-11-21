"""Tests for Ed25519-signed Rapid-Defense Feeds and declarative hunting rules."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wardr import assessment, feeds, hunting


def _keypair():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private, public_pem


def _sample_feed(*, mitigation_id="ssh-directory-permissions"):
    return {
        "schema_version": 1,
        "channel": "community",
        "version": "2026.11.21-1",
        "published_at": "2026-11-21T06:00:00+00:00",
        "rules": [
            {
                "id": "emerging-suspicious-listener",
                "title": "Suspected zero-day listener pattern",
                "severity": "critical",
                "confidence": "high",
                "summary": "Matched a signed rapid-response rule for an unexpected service port.",
                "actions": ["Inspect the owning binary immediately and isolate the port."],
                "mitigation_id": mitigation_id,
                "match": {
                    "kind": "event",
                    "source": "TCP listeners",
                    "detail_contains": [":31337"],
                },
            },
            {
                "id": "rapid-burst-probe",
                "title": "Rapid repeated failure burst",
                "severity": "high",
                "confidence": "medium",
                "summary": "Multiple matching events observed inside two minutes.",
                "actions": ["Review authentication logs."],
                "match": {
                    "kind": "burst",
                    "title_contains": ["failed"],
                    "minimum": 3,
                    "window_seconds": 120,
                },
            },
        ],
        "advisories": [
            {
                "id": "WARDR-2026-0001",
                "modified": "2026-11-21T06:00:00Z",
                "summary": "Rapid advisory for example vulnerable package",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo-vuln-pkg"},
                        "versions": ["1.2.3"],
                    }
                ],
            }
        ],
    }


class RapidDefenseFeedTests(unittest.TestCase):
    def test_signed_feed_import_and_hunting_evaluation(self):
        private, public_pem = _keypair()
        feed_bytes = json.dumps(_sample_feed()).encode("utf-8")
        signature = private.sign(feed_bytes)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "defense-v1.json"
            sig = root / "defense-v1.json.sig"
            key = root / "trusted.pem"
            state_dir = root / "state"
            bundle.write_bytes(feed_bytes)
            sig.write_bytes(signature)
            key.write_bytes(public_pem)

            status = feeds.import_feed(state_dir, bundle, sig, key)
            self.assertTrue(status["available"])
            self.assertEqual(status["version"], "2026.11.21-1")
            self.assertEqual(status["rule_count"], 2)
            self.assertEqual(status["advisory_count"], 1)

            rules = feeds.load_feed_rules(state_dir)
            now = datetime(2026, 11, 21, 7, 0, 0, tzinfo=timezone.utc)
            monitor_status = {
                "last_poll": "2026-11-21T07:00:00+00:00",
                "coverage": [{"id": "tcp", "label": "TCP listeners", "available": True, "detail": "ok"}],
                "events": [
                    {
                        "id": "ev-1",
                        "at": "2026-11-21T06:55:00+00:00",
                        "source": "TCP listeners",
                        "title": "New non-loopback TCP listener",
                        "detail": "A local service began listening on 0.0.0.0:31337.",
                    },
                    {
                        "id": "ev-2",
                        "at": "2026-11-21T06:56:00+00:00",
                        "source": "Linux SSH journal",
                        "title": "SSH authentication failed",
                        "detail": "attempt 1",
                    },
                    {
                        "id": "ev-3",
                        "at": "2026-11-21T06:56:30+00:00",
                        "source": "Linux SSH journal",
                        "title": "SSH authentication failed",
                        "detail": "attempt 2",
                    },
                    {
                        "id": "ev-4",
                        "at": "2026-11-21T06:57:00+00:00",
                        "source": "Linux SSH journal",
                        "title": "SSH authentication failed",
                        "detail": "attempt 3",
                    },
                ],
            }
            result = hunting.analyze(monitor_status, now=now, feed_rules=rules)
            self.assertEqual(result["feed_rules_active"], 2)
            rule_ids = {alert["rule_id"] for alert in result["alerts"]}
            self.assertIn("feed/emerging-suspicious-listener", rule_ids)
            self.assertIn("feed/rapid-burst-probe", rule_ids)
            listener_alert = next(a for a in result["alerts"] if a["rule_id"] == "feed/emerging-suspicious-listener")
            self.assertEqual(listener_alert["severity"], "critical")
            self.assertEqual(listener_alert["mitigation_id"], "ssh-directory-permissions")

            # Verify rapid advisories from the feed match in assessment.assess_documents.
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"name": "demo-vuln-pkg", "version": "1.2.3", "purl": "pkg:pypi/demo-vuln-pkg@1.2.3"}
                ],
            }
            matched = assessment.assess_documents(sbom, feeds.load_feed_advisories(state_dir))
            self.assertEqual(matched["summary"]["matched_findings"], 1)
            self.assertEqual(matched["findings"][0]["advisory_id"], "WARDR-2026-0001")

    def test_tampered_feed_or_wrong_key_rejected(self):
        private, public_pem = _keypair()
        _, other_public = _keypair()
        feed_bytes = json.dumps(_sample_feed()).encode("utf-8")
        signature = private.sign(feed_bytes)

        with self.assertRaises(feeds.FeedError):
            feeds.verify_feed_bytes(feed_bytes + b" ", signature, public_pem)
        with self.assertRaises(feeds.FeedError):
            feeds.verify_feed_bytes(feed_bytes, signature, other_public)

    def test_unallowlisted_mitigation_rejected_even_when_signed(self):
        private, public_pem = _keypair()
        bad_feed = _sample_feed(mitigation_id="arbitrary-shell-exec")
        feed_bytes = json.dumps(bad_feed).encode("utf-8")
        signature = private.sign(feed_bytes)
        with self.assertRaises(feeds.FeedError):
            feeds.verify_feed_bytes(feed_bytes, signature, public_pem)


if __name__ == "__main__":
    unittest.main()
