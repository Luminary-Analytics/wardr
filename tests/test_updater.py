"""Signed release and installer boundary tests."""

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from zipfile import ZipFile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wardr import updater


VERSION = "0.2.2"
WHEEL_NAME = f"wardr-{VERSION}-py3-none-any.whl"
WHEEL_PATH = f"/downloads/{WHEEL_NAME}"
SIGNATURE_PATH = f"/releases/{VERSION}/release.json.sig"


def sample_wheel(version=VERSION, requirements=()):
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        dependencies = "".join(f"Requires-Dist: {item}\n" for item in requirements)
        archive.writestr(
            f"wardr-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: wardr\nVersion: {version}\nRequires-Python: >=3.11\n{dependencies}",
        )
    return stream.getvalue()


class UpdateManifestTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.key = Ed25519PrivateKey.generate()
        pinned = Path(scratch.name) / "release.pem"
        pinned.write_bytes(self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self._patch("_PUBLIC_KEY", pinned)
        self._patch("installation_problem", return_value=None)
        self._patch("current_version", return_value="0.2.1")
        self.payload = sample_wheel()
        self.document = {
            "schema_version": 1,
            "channel": "community",
            "version": VERSION,
            "requires_python": ">=3.11",
            "signature": SIGNATURE_PATH,
            "artifacts": [{
                "name": WHEEL_NAME,
                "url": WHEEL_PATH,
                "bytes": len(self.payload),
                "sha256": hashlib.sha256(self.payload).hexdigest(),
            }],
        }
        self.replies = {}
        self.fetch = self._patch("_fetch", side_effect=lambda path, _limit: self.replies[path])

    def _patch(self, name, *args, **kwargs):
        mocked = patch.object(updater, name, *args, **kwargs)
        self.addCleanup(mocked.stop)
        return mocked.start()

    def sign(self, signature_key=None):
        raw = json.dumps(self.document).encode("utf-8")
        self.replies["/releases/latest.json"] = raw
        self.replies[SIGNATURE_PATH] = (signature_key or self.key).sign(raw)
        self.replies[WHEEL_PATH] = self.payload

    def test_signed_update_rechecked_and_verified_before_installation(self):
        self.sign()
        candidate = updater.check_for_update()
        self.assertEqual(candidate.version, VERSION)
        self.assertEqual([call.args[0] for call in self.fetch.call_args_list], [
            "/releases/latest.json", SIGNATURE_PATH,
        ])
        metadata = self._patch("metadata")
        metadata.distribution.return_value.requires = []
        seen = []
        installer = self._patch("_install_wheel", side_effect=lambda path, version: seen.append((path.read_bytes(), version)))
        self.assertEqual(updater.install_update(candidate), VERSION)
        self.assertEqual(seen, [(self.payload, VERSION)])
        self.assertEqual(installer.call_args.args[0].name, WHEEL_NAME)
        self.assertEqual([call.args[0] for call in self.fetch.call_args_list][-3:], [
            "/releases/latest.json", SIGNATURE_PATH, WHEEL_PATH,
        ])

    def test_unsigned_and_untrusted_manifests_cannot_send_wheel_requests(self):
        self.sign(Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(updater.UpdaterError, "trusted key"):
            updater.check_for_update()
        self.document["signature"] = None
        self.sign()
        with self.assertRaisesRegex(updater.UpdaterError, "signed update manifest"):
            updater.check_for_update()
        self.assertNotIn(WHEEL_PATH, [call.args[0] for call in self.fetch.call_args_list])

    def test_signed_release_cannot_redirect_update_to_another_origin(self):
        self.document["artifacts"][0]["url"] = "https://elsewhere.example/" + WHEEL_NAME
        self.sign()
        with self.assertRaisesRegex(updater.UpdaterError, "invalid Wardr wheel"):
            updater.check_for_update()
        self.assertEqual([call.args[0] for call in self.fetch.call_args_list], [
            "/releases/latest.json", SIGNATURE_PATH,
        ])

    def test_strictly_newer_version_required(self):
        self.sign()
        with patch.object(updater, "current_version", return_value="0.2.10"):
            self.assertIsNone(updater.check_for_update())
        with patch.object(updater, "current_version", return_value=VERSION):
            self.assertIsNone(updater.check_for_update())

    def test_altered_wheel_rejected_before_installation(self):
        self.sign()
        candidate = updater.check_for_update()
        self.replies[WHEEL_PATH] = bytes(len(self.payload))
        installer = self._patch("_install_wheel")
        with self.assertRaisesRegex(updater.UpdaterError, "does not match"):
            updater.install_update(candidate)
        installer.assert_not_called()

    def test_dependency_changes_require_manual_installation(self):
        self.payload = sample_wheel(requirements=("cryptography>=46",))
        self.document["artifacts"][0]["bytes"] = len(self.payload)
        self.document["artifacts"][0]["sha256"] = hashlib.sha256(self.payload).hexdigest()
        self.sign()
        candidate = updater.check_for_update()
        metadata = self._patch("metadata")
        metadata.distribution.return_value.requires = ["cryptography>=45"]
        installer = self._patch("_install_wheel")
        with self.assertRaisesRegex(updater.UpdaterError, "changes dependencies"):
            updater.install_update(candidate)
        installer.assert_not_called()


class UpdateTransportTests(unittest.TestCase):
    def test_redirect_is_rejected_at_fixed_https_origin(self):
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 302
        response.getheader.return_value = "https://elsewhere.example/"
        with patch.object(updater.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaisesRegex(updater.UpdaterError, "HTTP 302"):
                updater._fetch("/releases/latest.json", 1024)
        self.assertEqual(factory.call_args.args, ("getwardr.com",))
        self.assertEqual(connection.request.call_args.args, ("GET", "/releases/latest.json"))
        response.read1.assert_not_called()

    def test_unadvertised_oversized_download_rejected(self):
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 200
        response.getheader.return_value = None
        response.read1.return_value = b"01234"
        with patch.object(updater.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(updater.UpdaterError, "allowed size"):
                updater._fetch("/releases/latest.json", 4)
