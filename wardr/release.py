"""Offline release checks using a separately trusted Ed25519 public key."""

import hashlib
import hmac
import json
import re
import subprocess
import tempfile
from pathlib import Path


_ARTIFACT_NAME = re.compile(r"wardr-[0-9]+\.[0-9]+\.[0-9]+(?:-py3-none-any\.whl|\.tar\.gz)\Z")
_HEX_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class ReleaseError(ValueError):
    """A signed release could not be verified."""


def sha256_file(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _read_bounded(path, maximum):
    with Path(path).open("rb") as handle:
        payload = handle.read(maximum + 1)
    if not 0 < len(payload) <= maximum:
        raise ReleaseError("The release verification file has an invalid size.")
    return payload


def _openssl(arguments):
    try:
        return subprocess.run(
            ["openssl", *map(str, arguments)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("Release signatures require a working OpenSSL 3 command.") from exc


def sign_manifest(manifest, signing_key, signature, public_key):
    args = ("pkeyutl", "-sign", "-rawin", "-inkey", signing_key, "-in", manifest, "-out", signature)
    if _openssl(args).returncode:
        raise ReleaseError("OpenSSL could not sign the release manifest.")
    if Path(signature).stat().st_size != 64:
        raise ReleaseError("Use an Ed25519 release signing key.")
    if _openssl(("pkey", "-in", signing_key, "-pubout", "-out", public_key)).returncode:
        raise ReleaseError("OpenSSL could not export the release public key.")


def verify_release(manifest, signature, public_key, artifact):
    manifest_bytes = _read_bounded(manifest, 64 * 1024)
    signature_bytes = _read_bounded(signature, 64)
    key_bytes = _read_bounded(public_key, 2048)
    # Ed25519 SubjectPublicKeyInfo begins with OID 1.3.101.112 and a 32-byte key.
    import base64
    import binascii

    try:
        pem = key_bytes.strip().splitlines()
        if pem[0] != b"-----BEGIN PUBLIC KEY-----" or pem[-1] != b"-----END PUBLIC KEY-----":
            raise ValueError("Invalid public key")
        key_der = base64.b64decode(b"".join(pem[1:-1]), validate=True)
    except (ValueError, IndexError, binascii.Error) as exc:
        raise ReleaseError("Provide a trusted Ed25519 public key in PEM format.") from exc
    if len(signature_bytes) != 64 or len(key_der) != 44 or not key_der.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ReleaseError("Provide a trusted Ed25519 key and signature.")
    with tempfile.TemporaryDirectory(prefix="wardr-signature-") as directory:
        payload, sig, key = (Path(directory) / name for name in ("manifest.json", "manifest.sig", "trusted.pem"))
        for path, contents in ((payload, manifest_bytes), (sig, signature_bytes), (key, key_bytes)):
            path.write_bytes(contents)
        args = ("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", key, "-in", payload, "-sigfile", sig)
        if _openssl(args).returncode:
            raise ReleaseError("The release signature does not match the supplied trusted key.")

    try:
        document = json.loads(manifest_bytes)
        if document.get("schema_version") != 1 or document.get("channel") != "community":
            raise ValueError("Unexpected release manifest schema")
        name = Path(artifact).name
        matches = [entry for entry in document["artifacts"] if entry.get("name") == name]
        if len(matches) != 1 or not _ARTIFACT_NAME.fullmatch(name):
            raise ValueError("Artifact is absent from the manifest")
        expected = matches[0]["sha256"]
        if not isinstance(expected, str) or not _HEX_SHA256.fullmatch(expected):
            raise ValueError("Invalid SHA-256 digest")
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError) as exc:
        raise ReleaseError("The signed manifest does not identify this Wardr download.") from exc
    actual = sha256_file(Path(artifact))
    if not hmac.compare_digest(actual, expected):
        raise ReleaseError("The download does not match the signed release manifest.")
    return {"verified": True, "artifact": name, "sha256": actual}
