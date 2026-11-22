"""Offline release checks using a separately trusted Ed25519 public key."""

import hashlib
import hmac
import json
import re
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


def sign_manifest(manifest, signing_key, signature, public_key):
    """Sign a release manifest using PyCA cryptography Ed25519 (no external openssl subprocess)."""
    manifest_bytes = _read_bounded(manifest, 64 * 1024)
    key_bytes = _read_bounded(signing_key, 4096)
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, load_pem_private_key,
        )
    except ImportError as exc:
        raise ReleaseError("The release signing library is unavailable. Reinstall Wardr in its environment.") from exc
    try:
        private_key = load_pem_private_key(key_bytes, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Expected an Ed25519 signing key")
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise ReleaseError("Use an unencrypted Ed25519 release signing key in PEM format.") from exc
    sig_bytes = private_key.sign(manifest_bytes)
    if len(sig_bytes) != 64:
        raise ReleaseError("Use an Ed25519 release signing key.")
    Path(signature).write_bytes(sig_bytes)
    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    Path(public_key).write_bytes(pub_pem)


def verify_manifest_signature(manifest_bytes, signature_bytes, public_key_bytes):
    if not 0 < len(manifest_bytes) <= 64 * 1024 or len(signature_bytes) != 64 or not 0 < len(public_key_bytes) <= 2048:
        raise ReleaseError("The release signature data has an invalid size.")
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise ReleaseError("The release verification library is unavailable. Reinstall Wardr in its environment.") from exc
    try:
        public_key = load_pem_public_key(public_key_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Expected an Ed25519 public key")
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise ReleaseError("Provide a trusted Ed25519 public key in PEM format.") from exc
    try:
        public_key.verify(signature_bytes, manifest_bytes)
    except InvalidSignature as exc:
        raise ReleaseError("The release signature does not match the supplied trusted key.") from exc


def verify_release(manifest, signature, public_key, artifact):
    manifest_bytes = _read_bounded(manifest, 64 * 1024)
    verify_manifest_signature(manifest_bytes, _read_bounded(signature, 64), _read_bounded(public_key, 2048))

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
