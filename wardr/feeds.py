"""Verify, cache, and expose Ed25519-signed Wardr Rapid-Defense Feeds.

Defense feeds carry only declarative detection rules, emerging advisories, and
references to locally allowlisted remediation primitives. They never carry
executable code or shell commands.
"""

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


FEED_HOST = "getwardr.com"
FEED_PATH = "/feeds/defense-v1.json"
FEED_SIG_PATH = "/feeds/defense-v1.json.sig"
_PUBLIC_KEY = Path(__file__).with_name("keys") / "release.pem"
_CACHE_FILE = "defense-feed.json"
_MAX_FEED_BYTES = 2 * 1024 * 1024
_MAX_RULES = 250
_MAX_ADVISORIES = 2000
_IO_TIMEOUT = 8
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}\Z")
_SEVERITIES = ("critical", "high", "medium", "low")
_CONFIDENCES = ("high", "medium", "low")
ALLOWED_MITIGATIONS = frozenset({
    "ssh-directory-permissions",
    "ssh-identity-permissions",
    "ssh-authorized-keys-permissions",
    "aws-credentials-permissions",
    "kube-config-permissions",
    "gnupg-directory-permissions",
    "docker-config-permissions",
})


class FeedError(RuntimeError):
    """A Rapid-Defense Feed could not be fetched, verified, or loaded."""


def _text(value, limit: int, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise ValueError("Expected text field.")
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value).strip()
    if required and not cleaned:
        raise ValueError("Missing required text field.")
    if len(cleaned) > limit:
        raise ValueError("Text field exceeds limit.")
    return cleaned


def _tokens(value, *, max_items: int = 8, max_length: int = 120) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > max_items:
        raise ValueError("Invalid token list.")
    result = []
    for item in value:
        token = _text(item, max_length)
        result.append(token)
    return result


def _validate_rule(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Rule must be an object.")
    rule_id = _text(raw.get("id"), 80)
    if not _RULE_ID.fullmatch(rule_id):
        raise ValueError(f"Invalid rule ID: {rule_id}")
    severity = raw.get("severity")
    confidence = raw.get("confidence", "medium")
    if severity not in _SEVERITIES or confidence not in _CONFIDENCES:
        raise ValueError("Invalid rule severity or confidence.")
    title = _text(raw.get("title"), 200)
    summary = _text(raw.get("summary"), 1000)
    raw_actions = raw.get("actions")
    if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= 8:
        raise ValueError("Rule must include 1 to 8 remediation actions.")
    actions = [_text(step, 400) for step in raw_actions]
    mitigation_id = _text(raw.get("mitigation_id"), 80, required=False)
    if mitigation_id is not None and mitigation_id not in ALLOWED_MITIGATIONS:
        raise ValueError(f"Mitigation primitive is not allowlisted: {mitigation_id}")

    match = raw.get("match")
    if not isinstance(match, dict):
        raise ValueError("Rule match definition is required.")
    kind = match.get("kind")
    if kind not in ("event", "burst"):
        raise ValueError("Rule match kind must be 'event' or 'burst'.")
    source = _text(match.get("source"), 160, required=False)
    title_contains = _tokens(match.get("title_contains"))
    detail_contains = _tokens(match.get("detail_contains"))
    if not (source or title_contains or detail_contains):
        raise ValueError("Rule match must specify at least one predicate.")

    validated_match = {
        "kind": kind,
        "source": source,
        "title_contains": title_contains,
        "detail_contains": detail_contains,
    }
    if kind == "burst":
        minimum = match.get("minimum")
        window = match.get("window_seconds")
        if type(minimum) is not int or not 2 <= minimum <= 100:
            raise ValueError("Burst rule minimum must be an integer between 2 and 100.")
        if type(window) is not int or not 10 <= window <= 86400:
            raise ValueError("Burst rule window_seconds must be between 10 and 86400.")
        validated_match["minimum"] = minimum
        validated_match["window_seconds"] = window

    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "actions": actions,
        "mitigation_id": mitigation_id,
        "match": validated_match,
    }


def _validate_advisory(raw: object, default_modified: str) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Advisory entry must be an object.")
    adv_id = _text(raw.get("id"), 120)
    affected = raw.get("affected")
    if not isinstance(affected, list) or not affected or len(affected) > 64:
        raise ValueError(f"Advisory {adv_id} must contain affected package entries.")
    modified = _text(raw.get("modified"), 40, required=False) or default_modified
    # Preserve standard OSV-compatible structure while bounding summary/aliases.
    record = {
        "id": adv_id,
        "modified": modified,
        "affected": affected,
    }
    if "summary" in raw and raw["summary"] is not None:
        record["summary"] = _text(raw["summary"], 600, required=False) or ""
    if "aliases" in raw and isinstance(raw["aliases"], list):
        record["aliases"] = [_text(item, 120) for item in raw["aliases"][:16]]
    if "severity" in raw and isinstance(raw["severity"], list):
        record["severity"] = raw["severity"][:4]
    if "database_specific" in raw and isinstance(raw["database_specific"], dict):
        record["database_specific"] = raw["database_specific"]
    if "references" in raw and isinstance(raw["references"], list):
        record["references"] = raw["references"][:8]
    return record


def _parse_feed_document(feed_bytes: bytes) -> dict:
    try:
        doc = json.loads(feed_bytes)
        if not isinstance(doc, dict):
            raise ValueError("Feed must be a JSON object.")
        if doc.get("schema_version") != 1 or doc.get("channel") != "community":
            raise ValueError("Unsupported defense feed schema or channel.")
        version = _text(doc.get("version"), 64)
        published_at = _text(doc.get("published_at"), 64)
        parsed_time = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        if parsed_time.tzinfo is None:
            raise ValueError("Feed published_at must include a timezone.")

        if "rules" not in doc or "advisories" not in doc:
            raise ValueError("Defense feed must explicitly include rules and advisories collections.")
        raw_rules = doc["rules"]
        raw_advisories = doc["advisories"]
        if not isinstance(raw_rules, list) or len(raw_rules) > _MAX_RULES:
            raise ValueError("Invalid defense feed rules collection.")
        if not isinstance(raw_advisories, list) or len(raw_advisories) > _MAX_ADVISORIES:
            raise ValueError("Invalid defense feed advisories collection.")

        rules = []
        seen_ids = set()
        for item in raw_rules:
            rule = _validate_rule(item)
            if rule["id"] in seen_ids:
                raise ValueError(f"Duplicate rule ID in feed: {rule['id']}")
            seen_ids.add(rule["id"])
            rules.append(rule)

        default_modified = parsed_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        advisories = [_validate_advisory(item, default_modified) for item in raw_advisories]
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError) as exc:
        raise FeedError(f"The Rapid-Defense Feed failed validation: {exc}") from exc

    return {
        "schema_version": 1,
        "channel": "community",
        "version": version,
        "published_at": published_at,
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rules": rules,
        "advisories": advisories,
    }


def sign_feed_bytes(feed_bytes: bytes, private_key_pem: bytes) -> bytes:
    """Validate a declarative Rapid-Defense Feed and sign its exact bytes with Ed25519."""
    if not 0 < len(feed_bytes) <= _MAX_FEED_BYTES:
        raise FeedError("The Rapid-Defense Feed has an invalid size.")
    # Validate schema BEFORE signing so malformed or non-allowlisted feeds are never signed.
    _parse_feed_document(feed_bytes)
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Expected an Ed25519 private key.")
    except (UnsupportedAlgorithm, TypeError, ValueError) as exc:
        raise FeedError("Provide a valid unencrypted Ed25519 private key in PEM format.") from exc
    return private_key.sign(feed_bytes)


def verify_feed_bytes(feed_bytes: bytes, signature_bytes: bytes, public_key_bytes: bytes | None = None) -> dict:
    """Verify Ed25519 signature over raw feed bytes and validate its declarative schema."""
    if not 0 < len(feed_bytes) <= _MAX_FEED_BYTES:
        raise FeedError("The Rapid-Defense Feed has an invalid size.")
    if len(signature_bytes) != 64:
        raise FeedError("The Rapid-Defense Feed signature must be a 64-byte Ed25519 signature.")
    key_bytes = _PUBLIC_KEY.read_bytes() if public_key_bytes is None else public_key_bytes
    if not 0 < len(key_bytes) <= 2048:
        raise FeedError("Invalid Ed25519 public key size.")
    try:
        public_key = load_pem_public_key(key_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Expected an Ed25519 public key.")
    except (UnsupportedAlgorithm, TypeError, ValueError) as exc:
        raise FeedError("Provide a trusted Ed25519 public key in PEM format.") from exc
    try:
        public_key.verify(signature_bytes, feed_bytes)
    except InvalidSignature as exc:
        raise FeedError("The Rapid-Defense Feed signature does not match the trusted key.") from exc
    return _parse_feed_document(feed_bytes)


def _atomic_save(state_dir: Path, payload: dict) -> None:
    path = Path(state_dir) / _CACHE_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".feed-", suffix=".json")
    temporary = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_file_bounded(path: Path, maximum: int) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(maximum + 1)
    except OSError as exc:
        raise FeedError(f"Could not read feed file: {path}") from exc
    if not 0 < len(data) <= maximum:
        raise FeedError(f"Feed file has an invalid size: {path}")
    return data


def import_feed(
    state_dir: Path,
    bundle_path: Path,
    signature_path: Path,
    public_key_path: Path | None = None,
) -> dict:
    """Verify a local Ed25519-signed Defense Feed bundle and install it into state_dir."""
    feed_bytes = _read_file_bounded(bundle_path, _MAX_FEED_BYTES)
    sig_bytes = _read_file_bounded(signature_path, 64)
    key_bytes = _read_file_bounded(public_key_path, 2048) if public_key_path is not None else None
    verified = verify_feed_bytes(feed_bytes, sig_bytes, key_bytes)
    _enforce_monotonic_freshness(state_dir, verified)
    try:
        _atomic_save(state_dir, verified)
    except OSError as exc:
        raise FeedError("Could not save the verified Rapid-Defense Feed in Wardr's data directory.") from exc
    return public_feed_status(verified)


def _https_get(path: str, limit: int) -> bytes:
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(FEED_HOST, 443, timeout=_IO_TIMEOUT, context=context)
    deadline = time.monotonic() + _IO_TIMEOUT
    try:
        connection.request("GET", path, headers={"Accept": "application/octet-stream", "User-Agent": "Wardr/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            raise FeedError(f"Rapid-Defense Feed download returned HTTP {response.status}.")
        chunks = bytearray()
        while time.monotonic() < deadline:
            chunk = response.read(64 * 1024)
            if not chunk:
                return bytes(chunks)
            chunks.extend(chunk)
            if len(chunks) > limit:
                raise FeedError("Rapid-Defense Feed exceeded size limit.")
        raise FeedError("Rapid-Defense Feed download timed out.")
    except (OSError, http.client.HTTPException) as exc:
        raise FeedError("Could not reach the Wardr Rapid-Defense Feed server.") from exc
    finally:
        connection.close()


def _enforce_monotonic_freshness(state_dir: Path, verified: dict) -> None:
    existing = _load_cached(state_dir)
    if not existing or not isinstance(existing.get("published_at"), str):
        return
    try:
        old_dt = datetime.fromisoformat(existing["published_at"].replace("Z", "+00:00"))
        new_dt = datetime.fromisoformat(verified["published_at"].replace("Z", "+00:00"))
    except ValueError:
        return
    if new_dt < old_dt:
        raise FeedError("Refused older Rapid-Defense Feed (anti-rollback protection).")


def refresh_feed(state_dir: Path, *, public_key_bytes: bytes | None = None) -> dict:
    """Download, verify over Ed25519, and cache the latest signed Rapid-Defense Feed."""
    feed_bytes = _https_get(FEED_PATH, _MAX_FEED_BYTES)
    sig_bytes = _https_get(FEED_SIG_PATH, 64)
    verified = verify_feed_bytes(feed_bytes, sig_bytes, public_key_bytes)
    _enforce_monotonic_freshness(state_dir, verified)
    try:
        _atomic_save(state_dir, verified)
    except OSError as exc:
        raise FeedError("Could not save the verified Rapid-Defense Feed.") from exc
    return public_feed_status(verified)


def _load_cached(state_dir: Path) -> dict | None:
    path = Path(state_dir) / _CACHE_FILE
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_FEED_BYTES + 4096:
            return None
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get("schema_version") != 1:
            return None
        if not isinstance(doc.get("rules"), list) or not isinstance(doc.get("advisories"), list):
            return None
        return doc
    except (OSError, ValueError, RecursionError):
        return None


def public_feed_status(doc: dict | None, *, detail: str | None = None) -> dict:
    if not doc:
        return {
            "available": False,
            "version": None,
            "published_at": None,
            "verified_at": None,
            "rule_count": 0,
            "advisory_count": 0,
            "detail": detail or "No Rapid-Defense Feed installed yet. Import a signed bundle or refresh online.",
        }
    return {
        "available": True,
        "version": doc.get("version"),
        "published_at": doc.get("published_at"),
        "verified_at": doc.get("verified_at"),
        "rule_count": len(doc.get("rules", ())),
        "advisory_count": len(doc.get("advisories", ())),
        "detail": detail or "Verified with Ed25519. Declarative rules and rapid advisories active.",
    }


def feed_status(state_dir: Path) -> dict:
    return public_feed_status(_load_cached(state_dir))


def load_feed_rules(state_dir: Path) -> list[dict]:
    doc = _load_cached(state_dir)
    if not doc:
        return []
    rules = []
    for item in doc.get("rules", ()):
        try:
            rules.append(_validate_rule(item))
        except ValueError:
            continue
    return rules


def load_feed_advisories(state_dir: Path) -> list[dict]:
    doc = _load_cached(state_dir)
    if not doc:
        return []
    published = str(doc.get("published_at") or "2026-01-01T00:00:00Z")
    default_modified = published.replace("+00:00", "Z")
    advisories = []
    for item in doc.get("advisories", ()):
        try:
            advisories.append(_validate_advisory(item, default_modified))
        except ValueError:
            continue
    return advisories
