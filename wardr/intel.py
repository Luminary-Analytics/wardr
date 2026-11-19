"""Read and cache CISA's public Known Exploited Vulnerabilities catalog."""

import json
import os
import re
import tempfile
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener


CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_FILE = "cisa-kev.json"
_MAX_FEED_BYTES = 8 * 1024 * 1024
_MAX_CACHE_BYTES = 250_000
_RECENT_ADVISORIES = 25
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)


class AdvisoryError(RuntimeError):
    """The requested advisory refresh could not be completed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _download():
    request = Request(FEED_URL, headers={"Accept": "application/json", "User-Agent": "Wardr/1.0"})
    deadline = time.monotonic() + 10
    body = bytearray()
    try:
        with build_opener(_NoRedirect()).open(request, timeout=5) as response:
            while time.monotonic() < deadline:
                chunk = response.read1(64 * 1024)
                if not chunk:
                    return body
                body.extend(chunk)
                if len(body) > _MAX_FEED_BYTES:
                    raise AdvisoryError("The advisory catalog exceeded the download size limit.")
    except OSError as exc:
        raise AdvisoryError("Could not download the CISA catalog. Check that CISA is reachable and retry.") from exc
    raise AdvisoryError("The CISA catalog download timed out.")


def _field(row, key, limit):
    value = row.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Invalid catalog field: {key}")
    return value.strip()


def _decode_catalog(body):
    try:
        catalog = json.loads(body)
        entries = catalog["vulnerabilities"]
        if not isinstance(entries, list) or type(catalog["count"]) is not int or catalog["count"] != len(entries):
            raise ValueError("Catalog size does not match the count")
        released_at = _field(catalog, "dateReleased", 40)
        if datetime.fromisoformat(released_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("Missing time zone for catalog release")
        revision = _field(catalog, "catalogVersion", 64)
        advisories = []
        seen = set()
        for entry in entries:
            cve = _field(entry, "cveID", 32)
            if not _CVE.fullmatch(cve) or cve in seen:
                raise ValueError("Invalid or duplicate CVE identifier")
            seen.add(cve)
            date_added = date.fromisoformat(_field(entry, "dateAdded", 10)).isoformat()
            advisories.append({
                "id": cve,
                "title": _field(entry, "vulnerabilityName", 300),
                "vendor": _field(entry, "vendorProject", 200),
                "product": _field(entry, "product", 400),
                "date_added": date_added,
                "required_action": _field(entry, "requiredAction", 1000),
                "ransomware": _field(entry, "knownRansomwareCampaignUse", 24),
            })
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError) as exc:
        raise AdvisoryError("CISA returned an invalid advisory catalog. The saved catalog was preserved.") from exc

    advisories.sort(key=lambda advisory: (advisory["date_added"], advisory["id"]), reverse=True)
    return {
        "refreshed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": revision,
        "released_at": released_at,
        "count": len(advisories),
        "advisories": advisories[:_RECENT_ADVISORIES],
        "exploited_ids": sorted(seen),
    }


def _status(snapshot=None, detail=None):
    return {
        "available": snapshot is not None,
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": CATALOG_URL,
        "feed_url": FEED_URL,
        "scope": "Public advisories. Verify your installed product and version against the vendor advisory.",
        "detail": detail,
        "refreshed_at": None,
        "catalog_version": None,
        "released_at": None,
        "count": None,
        "advisories": [],
        **(snapshot or {}),
    }


def advisory_status(state_dir):
    """Return the saved catalog summary without making a network request."""
    try:
        with (Path(state_dir) / _CACHE_FILE).open("rb") as stream:
            raw = stream.read(_MAX_CACHE_BYTES + 1)
        if len(raw) > _MAX_CACHE_BYTES:
            raise ValueError("Oversized catalog summary")
        saved = json.loads(raw)
        snapshot = {key: _field(saved, key, 80) for key in ("refreshed_at", "catalog_version", "released_at")}
        count = saved["count"]
        advisories = saved["advisories"]
        if type(count) is not int or count < 0 or not isinstance(advisories, list):
            raise ValueError("Invalid catalog summary")
        if len(advisories) != min(count, _RECENT_ADVISORIES):
            raise ValueError("Incomplete catalog summary")
        fields = {"id": 32, "title": 300, "vendor": 200, "product": 400, "date_added": 10,
                  "required_action": 1000, "ransomware": 24}
        snapshot["count"] = count
        snapshot["advisories"] = [{key: _field(row, key, cap) for key, cap in fields.items()} for row in advisories]
        index = saved.get("exploited_ids")
        if index is not None:
            if not isinstance(index, list) or len(index) != count or not all(
                isinstance(identifier, str) and len(identifier) <= 32 and _CVE.fullmatch(identifier)
                for identifier in index
            ):
                raise ValueError("Invalid CISA identifier index")
            ids = set(index)
            if len(ids) != count or any(row["id"] not in ids for row in snapshot["advisories"]):
                raise ValueError("Invalid CISA identifier index")
            snapshot["exploited_ids"] = index
        return _status(snapshot)
    except FileNotFoundError:
        return _status(detail="Refresh to download the latest CISA catalog.")
    except (AttributeError, KeyError, OSError, RecursionError, TypeError, ValueError):
        return _status(detail="The saved CISA catalog could not be read. Refresh to replace it.")


def refresh_advisories(state_dir):
    """Download, validate, and atomically save a small local advisory summary."""
    snapshot = _decode_catalog(_download())
    path = Path(state_dir) / _CACHE_FILE
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise AdvisoryError("Could not save the advisory catalog in Wardr's data directory.") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return _status(snapshot)


def public_status(snapshot):
    """Omit the internal index from the catalog preview."""
    return {key: value for key, value in snapshot.items() if key != "exploited_ids"}


def exploited_index(snapshot):
    index = snapshot.get("exploited_ids")
    if index is not None:
        return set(index), "full"
    recent = {row["id"] for row in snapshot.get("advisories", ()) if _CVE.fullmatch(row["id"])}
    return recent, "recent_only" if snapshot.get("available") else "unavailable"
