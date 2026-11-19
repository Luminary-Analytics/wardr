"""Fetch authentic public artifacts for a native live release smoke test."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
from runpy import run_path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://getwardr.com"
GITHUB = "https://github.com/Luminary-Analytics/wardr/releases/download"
CDN = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
INSTALLER_LIMIT = 150 * 1024 * 1024
INSTALLERS = {
    ("windows", "x64"): "windows-x64-setup.exe",
    ("macos", "x64"): "macos-x64.dmg",
    ("macos", "arm64"): "macos-arm64.dmg",
    ("linux", "x64"): "linux-x64.run",
    ("linux", "arm64"): "linux-arm64.run",
}


class InstallerRedirects(HTTPRedirectHandler):
    def __init__(self, source, release_asset):
        self.source = source
        self.release_asset = release_asset

    def redirect_request(self, req, fp, code, message, headers, newurl):
        destination = urlsplit(newurl)
        if (req.full_url == self.source and newurl == self.release_asset) or (
            req.full_url == self.release_asset and destination.scheme == "https"
            and destination.netloc in CDN and not destination.fragment
        ):
            return super().redirect_request(req, fp, code, message, headers, newurl)
        raise ValueError("Unexpected native installer download redirect.")


def fetch_installer(version, target, output, fetch, key):
    catalog_path = f"/releases/{version}/installers.json"
    raw = fetch(catalog_path, 64 * 1024)
    key.verify(fetch(catalog_path + ".sig", 64), raw)
    catalog = json.loads(raw)
    if (not isinstance(catalog, dict) or type(catalog.get("schema_version")) is not int
            or (catalog.get("schema_version"), catalog.get("channel"), catalog.get("version")) != (1, "community", version)):
        raise ValueError("The signed installer catalog identifies a different release.")
    installer, = (row for row in catalog["installers"] if (row["platform"], row["arch"]) == target)
    name = f"wardr-{version}-{INSTALLERS[target]}"
    route = f"/installers/v{version}/{name}"
    size, digest = installer["bytes"], installer["sha256"]
    if (installer["name"], installer["url"]) != (name, route) or type(size) is not int or not (
        0 < size <= INSTALLER_LIMIT and re.fullmatch(r"[a-f0-9]{64}", digest)
    ):
        raise ValueError(f"Invalid metadata for {name} in the signed installer catalog.")

    source = ORIGIN + route
    opener = build_opener(InstallerRedirects(source, f"{GITHUB}/v{version}/{name}"))
    try:
        request = Request(source, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"})
        with opener.open(request, timeout=60) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ValueError(f"Expected a complete, unencoded HTTPS download for {name}.")
            data = response.read(size + 1)
    except (HTTPError, URLError, OSError) as exc:
        raise ValueError(f"Could not download {name} over HTTPS ({type(exc).__name__}).") from None
    if len(data) != size or sha256(data).hexdigest() != digest:
        raise ValueError(f"{name} differs from the signed installer catalog.")
    with (output / name).open("xb") as file:
        file.write(data)
    print(f"Verified signed-catalog SHA-256 for {name} ({digest}).", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("windows", "macos", "linux"))
    parser.add_argument("--arch", required=True, choices=("x64", "arm64"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("baseline")
    parser.add_argument("target")
    args = parser.parse_args()
    target = (args.platform, args.arch)
    if target not in INSTALLERS:
        parser.error("Choose Windows x64, macOS x64 or arm64, or Linux x64 or arm64.")
    if not all(VERSION.fullmatch(value) for value in (args.baseline, args.target)):
        parser.error("Use canonical three-part release versions.")
    if tuple(map(int, args.baseline.split("."))) >= tuple(map(int, args.target.split("."))):
        parser.error("Use a target newer than the baseline.")
    args.output.mkdir(parents=True, exist_ok=True)
    verifier = run_path(str(ROOT / "tests/smoke_update.py"))
    fetch = verifier["production_download"]
    key = load_pem_public_key((ROOT / "wardr/keys/release.pem").read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("The pinned Wardr release key must be Ed25519.")
    for version in (args.baseline, args.target):
        fetch_installer(version, target, args.output, fetch, key)

    wheel = verifier["production_wheel_record"](f"/releases/{args.baseline}/release.json", args.baseline, key)
    data = fetch(wheel["url"], wheel["bytes"])
    verifier["verify_wheel_bytes"](data, wheel)
    with (args.output / wheel["name"]).open("xb") as file:
        file.write(data)
    print(f"Verified the signed historical manifest and baseline wheel {wheel['name']}.", flush=True)


if __name__ == "__main__":
    main()
