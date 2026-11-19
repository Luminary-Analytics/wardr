"""Fetch the authentic public artifacts used by the Windows release smoke test."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
from runpy import run_path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

from cryptography.hazmat.primitives.serialization import load_pem_public_key


ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://getwardr.com"
GITHUB = "https://github.com/Luminary-Analytics/wardr/releases/download"
CDN = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")


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
        raise ValueError("Unexpected Windows installer download redirect.")


def windows_setup(version, output, fetch, key):
    catalog_url = f"{ORIGIN}/releases/{version}/installers.json"
    raw = fetch(catalog_url, 64 * 1024)
    key.verify(fetch(catalog_url + ".sig", 64), raw)
    catalog = json.loads(raw)
    if (catalog["schema_version"], catalog["channel"], catalog["version"]) != (1, "community", version):
        raise ValueError("The signed installer catalog identifies a different release.")
    installer, = (row for row in catalog["installers"] if (row["platform"], row["arch"]) == ("windows", "x64"))
    name = f"wardr-{version}-windows-x64-setup.exe"
    route = f"/installers/v{version}/{name}"
    size, digest = installer["bytes"], installer["sha256"]
    if (installer["name"], installer["url"]) != (name, route) or type(size) is not int or not (
        0 < size <= 128 * 1024 * 1024 and re.fullmatch(r"[a-f0-9]{64}", digest)
    ):
        raise ValueError("Invalid Windows installer metadata in the signed catalog.")

    source = ORIGIN + route
    opener = build_opener(InstallerRedirects(source, f"{GITHUB}/v{version}/{name}"))
    try:
        with opener.open(source, timeout=60) as response:
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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("baseline")
    parser.add_argument("target")
    args = parser.parse_args()
    if not all(VERSION.fullmatch(value) for value in (args.baseline, args.target)):
        parser.error("Use canonical three-part release versions.")
    if tuple(map(int, args.baseline.split("."))) >= tuple(map(int, args.target.split("."))):
        parser.error("Use a target newer than the baseline.")
    args.output.mkdir(parents=True, exist_ok=True)
    builder = run_path(str(ROOT / "packaging/build_payload.py"))
    key = load_pem_public_key((ROOT / "wardr/keys/release.pem").read_bytes())
    for version in (args.baseline, args.target):
        windows_setup(version, args.output, builder["fetch"], key)
    wheel = builder["published_wheel"](args.baseline, args.output)
    print(f"Verified the signed historical manifest and baseline wheel {wheel.name}.", flush=True)


if __name__ == "__main__":
    main()
