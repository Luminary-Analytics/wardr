"""Validate a Wardr installer signing request and print GitHub Actions outputs.

The release runner (packaging/release.py) commits ``packaging/signing/request.json`` to
``main`` and pushes the ``sign-vX.Y.Z`` tag on that commit. The request names the
version, the reviewed source commit and the SHA-256 of the sealed wheel, which the
runner has already put on the draft GitHub release ``vX.Y.Z``. Nothing else is
trusted from the tag.
"""

import argparse
import json
from pathlib import Path
import re


REQUEST = Path("packaging/signing/request.json")
REQUEST_FIELDS = {"schema_version", "version", "commit", "wheel_sha256"}
REQUEST_LIMIT = 4096
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TAG_PREFIX = "refs/tags/sign-v"


def unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("The signing request has duplicate JSON fields.")
        fields[key] = value
    return fields


def read_request(ref, root):
    path = Path(root) / REQUEST
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular signing request at {REQUEST.as_posix()}.")
    with path.open("rb") as handle:
        raw = handle.read(REQUEST_LIMIT + 1)
    if not 0 < len(raw) <= REQUEST_LIMIT:
        raise ValueError("The signing request is empty or too large.")
    request = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    if not isinstance(request, dict) or request.keys() != REQUEST_FIELDS:
        raise ValueError("The signing request does not match the required JSON fields.")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise ValueError("Unsupported signing request schema version.")
    version, commit, wheel_sha256 = request["version"], request["commit"], request["wheel_sha256"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("Use the stable Wardr release version in major.minor.patch format.")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError("Use the full lowercase Wardr source commit SHA.")
    if not isinstance(wheel_sha256, str) or not SHA256.fullmatch(wheel_sha256):
        raise ValueError("Use the lowercase SHA-256 of the sealed Wardr wheel.")
    if ref != f"{TAG_PREFIX}{version}":
        raise ValueError("The signing tag must name the requested Wardr version.")
    return {"version": version, "commit": commit, "wheel_sha256": wheel_sha256}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref", help="The full tag ref the signing workflow runs on")
    parser.add_argument("--root", default=".", help="The checkout of the signing tag")
    args = parser.parse_args()
    try:
        outputs = read_request(args.ref, args.root)
    except (OSError, RecursionError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    for name, value in outputs.items():
        print(f"{name}={value}")


if __name__ == "__main__":
    main()
