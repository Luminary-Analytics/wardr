"""Move files between Wardr's signing jobs through the draft GitHub release.

The repository is public, so its Actions artifacts can be downloaded by anyone
signed in to GitHub. Nothing that exists before a release is published (the sealed
wheel, payloads, unsigned and signed installers) is kept as an artifact: it goes on
the draft release ``vX.Y.Z``, which only people with write access can see. Files that
are only on their way from one job to the next are named ``staging-...`` and are
deleted once used; the release runner removes any that a failed run left behind.

Every download is checked against a SHA-256 the caller already knows. It runs the
GitHub CLI with the job's token (GH_TOKEN) and uses only the standard library.
"""

import argparse
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode


REPOSITORY = "Luminary-Analytics/wardr"
STAGING = "staging-"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"v(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")


class DraftError(ValueError):
    """The draft release or one of its files isn't what the signing job expects."""


def _gh(*arguments, stdout=subprocess.PIPE, timeout=600):
    result = subprocess.run(
        ("gh", "api", "--hostname", "github.com", *arguments), stdin=subprocess.DEVNULL,
        stdout=stdout, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    if result.returncode:
        raise DraftError(result.stderr.decode(errors="replace").strip() or "The GitHub CLI failed.")
    return result.stdout


def _json(*arguments):
    try:
        return json.loads(_gh(*arguments, "--header", "Accept: application/vnd.github+json"))
    except ValueError as exc:
        raise DraftError("GitHub returned invalid JSON.") from exc


def _sha256(path):
    with Path(path).open("rb") as handle:
        return file_digest(handle, "sha256").hexdigest()


def _id(value, what):
    if type(value) is not int or value < 1:
        raise DraftError(f"GitHub did not give a valid {what} ID.")
    return value


def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise DraftError(f"Invalid release file name {value!r}.")
    return value


def _sha(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise DraftError("Give the expected lowercase SHA-256.")
    return value


def _draft(release_id):
    release = _json(f"repos/{REPOSITORY}/releases/{_id(release_id, 'release')}")
    if not isinstance(release, dict) or release.get("id") != release_id:
        raise DraftError(f"Release {release_id} isn't readable.")
    if release.get("draft") is not True or release.get("prerelease") is not True:
        raise DraftError(f"Release {release_id} must be an unpublished Wardr Community prerelease draft.")
    return release


def _assets(release_id):
    pages = _json(f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100", "--paginate", "--slurp")
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise DraftError("GitHub returned an invalid asset listing.")
    return [asset for page in pages for asset in page]


def find(tag):
    if not _TAG.fullmatch(tag):
        raise DraftError("Use the release tag vX.Y.Z.")
    pages = _json(f"repos/{REPOSITORY}/releases?per_page=100", "--paginate", "--slurp")
    matches = [row for page in pages for row in page if isinstance(row, dict) and row.get("tag_name") == tag]
    if len(matches) != 1:
        raise DraftError(f"Expected exactly one release for {tag}; found {len(matches)}.")
    release_id = _id(matches[0].get("id"), "release")
    _draft(release_id)
    return {"release_id": release_id}


def _download(asset, expected, out):
    asset_id = _id(asset.get("id"), "asset")
    if asset.get("state") != "uploaded" or type(asset.get("size")) is not int or asset["size"] < 1:
        raise DraftError(f"Asset {asset_id} isn't a complete upload.")
    if asset.get("digest") not in (None, f"sha256:{expected}"):
        raise DraftError(f"Asset {asset_id} differs from the expected SHA-256.")
    out = Path(out)
    if out.exists() or out.is_symlink():
        raise DraftError(f"{out} exists already.")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("xb") as handle:
        _gh(f"repos/{REPOSITORY}/releases/assets/{asset_id}", "--header", "Accept: application/octet-stream",
            stdout=handle)
    if out.stat().st_size != asset["size"] or _sha256(out) != expected:
        out.unlink()
        raise DraftError(f"Asset {asset_id} didn't download as the expected bytes.")
    return {"asset_id": asset_id}


def download(release_id, name, sha256, out):
    _draft(release_id)
    matches = [asset for asset in _assets(release_id) if asset.get("name") == _name(name)]
    if len(matches) != 1:
        raise DraftError(f"Expected exactly one {name} on the draft release.")
    return _download(matches[0], _sha(sha256), out)


def fetch(release_id, asset_id, sha256, out):
    _draft(release_id)
    matches = [asset for asset in _assets(release_id) if asset.get("id") == _id(asset_id, "asset")]
    if len(matches) != 1:
        raise DraftError(f"Asset {asset_id} isn't on draft release {release_id}.")
    return _download(matches[0], _sha(sha256), out)


def upload(release_id, name, path):
    _draft(release_id)
    name, path = _name(name), Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size < 1:
        raise DraftError(f"Expected a regular, non-empty file at {path}.")
    expected = _sha256(path)
    existing = [asset for asset in _assets(release_id) if asset.get("name") == name]
    if existing:
        # A retried job may find its own earlier upload: the same bytes are kept, anything else refused.
        asset = existing[0]
        if asset.get("state") == "uploaded" and asset.get("size") == path.stat().st_size and (
            asset.get("digest") == f"sha256:{expected}"
        ):
            return {"asset_id": _id(asset.get("id"), "asset"), "sha256": expected}
        raise DraftError(f"The draft release already has a different {name}; nothing was replaced.")
    endpoint = f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?{urlencode({'name': name})}"
    asset = json.loads(_gh(endpoint, "--method", "POST", "--header", "Content-Type: application/octet-stream",
                           "--input", str(path.resolve()), timeout=1800))
    asset_id = _id(asset.get("id") if isinstance(asset, dict) else None, "asset")
    if asset.get("name") != name or asset.get("size") != path.stat().st_size or (
        asset.get("digest") not in (None, f"sha256:{expected}")
    ):
        raise DraftError(f"GitHub recorded {name} differently from the uploaded file.")
    return {"asset_id": asset_id, "sha256": expected}


def rename(release_id, asset_id, name):
    """Give a verified file its final name: only a staging file, and only to a free name."""
    _draft(release_id)
    assets = _assets(release_id)
    matches = [asset for asset in assets if asset.get("id") == _id(asset_id, "asset")]
    if len(matches) != 1 or not str(matches[0].get("name", "")).startswith(STAGING):
        raise DraftError(f"Asset {asset_id} isn't a staging file on draft release {release_id}.")
    if any(asset.get("name") == _name(name) for asset in assets):
        raise DraftError(f"The draft release already has {name}; nothing was replaced.")
    renamed = _json(f"repos/{REPOSITORY}/releases/assets/{asset_id}", "--method", "PATCH", "--raw-field", f"name={name}")
    if not isinstance(renamed, dict) or renamed.get("name") != name:
        raise DraftError(f"GitHub didn't confirm the new name {name}.")
    return {"asset_id": asset_id}


def delete(release_id, asset_id):
    """Delete a staging file once the next job has it; never a release file."""
    _draft(release_id)
    matches = [asset for asset in _assets(release_id) if asset.get("id") == _id(asset_id, "asset")]
    if not matches:
        return {}
    if not str(matches[0].get("name", "")).startswith(STAGING):
        raise DraftError(f"Asset {asset_id} isn't a staging file; it was kept.")
    _gh(f"repos/{REPOSITORY}/releases/assets/{asset_id}", "--method", "DELETE")
    return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("find")
    command.add_argument("--tag", required=True)
    command = commands.add_parser("download")
    command.add_argument("--release", type=int, required=True)
    command.add_argument("--name", required=True)
    command.add_argument("--sha256", required=True)
    command.add_argument("--out", required=True)
    command = commands.add_parser("fetch")
    command.add_argument("--release", type=int, required=True)
    command.add_argument("--asset", type=int, required=True)
    command.add_argument("--sha256", required=True)
    command.add_argument("--out", required=True)
    command = commands.add_parser("upload")
    command.add_argument("--release", type=int, required=True)
    command.add_argument("--name", required=True)
    command.add_argument("--path", required=True)
    command = commands.add_parser("rename")
    command.add_argument("--release", type=int, required=True)
    command.add_argument("--asset", type=int, required=True)
    command.add_argument("--name", required=True)
    command = commands.add_parser("delete")
    command.add_argument("--release", type=int, required=True)
    command.add_argument("--asset", type=int, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY", REPOSITORY) != REPOSITORY:
        parser.error(f"Only {REPOSITORY} signs Wardr.")
    try:
        if args.command == "find":
            outputs = find(args.tag)
        elif args.command == "download":
            outputs = download(args.release, args.name, args.sha256, args.out)
        elif args.command == "fetch":
            outputs = fetch(args.release, args.asset, args.sha256, args.out)
        elif args.command == "upload":
            outputs = upload(args.release, args.name, args.path)
        elif args.command == "rename":
            outputs = rename(args.release, args.asset, args.name)
        else:
            outputs = delete(args.release, args.asset)
    except (DraftError, OSError, subprocess.SubprocessError) as exc:
        print(f"release_draft: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    for key, value in outputs.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
