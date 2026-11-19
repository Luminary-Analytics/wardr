"""Read and stage Wardr release resources in GitHub's fixed repositories."""

from hashlib import file_digest
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.parse import urlencode
from zipfile import BadZipFile, ZipFile


PUBLIC_REPO = "Luminary-Analytics/wardr"
SIGNING_REPO = "Luminary-Analytics/resonant-client"
CHECKS = {"checks.yml": "Wardr checks", "update-smoke.yml": "Wardr update smoke"}
SIGNING_WORKFLOWS = ("wardr-windows-sign.yml", "wardr-macos-sign.yml", "wardr-linux-build.yml")
_VERSION = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSTALLER_LIMIT = 150 * 1024 * 1024
_PROOF_LIMIT = 64 * 1024
_ARCHIVE_LIMIT = _INSTALLER_LIMIT + 1024 * 1024
_POLL_INTERVAL = 10


class ReleaseError(ValueError):
    """A GitHub operation or release integrity check could not complete."""


def _gh(*arguments, timeout=60, stdout=subprocess.PIPE):
    environment = {key: value for key, value in os.environ.items() if key not in {"DEBUG", "GH_DEBUG", "GH_FORCE_TTY"}}
    environment.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", NO_COLOR="1")
    try:
        result = subprocess.run(
            ("gh", *arguments), env=environment, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise ReleaseError("Install the GitHub CLI and authenticate with github.com.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ReleaseError("A GitHub request timed out. Run the release command again to resume.") from exc
    except OSError as exc:
        raise ReleaseError(f"Could not run the GitHub CLI. {exc}") from exc
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        detail = re.sub(r"(https?://[^\s\"'<>?]+)\?[^\s\"'<>]+", r"\1?[query hidden]", detail)
        raise ReleaseError(detail or f"GitHub CLI exited with status {result.returncode}.")
    return result.stdout


def _api(path, *options, timeout=60):
    raw = _gh("api", "--hostname", "github.com", path,
              "--header", "Accept: application/vnd.github+json", *options, timeout=timeout)
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReleaseError(f"GitHub returned invalid JSON for {path}.") from exc


def _pages(path, field=None):
    pages = _api(path, "--paginate", "--slurp")
    if not isinstance(pages, list):
        raise ReleaseError(f"Invalid paginated response from GitHub for {path}.")
    for page in pages:
        rows = page if field is None else page.get(field) if isinstance(page, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ReleaseError(f"Invalid paginated response from GitHub for {path}.")
        yield from rows


def _version(version):
    if not isinstance(version, str) or not re.fullmatch(_VERSION, version):
        raise ReleaseError("Use a Wardr release version such as 0.2.1.")
    return version


def _commit(commit):
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise ReleaseError("Use a full lowercase Git commit SHA.")
    return commit


def _id(value, description):
    if type(value) is not int or value < 1:
        raise ReleaseError(f"GitHub did not provide a valid {description} ID.")
    return value


def _matches_run(run, workflow, commit, tag, name=None):
    path = run.get("path")
    return (
        isinstance(path, str) and path.split("@", 1)[0] == f".github/workflows/{workflow}"
        and run.get("event") == "push" and run.get("head_sha") == commit
        and (tag is None or run.get("head_branch") == tag)
        and (name is None or run.get("name") == name)
    )


def _wait_runs(repo, workflows, commit, tag, timeout, retry_failed):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ReleaseError("Set a positive workflow timeout in seconds.")
    deadline = monotonic() + timeout
    filters = {"head_sha": commit, "event": "push", "per_page": 100}
    if tag:
        filters["branch"] = tag
    pending = dict(workflows)
    completed = {}
    retried = {}
    progress = {}
    while pending:
        for workflow, name in tuple(pending.items()):
            left = deadline - monotonic()
            if left <= 0:
                break
            listing = _api(
                f"repos/{repo}/actions/workflows/{workflow}/runs?{urlencode(filters)}",
                timeout=min(60, left),
            )
            records = listing.get("workflow_runs") if isinstance(listing, dict) else None
            if not isinstance(records, list) or any(not isinstance(run, dict) for run in records):
                raise ReleaseError(f"Invalid workflow run listing for {workflow}.")
            candidates = [run for run in records if _matches_run(run, workflow, commit, tag, name)]
            if not candidates:
                continue
            run = max(candidates, key=lambda row: _id(row.get("id"), "workflow run"))
            run_id = _id(run.get("id"), "workflow run")
            status, conclusion = run.get("status"), run.get("conclusion")
            state = (run_id, status, conclusion)
            label = name or workflow
            link = f"https://github.com/{repo}/actions/runs/{run_id}"
            if progress.get(workflow) != state:
                print(f"GitHub reports {conclusion or status} for {label}. {link}", file=sys.stderr, flush=True)
                progress[workflow] = state
            if status != "completed":
                continue
            if conclusion == "success":
                completed[workflow] = run_id
                del pending[workflow]
                continue
            if retry_failed and conclusion in {"failure", "startup_failure", "timed_out"}:
                attempt = _id(run.get("run_attempt"), "workflow attempt")
                if run_id not in retried:
                    _gh("run", "rerun", str(run_id), "--failed", "--repo", f"github.com/{repo}",
                        timeout=min(60, max(1, deadline - monotonic())))
                    retried[run_id] = attempt
                    continue
                if attempt <= retried[run_id]:
                    continue
            raise ReleaseError(f"{label} concluded with {conclusion or 'an unknown result'}. {link}")
        if pending:
            left = deadline - monotonic()
            if left <= 0:
                missing = ", ".join(name or workflow for workflow, name in pending.items())
                raise ReleaseError(f"Timed out waiting for {missing} on {tag or commit}.")
            sleep(min(_POLL_INTERVAL, left))
    return completed


def wait_checks(commit, timeout):
    """Wait for both public push checks on the exact Wardr commit."""
    _wait_runs(PUBLIC_REPO, CHECKS, _commit(commit), None, timeout, False)


def wait_signing(tag, request_commit, timeout, retry_failed=False):
    """Return reviewed successful workflow run IDs for the private signing tag."""
    prefix = "vwardrsign-"
    if not isinstance(tag, str) or not tag.startswith(prefix) or "." in tag:
        raise ReleaseError("Use the versioned private Wardr signing tag.")
    _version(tag[len(prefix):].replace("_", "."))
    return _wait_runs(
        SIGNING_REPO, dict.fromkeys(SIGNING_WORKFLOWS), _commit(request_commit), tag, timeout, retry_failed,
    )


def _fingerprint(path):
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"Expected a regular release file at {path}.")
    with path.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        digest = file_digest(handle, "sha256").hexdigest()
    return size, f"sha256:{digest}"


def _installer_groups(version):
    prefix = f"wardr-{version}"
    return {
        "wardr-windows-sign.yml": {
            f"{prefix}-windows-x64-authenticode-verified": (f"{prefix}-windows-x64-setup.exe", "authenticode.json"),
        },
        "wardr-macos-sign.yml": {
            f"{prefix}-macos-{arch}-verified": (f"{prefix}-macos-{arch}.dmg",) for arch in ("arm64", "x64")
        },
        "wardr-linux-build.yml": {
            f"{prefix}-linux-{arch}-verified": (f"{prefix}-linux-{arch}.run",) for arch in ("arm64", "x64")
        },
    }


def _extract_installer(archive, members, directory):
    try:
        with ZipFile(archive) as package:
            entries = package.infolist()
            if len(entries) != len(members) or {entry.filename for entry in entries} != set(members):
                raise ReleaseError(f"Unexpected or duplicate ZIP entries for {', '.join(members)}.")
            for entry in entries:
                name = entry.filename
                limit = _PROOF_LIMIT if name == "authenticode.json" else _INSTALLER_LIMIT
                if (
                    entry.orig_filename != name or entry.is_dir() or entry.flag_bits & 1
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                    or not 0 < entry.file_size <= limit
                ):
                    raise ReleaseError(f"Invalid ZIP entry for {name}.")
                destination = directory / name
                with package.open(entry) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                if destination.stat().st_size != entry.file_size:
                    raise ReleaseError(f"The ZIP entry size differs for {name}.")
                if name.endswith(".run"):
                    destination.chmod(0o755)
    except (OSError, BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise ReleaseError(f"Could not read the expected installer archive. {exc}") from exc


def _download_installer(artifact, members, directory):
    asset_id = _id(artifact.get("id"), "artifact")
    digest, size = artifact.get("digest"), artifact.get("size_in_bytes")
    if (
        artifact.get("expired") is not False or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
        or type(size) is not int or not 0 < size <= _ARCHIVE_LIMIT
    ):
        raise ReleaseError(f"Artifact {asset_id} is expired or lacks valid ZIP integrity metadata.")
    archive = directory / f"artifact-{asset_id}.zip"
    with archive.open("xb") as handle:
        _gh("api", "--hostname", "github.com", f"repos/{SIGNING_REPO}/actions/artifacts/{asset_id}/zip",
            timeout=180, stdout=handle)
    if _fingerprint(archive) != (size, digest):
        raise ReleaseError(f"Artifact {asset_id} does not match its GitHub ZIP size and digest.")
    _extract_installer(archive, members, directory)
    archive.unlink()


def fetch_installers(version, runs, directory):
    """Fetch the five installers and Windows proof from their verified workflow runs."""
    version = _version(version)
    groups = _installer_groups(version)
    if set(runs) != set(groups):
        raise ReleaseError("Provide the reviewed Windows, macOS and Linux workflow run IDs.")
    tag = f"vwardrsign-{version.replace('.', '_')}"
    directory = Path(directory)
    if directory.is_symlink():
        raise ReleaseError("Choose a regular installer output directory.")
    directory.mkdir(parents=True, exist_ok=True)
    files = {}
    request_commit = None
    with TemporaryDirectory(prefix=".wardr-installers-", dir=directory) as temporary:
        staging = Path(temporary)
        for workflow, expected in groups.items():
            run_id = _id(runs[workflow], "workflow run")
            run = _api(f"repos/{SIGNING_REPO}/actions/runs/{run_id}")
            if not isinstance(run, dict):
                raise ReleaseError(f"Invalid GitHub workflow metadata for run {run_id}.")
            commit = _commit(run.get("head_sha"))
            if (
                run.get("id") != run_id or run.get("status") != "completed" or run.get("conclusion") != "success"
                or not _matches_run(run, workflow, commit, tag)
                or request_commit not in (None, commit)
            ):
                raise ReleaseError(f"Run {run_id} is not a successful {workflow} run for {tag} on the shared request commit.")
            request_commit = commit
            listing = list(_pages(f"repos/{SIGNING_REPO}/actions/runs/{run_id}/artifacts?per_page=100", "artifacts"))
            for artifact_name, members in expected.items():
                matches = [item for item in listing if item.get("name") == artifact_name]
                if len(matches) != 1:
                    raise ReleaseError(f"Expected exactly one {artifact_name} artifact in run {run_id}.")
                _download_installer(matches[0], members, staging)
                files.update({name: directory / name for name in members})
        for name, destination in files.items():
            if (destination.exists() or destination.is_symlink()) and _fingerprint(destination) != _fingerprint(staging / name):
                raise ReleaseError(f"A different release file already exists at {destination}.")
        for name, destination in files.items():
            try:
                os.link(staging / name, destination)
            except FileExistsError:
                if _fingerprint(destination) != _fingerprint(staging / name):
                    raise ReleaseError(f"A different release file already exists at {destination}.") from None
    return files


def _find_release(tag):
    matches = [row for row in _pages(f"repos/{PUBLIC_REPO}/releases?per_page=100") if row.get("tag_name") == tag]
    if len(matches) > 1:
        raise ReleaseError(f"GitHub has multiple Wardr releases for {tag}.")
    if not matches:
        return None
    release = matches[0]
    _id(release.get("id"), "release")
    if type(release.get("draft")) is not bool or release.get("prerelease") is not True:
        raise ReleaseError(f"GitHub release {tag} must use the existing Wardr Community prerelease status.")
    return release


def _same_release(tag, release_id):
    release = _find_release(tag)
    if release is None or release["id"] != release_id:
        raise ReleaseError(f"The GitHub release for {tag} changed during the operation.")
    return release


def _wait_for_draft(tag):
    for attempt in range(7):
        if attempt:
            sleep(2)
        release = _find_release(tag)
        if release is not None:
            return release
    return None


def _missing_assets(release_id, expected):
    missing = set(expected)
    for asset in _pages(f"repos/{PUBLIC_REPO}/releases/{release_id}/assets?per_page=100"):
        name = asset.get("name")
        if not isinstance(name, str) or name not in missing:
            raise ReleaseError(f"GitHub release {release_id} contains an unexpected or duplicate asset {name!r}.")
        path, size, digest = expected[name]
        if (asset.get("state"), type(asset.get("size")), asset.get("size"), asset.get("digest")) != (
            "uploaded", int, size, digest,
        ):
            raise ReleaseError(f"GitHub asset {name} differs from {path}. The existing asset was preserved.")
        missing.remove(name)
    return missing


def _expected_assets(assets):
    expected = {}
    for path in map(Path, assets):
        name = path.name
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or name in expected:
            raise ReleaseError(f"Invalid or duplicate release asset name {name!r}.")
        size, digest = _fingerprint(path)
        if size < 1:
            raise ReleaseError(f"Release asset {path} is empty.")
        expected[name] = (path, size, digest)
    if not expected:
        raise ReleaseError("Provide the complete set of local Wardr release assets.")
    return expected


def stage_draft(version, assets):
    """Stage missing exact assets on a draft and return whether it remains a draft."""
    tag = f"v{_version(version)}"
    expected = _expected_assets(assets)
    release = _find_release(tag)
    if release is None:
        try:
            _gh("release", "create", tag, "--repo", f"github.com/{PUBLIC_REPO}", "--draft", "--prerelease", "--verify-tag",
                "--title", f"Wardr Community {version}", "--notes", "Download Wardr for your platform below.")
        except ReleaseError:
            release = _wait_for_draft(tag)
            if release is None:
                raise
        else:
            release = _wait_for_draft(tag)
            if release is None:
                raise ReleaseError(f"Could not confirm the new draft GitHub release for {tag}.")

    release_id = release["id"]
    missing = _missing_assets(release_id, expected)
    for name in sorted(missing):
        if name not in _missing_assets(release_id, expected):
            continue
        path, size, digest = expected[name]
        if _fingerprint(path) != (size, digest):
            raise ReleaseError(f"Release asset {path} changed during staging.")
        if not _same_release(tag, release_id)["draft"]:
            raise ReleaseError(f"Published GitHub release {tag} is missing {name}.")
        endpoint = f"https://uploads.github.com/repos/{PUBLIC_REPO}/releases/{release_id}/assets?{urlencode({'name': name})}"
        try:
            _api(endpoint, "--method", "POST", "--header", "Content-Type: application/octet-stream",
                 "--input", str(path.resolve()), timeout=300)
        except ReleaseError:
            if name in _missing_assets(release_id, expected):
                raise

    if _missing_assets(release_id, expected):
        raise ReleaseError(f"GitHub release {tag} does not have the complete set of verified assets.")
    return _same_release(tag, release_id)["draft"]


def promote(version, assets):
    """Reverify every staged asset and publish an exact Wardr draft."""
    tag = f"v{_version(version)}"
    expected = _expected_assets(assets)
    release = _find_release(tag)
    if release is None:
        raise ReleaseError(f"Could not find the staged GitHub release for {tag}.")
    release_id = release["id"]
    if _missing_assets(release_id, expected):
        raise ReleaseError(f"GitHub release {tag} is missing staged assets and cannot be published.")
    release = _same_release(tag, release_id)
    if not release["draft"]:
        return
    try:
        _api(f"repos/{PUBLIC_REPO}/releases/{release_id}", "--method", "PATCH", "--field", "draft=false")
    except ReleaseError:
        if _same_release(tag, release_id)["draft"]:
            raise
    if _same_release(tag, release_id)["draft"]:
        raise ReleaseError(f"Could not verify publication of GitHub release {tag}.")
    if _missing_assets(release_id, expected):
        raise ReleaseError(f"Published GitHub release {tag} is missing verified assets.")
