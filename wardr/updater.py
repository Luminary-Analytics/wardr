"""Check and install authentic Community releases in the current environment."""

import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from importlib import metadata
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from . import release


RELEASE_HOST = "getwardr.com"
_MANIFEST_PATH = "/releases/latest.json"
_PUBLIC_KEY = Path(__file__).with_name("keys") / "release.pem"
_MANIFEST_LIMIT = 64 * 1024
_WHEEL_LIMIT = 20 * 1024 * 1024
_IO_TIMEOUT = 8
_DOWNLOAD_TIMEOUT = 45
_INSTALL_TIMEOUT = 150
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")
_PYTHON_FLOOR = re.compile(r">=\s*([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class UpdaterError(RuntimeError):
    """An update cannot be checked or completed safely."""


@dataclass(frozen=True)
class ReleaseUpdate:
    version: str
    wheel_url: str
    sha256: str
    size: int


def current_version() -> str:
    """Return the version installed on disk, or identify an unpackaged checkout."""
    try:
        return metadata.version("wardr")
    except metadata.PackageNotFoundError:
        return "development"


def _version_key(version):
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if not match:
        raise UpdaterError("Wardr updates require a version in major.minor.patch format.")
    return tuple(int(component) for component in match.groups())


def _uv_executable():
    executable = shutil.which("uv.exe" if sys.platform == "win32" else "uv")
    if executable:
        candidate = Path(executable)
        try:
            if candidate.is_absolute() and candidate.is_file():
                resolved = candidate.resolve(strict=True)
                if sys.platform == "win32":
                    if resolved.suffix.lower() == ".exe":
                        return str(resolved)
                else:
                    st_bin = resolved.stat()
                    st_dir = resolved.parent.stat()
                    trusted_uids = {0, os.geteuid()}
                    if (
                        st_bin.st_uid in trusted_uids
                        and st_dir.st_uid in trusted_uids
                        and (st_bin.st_mode & 0o022) == 0
                        and (st_dir.st_mode & 0o022) == 0
                    ):
                        return str(resolved)
        except OSError:
            pass
    return None


def _installer():
    if importlib.util.find_spec("pip") is not None:
        return (
            sys.executable, "-I", "-m", "pip", "--isolated", "--require-virtualenv",
            "--disable-pip-version-check", "--no-input", "install",
            "--no-index", "--no-deps", "--no-compile",
        )
    uv = _uv_executable()
    if uv:
        return (
            uv, "--no-config", "--offline", "--no-progress", "pip", "install",
            "--python", sys.executable, "--no-index", "--no-deps",
        )
    return None


def installation_problem() -> str | None:
    """Explain why this copy cannot be upgraded in place, if applicable."""
    if sys.prefix == sys.base_prefix or not Path(sys.executable).is_absolute():
        return "In-place updates require Wardr installed with pipx or in a virtual environment."
    try:
        distribution = metadata.distribution("wardr")
        package = Path(__file__).resolve().parent
        installed = Path(distribution.locate_file("wardr/__init__.py")).resolve()
        if (
            not package.is_relative_to(Path(sys.prefix).resolve())
            or installed != package / "__init__.py"
        ):
            return "This Wardr copy runs from source. Install a release into an isolated environment to use updates."
        _version_key(distribution.version)
    except (OSError, metadata.PackageNotFoundError, UpdaterError):
        return "This Wardr installation could not be identified. Install an official Wardr release with pipx."
    if _installer() is None:
        return "Wardr needs pip in its environment or uv on PATH to update in place."
    return None


def _require_installation():
    if problem := installation_problem():
        raise UpdaterError(problem)


def _fetch(path, limit):
    data = bytearray()
    deadline = time.monotonic() + _DOWNLOAD_TIMEOUT
    try:
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(RELEASE_HOST, timeout=_IO_TIMEOUT, context=context)
        with closing(connection):
            connection.request("GET", path, headers={
                "User-Agent": "Wardr Updater",
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache",
            })
            with connection.getresponse() as response:
                if response.status != 200:
                    raise UpdaterError(f"The Wardr release server returned HTTP {response.status}.")
                content_length = response.getheader("Content-Length")
                if content_length is not None and (
                    not content_length.isascii() or not content_length.isdecimal()
                    or len(content_length) > 9 or int(content_length) > limit
                ):
                    raise UpdaterError("The Wardr release download exceeds the allowed size.")
                while time.monotonic() < deadline:
                    block = response.read1(min(64 * 1024, limit + 1 - len(data)))
                    if not block:
                        return bytes(data)
                    data.extend(block)
                    if len(data) > limit:
                        raise UpdaterError("The Wardr release download exceeds the allowed size.")
    except (OSError, http.client.HTTPException) as exc:
        raise UpdaterError("Could not reach the Wardr release service over HTTPS.") from exc
    raise UpdaterError("The Wardr release download timed out.")


def _manifest():
    raw = _fetch(_MANIFEST_PATH, _MANIFEST_LIMIT)
    try:
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("Expected a manifest object")
        version = document.get("version")
        _version_key(version)
    except (RecursionError, UnicodeError, ValueError, UpdaterError) as exc:
        raise UpdaterError("The Wardr release manifest is invalid.") from exc

    # A validated version selects a fixed detached-signature path. No manifest
    # link, digest, or other installation data is used before authentication.
    signature_path = f"/releases/{version}/release.json.sig"
    if document.get("signature") != signature_path:
        raise UpdaterError("The current Wardr release does not include a signed update manifest.")
    signature = _fetch(signature_path, 64)
    try:
        with _PUBLIC_KEY.open("rb") as handle:
            key = handle.read(2049)
        release.verify_manifest_signature(raw, signature, key)
    except (OSError, release.ReleaseError) as exc:
        raise UpdaterError("The release manifest could not be verified with Wardr’s trusted key.") from exc
    schema = document.get("schema_version")
    if type(schema) is not int or schema != 1 or document.get("channel") != "community":
        raise UpdaterError("This Wardr release uses an unsupported manifest format.")
    return document


def _check_python(requirement):
    match = _PYTHON_FLOOR.fullmatch(requirement) if isinstance(requirement, str) else None
    if not match:
        raise UpdaterError("This release declares a Python requirement that needs manual installation.")
    minimum = tuple(int(component or 0) for component in match.groups())
    if sys.version_info[:3] < minimum:
        raise UpdaterError(f"This release requires Python {requirement[2:].strip()}.")


def _candidate(document):
    version = document["version"]
    _check_python(document.get("requires_python"))
    name = _wheel_name(version)
    path = f"/downloads/{name}"
    artifacts = document.get("artifacts")
    matches = [
        row for row in artifacts if isinstance(row, dict) and row.get("name") == name
    ] if isinstance(artifacts, list) else []
    if len(matches) != 1:
        raise UpdaterError("The signed release must identify one Wardr wheel.")
    wheel = matches[0]
    size, digest = wheel.get("bytes"), wheel.get("sha256")
    if (
        wheel.get("url") != path or type(size) is not int or not 0 < size <= _WHEEL_LIMIT
        or not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
    ):
        raise UpdaterError("The signed release has invalid Wardr wheel information.")
    return ReleaseUpdate(version, path, digest, size)


def _wheel_name(version):
    return f"wardr-{version}-py3-none-any.whl"


def check_for_update() -> ReleaseUpdate | None:
    """Authenticate the published manifest and return a strictly newer release."""
    _require_installation()
    now = _version_key(current_version())
    document = _manifest()
    if _version_key(document["version"]) <= now:
        return None
    return _candidate(document)


def _verify_wheel_metadata(path, version, requires_python):
    try:
        with ZipFile(path) as archive:
            name = f"wardr-{version}.dist-info/METADATA"
            records = [item for item in archive.infolist() if item.filename == name]
            if len(records) != 1 or not 0 < records[0].file_size <= _MANIFEST_LIMIT:
                raise ValueError("Invalid metadata archive entry")
            with archive.open(records[0]) as handle:
                raw = handle.read(_MANIFEST_LIMIT + 1)
            if not 0 < len(raw) <= _MANIFEST_LIMIT:
                raise ValueError("Invalid metadata size")
        details = BytesParser(policy=email_policy).parsebytes(raw, headersonly=True)
        if (
            [name.lower() for name in details.get_all("Name", [])] != ["wardr"]
            or details.get_all("Version", []) != [version]
            or details.get_all("Requires-Python", []) != [requires_python]
        ):
            raise ValueError("Invalid wheel metadata")
    except (BadZipFile, EOFError, OSError, RuntimeError, ValueError) as exc:
        raise UpdaterError("The signed wheel’s package metadata does not match the expected release.") from exc
    try:
        installed = metadata.distribution("wardr").requires or []
    except metadata.PackageNotFoundError as exc:
        raise UpdaterError("The installed Wardr package could not be found. Check the installation and try again.") from exc
    if sorted(details.get_all("Requires-Dist", [])) != sorted(installed):
        raise UpdaterError("This release changes dependencies. Install the signed release manually to apply it.")


def _install_wheel(path, version):
    command = _installer()
    if command is None:
        raise UpdaterError("Wardr needs pip in its environment or uv on PATH to update in place.")
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("PIP_", "PYTHON", "UV_"))
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    try:
        attempt = subprocess.run(
            (*command, str(path)), cwd=path.parent, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_INSTALL_TIMEOUT, check=False,
        )
        if attempt.returncode:
            raise UpdaterError("The installer could not finish the update. Use your package manager to repair this environment.")
        checked = subprocess.run(
            (sys.executable, "-I", "-c", "from importlib.metadata import version; print(version('wardr'))"),
            cwd=path.parent, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=_IO_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdaterError("The update could not be completed. Use your package manager to check this environment.") from exc
    if checked.returncode or checked.stdout.strip() != version.encode("ascii"):
        raise UpdaterError("Wardr could not confirm the newly installed version. Check the installation before restarting.")


def install_update(update: ReleaseUpdate) -> str:
    """Recheck the selected signed release and install its exact verified wheel."""
    _require_installation()
    now = _version_key(current_version())
    document = _manifest()
    candidate = _candidate(document)
    if update != candidate or _version_key(candidate.version) <= now:
        raise UpdaterError("The selected update is no longer available. Check for updates again.")
    payload = _fetch(candidate.wheel_url, candidate.size)
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) != candidate.size or not hmac.compare_digest(digest, candidate.sha256):
        raise UpdaterError("The Wardr wheel does not match the signed release manifest.")
    try:
        with tempfile.TemporaryDirectory(prefix="wardr-update-") as directory:
            wheel = Path(directory) / _wheel_name(candidate.version)
            with wheel.open("xb") as handle:
                handle.write(payload)
            _verify_wheel_metadata(wheel, candidate.version, document["requires_python"])
            _install_wheel(wheel, candidate.version)
    except OSError as exc:
        raise UpdaterError("The update could not be completed in its temporary directory.") from exc
    return candidate.version
