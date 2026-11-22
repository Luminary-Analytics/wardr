"""Run a real Wardr dashboard upgrade inside a disposable environment."""

import argparse
import base64
from contextlib import closing, contextmanager
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID


HOST = "getwardr.com"
LATEST = "/releases/latest.json"
RELEASE_KEY = Path(__file__).resolve().parents[1] / "wardr" / "keys" / "release.pem"
MANIFEST_LIMIT = 64 * 1024
WHEEL_LIMIT = 20 * 1024 * 1024
VERSION = r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}"
SENTINEL = "wardr-upgrade-smoke"
MARKER = b"<!-- Wardr update smoke fixture -->"
LAUNCH = re.compile(r"^Wardr is running at http://127\.0\.0\.1:(\d+)/#access=([A-Za-z0-9_-]{43})$", re.M)
MONITOR_INTERVAL = 47

# The installed CLI and its relaunched process keep their normal entry point.
# Reroute only the release host and load a disposable trust key for this test.
TRANSPORT = '''import os
from pathlib import Path
import socket
import sys

if sys.orig_argv[1:4] == ["-I", "-m", "wardr"] and "WARDR_SMOKE_FEED" in os.environ:
    from wardr import updater

    root = Path(os.environ["WARDR_SMOKE_ROOT"])
    with (root / "dashboard-pids").open("a", encoding="ascii") as pids:
        pids.write(str(os.getpid()) + "\\n")

    resolve = socket.getaddrinfo

    def resolve_release_fixture(host, port, *args, **kwargs):
        if host == "getwardr.com" and port == 443:
            return resolve("127.0.0.1", int(os.environ["WARDR_SMOKE_FEED"]), *args, **kwargs)
        return resolve(host, port, *args, **kwargs)

    socket.getaddrinfo = resolve_release_fixture
    updater._PUBLIC_KEY = root / "fixture-release-key.pem"
'''


def wheel_version(path):
    match = re.fullmatch(r"wardr-((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})-py3-none-any\.whl", path.name)
    if not match:
        raise ValueError("Use a canonical Wardr release wheel.")
    return match.group(1)


def fixture_wheel(baseline, current, target):
    original_info, target_info = f"wardr-{current}.dist-info/", f"wardr-{target}.dist-info/"
    records = []
    output = io.BytesIO()
    with ZipFile(baseline) as original, ZipFile(output, "w", compression=ZIP_DEFLATED) as fixture:
        for original_name in original.namelist():
            entry = original_name.replace(original_info, target_info, 1)
            if entry == target_info + "RECORD":
                continue
            data = original.read(original_name)
            if entry == target_info + "METADATA":
                version = re.search(rb"^Version: ([^\r\n]+)", data, re.M)
                requirement = re.search(rb"^Requires-Python: ([^\r\n]+)", data, re.M)
                assert version and version.group(1).decode() == current, "Baseline metadata does not match its version"
                assert requirement, "Baseline metadata does not declare a Python requirement"
                data = data[:version.start(1)] + target.encode() + data[version.end(1):]
            if entry == "wardr/static/index.html":
                data += b"\n" + MARKER + b"\n"
            fixture.writestr(entry, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            records.append((entry, "sha256=" + digest, len(data)))
        record = io.StringIO()
        csv.writer(record, lineterminator="\n").writerows([*records, (target_info + "RECORD", "", "")])
        fixture.writestr(target_info + "RECORD", record.getvalue())
    return output.getvalue()


def build_signed_feed(root, baseline, candidate=None):
    current = wheel_version(baseline)
    major, minor, patch = map(int, current.split("."))
    if candidate is None:
        target = f"{major}.{minor}.{patch + 1}"
        wheel = fixture_wheel(baseline, current, target)
    else:
        target = wheel_version(candidate)
        if tuple(map(int, target.split("."))) <= (major, minor, patch):
            raise ValueError("The candidate wheel must be newer than the installed release.")
        wheel = candidate.read_bytes()
    name = f"wardr-{target}-py3-none-any.whl"
    with ZipFile(baseline) as original, ZipFile(io.BytesIO(wheel)) as updated:
        metadata = updated.read(f"wardr-{target}.dist-info/METADATA")
        version = re.search(rb"^Version: ([^\r\n]+)", metadata, re.M)
        requirement = re.search(rb"^Requires-Python: ([^\r\n]+)", metadata, re.M)
        assert version and version.group(1).decode() == target and requirement, "Invalid candidate metadata"
        python_floor = requirement.group(1).decode()
        before_html = original.read("wardr/static/index.html")
        after_html = updated.read("wardr/static/index.html")
    signature, download = f"/releases/{target}/release.json.sig", f"/downloads/{name}"
    manifest = json.dumps({
        "schema_version": 1, "channel": "community", "version": target,
        "requires_python": python_floor, "signature": signature,
        "artifacts": [{"name": name, "url": download, "bytes": len(wheel), "sha256": hashlib.sha256(wheel).hexdigest()}],
    }).encode()
    signer = ed25519.Ed25519PrivateKey.generate()
    (root / "fixture-release-key.pem").write_bytes(
        signer.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return current, target, {LATEST: manifest, signature: signer.sign(manifest), download: wheel}, before_html, after_html


def production_download(path, limit):
    with closing(http.client.HTTPSConnection(HOST, timeout=15)) as connection:
        connection.request("GET", path, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"})
        with connection.getresponse() as response:
            if response.status != 200:
                raise RuntimeError(f"Production release returned HTTP {response.status} for {path}")
            data = response.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError(f"Unexpected production download size for {path}")
    return data


def production_wheel_record(path, version, key):
    manifest = production_download(path, MANIFEST_LIMIT)
    signature_path = f"/releases/{version}/release.json.sig"
    try:
        key.verify(production_download(signature_path, 64), manifest)
    except InvalidSignature as error:
        raise ValueError(f"The production manifest at {path} did not authenticate for Wardr {version}") from error
    document = json.loads(manifest)
    if (not isinstance(document, dict) or type(document.get("schema_version")) is not int
            or (document.get("schema_version"), document.get("channel"), document.get("version"),
                document.get("signature")) != (1, "community", version, signature_path)):
        raise ValueError(f"The signed production manifest does not describe Wardr {version}")
    name = f"wardr-{version}-py3-none-any.whl"
    artifact, = [row for row in document["artifacts"] if row["name"] == name]
    if (artifact["url"] != f"/downloads/{name}" or type(artifact["bytes"]) is not int
            or not 0 < artifact["bytes"] <= WHEEL_LIMIT
            or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])):
        raise ValueError(f"The signed production manifest has invalid metadata for {name}")
    return artifact


def verify_wheel_bytes(data, record):
    if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError(f"{record['name']} does not match its signed production manifest")


def release_public_key(pem):
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("The Wardr release key must be Ed25519")
    return key


def production_assets(baseline, target):
    current = wheel_version(baseline)
    if not re.fullmatch(VERSION, target) or tuple(map(int, target.split("."))) <= tuple(map(int, current.split("."))):
        raise ValueError("--live-target must name a stable release newer than the baseline wheel")
    key = release_public_key(RELEASE_KEY.read_bytes())
    published_baseline = production_wheel_record(f"/releases/{current}/release.json", current, key)
    with baseline.open("rb") as handle:
        baseline_data = handle.read(published_baseline["bytes"] + 1)
    verify_wheel_bytes(baseline_data, published_baseline)
    published_target = production_wheel_record(LATEST, target, key)
    target_data = production_download(published_target["url"], published_target["bytes"])
    verify_wheel_bytes(target_data, published_target)
    with ZipFile(io.BytesIO(baseline_data)) as original, ZipFile(io.BytesIO(target_data)) as updated:
        for wheel in (original, updated):
            bundled = release_public_key(wheel.read("wardr/keys/release.pem"))
            if bundled.public_bytes_raw() != key.public_bytes_raw():
                raise ValueError("The production wheels do not carry the same pinned Wardr release key")
        before_html = original.read("wardr/static/index.html")
        after_html = updated.read("wardr/static/index.html")
    return current, before_html, after_html, published_target["sha256"]


def require_live_installation(python, current):
    result = subprocess.check_output([str(python), "-I", "-c", """
import importlib.util
import json
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from wardr import updater

key = load_pem_public_key(updater._PUBLIC_KEY.read_bytes())
print(json.dumps([updater.current_version(), updater.installation_problem(),
                  importlib.util.find_spec('sitecustomize') is not None,
                  updater.RELEASE_HOST, key.public_bytes_raw().hex()]))
"""], text=True, timeout=15)
    version, problem, customized, host, installed_key = json.loads(result)
    if version != current or problem or customized or host != HOST:
        raise ValueError("Live smoke requires the official baseline in a fresh, updatable environment without sitecustomize")
    expected_key = release_public_key(RELEASE_KEY.read_bytes()).public_bytes_raw().hex()
    if installed_key != expected_key:
        raise ValueError("The installed runtime does not have the official pinned release key")


def secure_fixture(root, server, server_names):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert, private = root / "fixture-tls-cert.pem", root / "fixture-tls-key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, private)
    context.set_servername_callback(lambda _socket, name, _context: server_names.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    private.unlink()
    return cert


def launch_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def exchange_launch_token(port, token):
    """Exchange a single-use v0.4.0+ launch nonce for a session token, or keep legacy tokens as-is."""
    code, payload = request(port, token, "/api/auth/exchange", {"nonce": token})
    if code == 200 and isinstance(payload, dict) and isinstance(payload.get("token"), str) and payload["token"]:
        return payload["token"]
    return token


def launch_link(log, count, process):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        matches = LAUNCH.findall(log.read_text(encoding="utf-8", errors="replace"))
        if len(matches) >= count:
            port, token = matches[count - 1]
            port_num = int(port)
            return port_num, exchange_launch_token(port_num, token)
        if (count == 1 or os.name != "nt") and process.poll() is not None:
            raise RuntimeError(f"Dashboard exited with code {process.returncode} before launch {count}")
        time.sleep(0.1)
    raise RuntimeError(f"Dashboard did not announce launch {count}")


def request(port, token, path, body=None):
    headers = {"X-Wardr-Token": token}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET" if body is None else "POST", path, json.dumps(body) if body is not None else None, headers)
        with connection.getresponse() as response:
            data = response.read()
            return response.status, json.loads(data) if response.headers.get_content_type() == "application/json" else data
    finally:
        connection.close()


def await_update_state(port, token, expected, *, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, status = request(port, token, "/api/update")
        assert code == 200, "Could not read local update status"
        if status["state"] == expected:
            return status
        if status["state"] == "error":
            raise RuntimeError(status["message"])
        time.sleep(0.1)
    raise RuntimeError(f"Update did not reach {expected}")


def seed_state(directory):
    directory.mkdir(mode=0o700)
    timestamp = "2026-01-01T00:00:00+00:00"
    payloads = {
        "software-assessment.json": {"summary": {}, "inventory": {"name": SENTINEL}, "advisories": {}, "findings": []},
        "cisa-kev.json": {
            "refreshed_at": timestamp, "released_at": timestamp, "catalog_version": SENTINEL,
            "count": 0, "exploited_ids": [], "advisories": [],
        },
        "exported-report.json": {"host": SENTINEL, "checks": [], "summary": {"passed": 0}},
    }
    for name, payload in payloads.items():
        path = directory / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
    event = {
        "id": SENTINEL, "at": datetime.now(timezone.utc).isoformat(), "severity": "low",
        "title": "Existing test event", "detail": "Seeded before update.", "source": "Smoke test",
    }
    history = directory / "monitor-events.sqlite3"
    with closing(sqlite3.connect(history)) as database, database:
        database.execute("CREATE TABLE events (id TEXT PRIMARY KEY, at TEXT NOT NULL, payload TEXT NOT NULL)")
        database.execute("INSERT INTO events VALUES (?, ?, ?)", (event["id"], event["at"], json.dumps(event)))
    return {directory / name: (directory / name).read_bytes() for name in payloads}, history, event


def install_baseline(root, baseline):
    venv = root / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=90)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-I", "-m", "pip", "--disable-pip-version-check", "install", str(baseline)],
        check=True, timeout=120,
    )
    return python


@contextmanager
def fixture_transport(python):
    if not python.is_absolute() or not python.is_file():
        raise ValueError("Provide the absolute Python path of a disposable Wardr virtual environment")
    prefix, base_prefix, purelib = json.loads(subprocess.check_output(
        [str(python), "-I", "-c", "import json, sys, sysconfig; print(json.dumps("
         "[sys.prefix, sys.base_prefix, sysconfig.get_path('purelib')]))"],
        text=True, timeout=15,
    ))
    if prefix == base_prefix or not Path(purelib).resolve().is_relative_to(Path(prefix).resolve()):
        raise ValueError("The smoke test requires Python inside an isolated virtual environment")
    shim = Path(purelib) / "sitecustomize.py"
    if shim.is_symlink() or (shim.exists() and shim.stat().st_size):
        raise ValueError("The test environment already has a nonempty sitecustomize.py")
    cache = shim.parent / "__pycache__"
    existing_cache = {path: path.read_bytes() for path in cache.glob("sitecustomize.*.pyc")}
    existed = shim.exists()
    try:
        shim.write_text(TRANSPORT, encoding="utf-8")
        yield
    finally:
        if existed:
            shim.write_bytes(b"")
        else:
            shim.unlink(missing_ok=True)
        for path in cache.glob("sitecustomize.*.pyc"):
            if path not in existing_cache:
                path.unlink()
        for path, contents in existing_cache.items():
            path.write_bytes(contents)


def stop_dashboard(process, root):
    if os.name == "nt":
        pid_log = root / "dashboard-pids"
        if pid_log.exists():
            for pid in set(pid_log.read_text(encoding="ascii").splitlines()):
                if pid.isdecimal() and int(pid) != process.pid:
                    subprocess.run(["taskkill", "/T", "/F", "/PID", pid], capture_output=True, timeout=10)
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def stop_windows_live_dashboard(state):
    # After restart the first process has exited. Match the exact disposable
    # command line so cleanup cannot touch a regular user's Wardr dashboard.
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", r"""
$ErrorActionPreference = 'Stop'
$state = [regex]::Escape($env:WARDR_SMOKE_STATE)
$pattern = '(?:^|\s)-I\s+-m\s+wardr\s+--state-dir\s+(?:"' + $state + '"|' + $state + ')(?=\s|$)'
function Find-SmokeDashboard {
    Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
        Where-Object { $_.CommandLine -match $pattern }
}
for ($attempt = 0; $attempt -lt 4; $attempt++) {
    $owned = @(Find-SmokeDashboard)
    if (!$owned.Count) { exit 0 }
    foreach ($process in $owned) {
        try {
            & "$env:SystemRoot\System32\taskkill.exe" /T /F /PID $process.ProcessId 2>&1 | Out-Null
        } catch {
            # A process can exit after enumeration. Confirm via the next query.
        }
    }
    Start-Sleep -Milliseconds 250
}
if (Find-SmokeDashboard) { throw 'The disposable Wardr dashboard did not stop.' }
"""], env={**os.environ, "WARDR_SMOKE_STATE": str(state)}, capture_output=True, check=True, timeout=20)


def upgrade(root, python, current, target, before_html, after_html, *, environment=None, live=False):
    state = root / "device-state"
    saved, history, event = seed_state(state)
    port = launch_port()
    log, errors = root / "dashboard.log", root / "dashboard-errors.log"
    command = [
        str(python), "-I", "-m", "wardr", "--state-dir", str(state), "serve", "--port", str(port),
        "--interval", str(MONITOR_INTERVAL), "--no-browser",
    ]
    with log.open("wb") as output, errors.open("wb") as error_output:
        process = subprocess.Popen(command, cwd=root.parent, env=environment, stdout=output, stderr=error_output)
        try:
            old_port, token = launch_link(log, 1, process)
            assert old_port == port, "Dashboard ignored the selected port"
            status = await_update_state(port, token, "idle")
            assert status["current_version"] == current and status["can_check"], "Baseline cannot update"
            assert request(port, token, "/")[1] == before_html, "Baseline dashboard differs from its wheel"
            assert request(port, token, "/api/update/check", {})[0] == 202, "Update check failed"
            assert await_update_state(port, token, "available")["available_version"] == target, "Signed update was not offered"
            assert request(port, token, "/api/update/install", {"version": target})[0] == 202, "Install was refused"
            status = await_update_state(port, token, "installed", timeout=240 if live else 60)
            assert (status["current_version"], status["installed_version"]) == (current, target), "Unexpected install result"
            assert request(port, token, "/")[1] == before_html, "Dashboard switched assets before restart"
            assert request(port, token, "/api/update/restart", {})[0] == 202, "Restart was refused"

            new_port, new_token = launch_link(log, 2, process)
            assert new_port == port, "Restart lost the selected port"
            assert new_token != token, "Restart reused the original token"
            assert request(port, token, "/api/update")[0] == 403, "The old token still grants access"
            assert await_update_state(port, new_token, "idle")["current_version"] == target, "Dashboard did not restart into the new wheel"
            assert request(port, new_token, "/")[1] == after_html, "Restarted dashboard differs from the candidate wheel"
            if live:
                assert request(port, new_token, "/api/update/check", {})[0] == 202, "Post-restart live check failed"
                await_update_state(port, new_token, "current")
            _, defense = request(port, new_token, "/api/defense")
            assert defense["software"]["result"]["inventory"]["name"] == SENTINEL, "Saved software assessment was not loaded"
            _, status = request(port, new_token, "/api/status")
            assert status["intel"]["catalog_version"] == SENTINEL, "Saved advisory catalog was not loaded"
            assert status["monitoring"]["interval"] == MONITOR_INTERVAL, "Restart lost the selected monitoring interval"
            assert event in status["monitoring"]["events"], "Persisted event was not loaded"
            assert all(path.read_bytes() == data for path, data in saved.items()), "Update changed saved state"
            with closing(sqlite3.connect(history, timeout=5)) as database:
                row = database.execute("SELECT payload FROM events WHERE id = ?", (event["id"],)).fetchone()
            assert row and json.loads(row[0]) == event, "Persisted event changed or was removed"
        except Exception:
            diagnostics = errors.read_text(encoding="utf-8", errors="replace")
            diagnostics = re.sub(r"#access=[^\s]+", "#access=<redacted>", diagnostics)
            for _, secret in LAUNCH.findall(log.read_text(encoding="utf-8", errors="replace")):
                diagnostics = diagnostics.replace(secret, "<redacted>")
            if diagnostics.strip():
                print("Dashboard stderr:\n" + diagnostics.strip()[-4000:], file=sys.stderr)
            raise
        finally:
            try:
                stop_dashboard(process, root)
            finally:
                if live and os.name == "nt":
                    stop_windows_live_dashboard(state)


@contextmanager
def disposable_directory():
    directory = tempfile.TemporaryDirectory(prefix="wardr-update-smoke-")
    try:
        yield Path(directory.name).resolve()
    finally:
        deadline = time.monotonic() + 15
        while True:
            try:
                directory.cleanup()
                break
            except OSError as error:
                # Windows may briefly retain handles after the relaunched process stops.
                if getattr(error, "winerror", None) not in (5, 32) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)


def smoke(baseline, installed_python=None, candidate=None):
    with disposable_directory() as root:
        python = installed_python or install_baseline(root, baseline)
        current, target, feed, before_html, after_html = build_signed_feed(root, baseline, candidate)
        fetched, server_names = [], []

        class FeedHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                fetched.append((self.path, self.headers.get("Host")))
                payload = feed.get(self.path)
                if payload is None or self.headers.get("Host") != HOST:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        with ThreadingHTTPServer(("127.0.0.1", 0), FeedHandler) as server:
            cert = secure_fixture(root, server, server_names)
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            worker.start()
            try:
                with fixture_transport(python):
                    environment = {**os.environ, "SSL_CERT_FILE": str(cert), "WARDR_SMOKE_FEED": str(server.server_port),
                                   "WARDR_SMOKE_ROOT": str(root)}
                    upgrade(root, python, current, target, before_html, after_html, environment=environment)
            finally:
                server.shutdown()
                worker.join()
        manifest, signature, wheel = feed
        assert fetched == [(path, HOST) for path in (manifest, signature, manifest, signature, wheel)], "Unexpected HTTPS release requests"
        assert server_names == [HOST] * 5, "The release requests did not use the expected TLS server name"
        print(f"Verified Wardr {current} to {target} in-place update and restart with preserved local state.")


def live_smoke(baseline, target, installed_python):
    if any(os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "WARDR_SMOKE_FEED", "WARDR_SMOKE_ROOT")):
        raise ValueError("Live smoke requires the default TLS trust and production release transport")
    current, before_html, after_html, digest = production_assets(baseline, target)
    with disposable_directory() as root:
        python = installed_python or install_baseline(root, baseline)
        if not python.is_absolute() or not python.is_file():
            raise ValueError("Provide the absolute Python path of a disposable Wardr virtual environment")
        require_live_installation(python, current)
        upgrade(root, python, current, target, before_html, after_html, live=True)
        installed = subprocess.check_output(
            [str(python), "-I", "-c", "from importlib.metadata import version; print(version('wardr'))"],
            text=True, timeout=15,
        ).strip()
        assert installed == target, "The installed package metadata did not advance to the production version"
    print(f"Verified live Wardr {current} to {target} through https://{HOST} with preserved local state.")
    print(f"Production wheel SHA-256: {digest}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", metavar="WHEEL", nargs="+", type=Path)
    parser.add_argument("--installed-python", type=Path, help="Python in a disposable environment already provisioned from WHEEL")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--candidate", type=Path, help="Exercise an update to these exact newer wheel bytes")
    mode.add_argument("--live-target", help="Exercise the signed production update into this version")
    arguments = parser.parse_args()
    if (arguments.installed_python or arguments.candidate or arguments.live_target is not None) and len(arguments.wheels) != 1:
        parser.error("--installed-python, --candidate, and --live-target each require exactly one baseline wheel")
    # Exception context and captured dashboard output can include launch tokens.
    try:
        for wheel in arguments.wheels:
            if arguments.live_target is not None:
                live_smoke(wheel.resolve(), arguments.live_target, arguments.installed_python)
            else:
                smoke(wheel.resolve(), arguments.installed_python, arguments.candidate)
    except Exception as error:
        raise SystemExit(f"{type(error).__name__}: {error}") from None
