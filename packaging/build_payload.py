"""Stage a signed Wardr wheel and a pinned Python runtime on the target OS."""

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


HERE = Path(__file__).resolve().parent
SITE = "https://getwardr.com"
RUNTIME_RELEASE = "20261110"
PYTHON_VERSION = "3.13.18"
RUNTIMES = {
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540"),
    ("Darwin", "x86_64"): ("x86_64-apple-darwin", "d27d59a722db9f69926eb6d9564071247221f45a04da920ea7f3001c97e32f9b"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-gnu", "55c00325f7c1fddf325dfc621aabdfbbac4dc54adda224af88ec411dc12db239"),
    ("Linux", "x86_64"): ("x86_64-unknown-linux-gnu", "f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb"),
    ("Windows", "AMD64"): ("x86_64-pc-windows-msvc", "2e0fed09d48989f64c9305da9ff2d37a41c0d13ab2aa6283405b2b620dfbf805"),
}


def fetch(url, maximum):
    with urlopen(url, timeout=90) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError(f"Expected an HTTPS response for {url}")
        contents = response.read(maximum + 1)
    if not contents or len(contents) > maximum:
        raise ValueError(f"Download has unexpected size for {url}")
    return contents


def published_wheel(version, folder):
    name = f"wardr-{version}-py3-none-any.whl"
    manifest = fetch(f"{SITE}/releases/{version}/release.json", 64 * 1024)
    signature = fetch(f"{SITE}/releases/{version}/release.json.sig", 64)
    key = load_pem_public_key((HERE.parent / "wardr/keys/release.pem").read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected Wardr's pinned Ed25519 public key.")
    key.verify(signature, manifest)
    document = json.loads(manifest)
    if (document["version"], document["channel"], document["schema_version"]) != (version, "community", 1):
        raise ValueError("The signed manifest describes a different release.")
    artifact, = [item for item in document["artifacts"] if item["name"] == name]
    expected_path = f"/downloads/{name}"
    if artifact["url"] != expected_path or not 0 < artifact["bytes"] <= 20 * 1024 * 1024:
        raise ValueError("Invalid wheel metadata in signed manifest.")
    wheel = fetch(SITE + expected_path, artifact["bytes"])
    if len(wheel) != artifact["bytes"] or sha256(wheel).hexdigest() != artifact["sha256"]:
        raise ValueError("The Wardr wheel failed signed integrity verification.")
    (folder / name).write_bytes(wheel)
    return folder / name


def runtime(stage):
    target, digest = RUNTIMES[(platform.system(), platform.machine())]
    name = f"cpython-{PYTHON_VERSION}%2B{RUNTIME_RELEASE}-{target}-install_only_stripped.tar.gz"
    url = f"https://github.com/astral-sh/python-build-standalone/releases/download/{RUNTIME_RELEASE}/{name}"
    archive = fetch(url, 64 * 1024 * 1024)
    if sha256(archive).hexdigest() != digest:
        raise ValueError("The Python runtime failed pinned SHA-256 verification.")
    with tarfile.open(fileobj=BytesIO(archive), mode="r:gz") as source:
        source.extractall(stage, filter="data")
    return stage / ("python/python.exe" if os.name == "nt" else "python/bin/python3")


def stage_dependencies(python, wheel, wheelhouse):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("PYTHON", "PIP_"))}
    env["PIP_CONFIG_FILE"] = os.devnull
    pip = [str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check"]
    index = ["--index-url", "https://pypi.org/simple"]
    crypto = "cryptography==50.0.2"
    platform_options = []
    if platform.system() == "Linux":
        platform_options = ["--platform", f"manylinux2014_{platform.machine()}"]
    elif platform.system() == "Darwin" and platform.machine() == "x86_64":
        # PyCA publishes Apple Silicon wheels. Build the Intel wheel with static OpenSSL.
        openssl = subprocess.check_output(["brew", "--prefix", "openssl@3"], text=True, timeout=30).strip()
        subprocess.run(
            [*pip, "wheel", *index, "--wheel-dir", str(wheelhouse), "--no-deps", "--no-binary",
             "cryptography", crypto],
            check=True, env={**env, "OPENSSL_STATIC": "1", "OPENSSL_DIR": openssl,
                             "MACOSX_DEPLOYMENT_TARGET": "13.0"}, timeout=600,
        )
    subprocess.run(
        [*pip, "download", *index, "--only-binary=:all:", *platform_options, "--find-links", str(wheelhouse),
         "--dest", str(wheelhouse), str(wheel), crypto, "cffi==2.0.0", "pycparser==3.12"],
        check=True, env=env, timeout=150,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("Expected a stable major.minor.patch release version.")
    output = args.output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        parser.error("Choose a new output directory.")
    with TemporaryDirectory(prefix="wardr-build-", dir=output.parent) as directory:
        stage = Path(directory) / "payload"
        stage.mkdir()
        wheelhouse = stage / "wheelhouse"
        wheelhouse.mkdir()
        wheel = published_wheel(args.version, wheelhouse)
        stage_dependencies(runtime(stage), wheel, wheelhouse)
        shutil.copyfile(HERE / "install.py", stage / "install.py")
        stage.rename(output)
    print(f"Staged Wardr {args.version} for {platform.system()} {platform.machine()}.")


if __name__ == "__main__":
    main()
