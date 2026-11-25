"""Build a self-extracting Wardr installer for one Linux architecture."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory


SOURCE = Path(__file__).resolve().parent
REPO_ROOT = SOURCE.parents[1]
ARCHITECTURES = {"x64": "x86_64", "arm64": "aarch64"}
WARDR_WHEEL = re.compile(r"wardr-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl\Z")


def resolve_desktop_binary(desktop_bin: Path | None) -> Path:
    if desktop_bin is not None:
        resolved = desktop_bin.expanduser().resolve()
        if not resolved.is_file():
            raise ValueError(f"Desktop binary not found at {resolved}.")
        return resolved

    prebuilt = REPO_ROOT / "desktop" / "target" / "release" / "wardr-desktop"
    if prebuilt.is_file():
        return prebuilt

    manifest = REPO_ROOT / "desktop" / "Cargo.toml"
    if not manifest.is_file():
        raise ValueError(f"Missing desktop Cargo manifest at {manifest}.")

    env = dict(os.environ)
    cargo_home = Path.home() / ".cargo" / "bin"
    if cargo_home.is_dir():
        env["PATH"] = f"{cargo_home}{os.pathsep}{env.get('PATH', '')}"
    cargo = shutil.which("cargo", path=env.get("PATH"))
    if not cargo:
        raise ValueError("Rust cargo is required to build the native Linux Wardr desktop binary.")
    subprocess.run(
        [cargo, "build", "--release", "--locked", "--manifest-path", str(manifest)],
        check=True,
        env=env,
    )
    if not prebuilt.is_file():
        raise ValueError(f"Expected built desktop binary at {prebuilt}.")
    return prebuilt


def build(payload: Path, arch: str, output: Path, desktop_bin: Path | None = None) -> Path:
    wheels = list((payload / "wheelhouse").glob("wardr-*.whl"))
    version = WARDR_WHEEL.fullmatch(wheels[0].name) if len(wheels) == 1 else None
    if not version or not wheels[0].is_file():
        raise ValueError("The wheelhouse must contain one stable Wardr release wheel.")
    if not (payload / "python/bin/python3").is_file() or not (payload / "install.py").is_file():
        raise ValueError("The payload must contain python/bin/python3 and install.py.")

    binary = resolve_desktop_binary(desktop_bin)

    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"wardr-{version[1]}-linux-{arch}.run"
    with TemporaryDirectory(prefix=".wardr-linux-", dir=output) as directory:
        work = Path(directory)
        archive = work / "payload.tar.gz"
        with tarfile.open(archive, "w:gz", compresslevel=6) as bundle:
            for name in ("python", "wheelhouse", "install.py"):
                bundle.add(payload / name, arcname=name)
            bundle.add(SOURCE / "desktop.py", arcname="desktop.py")
            bundle.add(binary, arcname="wardr-desktop")
        with archive.open("rb") as artifact:
            digest = hashlib.file_digest(artifact, "sha256").hexdigest()
        prefix = (SOURCE / "installer.sh").read_text(encoding="utf-8")
        prefix = prefix.replace("@ARCH@", ARCHITECTURES[arch]).replace("@SHA256@", digest)
        prefix = prefix.replace("@ARCHIVE_LINE@", str(prefix.count("\n") + 1))
        temporary = work / destination.name
        with temporary.open("wb") as installer, archive.open("rb") as artifact:
            installer.write(prefix.encode("utf-8"))
            shutil.copyfileobj(artifact, installer)
        temporary.chmod(0o755)
        temporary.replace(destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--arch", choices=ARCHITECTURES, required=True)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--desktop-bin", type=Path, default=None, help="Optional prebuilt wardr-desktop binary.")
    args = parser.parse_args()
    try:
        print(build(args.payload, args.arch, args.output, desktop_bin=args.desktop_bin))
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Could not build the Linux installer: {exc}\n")
