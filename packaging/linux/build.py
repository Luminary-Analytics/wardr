"""Build a self-extracting Wardr installer for one Linux architecture."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import tarfile
from tempfile import TemporaryDirectory


SOURCE = Path(__file__).resolve().parent
ARCHITECTURES = {"x64": "x86_64", "arm64": "aarch64"}
WARDR_WHEEL = re.compile(r"wardr-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl\Z")


def build(payload: Path, arch: str, output: Path) -> Path:
    wheels = list((payload / "wheelhouse").glob("wardr-*.whl"))
    version = WARDR_WHEEL.fullmatch(wheels[0].name) if len(wheels) == 1 else None
    if not version or not wheels[0].is_file():
        raise ValueError("The wheelhouse must contain one stable Wardr release wheel.")
    if not (payload / "python/bin/python3").is_file() or not (payload / "install.py").is_file():
        raise ValueError("The payload must contain python/bin/python3 and install.py.")

    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"wardr-{version[1]}-linux-{arch}.run"
    with TemporaryDirectory(prefix=".wardr-linux-", dir=output) as directory:
        work = Path(directory)
        archive = work / "payload.tar.gz"
        with tarfile.open(archive, "w:gz", compresslevel=6) as bundle:
            for name in ("python", "wheelhouse", "install.py"):
                bundle.add(payload / name, arcname=name)
            bundle.add(SOURCE / "desktop.py", arcname="desktop.py")
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
    args = parser.parse_args()
    try:
        print(build(args.payload, args.arch, args.output))
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(1, f"Could not build the Linux installer: {exc}\n")
