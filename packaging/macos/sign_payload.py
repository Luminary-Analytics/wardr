"""Sign the Mach-O code in the staged standalone Python runtime."""

from pathlib import Path
import subprocess
import sys


MACH_O_MAGIC = {
    bytes.fromhex(value)
    for value in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")
}


def mach_o(path):
    if path.is_symlink() or not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(4) in MACH_O_MAGIC


def sign(runtime, identity, entitlements):
    python = (runtime / "bin/python3").resolve(strict=True)
    binaries = sorted(path for path in runtime.rglob("*") if mach_o(path))
    if python not in binaries:
        raise ValueError("Expected a Mach-O Python interpreter in the staged runtime.")

    timestamp = "--timestamp=none" if identity == "-" else "--timestamp"
    signing = ("/usr/bin/codesign", "--force", "--sign", identity, timestamp, "--options", "runtime")
    for path in binaries:
        if path == python:
            subprocess.run((*signing, "--entitlements", entitlements, path), check=True)
        else:
            subprocess.run((*signing, path), check=True)
        subprocess.run(("/usr/bin/codesign", "--verify", "--strict", path), check=True)
    print(f"Verified signatures on {len(binaries)} bundled Python binaries.")


if __name__ == "__main__":
    payload, identity, entitlements = sys.argv[1:]
    sign(Path(payload).resolve(strict=True), identity, entitlements)
