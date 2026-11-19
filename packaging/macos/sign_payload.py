"""Sign Mach-O code in the staged Python runtime and dependency wheels."""

from base64 import urlsafe_b64encode
from copy import copy
import csv
from hashlib import sha256
from io import StringIO
from pathlib import Path
import shutil
from stat import S_ISLNK, S_IMODE
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile


MACH_O_MAGIC = {
    bytes.fromhex(value)
    for value in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")
}


def mach_o(path):
    if path.is_symlink() or not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(4) in MACH_O_MAGIC


def sign_binary(path, signing, entitlements=None):
    options = ("--entitlements", entitlements) if entitlements else ()
    subprocess.run((*signing, *options, path), check=True)
    subprocess.run(("/usr/bin/codesign", "--verify", "--strict", path), check=True)


def wheel_entries(source):
    entries = source.infolist()
    names = {entry.filename for entry in entries}
    if len(names) != len(entries):
        raise ValueError("A dependency wheel has duplicate archive entries.")
    for entry in entries:
        name = entry.filename
        if (name != entry.orig_filename or "\\" in name or any(
            part in ("", ".", "..") for part in name.rstrip("/").split("/")
        ) or S_ISLNK(entry.external_attr >> 16)):
            raise ValueError("A dependency wheel has an unsafe archive entry.")
    return entries


def update_record(source, record, replacements):
    rows = list(csv.reader(StringIO(source.read(record).decode("utf-8"))))
    if any(len(row) != 3 for row in rows):
        raise ValueError("A dependency wheel has an invalid RECORD.")
    entries = {row[0]: row for row in rows}
    if len(entries) != len(rows) or not replacements.keys() <= entries.keys():
        raise ValueError("A dependency wheel's RECORD does not match its files.")
    for name, replacement in replacements.items():
        digest = urlsafe_b64encode(sha256(replacement.read_bytes()).digest()).rstrip(b"=").decode("ascii")
        entries[name][1:] = [f"sha256={digest}", str(replacement.stat().st_size)]
    result = StringIO(newline="")
    csv.writer(result, lineterminator="\n").writerows(rows)
    return result.getvalue().encode("utf-8")


def sign_wheel(wheel, signing):
    if wheel.is_symlink():
        raise ValueError("Expected a regular dependency wheel.")
    with TemporaryDirectory(prefix=".wardr-wheel-", dir=wheel.parent) as directory:
        work = Path(directory)
        rewritten = work / "signed.whl"
        replacements = {}
        with ZipFile(wheel) as source:
            entries = wheel_entries(source)
            for entry in entries:
                if entry.is_dir():
                    continue
                with source.open(entry) as member:
                    header = member.read(4)
                    if header not in MACH_O_MAGIC:
                        continue
                    # Use a private numbered directory. Archive paths are never extracted.
                    binary = work / str(len(replacements)) / Path(entry.filename).name
                    binary.parent.mkdir()
                    with binary.open("xb") as output:
                        output.write(header)
                        shutil.copyfileobj(member, output)
                sign_binary(binary, signing)
                replacements[entry.filename] = binary
            if not replacements:
                return 0

            records = [entry for entry in entries if entry.filename.endswith(".dist-info/RECORD")]
            if len(records) != 1 or any(entry.filename.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s")) for entry in entries):
                raise ValueError("Expected one unsigned RECORD in a dependency wheel.")
            record = records[0]
            updated_record = update_record(source, record, replacements)
            with ZipFile(rewritten, "w") as target:
                target.comment = source.comment
                for entry in entries:
                    if entry == record:
                        continue
                    replacement = replacements.get(entry.filename)
                    reader = replacement.open("rb") if replacement else source.open(entry)
                    with reader, target.open(copy(entry), "w") as output:
                        shutil.copyfileobj(reader, output)
                target.writestr(copy(record), updated_record)
        rewritten.chmod(S_IMODE(wheel.stat().st_mode))
        rewritten.replace(wheel)
    return len(replacements)


def sign(payload, identity, entitlements):
    runtime = payload / "python"
    python = (runtime / "bin/python3").resolve(strict=True)
    binaries = sorted(path for path in runtime.rglob("*") if mach_o(path))
    if python not in binaries:
        raise ValueError("Expected a Mach-O Python interpreter in the staged runtime.")

    timestamp = "--timestamp=none" if identity == "-" else "--timestamp"
    signing = ("/usr/bin/codesign", "--force", "--sign", identity, timestamp, "--options", "runtime")
    for path in binaries:
        sign_binary(path, signing, entitlements if path == python else None)
    print(f"Verified signatures on {len(binaries)} bundled Python binaries.")
    wheelhouse = payload / "wheelhouse"
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError("Expected a regular wheelhouse directory.")
    for wheel in sorted(wheelhouse.glob("*.whl")):
        # The public signed release manifest authenticates this exact wheel.
        if wheel.name.lower().startswith("wardr-"):
            continue
        count = sign_wheel(wheel, signing)
        if count:
            print(f"Verified signatures on {count} native files in {wheel.name}.")


if __name__ == "__main__":
    payload, identity, entitlements = sys.argv[1:]
    sign(Path(payload).resolve(strict=True), identity, entitlements)
