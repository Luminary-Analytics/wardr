"""Install an offline native payload without opening Wardr's state directory."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


MARKER = b"Luminary Analytics Wardr native installer v1\n"
WHEEL = re.compile(r"wardr-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl")
WINDOWS = os.name == "nt"


def interpreter(directory, *, venv=False):
    if WINDOWS:
        return directory / ("Scripts/python.exe" if venv else "python.exe")
    return directory / "bin/python3"


def run(python, *args):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("PYTHON", "PIP_"))}
    env["PIP_CONFIG_FILE"] = os.devnull
    return subprocess.run(
        [str(python), "-I", *map(str, args)], check=True, text=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, timeout=180,
    ).stdout


def linked(path):
    return path.is_symlink() or (WINDOWS and path.is_junction())


@contextmanager
def locked(path):
    if linked(path):
        raise ValueError(f"Invalid installation lock {path}")
    with path.open("a+b") as handle:
        if WINDOWS:
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError("The installed version needs to be updated through its original package manager.")
    return tuple(map(int, value.split(".")))


def installed_version(python):
    return json.loads(run(python, "-c", """
import json
from importlib.metadata import PackageNotFoundError, version
try:
    installed = version("wardr")
except PackageNotFoundError:
    installed = None
print(json.dumps(installed))
"""))


def install(payload, root):
    wheelhouse = payload / "wheelhouse"
    wheels = [(path, WHEEL.fullmatch(path.name)) for path in wheelhouse.glob("wardr-*.whl")]
    if len(wheels) != 1 or not wheels[0][1]:
        raise ValueError("The installer must include exactly one Wardr release wheel.")
    wheel, release = wheels[0]
    version = release.group(1)
    if linked(root):
        raise ValueError("Choose a regular installation directory.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime, venv = root / "python", root / "venv"
    marker = root / ".wardr-native-install"
    with locked(root / ".wardr-native-install.lock"):
        if any(linked(path) for path in (marker, runtime, venv)):
            raise ValueError("The installation directory contains an unexpected link.")
        if marker.exists():
            if not marker.is_file() or marker.read_bytes() != MARKER:
                raise ValueError("Choose the existing Wardr installation directory or an empty folder.")
        elif runtime.exists() or venv.exists():
            raise ValueError("This folder already contains a Python environment. Choose a different folder.")
        else:
            marker.write_bytes(MARKER)
        if not runtime.exists():
            with TemporaryDirectory(prefix=".wardr-runtime-", dir=root) as directory:
                runtime_copy = Path(directory) / "python"
                shutil.copytree(payload / "python", runtime_copy, symlinks=True)
                run(interpreter(runtime_copy), "-c", "import ensurepip")
                runtime_copy.rename(runtime)
        python = interpreter(venv, venv=True)
        if not venv.exists():
            try:
                run(interpreter(runtime), "-m", "venv", venv)
            except (OSError, subprocess.SubprocessError):
                if venv.exists():
                    shutil.rmtree(venv)
                raise
        with locked(venv / ".wardr-update.lock"):
            current = installed_version(python)
            if current is None or version_tuple(current) < version_tuple(version):
                run(python, "-m", "pip", "--isolated", "--require-virtualenv",
                    "--disable-pip-version-check", "--no-input", "install", "--no-index",
                    "--only-binary=:all:", "--no-compile", "--find-links", wheelhouse, wheel)
                if installed_version(python) != version:
                    raise ValueError("Wardr could not confirm the installed release.")
    print("Wardr is ready.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        install(Path(__file__).resolve().parent, args.install_dir.expanduser().absolute())
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f"Wardr setup could not complete. Close Wardr and try again.\n{exc.stdout or ''}")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Wardr setup could not complete. {exc}\n")


if __name__ == "__main__":
    main()
