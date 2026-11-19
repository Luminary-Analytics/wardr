"""Register a per-user Wardr launcher and desktop menu entry on Linux."""

from importlib.resources import files
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile


DESKTOP_ID = "com.getwardr.Wardr"


def desktop_value(value: str) -> str:
    return value.translate(str.maketrans({"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}))


def write_desktop(data_home: Path, interpreter: Path) -> None:
    if {"%", "="}.intersection(str(interpreter)):
        raise ValueError("The installation path uses characters reserved by desktop launchers.")
    executable = str(interpreter).translate(str.maketrans({char: f"\\{char}" for char in '\\"`$'}))
    icon = files("wardr").joinpath("static", "wardr-mark.png")
    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Wardr\n"
        "Comment=Review device security and verify fixes\n"
        f'Exec="{desktop_value(executable)}" -I -m wardr\n'
        f"Icon={desktop_value(str(icon))}\n"
        "Terminal=true\n"
        "Categories=System;Security;\n"
    )
    applications = data_home / "applications"
    applications.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=applications, mode="w", encoding="utf-8", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(entry)
        temporary.replace(applications / f"{DESKTOP_ID}.desktop")
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def add_command_shortcut(launcher: Path, command: Path) -> None:
    launcher.parent.mkdir(parents=True, exist_ok=True)
    try:
        launcher.symlink_to(command)
    except FileExistsError:
        if not launcher.is_symlink() or launcher.readlink() != command:
            print(f"Kept the existing launcher at {launcher}.")
            return
    print(f"Wardr launcher is available at {launcher}")


def integrate(no_desktop: bool) -> None:
    interpreter = Path(sys.executable)
    command = interpreter.with_name("wardr")
    home = Path.home()
    print(f"Launch Wardr with {command}")
    try:
        add_command_shortcut(home / ".local/bin/wardr", command)
    except OSError as exc:
        print(f"Could not add the command shortcut: {exc}", file=sys.stderr)
    if not no_desktop:
        configured = Path(os.environ.get("XDG_DATA_HOME", ""))
        data_home = configured if configured.is_absolute() else home / ".local/share"
        try:
            write_desktop(data_home, interpreter)
            print("Wardr was added to the desktop applications menu.")
        except (OSError, ValueError) as exc:
            print(f"Could not add the application menu entry: {exc}", file=sys.stderr)


if __name__ == "__main__":
    integrate("--no-desktop" in sys.argv[1:])
