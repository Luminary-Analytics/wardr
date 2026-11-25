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
    install_root = interpreter.parents[2] if len(interpreter.parents) >= 3 else interpreter.parent
    desktop_bin = install_root / "wardr-desktop"
    native_app = desktop_bin.is_file()
    target = desktop_bin if native_app else interpreter
    if {"%", "="}.intersection(str(target)):
        raise ValueError("The installation path uses characters reserved by desktop launchers.")
    executable = str(target).translate(str.maketrans({char: f"\\{char}" for char in '\\"`$'}))
    icon = files("wardr").joinpath("static", "wardr-mark.png")
    exec_line = (
        f'Exec="{desktop_value(executable)}"\n'
        if native_app
        else f'Exec="{desktop_value(executable)}" -I -m wardr\n'
    )
    terminal_line = "Terminal=false\n" if native_app else "Terminal=true\n"
    wm_class_line = "StartupWMClass=wardr-desktop\n" if native_app else ""
    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Wardr\n"
        "Comment=Review device security and verify fixes\n"
        f"{exec_line}"
        f"Icon={desktop_value(str(icon))}\n"
        f"{terminal_line}"
        f"{wm_class_line}"
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
