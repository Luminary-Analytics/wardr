"""Tests for native desktop shell integration across Windows, macOS, and Linux packaging."""

from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import patch

from wardr import cli
from wardr.server import RESTART_DASHBOARD


REPO_ROOT = Path(__file__).resolve().parents[1]


class DesktopShellIntegrationTests(unittest.TestCase):
    def test_serve_dashboard_returns_restart_exit_code_under_desktop_shell(self):
        args = types.SimpleNamespace(command="serve", port=0, no_browser=True, interval=30, auto_advisories=False, offline=True)
        with (
            TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"WARDR_DESKTOP_SHELL": "1"}, clear=False),
            patch.object(cli, "serve", return_value=RESTART_DASHBOARD),
            patch.object(cli, "_relaunch_dashboard", side_effect=AssertionError("should not exec/relaunch directly")) as relaunch,
        ):
            code = cli._serve_dashboard(Path(tmp), args, ["serve", "--no-browser"], windows_launcher=False)
        self.assertEqual(code, cli.DESKTOP_RESTART_EXIT_CODE)
        relaunch.assert_not_called()

    def test_serve_dashboard_still_relaunches_in_cli_mode(self):
        args = types.SimpleNamespace(command="serve", port=0, no_browser=True, interval=30, auto_advisories=False, offline=True)
        env = {k: v for k, v in os.environ.items() if k != "WARDR_DESKTOP_SHELL"}
        with (
            TemporaryDirectory() as tmp,
            patch.dict(os.environ, env, clear=True),
            patch.object(cli, "serve", return_value=RESTART_DASHBOARD),
            patch.object(cli, "_relaunch_dashboard", return_value=0) as relaunch,
        ):
            code = cli._serve_dashboard(Path(tmp), args, ["serve", "--no-browser"], windows_launcher=False)
        self.assertEqual(code, 0)
        relaunch.assert_called_once_with(["serve", "--no-browser"])

    def test_linux_desktop_entry_uses_native_app_without_terminal(self):
        spec = spec_from_file_location("wardr_linux_desktop", REPO_ROOT / "packaging/linux/desktop.py")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)

        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "wardr"
            interp = root / "venv/bin/python"
            interp.parent.mkdir(parents=True)
            interp.write_text("", encoding="utf-8")
            desktop_bin = root / "wardr-desktop"
            desktop_bin.write_text("", encoding="utf-8")
            data_home = Path(tmp) / "share"

            module.write_desktop(data_home, interp)
            entry = (data_home / "applications" / f"{module.DESKTOP_ID}.desktop").read_text(encoding="utf-8")
            self.assertIn(f'Exec="{desktop_bin}"\n', entry)
            self.assertIn("Terminal=false\n", entry)
            self.assertIn("StartupWMClass=wardr-desktop\n", entry)

    def test_windows_installer_uses_native_gui_binary_and_hidden_setup(self):
        iss = (REPO_ROOT / "packaging/windows/wardr.iss").read_text(encoding="utf-8")
        self.assertIn('DestName: "Wardr.exe"; Flags: ignoreversion signonce', iss)
        self.assertIn('Name: "{userprograms}\\Wardr"; Filename: "{app}\\Wardr.exe"', iss)
        self.assertIn('Filename: "{app}\\Wardr.exe"; WorkingDir: "{app}"; Description: "Launch Wardr"', iss)
        self.assertNotIn('Filename: "{app}\\venv\\Scripts\\python.exe"', iss)
        self.assertIn("SW_HIDE", iss)
        self.assertNotIn("SW_SHOWNORMAL", iss)

    def test_macos_build_script_configures_local_networking_and_native_app(self):
        build_sh = (REPO_ROOT / "packaging/macos/build.sh").read_text(encoding="utf-8")
        self.assertIn("desktop/Cargo.toml", build_sh)
        self.assertIn("NSAllowsLocalNetworking", build_sh)
        self.assertIn("NSHighResolutionCapable", build_sh)


if __name__ == "__main__":
    unittest.main()
