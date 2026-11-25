"""Tests for native desktop shell integration across Windows, macOS, and Linux packaging."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

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
            self.assertIn('wardr-desktop"\n', entry)
            self.assertNotIn("-m wardr", entry)
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

    def test_overview_hero_has_one_click_fix_and_depth_controls(self):
        html = (REPO_ROOT / "wardr/static/index.html").read_text(encoding="utf-8")
        js = (REPO_ROOT / "wardr/static/wardr.js").read_text(encoding="utf-8")
        css = (REPO_ROOT / "wardr/static/wardr.css").read_text(encoding="utf-8")
        self.assertIn('<html lang="en" data-theme="dark">', html)
        self.assertIn('id="theme-toggle-button"', html)
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn('id="hero-fix-button"', html)
        self.assertIn('id="hero-scan-depth"', html)
        self.assertIn('element("hero-scan-button").addEventListener("click", () => startScan(state.selectedScanProfile))', js)
        self.assertIn("window.__wardrOnFocus", js)

    def test_oauth_callback_signals_desktop_focus_without_browser_dashboard_link(self):
        server_src = (REPO_ROOT / "wardr/server.py").read_text(encoding="utf-8")
        self.assertIn('print("WARDR_DESKTOP_EVENT focus", flush=True)', server_src)
        self.assertIn("launch_url=None if desktop_shell else self.server.issue_launch_url()", server_src)

    def test_batch_disposition_turns_unverified_and_manual_checks_green(self):
        from wardr.report import assess_posture
        from wardr.state import WardrState

        with TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp), offline=True)
            state._scan = {
                "scanned_at": "2026-11-25T10:00:00+00:00",
                "checks": [
                    {"id": "windows-firewall", "title": "Firewall", "status": "pass", "severity": "high", "evidence": "ok"},
                    {"id": "windows-bitlocker", "title": "BitLocker", "status": "unknown", "severity": "high", "evidence": "unverified"},
                    {"id": "windows-pending-updates", "title": "Updates", "status": "fail", "severity": "medium", "evidence": "1 update"},
                ],
            }
            before = assess_posture(state.enriched_scan_snapshot())
            self.assertEqual(before["level"], "amber")
            self.assertEqual(before["unverified"], 1)
            self.assertEqual(before["failed"], 1)

            result = state.set_check_dispositions_batch(
                ["windows-bitlocker", "windows-pending-updates"],
                "acknowledged",
                note="Confirmed via Get-to-Green checklist",
            )
            self.assertEqual(result["count"], 2)

            after = assess_posture(state.enriched_scan_snapshot())
            self.assertEqual(after["level"], "green")
            self.assertTrue(after["as_safe_as_possible"])
            self.assertEqual(after["unverified"], 0)
            self.assertEqual(after["failed"], 0)
            self.assertEqual(after["coverage_pct"], 100)
            # Pending updates auto-uses 'queued' so reboot auto-verifies
            self.assertEqual(after["queued"], 1)
            self.assertEqual(after["acknowledged"], 1)

            # Changing evidence automatically invalidates the disposition and re-alerts
            state._scan["checks"][1]["status"] = "fail"
            state._scan["checks"][1]["evidence"] = "BitLocker disabled"
            recheck = assess_posture(state.enriched_scan_snapshot())
            self.assertEqual(recheck["level"], "red")
            self.assertEqual(recheck["failed"], 1)

    def test_desktop_shell_update_restart_exits_cleanly_with_open_stdin_pipe(self):
        # Reproduces the Windows Py_FinalizeEx _enter_buffered_busy crash when
        # watch_desktop_parent held sys.stdin's BufferedReader lock during restart.
        with TemporaryDirectory() as tmp:
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "from unittest.mock import patch\n"
                "from wardr import cli, server, update_session\n"
                "from wardr.state import WardrState\n"
                "orig_init = update_session.UpdateSession.__init__\n"
                "def ready_init(self, *a, **kw):\n"
                "    orig_init(self, *a, **kw)\n"
                "    self._record_installed('9.9.9')\n"
                "state = WardrState(Path(sys.argv[1]), offline=True)\n"
                "with (\n"
                "    patch.object(update_session.UpdateSession, '__init__', ready_init),\n"
                "    patch.object(state, 'start_scan', lambda *a, **k: None),\n"
                "    patch.object(state, 'start_exposure', lambda *a, **k: None),\n"
                "    patch.object(state.monitor, 'start', lambda: None),\n"
                "    patch.object(state.monitor, 'stop', lambda: None),\n"
                "    patch.object(state.accounts, 'refresh_broker_providers_async', lambda: None),\n"
                "):\n"
                "    outcome = server.serve(state, 0, False, False)\n"
                "raise SystemExit(cli.DESKTOP_RESTART_EXIT_CODE if outcome is server.RESTART_DASHBOARD else 1)\n"
            )
            env = {
                **os.environ,
                "WARDR_DESKTOP_SHELL": "1",
                "PYTHONUNBUFFERED": "1",
                "PYTHONPATH": str(REPO_ROOT),
            }
            proc = subprocess.Popen(
                [sys.executable, "-c", script, tmp],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            try:
                launch_line = proc.stdout.readline().strip()
                self.assertIn("Wardr is running at http://127.0.0.1:", launch_line)
                launch_url = launch_line.split("Wardr is running at ", 1)[1]
                origin, nonce = launch_url.split("/#access=", 1)

                exchange_req = Request(
                    f"{origin}/api/auth/exchange",
                    data=json.dumps({"nonce": nonce}).encode("utf-8"),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                    },
                )
                with urlopen(exchange_req, timeout=10) as exchange_resp:
                    self.assertEqual(exchange_resp.status, 200)
                    token = json.loads(exchange_resp.read().decode("utf-8"))["token"]

                req = Request(
                    f"{origin}/api/update/restart",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": origin,
                        "X-Wardr-Token": token,
                    },
                )
                with urlopen(req, timeout=10) as resp:
                    self.assertEqual(resp.status, 202)

                # Intentionally keep proc.stdin OPEN while Python shuts down,
                # matching both new and older native desktop hosts.
                exit_code = proc.wait(timeout=15)
                rest_out = proc.stdout.read()
                err_out = proc.stderr.read()
                self.assertEqual(exit_code, cli.DESKTOP_RESTART_EXIT_CODE, msg=f"stderr:\n{err_out}")
                self.assertIn("WARDR_DESKTOP_EVENT restart", rest_out)
                self.assertNotIn("Fatal Python error", err_out)
                self.assertNotIn("_enter_buffered_busy", err_out)
            finally:
                if proc.stdin is not None:
                    proc.stdin.close()
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
