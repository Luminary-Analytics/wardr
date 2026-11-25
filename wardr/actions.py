"""Strictly allowlisted OS Settings deep-links and scripted local security fixes."""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass

from . import checks


@dataclass(frozen=True)
class ActionSpec:
    check_id: str
    platforms: tuple[str, ...]
    settings_label: str | None = None
    settings_uri: str | None = None
    script_label: str | None = None
    script_preview: str | None = None
    script_note: str | None = None
    requires_admin: bool = True
    # Hardcoded command specification — never built from untrusted input.
    macos_admin_cmd: str | None = None
    windows_ps_cmd: str | None = None
    linux_argv: tuple[str, ...] | None = None


_SPECS: dict[str, ActionSpec] = {
    "macos-firewall": ActionSpec(
        check_id="macos-firewall",
        platforms=("Darwin",),
        settings_label="Open Firewall Settings",
        settings_uri="x-apple.systempreferences:com.apple.preference.security?Firewall",
        script_label="Enable Firewall (script)",
        script_preview="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        script_note="macOS will prompt for Touch ID or your administrator password, then Wardr will verify the firewall is enabled.",
        requires_admin=True,
        macos_admin_cmd="/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
    ),
    "macos-pending-updates": ActionSpec(
        check_id="macos-pending-updates",
        platforms=("Darwin",),
        settings_label="Open Software Update",
        settings_uri="x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
        script_label=None,
        script_preview=None,
        script_note="Apple Silicon macOS updates require Apple's Software Update window for volume-owner approval and a system restart.",
        requires_admin=True,
    ),
    "macos-background-updates": ActionSpec(
        check_id="macos-background-updates",
        platforms=("Darwin",),
        settings_label="Open Software Update",
        settings_uri="x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
        script_label="Enable Auto Security Updates",
        script_preview="sudo /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
        script_note="Enables Apple's automatic background security & system-file updates.",
        requires_admin=True,
        macos_admin_cmd="/usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
    ),
    "macos-filevault": ActionSpec(
        check_id="macos-filevault",
        platforms=("Darwin",),
        settings_label="Open FileVault Settings",
        settings_uri="x-apple.systempreferences:com.apple.preference.security?FDE",
        script_label=None,
        script_preview=None,
        script_note="FileVault requires reviewing and saving your recovery key in System Settings.",
        requires_admin=True,
    ),
    "macos-gatekeeper": ActionSpec(
        check_id="macos-gatekeeper",
        platforms=("Darwin",),
        settings_label="Open Privacy & Security",
        settings_uri="x-apple.systempreferences:com.apple.preference.security?General",
        script_label="Enable Gatekeeper (script)",
        script_preview="sudo /usr/sbin/spctl --master-enable",
        script_note="Restores macOS Gatekeeper app notarization and signature verification.",
        requires_admin=True,
        macos_admin_cmd="/usr/sbin/spctl --master-enable",
    ),
    "macos-sip": ActionSpec(
        check_id="macos-sip",
        platforms=("Darwin",),
        settings_label="Open Security Settings",
        settings_uri="x-apple.systempreferences:com.apple.preference.security?General",
        script_note="System Integrity Protection can only be re-enabled from macOS Recovery (csrutil enable).",
        requires_admin=True,
    ),
    "windows-firewall": ActionSpec(
        check_id="windows-firewall",
        platforms=("Windows",),
        settings_label="Open Firewall Settings",
        settings_uri="windowsdefender://network",
        script_label="Enable Firewall (script)",
        script_preview="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        script_note="Enables all Windows Defender Firewall profiles via elevated PowerShell.",
        requires_admin=True,
        windows_ps_cmd="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
    ),
    "windows-defender": ActionSpec(
        check_id="windows-defender",
        platforms=("Windows",),
        settings_label="Open Windows Security",
        settings_uri="windowsdefender://threat",
        script_label="Enable Real-Time Protection",
        script_preview="Set-MpPreference -DisableRealtimeMonitoring $false",
        script_note="Re-enables Microsoft Defender real-time protection.",
        requires_admin=True,
        windows_ps_cmd="Set-MpPreference -DisableRealtimeMonitoring $false",
    ),
    "windows-defender-signatures": ActionSpec(
        check_id="windows-defender-signatures",
        platforms=("Windows",),
        settings_label="Open Windows Security",
        settings_uri="windowsdefender://threat",
        script_label="Update Signatures (script)",
        script_preview="Update-MpSignature",
        script_note="Downloads the latest Microsoft Defender security intelligence definitions.",
        requires_admin=False,
        windows_ps_cmd="Update-MpSignature",
    ),
    "windows-pending-updates": ActionSpec(
        check_id="windows-pending-updates",
        platforms=("Windows",),
        settings_label="Open Windows Update",
        settings_uri="ms-settings:windowsupdate",
    ),
    "windows-bitlocker": ActionSpec(
        check_id="windows-bitlocker",
        platforms=("Windows",),
        settings_label="Open Device Encryption",
        settings_uri="ms-settings:deviceencryption",
    ),
    "windows-smb1": ActionSpec(
        check_id="windows-smb1",
        platforms=("Windows",),
        settings_label="Open Network Settings",
        settings_uri="ms-settings:network",
        script_label="Disable SMBv1 (script)",
        script_preview="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        script_note="Disables the obsolete SMBv1 server protocol.",
        requires_admin=True,
        windows_ps_cmd="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
    ),
    "windows-rdp-nla": ActionSpec(
        check_id="windows-rdp-nla",
        platforms=("Windows",),
        settings_label="Open Remote Desktop",
        settings_uri="ms-settings:remotedesktop",
    ),
    "windows-uac": ActionSpec(
        check_id="windows-uac",
        platforms=("Windows",),
        settings_label="Open Windows Security",
        settings_uri="windowsdefender://appbrowser",
        script_note="Verify User Account Control is enabled in Windows Security or Control Panel → User Accounts.",
    ),
    "windows-secure-boot": ActionSpec(
        check_id="windows-secure-boot",
        platforms=("Windows",),
        settings_label="Open Device Security",
        settings_uri="windowsdefender://devicesecurity",
        script_note="Check Secure Boot under Windows Security → Device Security (or UEFI/BIOS firmware settings).",
    ),
    "linux-firewall": ActionSpec(
        check_id="linux-firewall",
        platforms=("Linux",),
        script_label="Enable UFW Firewall (script)",
        script_preview="/usr/bin/pkexec /usr/sbin/ufw --force enable",
        script_note="Prompts for administrator authentication to enable UFW firewall.",
        requires_admin=True,
        linux_argv=("/usr/bin/pkexec", "/usr/sbin/ufw", "--force", "enable"),
    ),
    "linux-aslr": ActionSpec(
        check_id="linux-aslr",
        platforms=("Linux",),
        script_label="Enable ASLR (script)",
        script_preview="/usr/bin/pkexec /usr/sbin/sysctl -w kernel.randomize_va_space=2",
        script_note="Enables full kernel address space layout randomization.",
        requires_admin=True,
        linux_argv=("/usr/bin/pkexec", "/usr/sbin/sysctl", "-w", "kernel.randomize_va_space=2"),
    ),
}


def action_guide_for(check_id: str, *, system: str | None = None) -> dict | None:
    """Return safe, customer-facing settings & script action metadata for a check ID."""
    spec = _SPECS.get(check_id)
    current_os = system or platform.system()
    if spec is None or current_os not in spec.platforms:
        return None
    can_script = bool(
        (current_os == "Darwin" and spec.macos_admin_cmd)
        or (current_os == "Windows" and spec.windows_ps_cmd)
        or (current_os == "Linux" and spec.linux_argv)
    )
    return {
        "check_id": spec.check_id,
        "can_open_settings": bool(spec.settings_uri),
        "settings_label": spec.settings_label,
        "can_script_fix": can_script,
        "script_label": spec.script_label if can_script else None,
        "script_preview": spec.script_preview if can_script else None,
        "script_note": spec.script_note,
        "requires_admin": spec.requires_admin,
    }


def enrich_checks(items: list[dict], *, system: str | None = None) -> list[dict]:
    """Return copies of check dicts augmented with allowlisted action_guide metadata."""
    current_os = system or platform.system()
    enriched = []
    for item in items:
        copy = dict(item)
        guide = action_guide_for(str(item.get("id") or ""), system=current_os)
        if guide is not None:
            copy["action_guide"] = guide
        enriched.append(copy)
    return enriched


def open_settings(check_id: str) -> dict:
    """Open the allowlisted OS Settings pane for this check on the local desktop."""
    current_os = platform.system()
    spec = _SPECS.get(check_id)
    if spec is None or current_os not in spec.platforms or not spec.settings_uri:
        raise ValueError("No direct System Settings link is available for this check on this OS.")

    if current_os == "Darwin":
        result = subprocess.run(
            ["/usr/bin/open", spec.settings_uri],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8, check=False,
        )
        if result.returncode != 0 and check_id in ("macos-pending-updates", "macos-background-updates"):
            result = subprocess.run(
                ["/usr/bin/open", "/System/Library/PreferencePanes/SoftwareUpdate.prefPane"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8, check=False,
            )
        if result.returncode != 0:
            raise RuntimeError("macOS could not open that System Settings pane.")
    elif current_os == "Windows":
        os.startfile(spec.settings_uri)  # type: ignore[attr-defined]
    else:
        opener = shutil.which("xdg-open")
        if not opener:
            raise RuntimeError("No desktop settings launcher (xdg-open) is available on this system.")
        subprocess.run([opener, spec.settings_uri], stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False)

    return {
        "ok": True,
        "message": f"Opened {spec.settings_label or 'System Settings'}. After making your change, run a quick scan to verify it turns green.",
    }


def run_script_fix(check_id: str) -> dict:
    """Execute the strictly hardcoded, allowlisted local fix script and re-verify the check."""
    current_os = platform.system()
    spec = _SPECS.get(check_id)
    if spec is None or current_os not in spec.platforms:
        raise ValueError("No scripted fix is allowlisted for this check on this OS.")

    if current_os == "Darwin":
        if not spec.macos_admin_cmd:
            raise ValueError("This check requires manual confirmation in System Settings.")
        # Uses macOS's native administrator authentication prompt (Touch ID / password)
        # with a strictly hardcoded, non-interpolated command string.
        escaped = spec.macos_admin_cmd.replace("\\", "\\\\").replace('"', '\\"')
        applescript = f'do shell script "{escaped}" with administrator privileges'
        timeout = 180 if check_id == "macos-pending-updates" else 45
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", applescript],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if "User canceled" in stderr or "(-128)" in stderr:
                return {"ok": False, "message": "Administrator prompt was canceled. No changes were made."}
            return {"ok": False, "message": f"Script did not complete: {stderr or 'administrator approval required.'}"}
    elif current_os == "Windows":
        if not spec.windows_ps_cmd:
            raise ValueError("This check requires manual confirmation in Windows Security.")
        sys_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        if not sys_root.is_absolute():
            raise RuntimeError("SystemRoot is not an absolute path.")
        ps_path = sys_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if not ps_path.is_file():
            raise RuntimeError("Windows PowerShell executable could not be verified.")
        ps = str(ps_path)
        ps_escaped = ps.replace("'", "''")
        cmd = (
            f"Start-Process -FilePath '{ps_escaped}' -Verb RunAs -Wait -ArgumentList "
            f"'-NoProfile','-NonInteractive','-Command','{spec.windows_ps_cmd}'"
            if spec.requires_admin else spec.windows_ps_cmd
        )
        result = subprocess.run(
            [ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cmd],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=False,
        )
        if result.returncode != 0:
            return {"ok": False, "message": "Windows script did not complete. Administrator permission may have been declined."}
    elif current_os == "Linux":
        if not spec.linux_argv:
            raise ValueError("No scripted fix is allowlisted for this Linux check.")
        result = subprocess.run(
            list(spec.linux_argv),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45, check=False,
        )
        if result.returncode != 0:
            return {"ok": False, "message": "Administrator authorization was declined or the tool is unavailable."}
    else:
        raise ValueError("Scripted fix is not supported on this platform.")

    # Re-scan to verify the actual OS state after running the script.
    fresh = checks.scan()
    updated_check = next((c for c in fresh.get("checks", []) if c.get("id") == check_id), None)
    if updated_check and updated_check.get("status") == "pass":
        return {
            "ok": True,
            "message": f"{updated_check.get('title', check_id)} is now enabled and verified secure.",
            "check": updated_check,
        }
    return {
        "ok": True,
        "message": (
            f"Command completed for {updated_check.get('title', check_id) if updated_check else check_id}. "
            "If an update or reboot is pending, re-scan after restarting to verify."
        ),
        "check": updated_check,
    }
