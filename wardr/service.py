"""Generate hardened continuous-monitoring service templates for servers and desktops."""

import shlex
import sys
from xml.sax.saxutils import escape as xml_escape


def _validate_arg(label: str, value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{label} cannot contain control characters or newlines.")
    return value


def _systemd_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{escaped}"' if any(c.isspace() or c in "\"'\\$%" for c in value) else value


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ps_double_escape(value: str) -> str:
    return value.replace("`", "``").replace('"', '`"').replace("$", "`$")


def render_template(target: str, *, state_dir: str = "", interval: int = 30, fleet: bool = False) -> str:
    """Return a hardened systemd, launchd, or Windows scheduled-task template for wardr watch or fleet agent."""
    if not isinstance(interval, int) or interval <= 0:
        raise ValueError("Interval must be a positive integer.")
    python_bin = _validate_arg("python_bin", sys.executable or "/usr/bin/python3")
    clean_state = _validate_arg("state_dir", state_dir) if state_dir else ""
    subcmd = f"fleet agent --interval {interval}" if fleet else f"watch --interval {interval}"
    desc = "Wardr Continuous Fleet Agent" if fleet else "Wardr Continuous Local Security Monitor"
    unit_name = "wardr-fleet-agent" if fleet else "wardr-watch"
    launch_label = "com.getwardr.fleet-agent" if fleet else "com.getwardr.watch"
    win_task = "WardrFleetAgent" if fleet else "WardrContinuousMonitor"

    if target == "systemd":
        state_flag = f"--state-dir {_systemd_quote(clean_state)} " if clean_state else ""
        exec_py = _systemd_quote(python_bin)
        return f"""# Save to /etc/systemd/system/{unit_name}.service (or ~/.config/systemd/user/{unit_name}.service)
# Then run: systemctl daemon-reload && systemctl enable --now {unit_name}.service
[Unit]
Description={desc}
After=network.target

[Service]
Type=simple
ExecStart={exec_py} -m wardr {state_flag}{subcmd}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
MemoryMax=128M
CPUQuota=10%
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    if target == "launchd":
        args = [python_bin, "-m", "wardr"]
        if clean_state:
            args.extend(["--state-dir", clean_state])
        if fleet:
            args.extend(["fleet", "agent", "--interval", str(interval)])
        else:
            args.extend(["watch", "--interval", str(interval)])
        arg_xml = "\n".join(f"    <string>{xml_escape(a)}</string>" for a in args)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Save to ~/Library/LaunchAgents/{launch_label}.plist and load with launchctl bootstrap -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{xml_escape(launch_label)}</string>
  <key>ProgramArguments</key>
  <array>
{arg_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"""
    if target == "windows":
        extra = f"--state-dir '{_ps_double_escape(clean_state.replace(chr(39), chr(39) * 2))}' " if clean_state else ""
        return f"""# Run in an elevated PowerShell prompt to register a continuous Wardr background task
$Action = New-ScheduledTaskAction -Execute {_ps_single_quote(python_bin)} -Argument "-m wardr {extra}{subcmd}"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)
Register-ScheduledTask -TaskName {_ps_single_quote(win_task)} -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Limited
"""
    _ = shlex
    raise ValueError("Choose systemd, launchd, or windows.")
