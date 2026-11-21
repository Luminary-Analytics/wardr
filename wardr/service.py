"""Generate hardened continuous-monitoring service templates for servers and desktops."""

import sys


def render_template(target: str, *, state_dir: str = "", interval: int = 30) -> str:
    """Return a hardened systemd, launchd, or Windows scheduled-task template for wardr watch."""
    python_bin = sys.executable or "/usr/bin/python3"
    state_flag = f"--state-dir {state_dir} " if state_dir else ""

    if target == "systemd":
        return f"""# Save to /etc/systemd/system/wardr-watch.service (or ~/.config/systemd/user/wardr-watch.service)
# Then run: systemctl daemon-reload && systemctl enable --now wardr-watch.service
[Unit]
Description=Wardr Continuous Local Security Monitor
After=network.target

[Service]
Type=simple
ExecStart={python_bin} -m wardr {state_flag}watch --interval {interval}
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
        if state_dir:
            args.extend(["--state-dir", state_dir])
        args.extend(["watch", "--interval", str(interval)])
        arg_xml = "\n".join(f"    <string>{a}</string>" for a in args)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Save to ~/Library/LaunchAgents/com.getwardr.watch.plist and load with launchctl bootstrap -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.getwardr.watch</string>
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
        extra = f"--state-dir '{state_dir}' " if state_dir else ""
        return f"""# Run in an elevated PowerShell prompt to register a continuous Wardr background monitor
$Action = New-ScheduledTaskAction -Execute '{python_bin}' -Argument "-m wardr {extra}watch --interval {interval}"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)
Register-ScheduledTask -TaskName 'WardrContinuousMonitor' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Limited
"""
    raise ValueError("Choose systemd, launchd, or windows.")
