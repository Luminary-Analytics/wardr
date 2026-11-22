"""Bounded local monitoring for changes and selected operating-system events."""

import base64
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


_HISTORY_SIZE = 2000
_HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    at TEXT NOT NULL,
    payload TEXT NOT NULL
)
"""
_BASELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    kind TEXT NOT NULL,
    item TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (kind, item)
)
"""
_MAX_BASELINE_ITEMS = 4096
_LOG_LIMIT = 40
_SNAPSHOT_LIMIT = 8192
_SSH_FAILURE = re.compile(r"failed password|authentication failure|maximum authentication attempts", re.I)
_LISTENERS = "TCP listeners"
_LAUNCH_ITEMS = "macOS launch items"
_LINUX_SSH = "Linux SSH journal"
_WINDOWS_EVENTS = {
    "System": {
        7045: ("Service Control Manager", "medium", "Windows service installed",
               "Review the new service in the Windows System log."),
    },
    "Security": {
        4625: ("Microsoft-Windows-Security-Auditing", "low", "Windows sign-in failed",
               "Review repeated failures in the Windows Security log."),
        4720: ("Microsoft-Windows-Security-Auditing", "medium", "Windows account created",
               "Review the account creation in the Windows Security log."),
        1102: ("Microsoft-Windows-Eventlog", "high", "Windows Security log cleared",
               "Confirm the log was cleared by an authorized administrator."),
    },
    "Microsoft-Windows-Windows Defender/Operational": {
        1116: ("Microsoft-Windows-Windows Defender", "high", "Microsoft Defender detection",
               "Open Windows Security to review the Defender detection."),
        5001: ("Microsoft-Windows-Windows Defender", "high", "Defender real-time protection disabled",
               "Review the protection state in Windows Security."),
    },
}
_WINDOWS_SOURCES = {
    "System": ("windows-system", "Windows System log"),
    "Security": ("windows-security", "Windows Security log"),
    "Microsoft-Windows-Windows Defender/Operational": ("windows-defender", "Microsoft Defender log"),
}


def _utc(instant=None):
    return (instant or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="microseconds")


def _coverage(identifier, label, available, detail):
    return {"id": identifier, "label": label, "available": available, "detail": detail}


def _event(at, severity, title, detail, source, identity=None):
    event_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32] if identity else uuid.uuid4().hex
    return {"id": event_id, "at": at, "severity": severity, "title": title, "detail": detail, "source": source}


def _capture_command(*args, timeout=6):
    env = {**os.environ, "LC_ALL": "C"}
    return subprocess.run(
        args, env=env, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=timeout,
        text=True, encoding="utf-8", errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _endpoints(values):
    endpoints = set()
    for address, port in values:
        port = int(port)
        if not 0 < port <= 65535:
            continue
        if address == "*":
            endpoints.add((address, port))
            continue
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_loopback:
            endpoints.add((str(ip), port))
    if len(endpoints) > _SNAPSHOT_LIMIT:
        raise ValueError("Listener snapshot limit exceeded")
    return endpoints


def _mac_listeners():
    result = _capture_command("/usr/sbin/netstat", "-aLn", "-l", "-p", "tcp")
    if result.returncode:
        raise OSError("Could not read TCP listeners")
    lines = result.stdout.splitlines()
    if not lines or "listen queue" not in lines[0]:
        raise ValueError("Unexpected netstat output")
    return _endpoints(row.split()[1].rsplit(".", 1) for row in lines[2:] if row.strip())


def _linux_listeners():
    # Prefer zero-subprocess reads from /proc/net for minimal CPU and memory overhead.
    endpoints = []
    proc_ok = False
    for path, width in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 16)):
        try:
            with open(path, encoding="ascii") as stream:
                next(stream, None)
                for index, line in enumerate(stream):
                    if index >= 50_000:
                        raise ValueError("TCP table exceeded the read limit")
                    fields = line.split()
                    if len(fields) > 3 and fields[3] == "0A":
                        address, port = fields[1].split(":", 1)
                        # proc prints each 32-bit address word in host byte order.
                        packed = b"".join(int(address[i:i + 8], 16).to_bytes(4, sys.byteorder)
                                          for i in range(0, width * 2, 8))
                        endpoints.append((str(ipaddress.ip_address(packed)), int(port, 16)))
            if width == 4:
                proc_ok = True
        except FileNotFoundError:
            if width == 4:
                break
        except OSError:
            if width == 4:
                break
    if proc_ok:
        return _endpoints(endpoints)

    command = shutil.which("ss", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if command:
        result = _capture_command(command, "-lntH")
        if result.returncode == 0:
            listening = (row.split()[3] for row in result.stdout.splitlines() if row.startswith("LISTEN"))
            return _endpoints(endpoint.replace("[", "", 1).replace("]", "", 1).rsplit(":", 1) for endpoint in listening)
    raise OSError("Could not read Linux TCP listeners from /proc/net or ss")


def _mac_launch_items():
    entries = {}
    folders = {
        "System LaunchAgents": Path("/Library/LaunchAgents"),
        "System LaunchDaemons": Path("/Library/LaunchDaemons"),
        "User LaunchAgents": Path.home() / "Library" / "LaunchAgents",
    }
    for label, folder in folders.items():
        try:
            with os.scandir(folder) as paths:
                for entry in paths:
                    if entry.name.casefold().endswith(".plist"):
                        try:
                            stat = entry.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        entries[(label, entry.name)] = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
                        if len(entries) > _SNAPSHOT_LIMIT:
                            raise ValueError("Launch item snapshot limit exceeded")
        except FileNotFoundError:
            continue
    return entries


def _linux_ssh(lookback):
    command = shutil.which("journalctl", path="/usr/bin:/bin")
    if command is None:
        return False, "The systemd journal reader is unavailable.", []
    start = int(time.time()) - lookback
    try:
        result = _capture_command(command, "--no-pager", "--output=json", "--output-fields=MESSAGE",
                                  f"--lines={_LOG_LIMIT}", f"--since=@{start}",
                                  "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session")
    except (OSError, subprocess.SubprocessError):
        return False, "Wardr could not read the systemd journal.", []

    stderr = result.stderr.lower()
    if result.returncode or "no journal files were" in stderr:
        return False, "The systemd journal is unavailable to the Wardr account.", []
    partial = "not seeing messages" in stderr or "permission denied" in stderr
    events = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
            message = record.get("MESSAGE")
            cursor = record.get("__CURSOR")
            if not isinstance(message, str) or not _SSH_FAILURE.search(message) or not isinstance(cursor, str):
                continue
            timestamp = datetime.fromtimestamp(int(record["__REALTIME_TIMESTAMP"]) / 1_000_000, timezone.utc)
            events.append(_event(_utc(timestamp), "low", "SSH authentication failed",
                                 "Review repeated failures in the system SSH journal.", _LINUX_SSH, f"journal:{cursor}"))
        except (AttributeError, KeyError, OSError, OverflowError, TypeError, ValueError):
            continue
    detail = "Journal access is limited for the Wardr account." if partial else "Recent failed authentication reported by OpenSSH."
    return not partial, detail, events


def _windows_capture(lookback):
    logs = ",\n".join(
        f"@{{Name='{channel}'; Ids=@({','.join(map(str, ids))})}}" for channel, ids in _WINDOWS_EVENTS.items()
    )
    script = r"""
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$result = @{listeners = @(); listenersAvailable = $false; logs = @{}; events = @()}
try {
    $result.listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -First @LISTENER_LIMIT@ | ForEach-Object { '{0}|{1}' -f $_.LocalAddress, $_.LocalPort })
    $result.listenersAvailable = $true
} catch {
    $result.listenersAvailable = $_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*'
}
$start = (Get-Date).AddSeconds(-@LOOKBACK@)
foreach ($channel in @(@LOGS@)) {
    try {
        $result.events += @(Get-WinEvent -FilterHashtable @{LogName=$channel.Name; Id=$channel.Ids; StartTime=$start} `
            -MaxEvents @LOG_LIMIT@ -ErrorAction Stop | ForEach-Object {
                @{channel=$_.LogName; provider=$_.ProviderName; record=$_.RecordId; id=$_.Id;
                  at=$_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffff'Z'")}
            })
        $result.logs[$channel.Name] = $true
    } catch {
        $result.logs[$channel.Name] = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
    }
}
$result | ConvertTo-Json -Depth 4 -Compress
""".replace("@LOOKBACK@", str(lookback)).replace("@LOGS@", logs).replace("@LOG_LIMIT@", str(_LOG_LIMIT)).replace(
        "@LISTENER_LIMIT@", str(_SNAPSHOT_LIMIT + 1)
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = windows / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    result = _capture_command(str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded,
                              timeout=12)
    if result.returncode:
        raise OSError("Could not read Windows event channels")
    snapshot = json.loads(result.stdout)
    listeners = None
    if snapshot["listenersAvailable"] and len(snapshot["listeners"]) <= _SNAPSHOT_LIMIT:
        try:
            listeners = _endpoints(item.split("|", 1) for item in snapshot["listeners"])
        except (AttributeError, TypeError, ValueError):
            pass

    events = []
    for record in snapshot["events"]:
        try:
            channel = record["channel"]
            _, label = _WINDOWS_SOURCES[channel]
            provider, severity, title, detail = _WINDOWS_EVENTS[channel][record["id"]]
            if provider != record["provider"]:
                continue
            at = _utc(datetime.fromisoformat(record["at"].replace("Z", "+00:00")))
            events.append(_event(at, severity, title, detail, label, f"windows:{channel}:{record['record']}:{at}"))
        except (KeyError, TypeError, ValueError):
            continue
    coverage = []
    for channel, (identifier, label) in _WINDOWS_SOURCES.items():
        available = snapshot["logs"].get(channel) is True
        detail = "Selected events reported by Windows." if available else "This log is unavailable to the Wardr account."
        coverage.append(_coverage(identifier, label, available, detail))
    return listeners, events, coverage


def _listener_changes(at, previous, current):
    additions = current - previous
    events = []
    for address, port in sorted(additions)[:20]:
        if ":" in address:
            address = f"[{address}]"
        destination = f"{address}:{port}"
        events.append(_event(at, "medium", "New non-loopback TCP listener",
                             f"A local service began listening on {destination}. Review the service if the change is unexpected.",
                             _LISTENERS))
    if len(additions) > 20:
        events.append(_event(at, "medium", "Additional TCP listeners appeared",
                             f"{len(additions) - 20} more listeners appeared during this sample.", _LISTENERS))
    return events


def _launch_changes(at, previous, current):
    changed = sorted(key for key in previous.keys() | current.keys() if previous.get(key) != current.get(key))
    events = []
    for folder, name in changed[:20]:
        action = "Removed" if (folder, name) not in current else "Added" if (folder, name) not in previous else "Changed"
        safe_name = "".join(char if char.isprintable() else "?" for char in name)[:240]
        events.append(_event(at, "low" if action == "Removed" else "medium", "macOS launch item changed",
                             f"{action} {safe_name} in {folder}.", _LAUNCH_ITEMS))
    if len(changed) > 20:
        events.append(_event(at, "medium", "Additional macOS launch items changed",
                             f"{len(changed) - 20} more launch items changed during this sample.", _LAUNCH_ITEMS))
    return events


def _history_records(database):
    rows = database.execute("SELECT payload FROM events WHERE length(payload) <= 4096 ORDER BY at DESC, id DESC LIMIT ?",
                            (_HISTORY_SIZE,))
    fields = ("id", "at", "severity", "title", "detail", "source")
    records = []
    for (payload,) in rows:
        record = json.loads(payload)
        if isinstance(record, dict) and all(isinstance(record.get(key), str) for key in fields):
            records.append({key: record[key] for key in fields})
    return records


class Monitor:
    """Poll local defensive signals while Wardr runs, with optional on-disk history."""

    def __init__(self, interval: int | float = 30, state_dir: str | Path | None = None):
        self.interval = float(interval)
        if not math.isfinite(self.interval) or not 0 < self.interval <= 3600:
            raise ValueError("Monitoring interval must be greater than zero and at most 3600 seconds.")
        self._system = platform.system()
        self._guard = threading.Lock()
        self._poll_guard = threading.Lock()
        self._thread = None
        self._stop = None
        self._listeners = None
        self._launch_items = None
        self._last_poll = None
        self._last_sample = None
        self._poll_count = 0
        self._history_path = Path(state_dir) / "monitor-events.sqlite3" if state_dir is not None else None
        self._history_detail = None
        self._events = self._load_history()
        self._baselines = self._load_baselines()
        sources = [("tcp-listeners", _LISTENERS)]
        if self._system == "Darwin":
            sources.append(("macos-launch", _LAUNCH_ITEMS))
        elif self._system == "Linux":
            sources.append(("linux-ssh", _LINUX_SSH))
        elif self._system == "Windows":
            sources.extend(_WINDOWS_SOURCES.values())
        self._coverage = [_coverage(identifier, label, None, "Waiting for the first sample.") for identifier, label in sources]

    def start(self) -> None:
        """Start a background poller. Repeated calls leave one poller running."""
        with self._guard:
            if self._thread is None or not self._thread.is_alive():
                self._listeners = None
                self._launch_items = None
                self._stop = threading.Event()
                self._thread = threading.Thread(target=self._run, args=(self._stop,), name="wardr-monitor", daemon=True)
                self._thread.start()

    def stop(self) -> None:
        """Stop the poller; any in-progress read has a bounded timeout."""
        with self._guard:
            thread = self._thread
            if self._stop is not None:
                self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=15)

    def _run(self, stopping):
        while not stopping.is_set():
            started = time.monotonic()
            self._poll(stopping)
            stopping.wait(max(self.interval / 4, self.interval - (time.monotonic() - started)))

    def _load_baselines(self) -> dict[str, set[str]]:
        result = {"listener": set(), "launch_item": set()}
        if self._history_path is None:
            return result
        try:
            if not self._history_path.exists():
                return result
            with closing(sqlite3.connect(self._history_path, timeout=1)) as database:
                database.execute(_BASELINE_SCHEMA)
                for kind, item in database.execute("SELECT kind, item FROM baselines LIMIT ?", (_MAX_BASELINE_ITEMS,)):
                    if kind in result and isinstance(item, str):
                        result[kind].add(item)
        except (OSError, sqlite3.Error, ValueError):
            pass
        return result

    def _save_baselines(self, additions: list[tuple[str, str, str]]) -> None:
        if self._history_path is None or not additions:
            return
        path = self._history_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
            with closing(sqlite3.connect(path, timeout=1)) as database, database:
                database.execute(_BASELINE_SCHEMA)
                database.executemany(
                    "INSERT INTO baselines (kind, item, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(kind, item) DO UPDATE SET last_seen = excluded.last_seen",
                    [(kind, item, at, at) for kind, item, at in additions[:_MAX_BASELINE_ITEMS]],
                )
        except (OSError, sqlite3.Error, ValueError):
            pass

    def _load_history(self):
        if self._history_path is None:
            return []
        try:
            if not self._history_path.exists():
                return []
            with closing(sqlite3.connect(self._history_path, timeout=1)) as database:
                database.execute(_HISTORY_SCHEMA)
                return _history_records(database)
        except (OSError, RecursionError, sqlite3.Error, TypeError, ValueError):
            self._history_detail = "Wardr could not read the saved event history."
            return []

    def _save_history(self, records):
        if self._history_path is None:
            return
        path = self._history_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
            with closing(sqlite3.connect(path, timeout=1)) as database, database:
                database.execute(_HISTORY_SCHEMA)
                database.executemany("INSERT OR IGNORE INTO events (id, at, payload) VALUES (?, ?, ?)", (
                    (record["id"], record["at"], json.dumps(record, ensure_ascii=True, separators=(",", ":")))
                    for record in records
                ))
                database.execute("DELETE FROM events WHERE id IN ("
                                 "SELECT id FROM events ORDER BY at DESC, id DESC LIMIT -1 OFFSET ?)", (_HISTORY_SIZE,))
                latest = _history_records(database)
        except (OSError, RecursionError, sqlite3.Error, TypeError, ValueError):
            with self._guard:
                self._history_detail = "Wardr could not save the event history."
        else:
            with self._guard:
                self._events = latest
                self._history_detail = None

    def _capture(self, lookback):
        listeners = launch_items = None
        events = []
        coverage = []
        if self._system == "Windows":
            try:
                listeners, events, coverage = _windows_capture(lookback)
            except (AttributeError, KeyError, OSError, RecursionError, subprocess.SubprocessError, TypeError, ValueError):
                coverage = [_coverage(identifier, label, False, "Wardr could not read this event log.")
                            for identifier, label in _WINDOWS_SOURCES.values()]
        elif self._system == "Darwin":
            try:
                listeners = _mac_listeners()
            except (IndexError, OSError, subprocess.SubprocessError, ValueError):
                pass
            try:
                launch_items = _mac_launch_items()
            except (OSError, RuntimeError, ValueError):
                pass
            launch_detail = ("Changes to machine and current-user launch configuration files." if launch_items is not None
                             else "Wardr could not read the launch item directories.")
            coverage.append(_coverage("macos-launch", _LAUNCH_ITEMS, launch_items is not None, launch_detail))
        elif self._system == "Linux":
            try:
                listeners = _linux_listeners()
            except (IndexError, OSError, subprocess.SubprocessError, ValueError):
                pass
            available, detail, events = _linux_ssh(lookback)
            coverage.append(_coverage("linux-ssh", _LINUX_SSH, available, detail))

        listener_detail = ("New non-loopback TCP listeners observed between samples." if listeners is not None
                           else "Wardr could not read the local TCP listening sockets.")
        coverage.insert(0, _coverage("tcp-listeners", _LISTENERS, listeners is not None, listener_detail))
        return listeners, launch_items, events, coverage

    def _poll(self, stopping=None):
        with self._poll_guard:
            if stopping is not None and stopping.is_set():
                return
            now = datetime.now(timezone.utc)
            gap = (now - self._last_sample).total_seconds() if self._last_sample else 0
            lookback = int(min(3700, max(60, self.interval + 10, gap + 10)))
            listeners, launch_items, events, coverage = self._capture(lookback)
            baseline_updates: list[tuple[str, str, str]] = []
            with self._guard:
                if stopping is not None and stopping.is_set():
                    return
                at = _utc(now)
                if self._listeners is not None and listeners is not None:
                    events.extend(_listener_changes(at, self._listeners, listeners))
                if listeners is not None:
                    known_listeners = self._baselines["listener"]
                    had_baseline = bool(known_listeners)
                    current_keys = {f"{addr}:{port}" for addr, port in listeners}
                    novel = sorted(current_keys - known_listeners)
                    if had_baseline and novel:
                        for endpoint in novel[:16]:
                            events.append(_event(
                                at,
                                "high",
                                "Novel non-loopback TCP listener (baseline drift)",
                                f"Endpoint {endpoint} was not present in this host's persistent listener baseline.",
                                _LISTENERS,
                                identity=f"baseline-listener/{endpoint}",
                            ))
                    for endpoint in novel:
                        if len(known_listeners) < _MAX_BASELINE_ITEMS:
                            known_listeners.add(endpoint)
                            baseline_updates.append(("listener", endpoint, at))

                if self._launch_items is not None and launch_items is not None:
                    events.extend(_launch_changes(at, self._launch_items, launch_items))
                if launch_items is not None:
                    known_launch = self._baselines["launch_item"]
                    had_launch_baseline = bool(known_launch)
                    current_launch = {f"{label}/{name}" for label, name in launch_items}
                    novel_launch = sorted(current_launch - known_launch)
                    if had_launch_baseline and novel_launch:
                        for item_key in novel_launch[:16]:
                            events.append(_event(
                                at,
                                "high",
                                "Novel launch item (baseline drift)",
                                f"Launch item {item_key} was not present in this host's persistent persistence baseline.",
                                _LAUNCH_ITEMS,
                                identity=f"baseline-launch/{item_key}",
                            ))
                    for item_key in novel_launch:
                        if len(known_launch) < _MAX_BASELINE_ITEMS:
                            known_launch.add(item_key)
                            baseline_updates.append(("launch_item", item_key, at))

                self._listeners = listeners
                self._launch_items = launch_items
                self._coverage = coverage
                self._last_poll = _utc()
                self._last_sample = now
                self._poll_count += 1

                existing = {event["id"] for event in self._events}
                new_events = list({event["id"]: event for event in events if event["id"] not in existing}.values())
                if new_events:
                    self._events = sorted(self._events + new_events, key=lambda event: (event["at"], event["id"]),
                                          reverse=True)[:_HISTORY_SIZE]
                unsaved = self._events if self._history_detail else new_events
            if baseline_updates:
                self._save_baselines(baseline_updates)
            if unsaved:
                self._save_history(unsaved)

    def poll(self) -> dict:
        """Collect one sample and return the updated monitor status."""
        self._poll()
        return self.status()

    def status(self) -> dict:
        with self._guard:
            return {
                "running": bool(self._thread and self._thread.is_alive() and not self._stop.is_set()),
                "interval": self.interval,
                "last_poll": self._last_poll,
                "poll_count": self._poll_count,
                "coverage": [item.copy() for item in self._coverage],
                "events": [event.copy() for event in self._events],
                "history_persistent": self._history_path is not None and self._history_detail is None,
                "history_detail": self._history_detail,
            }
