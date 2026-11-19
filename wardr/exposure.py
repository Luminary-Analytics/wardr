"""Read-only inventory of local TCP listeners and UDP bindings."""

import base64
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import threading
from pathlib import Path

from .monitor import _coverage, _utc


_ROW_LIMIT = 4096
_LINUX_LINE_LIMIT = 50_000
_COMMAND_BYTE_LIMIT = 8 * 1024 * 1024
_OWNERSHIP_LIMIT = (1 << 32) - 1
_SCOPE_ORDER = {"wildcard": 0, "interface": 1, "loopback": 2}
_MAC_FAMILIES = {"4": "ipv4", "6": "ipv6", "46": "dual", "": "unknown"}
_WINDOWS_SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$result = @{ tcp = $null; udp = $null }
try {
    $result.tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -First @ROW_LIMIT@ -Property LocalAddress,LocalPort,OwningProcess)
} catch {
    if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') { $result.tcp = @() }
}
try {
    $result.udp = @(Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object -First @ROW_LIMIT@ -Property LocalAddress,LocalPort,OwningProcess)
} catch {
    if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') { $result.udp = @() }
}
$result | ConvertTo-Json -Depth 4 -Compress
""".replace("@ROW_LIMIT@", str(_ROW_LIMIT + 1))


def _command_output(*args, timeout):
    """Read bounded output from one fixed local operating-system command."""
    with subprocess.Popen(
        args, env={**os.environ, "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ) as process:
        timer = threading.Timer(timeout, process.kill)
        timer.daemon = True
        timer.start()
        try:
            capture = process.stdout.read(_COMMAND_BYTE_LIMIT + 1)
            if len(capture) > _COMMAND_BYTE_LIMIT:
                process.kill()
                raise ValueError("Local endpoint output limit exceeded")
            if process.wait():
                raise OSError("Could not read the local endpoint table")
            return capture.decode("utf-8-sig", errors="replace")
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()


def _endpoint(protocol, address, port, *, family=None, pid=None, process=None, uid=None):
    if isinstance(port, str) and port.isascii() and port.isdecimal():
        port = int(port)
    if type(port) is not int or not 0 < port <= 65535:
        raise ValueError("Invalid local endpoint port")
    if address == "*":
        scope = "wildcard"
    else:
        parsed = ipaddress.ip_address(address)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.scope_id:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", parsed.scope_id):
                raise ValueError("Invalid IPv6 scope")
        family = "ipv4" if parsed.version == 4 else "ipv6"
        address = str(parsed)
        classified = getattr(parsed, "ipv4_mapped", None) or parsed
        if classified.is_unspecified:
            scope = "wildcard"
        elif classified.is_loopback:
            scope = "loopback"
        else:
            scope = "interface"
    item = {"protocol": protocol, "address": address, "port": port, "scope": scope, "family": family or "unknown"}
    if isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid <= _OWNERSHIP_LIMIT:
        item["pid"] = pid
        if process:
            item["process"] = "".join(char for char in process if char.isprintable())[:128]
    if isinstance(uid, int) and not isinstance(uid, bool) and 0 <= uid <= _OWNERSHIP_LIMIT:
        item["uid"] = uid
    return item


def _mac_owner(line, columns, protocol):
    if "process:pid" not in columns:
        if "pid" in columns:
            index = columns.index("pid")
            index -= protocol == "udp" and "(state)" in columns[:index]
            fields = line.split()
            if index < len(fields) and fields[index].isascii() and fields[index].isdigit():
                return int(fields[index]), None
        return None, None

    owner_index = columns.index("process:pid")
    suffix = len(columns) - owner_index - 1
    owner_index -= protocol == "udp" and "(state)" in columns[:owner_index]
    fields = line.split(None, owner_index)
    if len(fields) <= owner_index:
        return None, None
    process, _, pid = fields[owner_index].rsplit(None, suffix)[0].rpartition(":")
    return (int(pid), process) if pid.isascii() and pid.isdigit() else (None, None)


def _parse_mac(output, protocol):
    columns = None
    endpoints = []
    complete = True
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "Proto" and "Local Address" in line:
            columns = line.replace("Local Address", "LocalAddress").replace("Foreign Address", "ForeignAddress").split()
            continue
        family = _MAC_FAMILIES.get(fields[0].removeprefix(protocol))
        if not fields[0].startswith(protocol) or family is None:
            continue
        if columns is None or len(fields) < 5:
            complete = False
            continue
        if protocol == "tcp" and (len(fields) < 6 or fields[5] != "LISTEN"):
            continue
        if protocol == "udp" and fields[4] not in ("*.*", "0.0.0.0.0", "::.*"):
            continue
        try:
            address, port = fields[3].rsplit(".", 1)
            if protocol == "udp" and port in ("*", "0"):
                continue
            pid, process = _mac_owner(line, columns, protocol)
            item = _endpoint(protocol, address, port, family=family, pid=pid, process=process)
        except (TypeError, ValueError):
            complete = False
            continue
        if len(endpoints) >= _ROW_LIMIT:
            complete = False
            break
        endpoints.append(item)
    if columns is None:
        complete = complete and not output.strip()
    return endpoints, complete


def _mac_snapshot():
    rows = []
    coverage = []
    for protocol, label in (("tcp", "TCP listeners"), ("udp", "Unconnected UDP bindings")):
        try:
            data, complete = _parse_mac(
                _command_output("/usr/sbin/netstat", "-anv", "-p", protocol, timeout=6), protocol,
            )
            detail = "Read the macOS socket table." if complete else "Some rows could not be captured or interpreted."
            rows.extend(data)
        except (OSError, ValueError):
            complete, detail = False, "The macOS socket table could not be read within the local limits."
        coverage.append(_coverage(f"macos-{protocol}", label, complete, detail))
    return rows, coverage


def _proc_endpoint(token, family):
    word, port = token.split(":", 1)
    width = 8 if family == "ipv4" else 32
    if len(word) != width or len(port) != 4:
        raise ValueError("Invalid kernel endpoint")
    # Linux emits IPv4 addresses and each IPv6 32-bit word in host byte order.
    packed = b"".join(
        int(word[index:index + 8], 16).to_bytes(4, sys.byteorder) for index in range(0, width, 8)
    )
    return str(ipaddress.ip_address(packed)), int(port, 16)


def _parse_linux(stream, protocol, family):
    header = stream.readline(2048)
    if "local_address" not in header or not any(key in header for key in ("rem_address", "remote_address")):
        return [], False
    endpoints = []
    complete = True
    for index in range(_LINUX_LINE_LIMIT + 1):
        line = stream.readline(2048)
        if not line:
            break
        if index == _LINUX_LINE_LIMIT or not line.endswith("\n"):
            complete = False
            break
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 4:
            complete = False
            continue
        if fields[3] != ("0A" if protocol == "tcp" else "07"):
            continue
        try:
            if protocol == "udp":
                peer, peer_port = _proc_endpoint(fields[2], family)
                if peer_port or not ipaddress.ip_address(peer).is_unspecified:
                    continue
            address, port = _proc_endpoint(fields[1], family)
            uid = int(fields[7]) if len(fields) > 7 else None
            item = _endpoint(protocol, address, port, family=family, uid=uid)
        except (IndexError, OverflowError, ValueError):
            complete = False
            continue
        if len(endpoints) >= _ROW_LIMIT:
            complete = False
            break
        endpoints.append(item)
    return endpoints, complete


def _linux_snapshot():
    rows = []
    coverage = []
    for protocol, label in (("tcp", "TCP listeners"), ("udp", "Unconnected UDP bindings")):
        for suffix, family in (("", "ipv4"), ("6", "ipv6")):
            table = f"{protocol}{suffix}"
            try:
                with open(f"/proc/net/{table}", encoding="ascii", errors="replace") as stream:
                    data, complete = _parse_linux(stream, protocol, family)
                rows.extend(data)
                detail = (
                    "Read the kernel socket table for the current network namespace." if complete else
                    "Some rows could not be captured or interpreted in the current network namespace."
                )
            except OSError:
                complete, detail = False, "The kernel socket table is unavailable in the current network namespace."
            coverage.append(_coverage(f"linux-{table}", f"{label} ({family.upper()})", complete, detail))
    return rows, coverage


def _parse_windows(snapshot):
    endpoints = []
    coverage = []
    for protocol, label in (("tcp", "TCP listeners"), ("udp", "UDP bindings")):
        rows = snapshot.get(protocol) if isinstance(snapshot, dict) else None
        complete = isinstance(rows, list) and len(rows) <= _ROW_LIMIT
        detail = "The Windows endpoint table is unavailable to the Wardr account."
        if isinstance(rows, list):
            for row in rows[:_ROW_LIMIT]:
                try:
                    if not isinstance(row.get("LocalAddress"), str):
                        raise ValueError("Invalid Windows endpoint")
                    endpoints.append(_endpoint(protocol, row["LocalAddress"], row["LocalPort"], pid=row.get("OwningProcess")))
                except (AttributeError, KeyError, TypeError, ValueError):
                    complete = False
            detail = "Read the local Windows endpoint table." if complete else "Some Windows endpoint rows could not be captured or interpreted."
        coverage.append(_coverage(f"windows-{protocol}", label, complete, detail))
    return endpoints, coverage


def _windows_snapshot():
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    encoded = base64.b64encode(_WINDOWS_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        snapshot = json.loads(_command_output(
            str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded, timeout=12,
        ))
    except (OSError, RecursionError, ValueError):
        snapshot = None
    return _parse_windows(snapshot)


def collect_exposure() -> dict:
    """Describe local bind scope based on socket tables, independently of reachability."""
    system = platform.system()
    collector = {"Darwin": _mac_snapshot, "Linux": _linux_snapshot, "Windows": _windows_snapshot}.get(system)
    if collector is None:
        rows, coverage = [], [_coverage("platform", "Endpoint tables", False, "The current platform is unsupported.")]
    else:
        rows, coverage = collector()
    unique = {tuple(item.items()): item for item in rows}
    listeners = sorted(
        unique.values(),
        key=lambda item: (_SCOPE_ORDER[item["scope"]], item["protocol"], item["port"], item["family"],
                          item["address"], item.get("pid", 0), item.get("uid", -1), item.get("process", "")),
    )
    if len(listeners) > _ROW_LIMIT:
        listeners = listeners[:_ROW_LIMIT]
        coverage.append(_coverage("display-limit", "Snapshot size", False, "The total endpoint limit was reached."))
    if all(source["available"] for source in coverage):
        state = "complete"
    else:
        state = "partial" if listeners or any(source["available"] for source in coverage) else "unavailable"
    summary = {scope: 0 for scope in _SCOPE_ORDER}
    for item in listeners:
        summary[item["scope"]] += 1
    return {
        "collected_at": _utc(),
        "platform": "macOS" if system == "Darwin" else system,
        "state": state,
        "coverage": coverage,
        "listeners": listeners,
        "summary": {"total": len(listeners), **summary},
    }
