"""Read-only host posture checks and Wardr's allowlisted local repair."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import socket
import stat
import subprocess
from xml.parsers.expat import ExpatError


_MAX_CACHE_AGE = timedelta(days=7)
_SSH_ID = "ssh-directory-permissions"
_SSH_IDENTITY_ID = "ssh-identity-permissions"
_SSH_AUTHORIZED_KEYS_ID = "ssh-authorized-keys-permissions"
_SSH_FILE_CHECKS = {
    _SSH_IDENTITY_ID: (
        ("id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_mldsa44_ed25519"),
        0o077,
    ),
    _SSH_AUTHORIZED_KEYS_ID: (("authorized_keys", "authorized_keys2"), 0o022),
}
_SSH_GUIDE = ("OpenSSH file permissions", "https://man.openbsd.org/ssh#FILES")
_MAC_UPDATES = ("Apple Software Update", "https://support.apple.com/guide/mac-help/mchla7037245/mac")
_WINDOWS_UPDATES = ("Windows Update", "https://learn.microsoft.com/windows/deployment/update/how-windows-update-works")
_APT_UPDATES = ("Ubuntu security updates", "https://documentation.ubuntu.com/security/security-updates/")
_DNF_UPDATES = ("DNF security advisories", "https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html")
_PATCH_RISK = "Missing vendor patches can leave publicly known vulnerabilities exploitable."


def _finding(check_id, title, category, severity, status, evidence, risk, remediation,
             reference=None, can_fix=False):
    return {
        "id": check_id,
        "title": title,
        "category": category,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "risk": risk,
        "remediation": remediation,
        "can_fix": can_fix,
        "references": [] if reference is None else [{"label": reference[0], "url": reference[1]}],
    }


def _run(*args, timeout=4):
    env = os.environ.copy()
    if os.name == "posix":
        env["LC_ALL"] = "C"
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=env,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return result.stdout.decode("utf-8-sig", errors="replace")
    return None


def _json_object(output):
    try:
        value = json.loads(output) if output else None
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _date(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return None


def _fresh(date):
    if date is None:
        return False
    return -timedelta(minutes=10) <= datetime.now(timezone.utc) - date <= _MAX_CACHE_AGE


def _summarize(names):
    visible = ", ".join(name[:150] for name in names[:4])
    if len(names) > 4:
        return f"{visible}, and {len(names) - 4} more"
    return visible


@contextmanager
def _ssh_directory():
    # The account database identifies the process user's own home even if HOME
    # is supplied by a caller, development environment, or service manager.
    import pwd

    uid = os.geteuid()
    home = Path(pwd.getpwuid(uid).pw_dir)
    if not home.is_absolute() or home == Path("/"):
        raise PermissionError("Account home is unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(home / ".ssh", flags)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid:
            raise PermissionError("Directory ownership does not match the process user")
        yield fd, stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def _can_repair_ssh():
    return os.geteuid() != 0 and os.geteuid() == os.getuid()


def _acl_absent(fd):
    if platform.system() == "Linux":
        # chmod can rewrite the POSIX access-ACL mask. Also refuse visible
        # ACLs from filesystems that expose a different access-control format.
        try:
            os.getxattr(fd, "system.posix_acl_access")
        except AttributeError:
            return False
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                return False
        else:
            return False
        try:
            return not any("acl" in name or name == "system.cifs_ntsd" for name in os.listxattr(fd))
        except (AttributeError, OSError):
            return False
    if platform.system() == "Darwin":
        import ctypes

        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.acl_get_fd.argtypes = [ctypes.c_int]
            libc.acl_get_fd.restype = ctypes.c_void_p
            libc.acl_free.argtypes = [ctypes.c_void_p]
            ctypes.set_errno(0)
            acl = libc.acl_get_fd(fd)
            if not acl:
                return ctypes.get_errno() == errno.ENOENT
            libc.acl_free(acl)
        except (AttributeError, OSError):
            pass
    return False


def _ssh_check():
    can_fix = False
    try:
        with _ssh_directory() as (fd, mode):
            evidence = f"The current account's ~/.ssh directory has POSIX mode {mode:04o}."
            no_acl = _acl_absent(fd)
            if mode & 0o077:
                status = "fail"
                can_fix = no_acl and _can_repair_ssh()
            else:
                status = "pass" if no_acl else "unknown"
            if not no_acl:
                evidence += " Review extended directory permissions manually."
    except FileNotFoundError:
        status, evidence = "not_applicable", "No ~/.ssh directory was found for the process account."
    except (OSError, KeyError):
        status, evidence = "unknown", "Wardr could not safely inspect a real ~/.ssh directory owned by this account."
    finding = _finding(
        _SSH_ID, "SSH directory permissions", "Access", "medium", status, evidence,
        "Group or other access can expose SSH metadata. Write access can let another account alter SSH configuration.",
        "Remove group and other access from your own ~/.ssh directory. Review file permissions separately.",
        _SSH_GUIDE, can_fix,
    )
    if can_fix:
        finding["fix_description"] = "Remove group and other permissions from the SSH directory itself."
    return finding


def _require_ssh_file(info, reference):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (reference.st_dev, reference.st_ino)):
        raise PermissionError("SSH file is unsupported or has changed")


@contextmanager
def _ssh_files(names):
    with _ssh_directory() as (directory, mode), ExitStack() as stack:
        files, skipped = [], []
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        for name in names:
            try:
                expected = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                skipped.append(name)
                continue

            try:
                _require_ssh_file(expected, expected)
                fd = os.open(name, flags, dir_fd=directory)
                stack.callback(os.close, fd)
                observed = os.fstat(fd)
                _require_ssh_file(observed, expected)
            except OSError:
                skipped.append(name)
            else:
                files.append((name, fd, observed))
        yield directory, mode, files, skipped


def _ssh_file_check(check_id):
    names, mask = _SSH_FILE_CHECKS[check_id]
    status, evidence, can_fix = "unknown", "The current account's SSH files could not be safely inspected.", False
    try:
        with _ssh_files(names) as (directory, mode, files, skipped):
            weak = [f"{name} ({stat.S_IMODE(info.st_mode):04o})" for name, _, info in files if info.st_mode & mask]
            unverified = sorted(skipped + [name for name, fd, _ in files if not _acl_absent(fd)])
            if weak:
                status, evidence = "fail", f"Permissions require attention on {_summarize(weak)}."
                can_fix = (not unverified and not (mode & 0o022) and _can_repair_ssh() and _acl_absent(directory))
                if not can_fix:
                    evidence += " Automatic repair requires a directory that only you can write and files without extended ACLs."
            elif files:
                status, evidence = "pass", "The standard SSH files found use the expected POSIX permissions."
            if unverified:
                if not weak:
                    status, evidence = "unknown", "The allowed modes could not be verified for every standard SSH file."
                evidence += f" Review {_summarize(unverified)} manually."
            elif not files:
                status, evidence = "not_applicable", "No matching standard files were found in this account's ~/.ssh directory."
    except FileNotFoundError:
        status, evidence = "not_applicable", "No ~/.ssh directory was found for the process account."
    except (OSError, KeyError):
        pass

    if check_id == _SSH_IDENTITY_ID:
        title = "SSH identity file permissions"
        risk = "Accessible private identities may be exposed to other local accounts. OpenSSH can refuse to use them."
        remediation = "Remove all group and other permissions from the listed standard SSH identity files."
        effect = "Remove group and other permissions from the affected standard SSH identity files."
    else:
        title = "SSH authorized keys permissions"
        risk = "Group or other write access can let another local account change which SSH keys can sign in."
        remediation = "Remove group and other write permissions from the listed authorized keys files."
        effect = "Remove group and other write permissions from the affected authorized keys files."
    finding = _finding(check_id, title, "Access", "high", status, evidence, risk, remediation, _SSH_GUIDE, can_fix)
    if can_fix:
        finding["fix_description"] = effect
    return finding


def _repair_ssh_files(check_id):
    names, mask = _SSH_FILE_CHECKS[check_id]
    changed = 0
    try:
        with _ssh_files(names) as (directory, mode, files, skipped):
            if skipped or mode & 0o022 or not _acl_absent(directory):
                raise PermissionError("The SSH directory or a standard file requires manual review")
            if any(not _acl_absent(fd) for _, fd, _ in files):
                raise PermissionError("An SSH file has an extended or unavailable ACL")
            for name, fd, expected in files:
                current = os.fstat(fd)
                _require_ssh_file(current, expected)
                if current.st_mode & mask:
                    current_path = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    _require_ssh_file(current_path, current)
                    if not _acl_absent(fd):
                        raise PermissionError("File ACL changed")
                    os.fchmod(fd, stat.S_IMODE(current.st_mode) & ~mask)
                    changed += 1
                    updated = os.fstat(fd)
                    _require_ssh_file(updated, current)
                    if updated.st_mode & mask or not _acl_absent(fd):
                        raise PermissionError("Could not verify the updated SSH file")
    except (OSError, KeyError):
        return {"ok": False, "message": "Wardr could not verify all SSH file permissions. Review the updated checklist.",
                "check": _ssh_file_check(check_id)}
    check = _ssh_file_check(check_id)
    if check["status"] != "pass":
        return {"ok": False, "message": "Wardr could not verify the current SSH files. Review the updated checklist.",
                "check": check}
    message = "Tightened permissions on the affected SSH files." if changed else "SSH file permissions already meet this check."
    return {"ok": True, "message": message, "check": check}


def _repair_ssh_directory():
    try:
        with _ssh_directory() as (fd, mode):
            if not _acl_absent(fd):
                raise PermissionError("Directory ACL requires manual review")
            changed = bool(mode & 0o077)
            if changed:
                os.fchmod(fd, mode & ~0o077)
            observed = os.fstat(fd)
            if observed.st_uid != os.geteuid() or observed.st_mode & 0o077 or not _acl_absent(fd):
                raise PermissionError("Could not verify the updated SSH directory")
    except (OSError, KeyError):
        return {"ok": False, "message": "Wardr could not verify a safe permission change for ~/.ssh.",
                "check": _ssh_check()}
    check = _ssh_check()
    if check["status"] != "pass":
        return {"ok": False, "message": "The ~/.ssh state changed. Rescan before retrying.", "check": check}
    message = "Removed group and other access from ~/.ssh." if changed else "~/.ssh already has private permissions."
    return {"ok": True, "message": message, "check": check}


def apply_fix(check_id):
    """Apply only an explicit Wardr repair and return its verified result."""
    if platform.system() not in ("Darwin", "Linux") or not _can_repair_ssh():
        return {"ok": False, "message": "No automatic fix is available for this check and account."}
    if check_id == _SSH_ID:
        return _repair_ssh_directory()
    if check_id in _SSH_FILE_CHECKS:
        return _repair_ssh_files(check_id)
    from . import remediation
    if check_id in remediation.ALL_FIX_IDS:
        return remediation.apply_fix(check_id)
    return {"ok": False, "message": "No automatic fix is available for this check and account."}


def _unix_ssh_checks():
    return [_ssh_check(), *(_ssh_file_check(check_id) for check_id in _SSH_FILE_CHECKS)]


def _macos_checks():
    firewall = (
        "macos-firewall", "Application firewall", "Network", "medium",
        "An inactive firewall can leave locally listening apps reachable on untrusted networks.",
        "Open System Settings → Network → Firewall. Review sharing and server access before enabling it.",
        ("Apple firewall settings", "https://support.apple.com/guide/mac-help/mh34041/mac"),
    )
    filevault = (
        "macos-filevault", "FileVault protection", "Data protection", "high",
        "FileVault ties access to protected volume contents to authorized credentials.",
        "Review your recovery options, then turn on FileVault in System Settings → Privacy & Security.",
        ("Apple FileVault settings", "https://support.apple.com/guide/mac-help/mh11785/mac"),
    )
    gatekeeper = (
        "macos-gatekeeper", "Gatekeeper app assessments", "System hardening", "high",
        "Disabling Gatekeeper removes an assessment layer for downloaded software.",
        "Review the application security policy in System Settings → Privacy & Security.",
        ("Apple Gatekeeper guidance", "https://support.apple.com/guide/security/sec5599b66df/web"),
    )
    sip = (
        "macos-sip", "System Integrity Protection", "System hardening", "high",
        "Disabling System Integrity Protection weakens safeguards on protected system files and processes.",
        "Ask the Mac administrator to review and restore System Integrity Protection using Apple's recovery procedure.",
        ("Apple System Integrity Protection", "https://support.apple.com/en-us/102149"),
    )

    def read_check(spec, args, yes, no, enabled, disabled):
        check_id, title, category, severity, risk, remediation, reference = spec
        output = (_run(*args) or "").strip().lower()
        status, evidence = "unknown", "The operating system did not return a recognized status."
        if yes(output):
            status, evidence = "pass", enabled
        elif no(output):
            status, evidence = "fail", disabled
        return _finding(check_id, title, category, severity, status, evidence,
                        risk, remediation, reference)

    return [
        read_check(firewall, ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"),
                   lambda s: "state = 1" in s or "state = 2" in s, lambda s: "state = 0" in s,
                   "The macOS application firewall is enabled.", "The macOS application firewall is disabled."),
        read_check(filevault, ("/usr/bin/fdesetup", "status"), lambda s: s == "filevault is on.",
                   lambda s: s == "filevault is off.", "FileVault reports that protection is on.",
                   "FileVault reports that protection is off."),
        read_check(gatekeeper, ("/usr/sbin/spctl", "--status"), lambda s: s == "assessments enabled",
                   lambda s: s == "assessments disabled", "Gatekeeper reports assessments enabled.",
                   "Gatekeeper reports assessments disabled."),
        read_check(sip, ("/usr/bin/csrutil", "status"), lambda s: s == "system integrity protection status: enabled.",
                   lambda s: s == "system integrity protection status: disabled.",
                   "System Integrity Protection is enabled.", "System Integrity Protection is disabled."),
        *_macos_patches(),
    ]


def _patches(check_id, status, evidence, remediation, reference, title="Operating system updates", severity="high"):
    return _finding(check_id, title, "Updates", severity, status, evidence, _PATCH_RISK, remediation, reference)


def _macos_patches():
    raw = _run("/usr/bin/defaults", "export", "/Library/Preferences/com.apple.SoftwareUpdate", "-")
    try:
        cache = plistlib.loads(raw.encode("utf-8")) if raw else {}
    except (ValueError, plistlib.InvalidFileException, ExpatError):
        cache = {}
    if not isinstance(cache, dict):
        cache = {}
    date = _date(cache.get("LastSuccessfulDate"))
    major = platform.mac_ver()[0].split(".")[0]
    recommendations = cache.get("RecommendedUpdates")
    status, evidence = "unknown", "A recent, readable Software Update cache was unavailable."
    if isinstance(recommendations, list) and major.isdecimal():
        pending = sorted({
            item["Display Version"] for item in recommendations
            if isinstance(item, dict) and isinstance(item.get("Display Version"), str)
            and item["Display Version"].startswith(major + ".")
            and (
                str(item.get("Identifier", "")).startswith("MSU_UPDATE_")
                or str(item.get("Display Name", "")).startswith("macOS ")
            )
        })
        if pending:
            age = f" recorded on {date.date().isoformat()} UTC" if date else ""
            evidence = f"The local Software Update cache{age} lists macOS {_summarize(pending)} for this release track."
            if _fresh(date):
                status = "fail"
            else:
                evidence += " Refresh Software Update to confirm that the listing is current."
        elif _fresh(date):
            status = "pass"
            evidence = f"The cache from {date.date().isoformat()} UTC lists no macOS update for this release track."
    background = cache.get("CriticalUpdateInstall")
    background_status = "unknown"
    background_evidence = "Wardr could not read the critical background update preference."
    if isinstance(background, bool):
        background_status = "pass" if background else "fail"
        action = "enables" if background else "disables"
        background_evidence = f"The local Software Update preference {action} critical background updates."
    return [
        _patches("macos-pending-updates", status, evidence,
                 "Open System Settings → General → Software Update. Verify and install applicable updates.", _MAC_UPDATES),
        _finding("macos-background-updates", "Background security updates", "Updates", "medium",
                 background_status, background_evidence, _PATCH_RISK,
                 "Enable security and system-file updates under Software Update → Automatic Updates.",
                 ("Apple background updates", "https://support.apple.com/en-us/101591")),
    ]


_WINDOWS_POSTURE = r"""
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$result = @{}
try {
    $result.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        @{name = [string]$_.Name; enabled = [string]$_.Enabled}
    })
} catch {}
try {
    $defender = Get-MpComputerStatus
    $result.defender = @{mode = [string]$defender.AMRunningMode; realtime = $defender.RealTimeProtectionEnabled}
    if ($defender.AntivirusSignatureLastUpdated) {
        $result.defender.signatures = $defender.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')
    }
} catch {}
try {
    $result.bitlocker = [string](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
} catch {}
try {
    $result.smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
} catch {}
try {
    $result.uac = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA
} catch {}
try {
    $result.secureBoot = Confirm-SecureBootUEFI
} catch {}
try {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $policy = Get-ItemProperty $policyPath -ErrorAction SilentlyContinue
    $deny = $policy.fDenyTSConnections
    if ($null -eq $deny) { $deny = (Get-ItemProperty $serverPath).fDenyTSConnections }
    $nla = $policy.UserAuthentication
    if ($null -eq $nla) {
        $nla = (Get-ItemProperty "$serverPath\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
    }
    $result.rdp = @{deny = $deny; nla = $nla}
} catch {}
$result | ConvertTo-Json -Compress -Depth 3
"""

_WINDOWS_PATCH_QUERY = r"""
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$result = @{}
try {
    $last = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate
    if ($last) { $result.date = ([datetime]$last).ToString('yyyy-MM-ddTHH:mm:ss') + 'Z' }
} catch {}
try {
    $categoryIds = @('0fa1201d-4330-4fa8-8ae9-b877473b6441', 'e6cf1350-c01b-414d-a61f-263d14d133b4')
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $searcher.Online = $false
    $searcher.CanAutomaticallyUpgradeService = $false
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if ($search.ResultCode -eq 2) {
        $result.count = 0
        $result.items = @()
        foreach ($update in $search.Updates) {
            foreach ($category in $update.Categories) {
                if ($categoryIds -contains $category.CategoryID) {
                    $result.count += 1
                    if ($result.items.Count -lt 4) { $result.items += [string]$update.Title }
                    break
                }
            }
        }
    }
} catch {}
$result | ConvertTo-Json -Compress -Depth 3
"""


def _powershell(script, timeout):
    directory = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    if not directory.is_absolute():
        return {}
    binary = directory / "System32/WindowsPowerShell/v1.0/powershell.exe"
    output = _run(str(binary), "-NoProfile", "-NonInteractive", "-Command", script, timeout=timeout)
    return _json_object(output)


def _windows_patches():
    result = _powershell(_WINDOWS_PATCH_QUERY, timeout=8)
    count, date = result.get("count"), _date(result.get("date"))
    status, evidence = "unknown", "Windows Update did not return a recent, complete local catalog result."
    if type(count) is int and count >= 0:
        if count > 0:
            evidence = f"The Windows Update cache lists {count} pending security or critical update(s)."
            items = result.get("items")
            if isinstance(items, list) and items:
                evidence += f" {_summarize([title for title in items if isinstance(title, str)])}."
        if _fresh(date):
            status = "fail" if count else "pass"
            if count == 0:
                evidence = f"The Windows Update cache from {date.date().isoformat()} UTC lists no pending security or critical updates."
            else:
                evidence += f" Last successful automatic search was {date.date().isoformat()} UTC."
        elif count > 0:
            evidence += " Refresh Windows Update to verify that these results are current."
    return _patches("windows-pending-updates", status, evidence,
                    "Use Windows Update or the server's managed update service to check and install applicable updates.",
                    _WINDOWS_UPDATES)


def _windows_checks(values):
    profiles = {row.get("name"): row.get("enabled") for row in values.get("firewall") or [] if isinstance(row, dict)}
    required = ("Domain", "Private", "Public")
    disabled = [name for name in required if profiles.get(name) == "False"]
    if disabled:
        firewall_status, firewall_evidence = "fail", f"Disabled profiles in the active policy store: {', '.join(disabled)}."
    elif all(profiles.get(name) == "True" for name in required):
        firewall_status, firewall_evidence = "pass", "Domain, Private, and Public firewall profiles are enabled."
    else:
        firewall_status, firewall_evidence = "unknown", "Wardr could not confirm the state of all firewall profiles."
    checks = [_finding(
        "windows-firewall", "Windows Firewall profiles", "Network", "high", firewall_status, firewall_evidence,
        "A disabled profile can leave listening services exposed on its network.",
        "Review all profiles in Windows Security → Firewall & network protection or managed firewall policy.",
        ("Microsoft firewall profiles", "https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallprofile"),
    )]

    defender = values.get("defender") or {}
    active = defender.get("mode") == "Normal"
    malware_status, malware_evidence = "unknown", "Defender is inactive or could not be inspected. Verify any alternate endpoint protection."
    if active and isinstance(defender.get("realtime"), bool):
        malware_status = "pass" if defender["realtime"] else "fail"
        malware_evidence = f"Microsoft Defender is active. Real-time protection is {'on' if defender['realtime'] else 'off'}."
    defender_help = ("Microsoft Defender Antivirus", "https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows")
    checks.append(_finding(
        "windows-defender", "Defender real-time protection", "Malware protection", "high", malware_status,
        malware_evidence, "Inactive real-time protection can allow malware to run before a scheduled scan.",
        "Review Windows Security → Virus & threat protection and any managed antivirus policy.", defender_help,
    ))
    stamp = _date(defender.get("signatures"))
    if active and stamp and stamp <= datetime.now(timezone.utc):
        old = not _fresh(stamp)
        checks.append(_finding(
            "windows-defender-signatures", "Defender security intelligence", "Malware protection", "medium",
            "fail" if old else "pass", f"Defender last updated its security intelligence on {stamp.date().isoformat()} UTC.",
            "Older malware intelligence may miss newly identified threats.",
            "Check for protection updates under Windows Security → Virus & threat protection.", defender_help,
        ))
    else:
        checks.append(_finding(
            "windows-defender-signatures", "Defender security intelligence", "Malware protection", "medium",
            "unknown", "Wardr could not verify a security intelligence timestamp for an active Defender installation.",
            "Older malware intelligence may miss newly identified threats.",
            "Check your endpoint protection's update status.", defender_help,
        ))

    def setting(check_id, title, category, severity, current, secure, insecure, risk, remediation, reference):
        if type(current) is type(secure) and current == secure:
            status, evidence = "pass", f"Windows reports {title.lower()} is {'off' if secure is False else 'on'}."
        elif type(current) is type(insecure) and current == insecure:
            status, evidence = "fail", f"Windows reports {title.lower()} is {'off' if secure is not False else 'on'}."
        else:
            status, evidence = "unknown", "The operating system did not provide a recognized status."
        return _finding(check_id, title, category, severity, status, evidence, risk, remediation, reference)

    checks.extend([
        setting("windows-bitlocker", "System drive BitLocker protection", "Data protection", "high",
                values.get("bitlocker"), "On", "Off", "Data may be accessible if the system drive is lost or removed.",
                "Review recovery key storage, then enable device encryption or BitLocker for the system drive.",
                ("Microsoft BitLocker overview", "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/")),
        setting("windows-smb1", "SMBv1 server support", "Network", "high", values.get("smb1"), False, True,
                "The obsolete SMBv1 protocol lacks security protections available in newer SMB versions.",
                "Review dependencies on legacy file sharing, then disable SMBv1 server support through Windows administration.",
                ("Microsoft SMB guidance", "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3")),
        setting("windows-uac", "User Account Control", "Access", "high", values.get("uac"), 1, 0,
                "Turning off User Account Control weakens protection against unintended administrative changes.",
                "Restore User Account Control through device administration or managed security policy.",
                ("Microsoft UAC settings", "https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration")),
        setting("windows-secure-boot", "Secure Boot", "System hardening", "medium", values.get("secureBoot"), True, False,
                "Without Secure Boot, the host lacks signature enforcement during boot.",
                "Review Secure Boot support with your system administrator or device vendor.",
                ("Microsoft Secure Boot", "https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot")),
    ])
    rdp = values.get("rdp") or {}
    rdp_status, rdp_evidence = "unknown", "Wardr could not verify Remote Desktop's Network Level Authentication policy."
    if rdp.get("deny") == 1:
        rdp_status, rdp_evidence = "not_applicable", "Windows policy disallows Remote Desktop connections."
    elif rdp.get("deny") == 0:
        if rdp.get("nla") == 1:
            rdp_status, rdp_evidence = "pass", "Remote Desktop allows connections and requires Network Level Authentication."
        elif rdp.get("nla") == 0:
            rdp_status, rdp_evidence = "fail", "Remote Desktop allows connections without requiring Network Level Authentication."
    checks.append(_finding(
        "windows-rdp-nla", "Remote Desktop authentication", "Access", "high", rdp_status, rdp_evidence,
        "Without Network Level Authentication, Remote Desktop handles more of a connection before authenticating the user.",
        "Review client support, then require Network Level Authentication through Remote Desktop settings or Group Policy.",
        ("Microsoft Remote Desktop policies", "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-terminalserver"),
    ))
    return checks


def _linux_firewall():
    ufw = _run("/usr/sbin/ufw", "status")
    if ufw and ufw.splitlines()[0].strip() == "Status: active":
        status, evidence = "pass", "UFW reports an active host firewall."
    elif (_run("/usr/bin/firewall-cmd", "--state") or "").strip() == "running":
        status, evidence = "pass", "firewalld reports an active firewall service."
    else:
        rules = _json_object(_run("/usr/sbin/nft", "-j", "list", "ruleset")).get("nftables") or []
        chains = [item["chain"] for item in rules if isinstance(item, dict) and isinstance(item.get("chain"), dict)]
        policies = {(chain.get("family"), chain.get("policy")) for chain in chains if chain.get("hook") == "input"}
        drop_applies = ("inet", "drop") in policies or {("ip", "drop"), ("ip6", "drop")} <= policies
        if drop_applies:
            status, evidence = "pass", "nftables reports an inbound default-drop chain for IPv4 and IPv6."
        else:
            status, evidence = "unknown", "Wardr could not confirm an active inbound firewall policy. Local access may limit visibility."
    return _finding(
        "linux-firewall", "Host firewall", "Network", "medium", status, evidence,
        "An unfiltered host can expose listening services to unnecessary network traffic.",
        "Have the system administrator verify the active inbound policy and required service rules.",
    )


def _read_text(path, count=64):
    try:
        with Path(path).open(encoding="utf-8") as source:
            return source.read(count).strip()
    except (OSError, UnicodeError):
        return None


def _linux_aslr():
    value = _read_text("/proc/sys/kernel/randomize_va_space")
    status, evidence = {
        "2": ("pass", "The kernel reports full address-space layout randomization (mode 2)."),
        "1": ("fail", "The kernel reports partial address-space layout randomization (mode 1)."),
        "0": ("fail", "The kernel reports that address-space layout randomization is disabled."),
    }.get(value, ("unknown", "The kernel's address randomization setting was unavailable."))
    return _finding(
        "linux-aslr", "Address space randomization", "System hardening", "medium", status, evidence,
        "Reduced address randomization can make memory-corruption attacks easier to exploit.",
        "Ask the system administrator to review the host's kernel.randomize_va_space setting.",
        ("Linux kernel sysctl documentation", "https://docs.kernel.org/admin-guide/sysctl/kernel.html#randomize-va-space"),
    )


def _linux_link_protections():
    values = {key: _read_text(f"/proc/sys/fs/{key}") for key in ("protected_hardlinks", "protected_symlinks")}
    off = [key for key, value in values.items() if value == "0"]
    if off:
        status, evidence = "fail", f"Kernel link protection is disabled for {', '.join(off)}."
    elif all(value == "1" for value in values.values()):
        status, evidence = "pass", "Linux hard-link and symbolic-link protections are enabled."
    else:
        status, evidence = "unknown", "The kernel's link protection settings were unavailable or unrecognized."
    return _finding(
        "linux-link-protections", "Kernel link protections", "System hardening", "medium", status, evidence,
        "Weaker link protections allow more unsafe link operations across users in shared directories.",
        "Ask the administrator to review fs.protected_hardlinks and fs.protected_symlinks.",
        ("Linux filesystem sysctl documentation", "https://docs.kernel.org/admin-guide/sysctl/fs.html"),
    )


def _linux_mandatory_access():
    selinux = (_run("/usr/sbin/getenforce") or "").strip()
    apparmor = _read_text("/sys/module/apparmor/parameters/enabled")
    if selinux == "Enforcing":
        status, evidence = "pass", "SELinux reports an enforcing policy."
    elif apparmor == "Y":
        status, evidence = "pass", "AppArmor is enabled in this kernel. Profile coverage varies by application."
    elif selinux in {"Permissive", "Disabled"} and apparmor == "N":
        status, evidence = "fail", f"SELinux is {selinux.lower()} and AppArmor is disabled."
    else:
        status, evidence = "unknown", "Wardr could not confirm enforcement by SELinux or AppArmor."
    return _finding(
        "linux-mandatory-access", "Mandatory access controls", "System hardening", "medium", status, evidence,
        "Operating system confinement can limit the files and operations available to a compromised process.",
        "Review your distribution's SELinux or AppArmor policy, including coverage for exposed services.",
        ("Linux security module documentation", "https://docs.kernel.org/admin-guide/LSM/index.html"),
    )


def _linux_ssh_root():
    status, evidence = "unknown", "Wardr could not read the default OpenSSH server policy."
    server = Path("/usr/sbin/sshd")
    if not server.is_file():
        status, evidence = "not_applicable", "OpenSSH server was not found at the standard system path."
    else:
        # The server's test mode prints configuration without opening any listener.
        output = _run(str(server), "-T") or ""
        result = re.search(r"^permitrootlogin (\S+)$", output, re.MULTILINE)
        if result:
            value = result.group(1)
            if value == "yes":
                status, evidence = "fail", "The default OpenSSH policy allows direct root logins."
            elif value in {"no", "prohibit-password", "without-password", "forced-commands-only"}:
                status, evidence = "pass", f"The default OpenSSH policy restricts direct root login ({value})."
            evidence += " Per-connection overrides may differ."
    return _finding(
        "linux-ssh-root", "OpenSSH root login policy", "Access", "medium", status, evidence,
        "Unrestricted direct root logins give remote credentials access to the highest-privilege account.",
        "Review the default policy and Match overrides. Verify another administrative login path before making changes.",
        ("OpenSSH server configuration", "https://man.openbsd.org/sshd_config#PermitRootLogin"),
    )


def _apt_security_cache_date():
    try:
        timestamps = []
        for entry in Path("/var/lib/apt/lists").glob("*security*_InRelease"):
            timestamp = entry.stat().st_mtime
            timestamps.append(datetime.fromtimestamp(timestamp, timezone.utc))
        return min(timestamps, default=None)
    except OSError:
        return None


def _linux_patches():
    if Path("/usr/bin/apt-get").is_file():
        cache_date = _apt_security_cache_date()
        output = _run("/usr/bin/apt-get", "--simulate", "--with-new-pkgs", "--no-download",
                      "-o", "Debug::NoLocking=1", "upgrade", timeout=5)
        status, evidence = "unknown", "A recent local APT security index and a readable simulation were unavailable."
        if output is not None:
            packages = sorted({
                line.split()[1] for line in output.splitlines()
                if line.startswith("Inst ") and len(line.split()) > 1 and re.search(r"-security[\s/\])]", line, re.I)
            })
            if packages:
                evidence = f"APT's local simulation proposes {len(packages)} package update(s) from a security source: {_summarize(packages)}."
                if _fresh(cache_date):
                    status = "fail"
                else:
                    evidence += " The cached security indexes may be stale."
            elif _fresh(cache_date):
                status, evidence = "pass", "The APT simulation found no candidates labeled from a cached security source."
        return _patches(
            "linux-pending-updates", status, evidence,
            "Refresh package lists through the distribution's update tool and review security upgrades, including held packages.",
            _APT_UPDATES, title="Package security updates",
        )

    if Path("/usr/bin/dnf").is_file() or Path("/usr/bin/dnf5").is_file():
        if Path("/usr/bin/dnf5").is_file():
            output = _run("/usr/bin/dnf5", "--cacheonly", "advisory", "list", "--updates", "--security", timeout=5)
        else:
            output = _run("/usr/bin/dnf", "--cacheonly", "updateinfo", "list", "--updates", "--security", timeout=5)
        status, evidence = "unknown", "DNF cache freshness could not be verified."
        if output:
            advisories = sorted({
                line.split()[0] for line in output.splitlines() if re.search(r"\bsecurity\b", line, re.I)
                and re.match(r"^\S+-[0-9]", line)
            })
            if advisories:
                status = "fail"
                evidence = f"DNF's local cache lists {len(advisories)} security advisory candidate(s): {_summarize(advisories)}. Verify with refreshed metadata."
        return _patches(
            "linux-pending-updates", status, evidence,
            "Refresh repository metadata through your standard update process and review applicable security advisories.",
            _DNF_UPDATES, title="Package security updates",
        )

    return _patches(
        "linux-pending-updates", "unknown", "Wardr has no local update reader for this Linux package manager.",
        "Use the distribution's package manager and official advisories to review available security updates.",
        None, title="Package security updates",
    )


def scan():
    """Return a JSON-compatible, timestamped snapshot of this host."""
    from . import inventory, remediation

    system = platform.system()
    if system == "Darwin":
        checks = _macos_checks() + _unix_ssh_checks() + remediation.credential_checks()
        os_version = platform.mac_ver()[0]
    elif system == "Windows":
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(_windows_patches)
            checks = _windows_checks(_powershell(_WINDOWS_POSTURE, timeout=10))
            checks.append(pending.result())
        os_version = platform.version()
    elif system == "Linux":
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(_linux_patches)
            checks = [
                _linux_firewall(), _linux_aslr(), _linux_link_protections(),
                _linux_mandatory_access(), _linux_ssh_root(), *_unix_ssh_checks(),
                *remediation.credential_checks(), pending.result(),
            ]
        os_version = platform.release()
    else:
        os_version, checks = platform.release(), []
    checks.extend(inventory.scan_ai_surface())
    return {
        "platform": {"Darwin": "macOS"}.get(system, system),
        "os_version": os_version,
        "host": socket.gethostname(),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": checks,
    }
