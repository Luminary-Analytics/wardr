"""Non-destructive local attack-surface and TLS hygiene audit."""

from datetime import datetime, timezone
import socket
import ssl


_RISKY_SERVICES = {
    2375: ("Unencrypted Docker daemon API", "critical", "Disable TCP :2375 immediately and use local Unix sockets or mutual-TLS (:2376)."),
    2379: ("etcd key-value store", "critical", "Restrict etcd strictly to loopback or a private mTLS-authenticated control-plane network."),
    6379: ("Redis in-memory store", "high", "Bind Redis to 127.0.0.1, enable ACL/requirepass, and block port 6379 on external interfaces."),
    11211: ("Memcached server", "high", "Bind Memcached to 127.0.0.1 (-l 127.0.0.1) and disable UDP to prevent amplification and data exposure."),
    27017: ("MongoDB server", "high", "Bind MongoDB to 127.0.0.1 or a private subnet and enforce authentication and TLS."),
    9200: ("Elasticsearch HTTP API", "high", "Restrict Elasticsearch to localhost or enable TLS and role-based authentication."),
    11434: ("Ollama local AI server", "high", "Set OLLAMA_HOST=127.0.0.1:11434 so local models and APIs are not exposed on the network."),
    1234: ("LM Studio local AI server", "high", "Restrict LM Studio's local inference server to 127.0.0.1."),
    8188: ("ComfyUI local AI workflow server", "high", "Bind ComfyUI to 127.0.0.1 unless placed behind an authenticated reverse proxy."),
    5900: ("VNC / macOS Screen Sharing", "high", "Disable Screen Sharing / VNC unless required, or restrict port 5900 behind a host firewall or VPN/SSH tunnel."),
    3389: ("Remote Desktop Protocol (RDP)", "high", "Restrict RDP (port 3389) to a private VPN or subnet, require Network Level Authentication (NLA), and block public network exposure."),
    445: ("SMB file sharing", "medium", "Disable SMB file sharing if unused, keep SMBv1 disabled, and block port 445 on untrusted networks."),
    5432: ("PostgreSQL database", "medium", "Confirm PostgreSQL listen_addresses, pg_hba.conf, and firewall rules restrict access to trusted hosts."),
    3306: ("MySQL / MariaDB database", "medium", "Bind MySQL/MariaDB to 127.0.0.1 or a private subnet and verify TLS and host firewall rules."),
    6443: ("Kubernetes API server", "medium", "Verify RBAC, client certificate/OIDC auth, and network firewall restrictions on port 6443."),
}

_LOCAL_TLS_PORTS = (443, 8443, 9443, 6443)
_DEPRECATED_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _probe_loopback_tls(port: int, *, timeout: float = 1.5) -> dict | None:
    """Perform a strictly local-loopback TLS handshake to check protocol version and cert expiry."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                version = tls_sock.version() or "unknown"
                cert = tls_sock.getpeercert(binary_form=False) or {}
                not_after_raw = cert.get("notAfter")
                days_remaining = None
                if not_after_raw:
                    try:
                        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_raw), timezone.utc)
                        days_remaining = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
                    except (OSError, ValueError):
                        pass
                return {
                    "port": port,
                    "tls_version": version,
                    "deprecated_protocol": version in _DEPRECATED_TLS,
                    "days_remaining": days_remaining,
                }
    except (OSError, ssl.SSLError):
        return None


def audit_exposure(exposure_result: dict, *, probe_local_tls: bool = True) -> dict:
    """Analyze local socket exposure for risky non-loopback services and local TLS hygiene."""
    listeners = exposure_result.get("listeners", ()) if isinstance(exposure_result, dict) else ()
    service_findings = []
    seen_keys = set()
    tls_ports = []

    for row in listeners:
        port = row.get("port")
        protocol = str(row.get("protocol") or "tcp").lower()
        scope = row.get("scope")
        if protocol == "tcp" and port in _LOCAL_TLS_PORTS and port not in tls_ports:
            tls_ports.append(port)
        if scope not in ("wildcard", "interface"):
            continue
        spec = _RISKY_SERVICES.get(port)
        if spec is None:
            continue
        key = (port, scope)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        service_name, severity, remediation = spec
        service_findings.append({
            "id": f"surface-port-{port}",
            "service": service_name,
            "port": port,
            "protocol": protocol,
            "address": row.get("address"),
            "scope": scope,
            "process": row.get("process"),
            "severity": severity,
            "remediation": remediation,
        })

    tls_findings = []
    if probe_local_tls:
        for port in tls_ports[:4]:
            probed = _probe_loopback_tls(port)
            if probed is None:
                continue
            issues = []
            severity = "low"
            if probed["deprecated_protocol"]:
                issues.append(f"Negotiated deprecated protocol {probed['tls_version']}.")
                severity = "high"
            days = probed["days_remaining"]
            if days is not None and days < 0:
                issues.append("Local TLS certificate is expired.")
                severity = "high"
            elif days is not None and days <= 14:
                issues.append(f"Local TLS certificate expires in {days} day(s).")
                severity = max(severity, "medium", key=lambda s: ("low", "medium", "high").index(s))
            tls_findings.append({
                **probed,
                "status": "fail" if issues else "pass",
                "severity": severity if issues else "low",
                "issues": issues,
            })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    service_findings.sort(key=lambda item: (order[item["severity"]], item["port"]))
    return {
        "audited_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risky_services": service_findings,
        "local_tls": tls_findings,
        "summary": {
            "risky_service_count": len(service_findings),
            "tls_endpoints_checked": len(tls_findings),
            "tls_issues": sum(1 for item in tls_findings if item["status"] == "fail"),
        },
    }
