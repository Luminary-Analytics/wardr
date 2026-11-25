"""Versioned release notes and 'What's New?' modal state for Wardr."""

from __future__ import annotations

from . import updater


RELEASES: tuple[dict, ...] = (
    {
        "version": "0.4.3",
        "date": "2026-11-25",
        "title": "Guided Fix-All-to-Green Checklist & Unverified Check Resolution",
        "summary": "Any non-Green scan now pops up a unified Fix All \u2192 Go Green flow that auto-fixes eligible issues first, then opens a guided checklist with direct OS Settings links, how-to guides, individual checkboxes, and Select All to reach 100% Green in one session.",
        "highlights": [
            {
                "tag": "New",
                "title": "Unified Fix All → Go Green Flow on Every Non-Green Scan",
                "detail": "Whenever your device is Yellow or Red (including manual or unverified checks), a prominent Fix All → Go Green button appears right on the scan completion modal and Overview hero banner.",
            },
            {
                "tag": "New",
                "title": "Guided Manual Checklist with Quick OS Settings Links & Select All",
                "detail": "Auto-fixable issues run automatically first, then any remaining manual or unverified items open in a clean checklist with one-click Windows/macOS Settings shortcuts, official guides, individual checkboxes, and Select All → Mark fixed.",
            },
            {
                "tag": "Improved",
                "title": "Evidence-Tracked Verification for Unverified Checks",
                "detail": "Manual and unverified checks can now be confirmed in batch to reach 100% Green, while Wardr automatically re-alerts if the underlying system evidence ever changes on a future scan.",
            },
        ],
    },
    {
        "version": "0.4.2",
        "date": "2026-11-25",
        "title": "Seamless OAuth Auto-Focus & True One-Click Scan and Fix-to-Green",
        "summary": "Completing Google or Microsoft sign-in now automatically unlocks and raises the native Wardr desktop app, Run Scan starts in a single click with no scrolling, and a prominent Fix-to-Green CTA appears right on the Overview hero.",
        "highlights": [
            {
                "tag": "Improved",
                "title": "Seamless OAuth Auto-Unlock & Window Focus",
                "detail": "Finishing Google or Microsoft sign-in in your browser now automatically unlocks Wardr in under a second and brings the native desktop app right back to the front—no localhost links or extra clicks.",
            },
            {
                "tag": "Improved",
                "title": "True One-Click Run Scan (Zero Scrolling)",
                "detail": "Clicking Run Scan now starts the recommended Medium scan immediately in one click, with a compact Depth selector right next to it if you want Light or Heavy scans.",
            },
            {
                "tag": "New",
                "title": "One-Click Fix-to-Green Button on Overview Hero",
                "detail": "Whenever Wardr finds open issues, a glowing green Fix & Protect / Open Settings CTA appears right at the top of the Overview banner so reaching 100% Green is always one click away.",
            },
        ],
    },
    {
        "version": "0.4.1",
        "date": "2026-11-25",
        "title": "Native Desktop Apps, System Tray & Stateless Google Sign-In",
        "summary": "Wardr now runs as a true native desktop application on Windows, macOS, and Linux with no console window, system tray background monitoring, redesigned sign-in consent UX, and stateless PKCE Google Sign-In.",
        "highlights": [
            {
                "tag": "New",
                "title": "Native Desktop Apps for Windows, macOS & Linux",
                "detail": "Wardr now launches in its own lightweight native window (Edge WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux) with zero console or CMD prompt windows.",
            },
            {
                "tag": "New",
                "title": "System Tray & Menu Bar Background Monitoring",
                "detail": "Closing the Wardr window keeps continuous security scanning active in your system tray or menu bar, with single-instance focus and seamless in-place update restarts.",
            },
            {
                "tag": "New",
                "title": "Stateless PKCE Google Sign-In (Zero Client Secrets)",
                "detail": "Added a zero-retention PKCE S256 OAuth broker on api.getwardr.com so Continue with Google works cleanly without embedding any OAuth secrets in desktop binaries.",
            },
            {
                "tag": "Improved",
                "title": "Clearer Sign-In Consent & Scrollable Account Modal",
                "detail": "Moved the required Privacy Policy & Terms checkbox above the sign-in buttons, clearly separated optional telemetry toggles, and fixed modal clipping on smaller screens.",
            },
        ],
    },
    {
        "version": "0.4.0",
        "date": "2026-11-22",
        "title": "Purple-Team Self-Pen-Test, Supply-Chain Scanner, Accounts & Hardened Telemetry",
        "summary": "Major security upgrade adding authorized local self-pen-testing, compromised npm/framework exploit detection, a Dual-View Defense Matrix, Wardr Accounts with Google/Microsoft SSO, central opt-in diagnostics, and comprehensive security-audit hardening.",
        "highlights": [
            {
                "tag": "New",
                "title": "Authorized Local Self-Pen-Test Lab + One-Click Hardening",
                "detail": "Safely simulates 6 real attacker techniques (exposed AI/database ports, infostealer secret harvest, startup backdoors, PATH hijacks, firewall boundaries, and live tamper canaries) with animated Fix & Harden verification.",
            },
            {
                "tag": "New",
                "title": "Compromised Package & Exploit Scanner (NPM, React2Shell, PHP2Shell)",
                "detail": "Scans your local repos and installed packages for compromised npm packages, malicious postinstall hooks, React2Shell (CVE-2025-55182), PHP-CGI/PHP2Shell (CVE-2024-4577), Next.js middleware bypass, and Log4Shell.",
            },
            {
                "tag": "New",
                "title": "Everyday vs. Technical Defense Matrix",
                "detail": "Toggle instantly between plain-English threat explanations and MITRE ATT&CK / telemetry proof across all 6 core protection domains.",
            },
            {
                "tag": "New",
                "title": "Wardr Accounts, Google/Microsoft SSO & Central Opt-In Diagnostics",
                "detail": "Connect your Wardr account with OAuth 2.0 + PKCE SSO, explicit Privacy Policy & Terms consent, and strictly redacted opt-in system & scan diagnostics with live payload preview.",
            },
            {
                "tag": "Improved",
                "title": "Security Audit Hardening, Queued OS Updates & GPU Performance",
                "detail": "Completed full security-audit remediations (single-use auth nonces, IP-pinned TLS, Fleet rate-limiting, feed anti-rollback), queued OS updates for Green Protected status, and near-zero idle CPU/GPU usage.",
            },
        ],
    },
    {
        "version": "0.3.1",
        "date": "2026-11-21",
        "title": "Wardr Fleet Control Plane, RBAC & Continuous Agent",
        "summary": "Added the self-hostable Wardr Fleet control plane, role-based access control, agent enrollment, and fleet Web Console.",
        "highlights": [
            {
                "tag": "New",
                "title": "Self-Hosted Wardr Fleet & RBAC",
                "detail": "Enroll servers and workstations into a centralized control plane with allowlisted remote actions and full audit history.",
            },
        ],
    },
    {
        "version": "0.3.0",
        "date": "2026-11-21",
        "title": "3-Tier AI Protection & Visual Security Reports",
        "summary": "Introduced Tier 1 Always-On Radar, Tier 2 Free Cloud AI Offload, Tier 3 Heavy Local AI, and Red/Amber/Green visual security reports.",
        "highlights": [
            {
                "tag": "New",
                "title": "Red / Amber / Green Shield & Interactive Visual Report",
                "detail": "At-a-glance protection verdict with continuous sweeping radar, active threats panel, and printable/exportable RAG security reports.",
            },
            {
                "tag": "New",
                "title": "Light, Medium & Heavy Scan Profiles",
                "detail": "Choose scan depth with transparent benefit and CPU/battery trade-off guidance before running.",
            },
        ],
    },
)


def current_release() -> dict:
    version = updater.current_version()
    for rel in RELEASES:
        if rel["version"] == version:
            return dict(rel)
    latest = dict(RELEASES[0])
    if version and version != "development":
        latest["version"] = version
    return latest


def whats_new_payload(last_seen_version: str | None) -> dict:
    current = current_release()
    version = current["version"]
    should_show = last_seen_version != version
    return {
        "current_version": version,
        "last_seen_version": last_seen_version,
        "should_show": should_show,
        "latest": current,
        "history": [dict(r) for r in RELEASES],
    }
