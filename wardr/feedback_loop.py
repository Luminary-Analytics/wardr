"""Automated feedback-to-release pipeline connecting live Threat Network telemetry to signed Wardr updates."""

from __future__ import annotations

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import tomllib
from urllib.parse import urlsplit

from . import feeds, updater


DEFAULT_API_URL = "https://api.getwardr.com"
_IO_TIMEOUT = 15
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")


class FeedbackLoopError(RuntimeError):
    """Could not fetch live telemetry signals or prepare the next release."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_text(value: object, limit: int = 160) -> str:
    """Strip control chars and markdown-breaking characters from untrusted remote strings."""
    raw = str(value or "")
    cleaned = "".join(ch if ch.isprintable() and ch not in ("\r", "\n", "\t") else " " for ch in raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = cleaned.replace("`", "'").replace("|", "/").replace("[", "(").replace("]", ")")
    return cleaned[:limit]


def _validate_server_url(url: str) -> str:
    cleaned = (url or DEFAULT_API_URL).strip().rstrip("/")
    parsed = urlsplit(cleaned)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise FeedbackLoopError("Server URL must be a valid HTTPS URL without embedded credentials.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise FeedbackLoopError("Remote Wardr API servers must use HTTPS.")
    return cleaned


def _http_get_json(base_url: str, path: str, *, bearer_token: str | None = None, timeout: int = _IO_TIMEOUT) -> dict:
    validated = _validate_server_url(base_url)
    parsed = urlsplit(validated)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    headers = {
        "User-Agent": f"Wardr-FeedbackLoop/{updater.current_version()}",
        "Accept": "application/json",
    }
    if bearer_token:
        if any(ch in bearer_token for ch in ("\r", "\n")):
            raise FeedbackLoopError("Admin Bearer token contains invalid control characters.")
        headers["Authorization"] = f"Bearer {bearer_token}"

    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise FeedbackLoopError(f"Response from {path} exceeded size limit.")
        if resp.status == 401:
            raise FeedbackLoopError(f"Unauthorized (HTTP 401) calling {path}. Verify WARDR_ADMIN_TOKEN.")
        if resp.status != 200:
            raise FeedbackLoopError(f"API returned HTTP {resp.status} for {path}.")
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise FeedbackLoopError(f"Invalid JSON returned by {path}.") from exc
        if not isinstance(doc, dict):
            raise FeedbackLoopError(f"Expected JSON object from {path}.")
        return doc
    except OSError as exc:
        raise FeedbackLoopError(f"Could not reach {validated}{path}: {exc}") from exc
    finally:
        conn.close()


def fetch_live_signals(server_url: str = DEFAULT_API_URL, *, admin_token: str) -> dict:
    """Fetch live health, aggregated telemetry summary, and clustered zero-day reports."""
    token = (admin_token or "").strip()
    if not token:
        raise FeedbackLoopError("Set WARDR_ADMIN_TOKEN to query live central telemetry and clusters.")
    validated = _validate_server_url(server_url)
    health = _http_get_json(validated, "/v1/health")
    summary = _http_get_json(validated, "/api/v1/telemetry/summary", bearer_token=token)
    clusters_doc = _http_get_json(validated, "/v1/clusters", bearer_token=token)
    clusters = clusters_doc.get("clusters") if isinstance(clusters_doc.get("clusters"), list) else []
    return {
        "fetched_at": _utc_now(),
        "server_url": validated,
        "health": health,
        "summary": summary,
        "clusters": clusters,
    }


def next_version(current: str, bump: str = "patch") -> str:
    match = _VERSION_RE.fullmatch(current.strip())
    if not match:
        raise FeedbackLoopError(f"Unsupported semantic version: {current!r}")
    major, minor, patch = (int(g) for g in match.groups())
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "major":
        return f"{major + 1}.0.0"
    raise FeedbackLoopError("Choose bump type: patch, minor, or major.")


def _build_draft_feed(supply_chain_matches: list[dict], *, feed_version: str) -> dict:
    now = _utc_now()
    advisories: list[dict] = []
    seen_ids: set[str] = set()
    for idx, row in enumerate(supply_chain_matches[:25], start=1):
        pkg = _clean_text(row.get("package") or "", 80)
        cve = _clean_text(row.get("cve") or "", 40)
        adv_id = cve if re.fullmatch(r"[A-Za-z0-9._-]{4,40}", cve) else f"WARDR-{feed_version}-{idx:02d}"
        if adv_id in seen_ids or not pkg:
            continue
        seen_ids.add(adv_id)
        advisories.append({
            "id": adv_id,
            "modified": now,
            "summary": f"Community-observed supply-chain match for {pkg} ({_clean_text(row.get('kind') or 'package', 40)}).",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": pkg},
                    "versions": ["0.0.0"],
                }
            ],
        })
    draft = {
        "schema_version": 1,
        "channel": "community",
        "version": feed_version,
        "published_at": now,
        "rules": [],
        "advisories": advisories,
    }
    # Validate against Wardr's strict Zero-RCE feed validator before emitting
    feeds._parse_feed_document(json.dumps(draft).encode("utf-8"))
    return draft


def build_triage_digest(
    signals: dict,
    *,
    current_version: str | None = None,
    min_check_failures: int = 3,
    min_pentest_exposures: int = 2,
) -> dict:
    """Turn raw central telemetry + zero-day clusters into an actionable release triage digest."""
    cur_ver = current_version or updater.current_version()
    if not _VERSION_RE.fullmatch(cur_ver):
        cur_ver = "0.4.0"

    summary = signals.get("summary") if isinstance(signals.get("summary"), dict) else {}
    clusters = signals.get("clusters") if isinstance(signals.get("clusters"), list) else []
    health = signals.get("health") if isinstance(signals.get("health"), dict) else {}

    escalated_clusters = [
        c for c in clusters
        if isinstance(c, dict) and (c.get("triage_status") == "escalated" or int(c.get("zero_day_votes") or 0) >= 2)
    ]
    open_clusters = [
        c for c in clusters
        if isinstance(c, dict) and c.get("triage_status") in ("open", "escalated")
    ]

    failing_checks = [
        c for c in (summary.get("top_failing_checks") or [])
        if isinstance(c, dict) and c.get("id")
    ]
    failing_checks.sort(
        key=lambda r: (int(r.get("fail_count") or 0) - int(r.get("handled_count") or 0), int(r.get("fail_count") or 0)),
        reverse=True,
    )
    high_impact_checks = [
        c for c in failing_checks
        if (int(c.get("fail_count") or 0) - int(c.get("handled_count") or 0)) >= min_check_failures
    ]

    pentest_exposures = [
        p for p in (summary.get("top_pentest_exposures") or [])
        if isinstance(p, dict) and p.get("id")
    ]
    high_impact_pentest = [
        p for p in pentest_exposures
        if int(p.get("count") or 0) >= min_pentest_exposures
    ]

    risky_ports = [
        r for r in (summary.get("top_exposed_risky_ports") or [])
        if isinstance(r, dict) and r.get("port")
    ]
    supply_chain_matches = [
        m for m in (summary.get("top_supply_chain_matches") or [])
        if isinstance(m, dict) and (m.get("package") or m.get("cve"))
    ]

    needs_attention = bool(
        escalated_clusters or supply_chain_matches or high_impact_checks or high_impact_pentest or risky_ports
    )
    recommended_version = next_version(cur_ver, "patch")

    # Build ready-to-edit changelog highlights grounded in live telemetry
    highlights: list[dict] = []
    if escalated_clusters:
        top_title = _clean_text(escalated_clusters[0].get("sample_title") or "Escalated zero-day signal", 90)
        highlights.append({
            "tag": "Security",
            "title": f"Rapid mitigation for {len(escalated_clusters)} escalated Threat Network cluster(s)",
            "detail": f"Added targeted detection and hardening guidance addressing community-reported anomalies including: {top_title}.",
        })
    if supply_chain_matches:
        pkgs = ", ".join(_clean_text(m.get("package") or m.get("cve"), 40) for m in supply_chain_matches[:3])
        highlights.append({
            "tag": "Security",
            "title": "Updated supply-chain & compromised package signatures",
            "detail": f"Expanded detection and remediation guidance for actively observed ecosystem matches ({pkgs}).",
        })
    if high_impact_checks:
        top_ids = ", ".join(_clean_text(c.get("id"), 40) for c in high_impact_checks[:3])
        highlights.append({
            "tag": "Improved",
            "title": "Enhanced auto-remediation for top failing posture checks",
            "detail": f"Improved guided fixes and verification reliability for the most frequent failing checks ({top_ids}).",
        })
    if high_impact_pentest or risky_ports:
        items = [_clean_text(p.get("id"), 40) for p in high_impact_pentest[:2]]
        if risky_ports:
            items.append(f"port {risky_ports[0]['port']}")
        highlights.append({
            "tag": "Improved",
            "title": "Expanded Self-Pen-Test hardening & exposed port protection",
            "detail": f"Strengthened one-click hardening coverage for top observed exposures ({', '.join(items)}).",
        })
    if not highlights:
        highlights.append({
            "tag": "Improved",
            "title": "Security rules, reliability & telemetry polish",
            "detail": "Routine detection tuning, signed feed freshness, and cross-platform stability updates.",
        })

    today = datetime.now(timezone.utc).strftime("%Y.%m.%d-1")
    draft_feed = _build_draft_feed(supply_chain_matches, feed_version=today)

    # Render clean GitHub-Flavored Markdown digest
    lines: list[str] = [
        f"# Wardr Live Feedback & Release Triage Digest",
        "",
        f"- **Generated:** `{signals.get('fetched_at') or _utc_now()}`",
        f"- **Source API:** `{_clean_text(signals.get('server_url') or DEFAULT_API_URL, 120)}`",
        f"- **Current Version:** `v{cur_ver}` → **Next Recommended Release:** `v{recommended_version}`",
        f"- **Needs Release / Feed Attention:** **{'YES' if needs_attention else 'No urgent spikes'}**",
        "",
        "## Fleet & Telemetry Snapshot",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| Total Redacted Snapshots | `{int(summary.get('total_snapshots') or 0)}` |",
        f"| Unique Opted-In Accounts | `{int(summary.get('unique_accounts') or 0)}` |",
        f"| Average Posture Coverage | `{summary.get('avg_coverage_pct') if summary.get('avg_coverage_pct') is not None else '—'}%` |",
        f"| Average Self-Pen-Test Score | `{summary.get('avg_pentest_score_pct') if summary.get('avg_pentest_score_pct') is not None else '—'}%` |",
        f"| Escalated Zero-Day Clusters | `{len(escalated_clusters)}` (Open total: `{len(open_clusters)}`) |",
        f"| Active Signed Feed Version | `{_clean_text(health.get('active_feed_version') or 'none', 40)}` |",
        "",
    ]

    by_ver = summary.get("by_wardr_version") if isinstance(summary.get("by_wardr_version"), dict) else {}
    by_os = summary.get("by_os") if isinstance(summary.get("by_os"), dict) else {}
    if by_ver or by_os:
        lines.append("### Platform & Version Distribution")
        lines.append("")
        if by_os:
            os_str = ", ".join(f"`{_clean_text(k, 32)}`: {v}" for k, v in sorted(by_os.items(), key=lambda kv: -kv[1]))
            lines.append(f"- **OS:** {os_str}")
        if by_ver:
            ver_str = ", ".join(f"`v{_clean_text(k, 24)}`: {v}" for k, v in sorted(by_ver.items(), key=lambda kv: -kv[1]))
            lines.append(f"- **Versions:** {ver_str}")
        lines.append("")

    if escalated_clusters:
        lines.extend([
            "## Escalated Zero-Day & Vulnerability Clusters (Action Required)",
            "",
            "| Fingerprint | Kind | Reports | Unique Reporters | Zero-Day Votes | Sample Title |",
            "| :--- | :--- | ---: | ---: | ---: | :--- |",
        ])
        for c in escalated_clusters[:15]:
            lines.append(
                f"| `{_clean_text(c.get('fingerprint'), 20)}` | `{_clean_text(c.get('sample_kind'), 20)}` "
                f"| {int(c.get('report_count') or 0)} | {int(c.get('unique_reporters') or 0)} "
                f"| {int(c.get('zero_day_votes') or 0)} | {_clean_text(c.get('sample_title'), 90)} |"
            )
        lines.append("")

    if failing_checks:
        lines.extend([
            "## Top Failing Posture Checks",
            "",
            "| Check ID | Category | Severity | Fail Count | Handled | Unhandled |",
            "| :--- | :--- | :--- | ---: | ---: | ---: |",
        ])
        for c in failing_checks[:12]:
            fc = int(c.get("fail_count") or 0)
            hc = int(c.get("handled_count") or 0)
            lines.append(
                f"| `{_clean_text(c.get('id'), 60)}` | {_clean_text(c.get('category'), 32)} "
                f"| `{_clean_text(c.get('severity'), 16)}` | {fc} | {hc} | {max(0, fc - hc)} |"
            )
        lines.append("")

    if pentest_exposures or risky_ports or supply_chain_matches:
        lines.append("## Active Attack-Surface & Supply-Chain Signals")
        lines.append("")
        if supply_chain_matches:
            lines.append("**Supply-Chain / Compromised Package Matches:**")
            for m in supply_chain_matches[:10]:
                lines.append(
                    f"- `{_clean_text(m.get('package') or 'unknown', 60)}` "
                    f"(`{_clean_text(m.get('cve') or m.get('kind'), 40)}`, `{_clean_text(m.get('severity'), 16)}`) — {int(m.get('count') or 0)} hit(s)"
                )
            lines.append("")
        if pentest_exposures:
            lines.append("**Top Self-Pen-Test Exposures:**")
            for p in pentest_exposures[:10]:
                lines.append(f"- `{_clean_text(p.get('id'), 60)}` — {int(p.get('count') or 0)} host(s)")
            lines.append("")
        if risky_ports:
            lines.append("**Top Exposed Risky Ports:**")
            for r in risky_ports[:10]:
                lines.append(
                    f"- Port `{int(r.get('port') or 0)}` ({_clean_text(r.get('service'), 60)}, "
                    f"`{_clean_text(r.get('severity'), 16)}`) — {int(r.get('count') or 0)} host(s)"
                )
            lines.append("")

    lines.extend([
        f"## Ship `v{recommended_version}` (Reviewed Release Commands)",
        "",
        "```bash",
        f"# 1. Prepare version bump + changelog notes from live telemetry",
        f"wardr feedback-loop prepare-release --version {recommended_version} --from-live",
        "",
        "# 2. Review diff, implement any targeted check/remediation fixes, and run tests",
        "python3 -m unittest discover -s tests -q",
        "",
        "# 3. Commit, push, sign all 5 installers & publish live to GitHub + getwardr.com",
        f"wardr feedback-loop publish-release --version {recommended_version}",
        "```",
        "",
    ])

    return {
        "generated_at": _utc_now(),
        "current_version": cur_ver,
        "recommended_version": recommended_version,
        "needs_attention": needs_attention,
        "escalated_count": len(escalated_clusters),
        "total_snapshots": int(summary.get("total_snapshots") or 0),
        "unique_accounts": int(summary.get("unique_accounts") or 0),
        "escalated_clusters": escalated_clusters[:20],
        "high_impact_checks": high_impact_checks[:15],
        "high_impact_pentest": high_impact_pentest[:10],
        "risky_ports": risky_ports[:15],
        "supply_chain_matches": supply_chain_matches[:20],
        "recommended_highlights": highlights,
        "draft_feed": draft_feed,
        "markdown": "\n".join(lines),
    }


def write_digest_artifacts(digest: dict, out_dir: Path) -> dict:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    md_path = target / "digest.md"
    json_path = target / "digest.json"
    feed_path = target / "defense-v1.draft.json"
    md_path.write_text(str(digest.get("markdown") or "") + "\n", encoding="utf-8")
    json_copy = {k: v for k, v in digest.items() if k != "markdown"}
    json_path.write_text(json.dumps(json_copy, indent=2) + "\n", encoding="utf-8")
    feed_path.write_text(json.dumps(digest.get("draft_feed") or {}, indent=2) + "\n", encoding="utf-8")
    return {
        "digest_md": str(md_path),
        "digest_json": str(json_path),
        "draft_feed": str(feed_path),
    }


def _format_release_entry(version: str, date_str: str, title: str, summary: str, highlights: list[dict]) -> str:
    hl_blocks = []
    for item in highlights[:6]:
        tag = _clean_text(item.get("tag") or "Improved", 24) or "Improved"
        htitle = _clean_text(item.get("title") or "Security update", 120)
        detail = _clean_text(item.get("detail") or "", 320)
        hl_blocks.append(
            "            {\n"
            f"                \"tag\": {json.dumps(tag)},\n"
            f"                \"title\": {json.dumps(htitle)},\n"
            f"                \"detail\": {json.dumps(detail)},\n"
            "            },"
        )
    joined_hl = "\n".join(hl_blocks)
    return (
        "    {\n"
        f"        \"version\": {json.dumps(version)},\n"
        f"        \"date\": {json.dumps(date_str)},\n"
        f"        \"title\": {json.dumps(_clean_text(title, 120))},\n"
        f"        \"summary\": {json.dumps(_clean_text(summary, 320))},\n"
        "        \"highlights\": [\n"
        f"{joined_hl}\n"
        "        ],\n"
        "    },\n"
    )


def prepare_release_bump(
    repo_root: Path,
    *,
    target_version: str | None = None,
    bump: str = "patch",
    title: str = "",
    summary: str = "",
    highlights: list[dict] | None = None,
    dry_run: bool = False,
) -> dict:
    """Safely bump pyproject.toml, prepend changelog.py release notes, and sync index.html fallback badge."""
    root = Path(repo_root).resolve()
    pyproject_path = root / "pyproject.toml"
    changelog_path = root / "wardr" / "changelog.py"
    index_path = root / "wardr" / "static" / "index.html"

    if not pyproject_path.is_file() or not changelog_path.is_file():
        raise FeedbackLoopError("Run prepare-release from the Wardr repository root.")

    with pyproject_path.open("rb") as handle:
        project = tomllib.load(handle).get("project") or {}
    current = str(project.get("version") or "")
    if not _VERSION_RE.fullmatch(current):
        raise FeedbackLoopError(f"Could not parse current version from pyproject.toml: {current!r}")

    resolved_target = target_version.strip() if target_version else next_version(current, bump)
    if not _VERSION_RE.fullmatch(resolved_target):
        raise FeedbackLoopError(f"Target version must use X.Y.Z format: {resolved_target!r}")
    if tuple(map(int, resolved_target.split("."))) <= tuple(map(int, current.split("."))):
        raise FeedbackLoopError(f"Target version {resolved_target} must be strictly newer than {current}.")

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rel_title = title.strip() or f"Security Hardening & Community Telemetry Update (v{resolved_target})"
    rel_summary = summary.strip() or (
        f"Security update informed by opt-in Wardr telemetry and Threat Network signals, "
        f"delivering updated detections, hardening fixes, and stability improvements."
    )
    rel_highlights = highlights if highlights else [
        {
            "tag": "Improved",
            "title": "Telemetry-guided security detections & hardening",
            "detail": "Refined posture checks, Self-Pen-Test fixes, and signed feed compatibility based on live community diagnostics.",
        }
    ]

    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    new_pyproject, n_py = re.subn(
        r'(?m)^version\s*=\s*"[^"]+"',
        f'version = "{resolved_target}"',
        pyproject_text,
        count=1,
    )
    if n_py != 1:
        raise FeedbackLoopError("Could not locate project version line in pyproject.toml.")

    changelog_text = changelog_path.read_text(encoding="utf-8")
    marker = "RELEASES: tuple[dict, ...] = (\n"
    if marker not in changelog_text:
        raise FeedbackLoopError("Could not locate RELEASES tuple in wardr/changelog.py.")
    if f'"version": "{resolved_target}"' in changelog_text:
        raise FeedbackLoopError(f"wardr/changelog.py already contains an entry for {resolved_target}.")
    entry_block = _format_release_entry(resolved_target, date_str, rel_title, rel_summary, rel_highlights)
    new_changelog = changelog_text.replace(marker, marker + entry_block, 1)

    files_updated = ["pyproject.toml", "wardr/changelog.py"]
    new_index = None
    if index_path.is_file():
        idx_text = index_path.read_text(encoding="utf-8")
        replaced_idx, n_idx = re.subn(
            r'id="whats-new-version">Wardr v[0-9]+\.[0-9]+\.[0-9]+<',
            f'id="whats-new-version">Wardr v{resolved_target}<',
            idx_text,
            count=1,
        )
        if n_idx == 1:
            new_index = replaced_idx
            files_updated.append("wardr/static/index.html")

    if not dry_run:
        pyproject_path.write_text(new_pyproject, encoding="utf-8")
        changelog_path.write_text(new_changelog, encoding="utf-8")
        if new_index is not None:
            index_path.write_text(new_index, encoding="utf-8")

    return {
        "previous_version": current,
        "target_version": resolved_target,
        "date": date_str,
        "title": rel_title,
        "files_updated": files_updated,
        "dry_run": dry_run,
    }
