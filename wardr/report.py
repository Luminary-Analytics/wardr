"""Portable reports with the evidence and outcome of the last local scan."""

import json
from collections import Counter
from html import escape

SEVERITIES = ("critical", "high", "medium", "low")
REPORT_CSS = """
:root{color-scheme:light;font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif;color:#172820;background:#f3f5ee}
*{box-sizing:border-box}
body{margin:0}
main{max-width:58rem;margin:auto;padding:clamp(1.2rem,4vw,3rem)}
h1,h2,h3,p{margin:0}
h1{font-size:clamp(1.9rem,4.5vw,2.75rem);letter-spacing:-.05em;line-height:1.08}
h2{font-size:1.2rem;letter-spacing:-.025em;margin:0 0 .85rem}
h3{font-size:.98rem;line-height:1.4}
p{overflow-wrap:anywhere}
section{margin:1.75rem 0}
.brand{display:inline-flex;align-items:center;gap:.45rem;font-weight:800;letter-spacing:.14em;font-size:.78rem;color:#c9ef8b}
.brand-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#c9ef8b}
.muted{color:#4d6255}
.hero{border-radius:20px;padding:1.65rem 1.85rem;color:#f5faf4;background:linear-gradient(125deg,#122b24 0%,#1a3d31 65%,#224f3c 100%);
display:grid;grid-template-columns:auto minmax(0,1fr);gap:1.5rem;align-items:center;margin-bottom:1.25rem}
.hero.rag-green{background:linear-gradient(125deg,#0f2d23 0%,#164632 62%,#1e5c41 100%)}
.hero.rag-amber{background:linear-gradient(125deg,#2b2210 0%,#493613 62%,#5e4517 100%)}
.hero.rag-red{background:linear-gradient(125deg,#301116 0%,#511820 62%,#6b1e29 100%)}
.shield-wrap{width:96px;height:108px;display:grid;place-items:center;flex:none}
.shield-wrap svg{width:92px;height:104px;filter:drop-shadow(0 8px 18px rgba(0,0,0,.32))}
.hero-meta{font-size:.86rem;color:#cfe2d4;margin-top:.35rem}
.hero.rag-amber .hero-meta{color:#f4dfb3}
.hero.rag-red .hero-meta{color:#f7cfd5}
.hero-summary{margin-top:.65rem;font-size:.96rem;color:#ebf5ed;max-width:44ch}
.rag-bar{display:inline-flex;align-items:center;gap:.55rem;margin:.6rem 0 .45rem;padding:.3rem .7rem;border-radius:999px;
background:rgba(255,255,255,.11);font-size:.8rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase}
.rag-lights{display:inline-flex;gap:5px;align-items:center}
.rag-light{width:9px;height:9px;border-radius:50%;opacity:.26}
.rag-light.red{background:#f87171}.rag-light.amber{background:#fbbf24}.rag-light.green{background:#4ade80}
.rag-light.active{opacity:1;box-shadow:0 0 0 3px rgba(255,255,255,.22)}
.meter-block{margin-top:1rem;max-width:28rem}
.meter-row{display:flex;justify-content:space-between;gap:1rem;font-size:.82rem;font-weight:650;margin-bottom:.35rem;color:#e5f2e8}
.protection-meter{width:100%;height:10px;border:0;border-radius:999px;overflow:hidden;background:rgba(255,255,255,.18);appearance:none}
.protection-meter::-webkit-progress-bar{background:rgba(255,255,255,.18);border-radius:999px}
.protection-meter::-webkit-progress-value{background:#4ade80;border-radius:999px}
.protection-meter::-moz-progress-bar{background:#4ade80;border-radius:999px}
.hero.rag-amber .protection-meter::-webkit-progress-value{background:#fbbf24}
.hero.rag-amber .protection-meter::-moz-progress-bar{background:#fbbf24}
.hero.rag-red .protection-meter::-webkit-progress-value{background:#f87171}
.hero.rag-red .protection-meter::-moz-progress-bar{background:#f87171}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:.75rem;margin:1rem 0 1.5rem}
.metric{background:#fff;border:1px solid #dbe4d7;border-radius:14px;padding:.85rem 1rem}
.metric span{display:block;font-size:.78rem;color:#516457;font-weight:650}
.metric strong{display:block;font-size:1.55rem;line-height:1.15;margin-top:.2rem;font-variant-numeric:tabular-nums}
.metric.green strong{color:#166534}.metric.red strong{color:#991b1b}.metric.amber strong{color:#92400e}
.banner{display:flex;align-items:flex-start;gap:.9rem;padding:1rem 1.15rem;border-radius:14px;border:1px solid #cce3d2;background:#edf7ef;color:#174228;margin-bottom:1.25rem}
.banner.threat{border-color:#f3c4c8;background:#fef0f1;color:#7f1d1d}
.banner.warning{border-color:#f3dca8;background:#fff8e6;color:#78350f}
.banner-icon{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font-weight:800;font-size:.9rem;flex:none;background:#16a34a;color:#fff}
.banner.threat .banner-icon{background:#dc2626}.banner.warning .banner-icon{background:#d97706}
.banner p{margin-top:.2rem;font-size:.88rem}
.risks{display:flex;flex-wrap:wrap;gap:.5rem;margin:.85rem 0 0}
.risks span{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:.24rem .6rem;font-size:.8rem;color:#f3faf4}
.checklist{display:grid;gap:.65rem}
article{background:#fff;border:1px solid #d7e2d4;border-radius:14px;padding:.95rem 1.1rem;display:grid;grid-template-columns:28px minmax(0,1fr);gap:.85rem;align-items:start}
article.item-pass{border-left:4px solid #16a34a}
article.item-red{border-left:4px solid #dc2626}
article.item-amber{border-left:4px solid #d97706}
article.item-neutral{border-left:4px solid #94a3b8}
.check-mark{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-weight:800;font-size:.85rem;margin-top:.1rem}
.check-mark.pass{background:#dcfce7;color:#15803d}
.check-mark.red{background:#fee2e2;color:#b91c1c}
.check-mark.amber{background:#fef3c7;color:#b45309}
.check-mark.neutral{background:#e2e8f0;color:#475569}
.item-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.35rem}
.item-cat{font-size:.76rem;color:#55685b;margin-left:.45rem;font-weight:600}
article p{margin:.32rem 0;font-size:.88rem;color:#33463a;white-space:pre-wrap}
article p strong{color:#172820}
.flag{display:inline-block;border-radius:999px;padding:.16rem .6rem;font-size:.74rem;font-weight:700;color:#2a4840;background:#e4efe9}
.flag.critical,.flag.high{color:#991b1b;background:#fee2e2}
.flag.medium{color:#92400e;background:#fef3c7}
.flag.low{color:#1e40af;background:#dbeafe}
.flag.pass{color:#166534;background:#dcfce7}
.flag.unverified{color:#92400e;background:#fef3c7}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #d5e0d2;font-size:.82rem}
@media (max-width:640px){.hero{grid-template-columns:1fr;text-align:left}}
@media print{
  :root{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  main{max-width:none;padding:0}
  article,.banner,.metric,.hero{break-inside:avoid}
}
"""


def _is_pending_update_id(check_id) -> bool:
    return isinstance(check_id, str) and check_id.endswith("-pending-updates")


def _is_handled(check: dict) -> bool:
    """Return True for legitimately queued OS updates or manually verified unknown checks."""
    disp = check.get("disposition")
    if not isinstance(disp, dict):
        return False
    status = check.get("status")
    kind = disp.get("kind")
    if status == "unknown" and kind == "acknowledged":
        return True
    if status == "fail" and _is_pending_update_id(check.get("id")) and kind == "queued":
        return True
    return False


def _is_accepted_risk(check: dict) -> bool:
    """Return True when a failing non-update OS control was acknowledged without actually passing."""
    disp = check.get("disposition")
    return (
        check.get("status") == "fail"
        and not _is_pending_update_id(check.get("id"))
        and isinstance(disp, dict)
        and disp.get("kind") == "acknowledged"
    )


def assess_posture(scan: dict | None, *, monitoring: dict | None = None, threats: dict | None = None) -> dict:
    """Compute a transparent Red / Amber / Green protection verdict from local evidence."""
    checks = list((scan or {}).get("checks") or [])
    ready = bool((scan or {}).get("scanned_at") or (scan or {}).get("updated_at"))
    outcomes = Counter(check.get("status") for check in checks)
    handled_items = [check for check in checks if _is_handled(check)]
    accepted_risk_items = [check for check in checks if _is_accepted_risk(check)]
    unhandled_failures = [
        check for check in checks
        if check.get("status") == "fail" and not _is_handled(check) and not _is_accepted_risk(check)
    ]
    unhandled_unverified = [check for check in checks if check.get("status") == "unknown" and not _is_handled(check)]
    queued_count = sum(1 for check in handled_items if check["disposition"]["kind"] == "queued")
    acked_count = sum(1 for check in handled_items if check["disposition"]["kind"] == "acknowledged")
    accepted_risks = len(accepted_risk_items)
    findings = Counter(check.get("severity") for check in unhandled_failures)
    by_severity = {severity: findings[severity] for severity in SEVERITIES}

    secured = outcomes["pass"]
    handled = len(handled_items)
    addressed = secured + handled
    failed = len(unhandled_failures)
    unverified = len(unhandled_unverified)
    not_applicable = outcomes["not_applicable"]
    securable_total = secured + handled + accepted_risks + failed + unverified
    fixable = sum(1 for check in unhandled_failures if check.get("can_fix") is True)
    coverage_pct = round(100 * addressed / securable_total) if securable_total > 0 else None

    threat_status = (threats or {}).get("status", "clear")
    threat_count = int((threats or {}).get("count", 0) or 0)
    monitor_running = monitoring.get("running") if isinstance(monitoring, dict) else None

    if not ready:
        level = "pending"
        label = "Scanning"
        headline = "Running initial protection scan"
        summary = "Wardr is checking your device settings to verify everything it can secure."
        as_safe_as_possible = False
    elif threat_status == "threat":
        level = "red"
        label = "Active threat"
        headline = f"{threat_count} active {'threat' if threat_count == 1 else 'threats'} detected"
        summary = "Immediate review required. Wardr's continuous monitor detected high-priority threat activity right now."
        as_safe_as_possible = False
    elif by_severity["critical"] > 0 or by_severity["high"] > 0:
        level = "red"
        label = "At risk"
        urgent = by_severity["critical"] + by_severity["high"]
        headline = "Action required to protect this device"
        summary = (
            f"{addressed} of {securable_total} securable checks are addressed. "
            f"{urgent} high-impact {'issue needs' if urgent == 1 else 'issues need'} attention."
        )
        as_safe_as_possible = False
    elif threat_status == "warning" or failed > 0 or unverified > 0 or accepted_risks > 0 or monitor_running is False:
        level = "amber"
        label = "Needs attention"
        if threat_status == "warning":
            headline = "Suspicious activity needs review"
            summary = f"Continuous protection flagged {threat_count} {'pattern' if threat_count == 1 else 'patterns'} to inspect."
        elif failed > 0:
            headline = "Almost fully protected"
            summary = (
                f"{addressed} of {securable_total} securable checks are addressed. "
                f"Resolve {failed} remaining {'item' if failed == 1 else 'items'} to reach maximum protection."
            )
        elif accepted_risks > 0:
            label = "Risk accepted"
            headline = "Not fully protected — failing checks acknowledged"
            summary = (
                f"{secured} of {securable_total} checks verified secure · "
                f"{accepted_risks} failing {'check' if accepted_risks == 1 else 'checks'} acknowledged as accepted risk — "
                "fix and re-scan to reach Green Protected."
            )
        elif unverified > 0:
            headline = "Protected — some checks unverified"
            summary = (
                f"{addressed} of {securable_total} checks are verified or handled. "
                f"{unverified} {'check' if unverified == 1 else 'checks'} could not be verified automatically."
            )
        else:
            headline = "Continuous scanning is paused"
            summary = f"All {addressed} securable checks are addressed, but real-time monitoring is currently inactive."
        as_safe_as_possible = False
    elif addressed > 0:
        level = "green"
        label = "Protected"
        headline = "You are protected"
        if handled > 0:
            notes = []
            if queued_count:
                notes.append(f"{queued_count} queued (pending restart)")
            if acked_count:
                notes.append(f"{acked_count} acknowledged")
            summary = (
                f"{secured} of {securable_total} checks verified secure · "
                f"{', '.join(notes)} · 0 active threats."
            )
        else:
            summary = (
                f"All {secured} of {securable_total} securable items are verified secure with zero active threats. "
                "Your device is as safe as Wardr can make it."
            )
        as_safe_as_possible = True
    else:
        level = "amber"
        label = "Limited coverage"
        headline = "Protection coverage unavailable"
        summary = "No verifiable security checks completed on this device."
        as_safe_as_possible = False

    return {
        "level": level,
        "label": label,
        "headline": headline,
        "summary": summary,
        "as_safe_as_possible": as_safe_as_possible,
        "secured": secured,
        "handled": handled,
        "queued": queued_count,
        "acknowledged": acked_count,
        "accepted_risks": accepted_risks,
        "addressed": addressed,
        "failed": failed,
        "unverified": unverified,
        "not_applicable": not_applicable,
        "securable_total": securable_total,
        "fixable": fixable,
        "coverage_pct": coverage_pct,
        "by_severity": by_severity,
    }


def report_data(host: dict, scan: dict, *, monitoring: dict | None = None, threats: dict | None = None) -> dict:
    checks = scan["checks"]
    outcomes = Counter(check.get("status") for check in checks)
    posture = assess_posture(scan, monitoring=monitoring, threats=threats)
    payload = {
        "schema_version": 1,
        "host": host,
        "scanned_at": scan["scanned_at"],
        "posture": posture,
        "summary": {
            "action_needed": posture["failed"],
            "passed": outcomes["pass"],
            "handled": posture["handled"],
            "unverified": outcomes["unknown"],
            "not_applicable": outcomes["not_applicable"],
            "by_severity": dict(posture["by_severity"]),
        },
        "checks": checks,
    }
    if threats is not None:
        payload["threats"] = threats
    if monitoring is not None:
        payload["monitoring"] = {
            "running": bool(monitoring.get("running")),
            "interval": monitoring.get("interval"),
            "last_poll": monitoring.get("last_poll"),
            "poll_count": monitoring.get("poll_count", 0),
        }
    return payload


def json_report(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def text_report(data: dict) -> str:
    host = data["host"]
    summary = data["summary"]
    posture = data.get("posture") or assess_posture(data)
    lines = [
        f"Wardr security report — {host['name']} ({host['os']})",
        f"Status           [{posture['level'].upper()}] {posture['label']} — {posture['headline']}",
        f"Scan time (UTC)  {data['scanned_at']}",
        "",
        (
            f"{summary['action_needed']} action needed  ·  {summary['passed']} passed  ·  "
            f"{summary['unverified']} unverified  ·  {summary['not_applicable']} inapplicable"
        ),
    ]
    for item in _ordered_checks(data["checks"]):
        if item.get("status") not in ("fail", "unknown"):
            continue
        status = item.get("severity", "unknown").upper() if item["status"] == "fail" else "UNVERIFIED"
        lines.extend(["", f"[{status}] {item['title']} ({item['id']})"])
        for field in ("risk", "evidence", "remediation"):
            if item.get(field):
                lines.append(f"  {item[field]}")
    return "\n".join(lines) + "\n"


def _ordered_checks(checks: list) -> list:
    statuses = {"fail": 0, "unknown": 1, "pass": 2, "not_applicable": 3}
    severity_order = {severity: index for index, severity in enumerate(SEVERITIES)}
    return sorted(
        checks,
        key=lambda check: (
            statuses.get(check.get("status"), 4),
            severity_order.get(check.get("severity"), len(SEVERITIES)),
            str(check.get("title", "")),
        ),
    )


def _shield_svg(level: str) -> str:
    palette = {
        "green": ("#15803d", "#4ade80", "#f0fdf4"),
        "amber": ("#b45309", "#fbbf24", "#fffbeb"),
        "red": ("#b91c1c", "#f87171", "#fef2f2"),
    }
    fill, stroke, glyph = palette.get(level, ("#2b5441", "#9fd78b", "#f0fdf4"))
    if level == "green":
        icon = (
            f'<path d="M34 52 L45 63 L67 39" fill="none" stroke="{glyph}" '
            'stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>'
        )
    elif level == "red":
        icon = (
            f'<path d="M50 32 L50 56" stroke="{glyph}" stroke-width="7" stroke-linecap="round"/>'
            f'<circle cx="50" cy="69" r="4.5" fill="{glyph}"/>'
        )
    else:
        icon = (
            f'<path d="M50 33 L50 55" stroke="{glyph}" stroke-width="7" stroke-linecap="round"/>'
            f'<circle cx="50" cy="68" r="4.5" fill="{glyph}"/>'
        )
    return (
        '<svg viewBox="0 0 100 112" role="img" aria-label="Security shield">'
        f'<path d="M50 5 L90 21 V55 C90 80 73 97 50 107 C27 97 10 80 10 55 V21 Z" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="4.5" stroke-linejoin="round"/>'
        f'{icon}</svg>'
    )


def _check_markup(check: dict) -> str:
    status = check.get("status")
    severity = check.get("severity")
    handled = _is_handled(check)
    accepted_risk = _is_accepted_risk(check)
    disp = check.get("disposition") if (handled or accepted_risk) else None
    if status == "pass":
        item_cls, mark_cls, mark_glyph = "item-pass", "pass", "✓"
        flag_style, label = "pass", "Secured"
    elif handled and disp is not None:
        item_cls, mark_cls, mark_glyph = "item-pass", "pass", "✓"
        flag_style = "pass"
        label = "Queued · Pending restart" if disp["kind"] == "queued" else "Acknowledged"
    elif accepted_risk and disp is not None:
        item_cls, mark_cls, mark_glyph = "item-amber", "amber", "!"
        flag_style, label = "unverified", "Accepted risk (still failing)"
    elif status == "fail":
        is_red = severity in ("critical", "high")
        item_cls = "item-red" if is_red else "item-amber"
        mark_cls = "red" if is_red else "amber"
        mark_glyph = "!"
        flag_style = severity if severity in SEVERITIES else "high"
        label = f"{str(severity or 'high').title()} risk"
    elif status == "unknown":
        item_cls, mark_cls, mark_glyph = "item-amber", "amber", "?"
        flag_style, label = "unverified", "Unable to verify"
    else:
        item_cls, mark_cls, mark_glyph = "item-neutral", "neutral", "–"
        flag_style, label = "neutral", "Not applicable"

    category = f'<span class="item-cat">{escape(str(check["category"]))}</span>' if check.get("category") else ""
    descriptions = []
    if disp is not None:
        note = disp.get("note") or (
            "Queued to install on next restart." if disp["kind"] == "queued"
            else ("Acknowledged as accepted risk (check is still failing on OS)." if accepted_risk else "Manually confirmed by user.")
        )
        descriptions.append(f"<p><strong>Status note:</strong> {escape(str(note))}</p>")
    for label_text, key in (("Risk", "risk"), ("Evidence", "evidence"), ("Next step", "remediation")):
        if check.get(key) and (label_text == "Evidence" or (status in ("fail", "unknown") and not handled)):
            descriptions.append(f"<p><strong>{label_text}:</strong> {escape(str(check[key]))}</p>")
    if check.get("verified_at"):
        descriptions.append(f"<p><strong>Rechecked:</strong> {escape(str(check['verified_at']))}</p>")
    return (
        f'<article class="{item_cls}">'
        f'<span class="check-mark {mark_cls}" aria-hidden="true">{mark_glyph}</span>'
        f'<div><div class="item-head"><h3>{escape(str(check.get("title", check["id"])))}{category}</h3>'
        f'<span class="flag {flag_style}">{escape(label)}</span></div>'
        + "".join(descriptions)
        + "</div></article>"
    )


def html_report(data: dict) -> str:
    host = data["host"]
    summary = data["summary"]
    posture = data.get("posture") or assess_posture(
        data, monitoring=data.get("monitoring"), threats=data.get("threats")
    )
    level = posture["level"] if posture["level"] in ("green", "amber", "red") else "amber"
    securable = posture["securable_total"]
    addressed = posture.get("addressed", posture["secured"])
    pct = posture["coverage_pct"] if posture["coverage_pct"] is not None else 0

    threats = data.get("threats")
    monitoring = data.get("monitoring")
    if threats is not None:
        t_status = threats.get("status", "clear")
        t_count = int(threats.get("count", 0) or 0)
        if t_status == "threat":
            b_cls, b_icon = "banner threat", "!"
            b_title = f"{t_count} active {'threat' if t_count == 1 else 'threats'} detected at report time"
            b_body = "Immediate investigation recommended. Open Wardr → Defense → Threat Hunting for full evidence."
        elif t_status == "warning":
            b_cls, b_icon = "banner warning", "!"
            b_title = f"{t_count} suspicious {'pattern' if t_count == 1 else 'patterns'} flagged"
            b_body = "Review the flagged telemetry in Wardr to confirm whether the activity is authorized."
        else:
            b_cls, b_icon = "banner", "✓"
            b_title = "No active threats detected"
            cadence = (
                f"Continuous scanning is active (every {int(monitoring['interval'])}s)."
                if monitoring and monitoring.get("running") and monitoring.get("interval")
                else "No active threat patterns were present in the local telemetry window."
            )
            b_body = cadence
        threat_banner = (
            f'<div class="{b_cls}"><span class="banner-icon" aria-hidden="true">{b_icon}</span>'
            f'<div><h3>{escape(b_title)}</h3><p>{escape(b_body)}</p></div></div>'
        )
    else:
        threat_banner = ""

    groups = []
    ordered = _ordered_checks(data["checks"])
    for title, included, empty in (
        ("Needs attention", ("fail",), "Every applicable security check passed — no open findings."),
        ("Secured checks", ("pass",), "No checks are currently marked secured."),
        ("Unable to verify", ("unknown",), "All applicable checks were verified."),
        ("Not applicable to this device", ("not_applicable",), ""),
    ):
        items = [item for item in ordered if item.get("status") in included]
        if not items and not empty:
            continue
        markup = "".join(_check_markup(item) for item in items)
        content = f'<div class="checklist">{markup}</div>' if markup else f'<p class="muted">{empty}</p>'
        groups.append(f"<section><h2>{title} ({len(items)})</h2>{content}</section>")

    risk_summary = "".join(
        f"<span><strong>{count}</strong> {escape(severity.title())}</span>"
        for severity, count in summary["by_severity"].items()
    )
    lights = "".join(
        f'<span class="rag-light {tone}{" active" if level == tone else ""}"></span>'
        for tone in ("red", "amber", "green")
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardr Security Report — {escape(posture['label'])}</title><style>{REPORT_CSS}</style></head><body><main>
<header class="hero rag-{level}">
  <div class="shield-wrap">{_shield_svg(level)}</div>
  <div>
    <span class="brand"><span class="brand-dot"></span>WARDR SECURITY REPORT</span>
    <div><span class="rag-bar"><span class="rag-lights" aria-hidden="true">{lights}</span>{escape(posture['label'])}</span></div>
    <h1>{escape(posture['headline'])}</h1>
    <p class="hero-summary">{escape(posture['summary'])}</p>
    <p class="hero-meta">{escape(host['name'])} · {escape(host['os'])} {escape(host['version'])} · Scanned {escape(data['scanned_at'])} (UTC)</p>
    <div class="meter-block">
      <div class="meter-row"><span>Securable checks protected</span><span>{addressed} of {securable} ({pct}%)</span></div>
      <progress class="protection-meter" value="{addressed}" max="{max(securable, 1)}"></progress>
    </div>
    <div class="risks" aria-label="Open issues by severity">{risk_summary}</div>
  </div>
</header>
{threat_banner}
<div class="summary-grid" aria-label="Checklist totals">
  <div class="metric green"><span>Secured</span><strong>{summary['passed']}</strong></div>
  <div class="metric red"><span>Needs attention</span><strong>{summary['action_needed']}</strong></div>
  <div class="metric amber"><span>Unable to verify</span><strong>{summary['unverified']}</strong></div>
  <div class="metric"><span>Not applicable</span><strong>{summary['not_applicable']}</strong></div>
</div>
{''.join(groups)}
<footer class="muted"><p>This visual Red / Amber / Green report reflects all local checks Wardr can verify and secure on this device at scan time.</p></footer>
</main></body></html>
"""
