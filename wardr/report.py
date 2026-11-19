"""Portable reports with the evidence and outcome of the last local scan."""

import json
from collections import Counter
from html import escape

SEVERITIES = ("critical", "high", "medium", "low")
REPORT_CSS = """
:root{color-scheme:light;font:16px/1.55 system-ui,sans-serif;color:#152925;background:#f4f7f5}
body{margin:0}main{max-width:54rem;margin:auto;padding:clamp(1.2rem,5vw,4rem)}
header{border-bottom:1px solid #c9d8d1;padding-bottom:1.5rem}
h1{font-size:clamp(2.2rem,6vw,3.8rem);letter-spacing:-.06em;line-height:1.06;margin:.35rem 0 .9rem}
h2{letter-spacing:-.025em;margin:0 0 .7rem}h3{font-size:1.05rem;margin:0 0 .5rem;line-height:1.5}
p{margin:.4rem 0;overflow-wrap:anywhere}article p{white-space:pre-wrap}section{margin:2rem 0}
.brand{font-weight:800;letter-spacing:.14em;color:#205d47}.muted{color:#416159}
.risks{display:flex;flex-wrap:wrap;gap:.5rem;margin:1.25rem 0 .55rem}
.risks span{background:#e4efe9;border-radius:.45rem;padding:.3rem .65rem}
article{background:#fff;border:1px solid #d1dfd7;border-radius:.65rem;padding:.9rem 1.15rem;margin:.75rem 0}
.flag{display:inline-block;margin:0 .65rem .15rem 0;border-radius:.3rem;padding:.12rem .45rem;
font-size:.78rem;color:#2a4840;background:#e4efe9}
.flag.critical,.flag.high{color:#8d2023;background:#fce4e4}
.flag.medium{color:#654506;background:#fff0c9}.flag.low{color:#185a47;background:#dbefe8}
@media print{:root{background:#fff}main{max-width:none;padding:0}article{break-inside:avoid}}
"""


def report_data(host: dict, scan: dict) -> dict:
    checks = scan["checks"]
    outcomes = Counter(check.get("status") for check in checks)
    findings = Counter(check.get("severity") for check in checks if check.get("status") == "fail")
    return {
        "schema_version": 1,
        "host": host,
        "scanned_at": scan["scanned_at"],
        "summary": {
            "action_needed": outcomes["fail"],
            "passed": outcomes["pass"],
            "unverified": outcomes["unknown"],
            "not_applicable": outcomes["not_applicable"],
            "by_severity": {severity: findings[severity] for severity in SEVERITIES},
        },
        "checks": checks,
    }


def json_report(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def text_report(data: dict) -> str:
    host = data["host"]
    summary = data["summary"]
    lines = [
        f"Wardr security report — {host['name']} ({host['os']})",
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


def _check_markup(check: dict) -> str:
    status = check.get("status")
    severity = check.get("severity")
    labels = {"unknown": "Unverified", "pass": "Passed", "not_applicable": "Inapplicable"}
    style = severity if status == "fail" and severity in SEVERITIES else "neutral"
    label = str(severity if status == "fail" else labels.get(status, "Unverified")).title()
    descriptions = []
    for label_text, key in (("Risk", "risk"), ("Evidence", "evidence"), ("Next step", "remediation")):
        if check.get(key) and (label_text == "Evidence" or status in ("fail", "unknown")):
            descriptions.append(f"<p><strong>{label_text}</strong> {escape(str(check[key]))}</p>")
    if check.get("verified_at"):
        descriptions.append(f"<p><strong>Rechecked</strong> {escape(str(check['verified_at']))}</p>")
    return (
        f'<article><h3><span class="flag {style}">{escape(label)}</span>'
        f'{escape(str(check.get("title", check["id"])))}</h3>'
        + "".join(descriptions)
        + "</article>"
    )


def html_report(data: dict) -> str:
    host = data["host"]
    summary = data["summary"]
    groups = []
    ordered = _ordered_checks(data["checks"])
    for title, included, empty in (
        ("Action needed", ("fail",), "The scan found no issues in the checks that ran."),
        ("Unverified checks", ("unknown",), "The scan has no unverified checks."),
        ("Completed checks", ("pass", "not_applicable"), "There are no additional checks."),
    ):
        markup = "".join(_check_markup(item) for item in ordered if item.get("status") in included)
        groups.append(f"<section><h2>{title}</h2>{markup or f'<p>{empty}</p>'}</section>")
    risk_summary = "".join(
        f"<span><strong>{count}</strong> {escape(severity.title())}</span>"
        for severity, count in summary["by_severity"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardr Security Report</title><style>{REPORT_CSS}</style></head><body><main>
<header><span class="brand">WARDR</span><h1>Security report</h1>
<p class="muted">{escape(host['name'])} · {escape(host['os'])} · {escape(host['version'])}</p>
<p class="muted">Scanned at {escape(data['scanned_at'])} (UTC)</p>
<div class="risks" aria-label="Open issues by severity">{risk_summary}</div>
<p>{summary['action_needed']} action needed · {summary['passed']} passed · {summary['unverified']} unverified · {summary['not_applicable']} inapplicable</p></header>
{''.join(groups)}
<footer class="muted"><p>Results cover the local checks listed in this report and reflect the evidence available when each check ran.</p></footer>
</main></body></html>
"""
