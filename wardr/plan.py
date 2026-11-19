"""Turn local evidence into ordered, verifiable remediation tasks."""

from datetime import datetime, timezone
from html import escape

from .intel import exploited_index
from .report import REPORT_CSS


PRIORITIES = {"urgent": "Review now", "high": "Prioritize", "scheduled": "Schedule", "verify": "Verify"}
PRIORITY_STYLE = {"urgent": "critical", "high": "high", "scheduled": "medium", "verify": "neutral"}
SEVERITY_PRIORITY = {"critical": "urgent", "high": "high", "medium": "scheduled", "low": "scheduled"}


def prioritize_software(assessment, catalog):
    if assessment is None:
        return None
    index, coverage = exploited_index(catalog)
    findings = [
        {
            **item,
            "known_exploited": any(
                identifier.upper() in index for identifier in (item["advisory_id"], *item.get("aliases", ()))
            ),
        }
        for item in assessment["findings"]
    ]
    return {
        **assessment,
        "findings": findings,
        "kev": {
            "coverage": coverage,
            "catalog_version": catalog.get("catalog_version"),
            "refreshed_at": catalog.get("refreshed_at"),
        },
    }


def _task(identifier, source, priority, rationale, title, evidence, steps, verification):
    return {
        "id": identifier,
        "source": source,
        "priority": priority,
        "priority_label": PRIORITIES[priority],
        "rationale": rationale,
        "title": title,
        "evidence": [line for line in evidence if line],
        "steps": [line for line in steps if line],
        "verification": verification,
    }


def _advisory_task(item):
    severity = item.get("severity", "unknown")
    exploited = item.get("known_exploited", False)
    priority = "urgent" if exploited else SEVERITY_PRIORITY.get(severity, "high")
    rationale = (
        "The supplied package version matches published affected data and this advisory appears in the cached CISA catalog."
        if exploited else
        "The supplied package version matches published affected data. Review vendor severity and deployment impact."
        if severity == "unknown" else
        f"The supplied package version matches published affected data with {severity} severity."
    )
    task = _task(
        "software/" + item["id"], "Published advisory", priority, rationale,
        f"{item['package']} {item['version']} · {item['advisory_id']}", [item.get("evidence")],
        [item.get("remediation")],
        "Regenerate the deployed software inventory after the change and reassess it using a current advisory export.",
    )
    task["source_url"] = item.get("source_url")
    return task


def _alert_task(item):
    severity = item.get("severity")
    priority = "urgent" if severity in ("critical", "high") else "scheduled"
    evidence = [
        f"{row['at']} · {row['source']} · {row['title']}" + (f" · {row['detail']}" if row.get("detail") else "")
        for row in item.get("evidence", ())
    ]
    task = _task(
        "alert/" + item["id"], "Local telemetry", priority,
        item.get("summary"), item["title"], evidence, item.get("actions", ()),
        item.get("validation") or "Review the source records and document whether the activity was expected.",
    )
    task["event_ids"] = item.get("event_ids", [])
    return task


def _posture_task(item):
    return _task(
        "posture/" + item["id"], "Device check",
        SEVERITY_PRIORITY.get(item["severity"], "verify") if item["status"] == "fail" else "verify",
        item.get("risk"), item["title"], [item.get("evidence")], [item.get("remediation")],
        "Run a fresh device scan and confirm the check passes.",
    )


def _endpoint(listener):
    address = listener["address"]
    if ":" in address:
        address = f"[{address}]"
    return f"{listener['protocol'].upper()} {address}:{listener['port']}"


def build_plan(host, scan, exposure, hunting, software):
    checks = scan["checks"] if scan else ()
    alerts = hunting.get("alerts", ())
    listeners = exposure.get("listeners", ()) if exposure else ()
    non_loopback = [row for row in listeners if row["scope"] in ("wildcard", "interface")]
    tasks = [_posture_task(item) for item in checks if item["status"] in ("fail", "unknown")]
    tasks.extend(_alert_task(item) for item in alerts)
    if software is not None:
        tasks.extend(_advisory_task(item) for item in software["findings"])
    if non_loopback:
        examples = [_endpoint(row) for row in non_loopback[:8]]
        if len(non_loopback) > 8:
            examples.append(f"{len(non_loopback) - 8} more in the local exposure inventory.")
        tasks.append(_task(
            "exposure/non-loopback", "Local exposure", "verify",
            "These sockets bind to network interfaces. Their reachability depends on host and network policy.",
            "Review non-loopback listeners and bindings", examples,
            ["Confirm the owner and purpose of each binding. For unintended exposure, use the service's "
             "configuration or the approved firewall policy to restrict it."],
            "Refresh local exposure and confirm each binding and its intended scope.",
        ))

    rank = {name: index for index, name in enumerate(PRIORITIES)}
    tasks.sort(key=lambda row: (rank[row["priority"]], row["source"], row["title"], row["id"]))
    coverage = [
        {"label": "Device checks", "detail": f"{len(checks)} checks in the latest scan." if scan else "A device scan has yet to run."},
        {
            "label": "Local exposure",
            "detail": (
                f"{len(listeners)} TCP listeners and UDP bindings · {exposure['state']} collection."
                if exposure else "Collect a local socket snapshot to assess exposure."
            ),
        },
        {
            "label": "Threat hunting",
            "detail": f"{hunting.get('events_considered', 0)} local records reviewed over the last "
                      f"{hunting.get('lookback_hours', 24)} hours. Signal availability depends on the monitor.",
        },
        {
            "label": "Software advisories",
            "detail": "Assessment covers the imported inventory and supplied advisory records."
                      if software is not None else "Import an inventory and OSV advisories to assess software versions.",
        },
    ]
    return {
        "schema_version": 1,
        "host": host,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": coverage,
        "counts": {priority: sum(row["priority"] == priority for row in tasks) for priority in PRIORITIES},
        "tasks": tasks,
    }


def _text(value):
    return "".join(char if char.isprintable() else " " for char in str(value or ""))


def text_plan(plan):
    lines = [
        f"Wardr remediation plan — {_text(plan['host']['name'])}",
        f"Generated (UTC)  {plan['generated_at']}",
        "",
    ]
    lines.extend(f"{source['label']}  {source['detail']}" for source in plan["sources"])
    if not plan["tasks"]:
        lines.extend(("", "No tasks from the available evidence. Review coverage above."))
    for task in plan["tasks"]:
        lines.extend(("", f"[{task['priority_label']}] {_text(task['title'])}", f"  {task['source']}"))
        for value in (task["rationale"], *task["evidence"], *task["steps"], task["verification"]):
            if value:
                lines.append("  " + _text(value))
    return "\n".join(lines) + "\n"


def _task_markup(task):
    label = escape(task["priority_label"])
    style = PRIORITY_STYLE[task["priority"]]
    pieces = [
        f'<article><h3><span class="flag {style}">{label}</span>{escape(task["title"])}</h3>',
        f'<p class="muted">{escape(task["source"])}</p>',
    ]
    if task["rationale"]:
        pieces.append(f'<p>{escape(task["rationale"])}</p>')
    for heading, values in (("Evidence", task["evidence"]), ("Actions", task["steps"])):
        if values:
            items = "".join(f"<li>{escape(value)}</li>" for value in values)
            pieces.append(f"<p><strong>{heading}</strong></p><ul>{items}</ul>")
    pieces.append(f'<p><strong>Verify</strong> {escape(task["verification"])}</p></article>')
    return "".join(pieces)


def html_plan(plan):
    host = plan["host"]
    badges = "".join(
        f"<span><strong>{plan['counts'][key]}</strong> {label}</span>" for key, label in PRIORITIES.items()
    )
    tasks = "".join(_task_markup(task) for task in plan["tasks"])
    if not tasks:
        tasks = "<p>No tasks from the available evidence. Review coverage below.</p>"
    coverage = "".join(
        f"<li><strong>{escape(row['label'])}</strong> {escape(row['detail'])}</li>" for row in plan["sources"]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardr Remediation Plan</title><style>{REPORT_CSS}</style></head><body><main>
<header><span class="brand">WARDR</span><h1>Remediation plan</h1>
<p class="muted">{escape(host['name'])} · {escape(host['os'])}</p>
<p class="muted">Generated {escape(plan['generated_at'])} (UTC)</p><div class="risks">{badges}</div></header>
<section><h2>Prioritized actions</h2>{tasks}</section>
<section><h2>Coverage</h2><ul>{coverage}</ul></section>
</main></body></html>
"""
