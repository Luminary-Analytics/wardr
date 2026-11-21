"use strict";

const $ = (id) => document.getElementById(id);
const TOKEN_KEY = "wardr-fleet-session";
const state = {
  token: sessionStorage.getItem(TOKEN_KEY) || "",
  me: null,
  tab: "fleet",
  overview: null,
  selectedHost: null,
};

function make(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

function notice(msg, isError = false) {
  const el = $("fleet-notice");
  if (!msg) { el.hidden = true; return; }
  el.textContent = msg;
  el.className = isError ? "notice notice-error" : "notice";
  el.hidden = false;
}

async function api(path, body, raw = false) {
  const headers = {};
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  const opts = { headers };
  if (body !== undefined) {
    opts.method = "POST";
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  if (resp.status === 401 && path !== "/api/fleet/login") {
    signOutLocal();
    throw new Error("Session expired. Sign in again.");
  }
  if (raw) {
    if (!resp.ok) throw new Error("Could not fetch export.");
    return await resp.blob();
  }
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function signOutLocal() {
  state.token = "";
  state.me = null;
  sessionStorage.removeItem(TOKEN_KEY);
  $("app-shell").hidden = true;
  $("login-screen").hidden = false;
}

function severityPill(sev) {
  const cls = sev === "critical" || sev === "high" ? "pill-danger"
    : sev === "medium" ? "pill-warn" : "pill-neutral";
  return make("span", "pill " + cls, sev || "info");
}

function statusPill(st) {
  const cls = st === "online" || st === "pass" || st === "completed" ? "pill-ok"
    : st === "stale" || st === "queued" || st === "dispatched" ? "pill-warn"
    : st === "revoked" || st === "fail" || st === "failed" ? "pill-danger" : "pill-neutral";
  return make("span", "pill " + cls, st || "unknown");
}

function canAct() {
  return state.me && (state.me.role === "admin" || state.me.role === "responder");
}

function renderOverview(data) {
  state.overview = data;
  const s = data.summary;
  $("kpi-hosts").textContent = String(s.total_hosts);
  $("kpi-online").textContent = `${s.online} online · ${s.stale} stale · ${s.offline} offline`;
  $("kpi-score").textContent = `${s.fleet_score}%`;
  $("kpi-crit-high").textContent = `${s.open_critical} / ${s.open_high}`;
  $("kpi-alerts").textContent = String(s.active_alerts);
  $("kpi-surface").textContent = String(s.risky_services);
  $("kpi-fim").textContent = String(s.fim_failures);

  // Populate tag filter preserving current selection.
  const tagSelect = $("filter-tag");
  const prevTag = tagSelect.value;
  tagSelect.replaceChildren(make("option", "", "All tags"));
  tagSelect.firstChild.value = "";
  for (const tag of data.tags || []) {
    const opt = make("option", "", tag);
    opt.value = tag;
    tagSelect.append(opt);
  }
  tagSelect.value = prevTag;

  // Cross-host correlations.
  const corrRoot = $("correlations-list");
  if (!data.correlations.length) {
    corrRoot.replaceChildren(make("p", "empty", "No open cross-host findings or zero-day drift alerts."));
  } else {
    corrRoot.replaceChildren(...data.correlations.map((c) => {
      const row = make("div", "corr-item");
      const left = make("div");
      const head = make("div");
      head.append(severityPill(c.severity), make("strong", "", " " + c.title));
      const meta = make("div", "corr-meta",
        `${c.kind.toUpperCase()} · ${c.host_count} host(s): ${c.hostnames.slice(0, 5).join(", ")}`
        + (c.hostnames.length > 5 ? ` +${c.hostnames.length - 5} more` : ""));
      left.append(head, meta);
      const right = make("div", "btn-row");
      if (canAct() && c.can_bulk_fix) {
        const fixBtn = make("button", "btn btn-primary btn-sm", `Fix on ${c.host_count} host(s)`);
        fixBtn.type = "button";
        fixBtn.addEventListener("click", () => dispatchCommand("apply_fix", { id: c.id }, c.host_ids));
        right.append(fixBtn);
      } else if (canAct()) {
        const scanBtn = make("button", "btn btn-secondary btn-sm", "Rescan affected");
        scanBtn.type = "button";
        scanBtn.addEventListener("click", () => dispatchCommand("scan", {}, c.host_ids));
        right.append(scanBtn);
      }
      row.append(left, right);
      return row;
    }));
  }

  // Host table with client-side hostname search.
  const search = ($("filter-search").value || "").trim().toLowerCase();
  const hosts = (data.hosts || []).filter((h) => !search || h.hostname.toLowerCase().includes(search));
  const tbody = $("hosts-tbody");
  if (!hosts.length) {
    tbody.replaceChildren(make("tr"));
    const td = make("td", "empty", "No matching hosts found.");
    td.colSpan = 9;
    tbody.firstChild.append(td);
  } else {
    tbody.replaceChildren(...hosts.map((h) => {
      const tr = make("tr");
      const nameTd = make("td");
      nameTd.append(make("strong", "", h.hostname), make("div", "corr-meta", `${h.host_id} · v${h.wardr_version}`));
      const roleTd = make("td");
      roleTd.append(make("span", "pill pill-neutral", h.role), " ");
      for (const t of h.tags || []) roleTd.append(make("span", "tag", t));
      const osTd = make("td", "", `${h.os} (${h.arch})`);
      const stTd = make("td"); stTd.append(statusPill(h.status));
      const scoreTd = make("td"); scoreTd.append(make("strong", "", `${h.posture_score}%`));
      const chTd = make("td", "", `${h.open_critical} / ${h.open_high}`);
      const alTd = make("td", "", String(h.active_alerts));
      const fimTd = make("td"); fimTd.append(statusPill(h.fim_status));
      const actTd = make("td");
      const btn = make("button", "btn btn-secondary btn-sm", "Inspect");
      btn.type = "button";
      btn.addEventListener("click", () => openHostDetail(h.host_id));
      actTd.append(btn);
      tr.append(nameTd, roleTd, osTd, stTd, scoreTd, chTd, alTd, fimTd, actTd);
      return tr;
    }));
  }

  // Recent commands.
  const cmdRoot = $("commands-list");
  if (!data.recent_commands.length) {
    cmdRoot.replaceChildren(make("p", "empty", "No commands dispatched yet."));
  } else {
    cmdRoot.replaceChildren(...data.recent_commands.slice(0, 12).map((c) => {
      const row = make("div", "cmd-item");
      const left = make("div");
      const paramText = Object.keys(c.params || {}).length ? " " + JSON.stringify(c.params) : "";
      left.append(make("strong", "", `${c.action}${paramText}`),
        make("div", "corr-meta", `${c.command_id} · ${c.host_id} · by ${c.created_by} at ${c.created_at}`));
      const right = make("div");
      right.append(statusPill(c.status));
      row.append(left, right);
      return row;
    }));
  }
}

async function dispatchCommand(action, params, hostIds, tag) {
  try {
    const body = { action, params: params || {} };
    if (hostIds) body.host_ids = hostIds;
    if (tag) body.tag = tag;
    const res = await api("/api/fleet/commands", body);
    notice(`Queued allowlisted action "${res.action}" on ${res.queued} host(s).`);
    await loadOverview();
  } catch (err) {
    notice(err.message, true);
  }
}

async function openHostDetail(hostId) {
  try {
    const detail = await api(`/api/fleet/hosts/${encodeURIComponent(hostId)}`);
    state.selectedHost = detail;
    $("host-dialog-title").textContent = detail.hostname;
    $("host-dialog-meta").textContent = `${detail.host_id} · ${detail.os} ${detail.os_version} (${detail.arch}) · Score ${detail.posture_score}% · Last seen ${detail.last_seen}`;

    const actions = $("host-dialog-actions");
    actions.replaceChildren();
    if (canAct() && detail.status !== "revoked") {
      for (const [act, label] of [["scan", "Run scan"], ["fim_check", "Check FIM"], ["inventory", "Refresh Auto-SBOM"]]) {
        const b = make("button", "btn btn-secondary btn-sm", label);
        b.type = "button";
        b.addEventListener("click", () => dispatchCommand(act, {}, [detail.host_id]));
        actions.append(b);
      }
    }
    if (state.me?.role === "admin" && detail.status !== "revoked") {
      const rev = make("button", "btn btn-danger btn-sm", "Revoke host");
      rev.type = "button";
      rev.addEventListener("click", async () => {
        await api(`/api/fleet/hosts/${encodeURIComponent(detail.host_id)}/revoke`, {});
        $("host-dialog").close();
        notice(`Revoked device credentials for ${detail.hostname}.`);
        await loadOverview();
      });
      actions.append(rev);
    }

    const body = $("host-dialog-body");
    body.replaceChildren();
    const snap = detail.snapshot || {};

    const addSection = (title, items, renderItem) => {
      const sec = make("div", "detail-section");
      sec.append(make("h3", "", `${title} (${items.length})`));
      if (!items.length) sec.append(make("p", "empty", "None observed."));
      else items.forEach((it) => sec.append(renderItem(it)));
      body.append(sec);
    };

    addSection("Open posture checks", (snap.checks || []).filter((c) => c.status === "fail"), (c) => {
      const row = make("div", "detail-row");
      const left = make("div");
      left.append(severityPill(c.severity), make("strong", "", " " + c.title), make("div", "corr-meta", c.evidence));
      row.append(left);
      if (canAct() && c.can_fix && detail.status !== "revoked") {
        const b = make("button", "btn btn-primary btn-sm", "1-Click Fix");
        b.type = "button";
        b.addEventListener("click", () => dispatchCommand("apply_fix", { id: c.id }, [detail.host_id]));
        row.append(b);
      }
      return row;
    });

    addSection("Active alerts & baseline drift", snap.alerts || [], (a) => {
      const row = make("div", "detail-row");
      const left = make("div");
      left.append(severityPill(a.severity), make("strong", "", " " + a.title), make("div", "corr-meta", a.summary));
      row.append(left);
      return row;
    });

    addSection("Exposed risky services", snap.risky_services || [], (s) => {
      const row = make("div", "detail-row");
      const left = make("div");
      left.append(severityPill(s.severity), make("strong", "", ` ${s.service} (:${s.port})`),
        make("div", "corr-meta", `Scope: ${s.scope}` + (s.process ? ` · Process: ${s.process}` : "")));
      row.append(left);
      return row;
    });

    $("host-dialog").showModal();
  } catch (err) {
    notice(err.message, true);
  }
}

async function loadOverview() {
  const params = new URLSearchParams();
  if ($("filter-tag").value) params.set("tag", $("filter-tag").value);
  if ($("filter-os").value) params.set("os", $("filter-os").value);
  if ($("filter-status").value) params.set("status", $("filter-status").value);
  const qs = params.toString() ? "?" + params.toString() : "";
  const data = await api("/api/fleet/overview" + qs);
  renderOverview(data);
}

async function loadAdminTab() {
  if (state.me?.role !== "admin") {
    $("tokens-list").replaceChildren(make("p", "empty", "Admin role required to view enrollment tokens."));
    $("operators-list").replaceChildren(make("p", "empty", "Admin role required to manage team operators."));
    return;
  }
  const [tokData, opData] = await Promise.all([api("/api/fleet/tokens"), api("/api/fleet/operators")]);
  $("tokens-list").replaceChildren(...(tokData.tokens || []).map((t) => {
    const row = make("div", "token-item");
    const left = make("div");
    left.append(make("strong", "", `${t.label} (${t.token_id})`),
      make("div", "corr-meta", `${t.default_role} · ${t.uses}/${t.max_uses} uses · expires ${t.expires_at}`));
    const right = make("div", "btn-row");
    right.append(statusPill(t.active ? "online" : "revoked"));
    if (t.active) {
      const b = make("button", "btn btn-danger btn-sm", "Revoke");
      b.type = "button";
      b.addEventListener("click", async () => {
        await api(`/api/fleet/tokens/${encodeURIComponent(t.token_id)}/revoke`, {});
        notice(`Revoked token ${t.token_id}.`);
        loadAdminTab();
      });
      right.append(b);
    }
    row.append(left, right);
    return row;
  }));
  $("operators-list").replaceChildren(...(opData.operators || []).map((o) => {
    const row = make("div", "token-item");
    row.append(make("strong", "", o.username), make("span", "pill pill-neutral", o.role));
    return row;
  }));
}

async function loadAuditTab() {
  const data = await api("/api/fleet/audit");
  const tbody = $("audit-tbody");
  const rows = data.entries || [];
  if (!rows.length) {
    tbody.replaceChildren(make("tr"));
    const td = make("td", "empty", "No audit records.");
    td.colSpan = 6;
    tbody.firstChild.append(td);
    return;
  }
  tbody.replaceChildren(...rows.map((e) => {
    const tr = make("tr");
    tr.append(
      make("td", "", e.at), make("td", "", e.actor), make("td", "", e.role),
      make("td", "", e.action), make("td", "", e.target), make("td", "", e.detail),
    );
    return tr;
  }));
}

async function selectTab(name) {
  state.tab = name;
  notice("");
  for (const btn of document.querySelectorAll(".nav-tab")) {
    btn.setAttribute("aria-selected", String(btn.dataset.tab === name));
  }
  for (const id of ["fleet", "enroll", "audit"]) {
    $("tab-" + id).hidden = id !== name;
  }
  if (name === "fleet") await loadOverview();
  else if (name === "enroll") await loadAdminTab();
  else if (name === "audit") await loadAuditTab();
}

async function enterApp() {
  try {
    state.me = await api("/api/fleet/me");
    $("op-identity").textContent = `${state.me.username} (${state.me.role})`;
    $("fleet-bulk-actions").hidden = !canAct();
    $("login-screen").hidden = true;
    $("app-shell").hidden = false;
    await selectTab(state.tab);
  } catch {
    signOutLocal();
  }
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").hidden = true;
  try {
    const res = await api("/api/fleet/login", {
      username: $("login-user").value.trim(),
      password: $("login-pass").value,
    });
    state.token = res.token;
    sessionStorage.setItem(TOKEN_KEY, res.token);
    $("login-pass").value = "";
    await enterApp();
  } catch (err) {
    $("login-error").textContent = err.message;
    $("login-error").hidden = false;
  }
});

$("logout-btn").addEventListener("click", async () => {
  try { await api("/api/fleet/logout", {}); } catch { /* ignore */ }
  signOutLocal();
});
$("refresh-btn").addEventListener("click", () => selectTab(state.tab));
$("close-host-dialog").addEventListener("click", () => $("host-dialog").close());

for (const btn of document.querySelectorAll(".nav-tab")) {
  btn.addEventListener("click", () => selectTab(btn.dataset.tab));
}
for (const btn of document.querySelectorAll("[data-bulk-action]")) {
  btn.addEventListener("click", () => dispatchCommand(btn.dataset.bulkAction, {}, null, $("filter-tag").value || null));
}
for (const id of ["filter-tag", "filter-os", "filter-status"]) {
  $(id).addEventListener("change", () => loadOverview());
}
$("filter-search").addEventListener("input", () => { if (state.overview) renderOverview(state.overview); });

$("token-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/fleet/tokens", {
      label: $("tok-label").value.trim(),
      default_role: $("tok-role").value,
      default_tags: $("tok-tags").value.trim(),
      max_uses: Number($("tok-uses").value || 25),
    });
    $("enroll-command-text").textContent =
      `wardr fleet enroll --server ${window.location.origin} --token ${res.enrollment_token}`;
    $("enroll-command-box").hidden = false;
    $("tok-label").value = "";
    $("tok-tags").value = "";
    notice(`Generated enrollment token ${res.token_id}.`);
    await loadAdminTab();
  } catch (err) {
    notice(err.message, true);
  }
});

$("copy-enroll-btn").addEventListener("click", async () => {
  const cmd = $("enroll-command-text").textContent || "";
  if (!cmd) return;
  try {
    await navigator.clipboard.writeText(cmd);
    notice("Copied enrollment command to clipboard.");
  } catch {
    notice("Select and copy the command from the box below.");
  }
});

$("operator-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/fleet/operators", {
      username: $("op-user").value.trim(),
      password: $("op-pass").value,
      role: $("op-role").value,
    });
    $("op-user").value = "";
    $("op-pass").value = "";
    notice(`Added ${res.role} operator "${res.username}".`);
    await loadAdminTab();
  } catch (err) {
    notice(err.message, true);
  }
});

$("open-html-report").addEventListener("click", async () => {
  const blob = await api("/api/fleet/report.html", undefined, true);
  window.open(URL.createObjectURL(blob), "_blank", "noopener");
});
$("download-json-report").addEventListener("click", async () => {
  const blob = await api("/api/fleet/report.json?download=1", undefined, true);
  const a = make("a");
  a.href = URL.createObjectURL(blob);
  a.download = "wardr-fleet-compliance.json";
  a.click();
});

if (state.token) enterApp();
