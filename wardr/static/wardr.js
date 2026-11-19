"use strict";

const element = (id) => document.getElementById(id);
let token = launchToken();
const launchInstruction = "Open the launch link printed by Wardr to access this dashboard.";
const views = {
  overview: ["Overview", "Security checks and activity for this device."],
  checklist: ["Checklist", "Review each device check and its recommended action."],
  defense: ["Defense", "Review local evidence and decide what to address first."],
  events: ["Events", "Review changes observed by Wardr on this device."],
  reports: ["Reports", "Open or download the assessment for this device."],
};
const severities = ["critical", "high", "medium", "low"];
const state = {
  data: null,
  view: "overview",
  defense: null,
  defenseTab: "plan",
  defenseLimits: { plan: 12, exposure: 20, software: 12 },
  defenseNotice: null,
  pendingExposure: false,
  pendingSoftware: false,
  pendingModel: false,
  model: null,
  modelReview: null,
  update: null,
  updateError: null,
  pendingUpdate: null,
  connected: false,
  pendingScan: false,
  pendingIntel: false,
  pendingFix: false,
  pendingReport: false,
  needsLaunch: !token,
  actionNotice: null,
  fixId: null,
  rendered: new Map(),
};
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const numberFormat = new Intl.NumberFormat();
let refreshRequest;
let defenseRequest;
let updateRequest;
let defenseRefreshed = 0;
let pollTimer;
let pollGeneration = 0;

function launchToken() {
  const key = "wardr-launch-token";
  const hash = window.location.hash.slice(1);
  const supplied = new URLSearchParams(hash).get("access");
  if (supplied === null) {
    try { return sessionStorage.getItem(key); } catch { return null; }
  }
  window.history.replaceState(null, "", "#overview");
  if (!/^[A-Za-z0-9_-]{43}$/.test(supplied)) return null;
  try { sessionStorage.setItem(key, supplied); } catch { /* Keep this tab usable without storage. */ }
  return supplied;
}

function setText(id, value) {
  const node = element(id);
  if (node.textContent !== value) node.textContent = value;
}

function make(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

function humanDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "" : dateFormat.format(date);
}

function capitalized(value) {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : "";
}

function plural(count, word, pluralWord = word + "s") {
  return numberFormat.format(count) + " " + (count === 1 ? word : pluralWord);
}

function httpUrl(value) {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

function replaceWhenChanged(target, data, render) {
  const signature = JSON.stringify(data);
  if (state.rendered.get(target) === signature) return;
  state.rendered.set(target, signature);
  render();
}

function selectView(steered = false) {
  const hash = window.location.hash.slice(1);
  if (steered && hash === "main") return;
  const selected = Object.hasOwn(views, hash) ? hash : "overview";
  state.view = selected;
  const [heading, description] = views[selected];
  setText("page-title", heading);
  setText("page-description", description);
  document.title = heading + " · Wardr";
  for (const name of Object.keys(views)) {
    element(name + "-view").hidden = name !== selected;
    const link = document.querySelector('[data-nav="' + name + '"]');
    if (name === selected) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (steered) {
    element("main").focus();
    window.scrollTo(0, 0);
  }
  element("scan-button").hidden = selected === "defense";
}

function renderConnection() {
  const mode = state.connected ? "connected" : state.data ? "offline" : "connecting";
  element("connection").dataset.state = mode;
  setText("connection-label", mode === "connected" ? "Local connection" : mode === "offline" ? "Disconnected" : "Connecting");
}

function connectionError(error) {
  if (error?.status === 403) state.needsLaunch = true;
  state.connected = false;
  renderConnection();
  element("connection").dataset.state = "offline";
  setText("connection-label", "Disconnected");
  const notice = element("connection-error");
  notice.dataset.tone = "error";
  notice.hidden = false;
  setText("connection-error", state.needsLaunch ? launchInstruction : state.data
    ? "Wardr lost its local connection. This page shows the last available results."
    : "Wardr could not connect to its local service. Start Wardr and open the address it prints.");
  renderControls();
}

function renderControls() {
  const scan = state.data?.scan;
  const intel = state.data?.intel;
  const scanning = state.pendingScan || scan?.state === "running";
  const fixing = state.pendingFix || scan?.fix_running === true;
  const refreshing = state.pendingIntel || intel?.state === "running";
  element("scan-button").disabled = !state.connected || scanning || fixing;
  element("scan-button").dataset.running = String(scanning);
  setText("scan-label", scanning ? "Scanning…" : "Run scan");
  element("intel-button").disabled = !state.connected || refreshing || state.data?.offline === true;
  setText("intel-button", state.data?.offline ? "Offline mode" : refreshing ? "Refreshing…" : "Refresh catalog");
  for (const button of document.querySelectorAll("[data-fix]")) {
    button.disabled = !state.connected || scanning || fixing;
  }
  const current = scan?.checks?.find((check) => check.id === state.fixId);
  element("confirm-fix").disabled = !state.connected || scanning || fixing || !current?.can_fix || current.status !== "fail";
  for (const button of document.querySelectorAll("[data-report]")) {
    const ready = button.dataset.report.startsWith("/plan.") ? state.defense?.plan : scan?.updated_at;
    button.disabled = !state.connected || !ready || state.pendingReport;
  }
  renderDefenseControls();
  renderUpdates();
}

function renderNotice() {
  const failure = state.data?.scan?.error;
  const message = state.actionNotice || (failure ? { text: failure, error: true } : null);
  const notice = element("scan-notice");
  notice.hidden = !message;
  notice.dataset.tone = message?.error ? "error" : "ok";
  setText("scan-notice", message?.text || "");
}

function statusBadge(label, tone) {
  const badge = make("span", "status-label", label);
  badge.dataset.tone = tone;
  return badge;
}

function checkStatus(check) {
  if (check.status === "fail") {
    const severity = severities.includes(check.severity) ? check.severity : "unknown";
    return [severity === "unknown" ? "Needs attention" : capitalized(severity), severity];
  }
  if (check.status === "pass") return ["Passed", "pass"];
  if (check.status === "not_applicable") return ["Not applicable", "unknown"];
  return ["Unable to verify", "unknown"];
}

function detailBlock(label, value) {
  const block = make("div");
  block.append(make("h3", null, label), make("p", null, value));
  return block;
}

function referencesBlock(references) {
  const links = make("ul", "reference-list");
  for (const reference of references || []) {
    const url = httpUrl(typeof reference === "string" ? reference : reference?.url);
    if (!url) continue;
    const link = make("a", "text-link", reference.title || reference.label || url.hostname);
    link.href = url.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    const item = make("li");
    item.append(link);
    links.append(item);
  }
  if (!links.childElementCount) return null;
  const block = make("div");
  block.append(make("h3", null, "References"), links);
  return block;
}

function findingCard(check, open) {
  const card = make("details", "finding");
  card.dataset.checkId = check.id;
  card.open = open;
  const summary = make("summary");
  const heading = make("span", "finding-heading");
  heading.append(make("span", "finding-title", check.title));
  if (check.category) heading.append(make("span", "finding-category", check.category));
  summary.append(heading, statusBadge(...checkStatus(check)));
  const body = make("div", "finding-body");
  if (check.risk && check.status === "fail") body.append(detailBlock("Risk", check.risk));
  if (check.evidence) body.append(detailBlock("What Wardr found", check.evidence));
  if (check.remediation && check.status !== "pass") body.append(detailBlock("Recommended action", check.remediation));
  const references = referencesBlock(check.references);
  if (references) body.append(references);
  if (check.can_fix === true && check.status === "fail") {
    const button = make("button", "button button-secondary button-small", "Review fix");
    button.type = "button";
    button.dataset.fix = check.id;
    button.addEventListener("click", () => showFix(check.id));
    body.append(button);
  }
  card.append(summary, body);
  return card;
}

function renderFindings(targetId, checks, fallback) {
  replaceWhenChanged(targetId, [checks, fallback], () => {
    const target = element(targetId);
    const expanded = new Set(Array.from(target.querySelectorAll("details[open]"), (row) => row.dataset.checkId));
    const focused = target.contains(document.activeElement) ? document.activeElement : null;
    const focusedId = focused?.closest("details")?.dataset.checkId;
    const cards = checks.map((check) => findingCard(check, expanded.has(check.id)));
    target.replaceChildren(...(cards.length ? cards : [make("p", "empty", fallback)]));
    if (focused) {
      const replacement = cards.find((row) => row.dataset.checkId === focusedId);
      const nextFocus = replacement?.querySelector(focused.matches("[data-fix]") ? "[data-fix]" : "summary")
        || cards[0]?.querySelector("summary") || element("main");
      nextFocus.focus({ preventScroll: true });
    }
  });
}

function sortedChecks(checks) {
  const order = { fail: 0, unknown: 1, pass: 2, not_applicable: 3 };
  function priority(check) {
    const index = severities.indexOf(check.severity);
    return index < 0 ? severities.length : index;
  }
  return [...checks].sort((a, b) => (order[a.status] ?? 4) - (order[b.status] ?? 4)
    || priority(a) - priority(b) || String(a.title).localeCompare(b.title));
}

function showScan(scan) {
  const checks = sortedChecks(scan.checks);
  const attention = checks.filter((check) => check.status === "fail");
  const unknown = checks.filter((check) => check.status === "unknown");
  const passed = checks.filter((check) => check.status === "pass");
  const ready = Boolean(scan.updated_at);
  const scanDate = humanDate(scan.updated_at);
  const waiting = scan.state === "running" ? "Device scan is running." : "Run a scan to review this device.";
  let headline = "Waiting for results";
  let description = waiting;
  if (ready) {
    headline = attention.length ? plural(attention.length, "open finding")
      : passed.length ? "No open findings" : "Coverage unavailable";
    const coverage = [plural(passed.length, "check") + " passed"];
    if (unknown.length) coverage.push(plural(unknown.length, "check") + " could not be verified");
    if (scan.state === "running") coverage.push("A new scan is running");
    description = coverage.join(" · ");
  }
  setText("posture-headline", headline);
  setText("posture-description", description);
  for (const severity of severities) {
    setText("risk-" + severity, ready ? numberFormat.format(attention.filter((check) => check.severity === severity).length) : "–");
  }
  setText("checklist-subtitle", ready
    ? plural(attention.length, "open finding") + " · " + plural(unknown.length, "check") + " unable to verify"
    : waiting);
  setText("last-scan", scanDate ? "Last scan " + scanDate : "No scan recorded");
  setText("report-detail", scanDate ? "Based on the scan completed " + scanDate + "." : "Complete a device scan to generate a report.");
  renderFindings("priority-list", attention.slice(0, 3), ready ? "No checks flagged for action in this scan." : waiting);
  const filter = element("check-filter").value;
  const shown = filter === "attention" ? attention : filter === "unknown" ? unknown : checks;
  const empty = filter === "attention" ? "No checks flagged for action in this scan."
    : filter === "unknown" ? "No checks are marked unable to verify." : "No checks were recorded in this scan.";
  renderFindings("full-checklist", shown, ready ? empty : waiting);
}

function coverageRow(item) {
  const row = make("li");
  const label = String(item.label || item.id || "Local signal");
  row.append(make("strong", null, label));
  const status = item.available === null ? "Pending" : item.available ? "Available" : "Unavailable";
  row.append(" — " + status);
  if (item.detail) row.append(". " + item.detail);
  return row;
}

function eventCard(event) {
  const card = make("article", "event");
  const heading = make("div", "event-heading");
  heading.append(make("h3", null, event.title));
  if (event.detail) heading.append(make("p", null, event.detail));
  const meta = [humanDate(event.at), event.source].filter(Boolean).join(" · ");
  if (meta) heading.append(make("p", "event-meta", meta));
  card.append(heading, statusBadge(capitalized(event.severity) || "Info", event.severity || "info"));
  return card;
}

function showMonitoring(monitor) {
  const checked = humanDate(monitor.last_poll);
  const label = monitor.running ? "Active" : "Inactive";
  const message = checked ? "Last sampled " + checked + "." : "Waiting for the first sample.";
  setText("monitor-label", label);
  setText("monitor-detail", message);
  element("monitor-status").dataset.running = String(monitor.running);
  setText("events-status", label);
  element("events-status").dataset.tone = monitor.running ? "pass" : "unknown";
  const cadence = monitor.running && monitor.interval > 0 ? " Checks every " + monitor.interval + " seconds." : "";
  setText("events-detail", message + cadence);
  const coverage = monitor.coverage || [];
  const available = coverage.filter((item) => item.available === true).length;
  const coverageSummary = checked && coverage.length
    ? numberFormat.format(available) + " of " + plural(coverage.length, "source") + " available"
    : "";
  setText("monitor-coverage", coverageSummary);
  element("monitor-coverage").hidden = !coverageSummary;
  setText("history-detail", monitor.history_detail || "");
  element("history-detail").hidden = !monitor.history_detail;
  element("events-coverage").hidden = coverage.length === 0;
  replaceWhenChanged("coverage-list", coverage, () => {
    element("coverage-list").replaceChildren(...coverage.map(coverageRow));
  });
  const events = monitor.events || [];
  const empty = checked ? "No changes recorded in the signals Wardr monitors." : "Events will appear here when Wardr detects a change.";
  replaceWhenChanged("event-list", [events, empty], () => {
    element("event-list").replaceChildren(...(events.length ? events.map(eventCard) : [make("p", "empty", empty)]));
  });
}

function showIntel(intel) {
  const date = humanDate(intel.refreshed_at);
  const label = state.data?.offline ? (intel.available
    ? "Offline mode uses the downloaded catalog." : "No downloaded catalog is available in offline mode.")
    : intel.state === "running" ? "Fetching the CISA catalog…"
    : intel.error || (intel.available && Number.isInteger(intel.count) ? plural(intel.count, "advisory", "advisories")
      : intel.detail || "Catalog not downloaded");
  setText("intel-state", label);
  element("intel-state").dataset.tone = intel.error ? "error" : "ok";
  element("intel-version").hidden = !date;
  setText("intel-version", date ? "Refreshed " + date : "");
  const advisories = (intel.advisories || []).slice(0, 5);
  element("intel-advisories").hidden = advisories.length === 0;
  setText("intel-scope", intel.scope || "Public advisories for review.");
  replaceWhenChanged("intel-list", advisories, () => {
    element("intel-list").replaceChildren(...advisories.map((advisory) => {
      const item = make("li");
      item.append(make("strong", null, advisory.id), " " + advisory.title);
      return item;
    }));
  });
  const source = httpUrl(intel.source_url);
  element("intel-source").hidden = !source || state.data?.offline === true;
  if (source) element("intel-source").href = source.href;
  else element("intel-source").removeAttribute("href");
}

function renderStatus(data) {
  state.connected = true;
  state.data = data;
  element("connection-error").hidden = true;
  renderConnection();
  setText("device-name", data.host.name || "This device");
  setText("device-os", [data.host.os, data.host.version].filter(Boolean).join(" "));
  setText("workspace-mode", data.offline ? "Offline mode" : "Local workspace");
  showScan(data.scan);
  showMonitoring(data.monitoring);
  showIntel(data.intel);
  renderNotice();
  renderControls();
}

async function request(path, body, format = "json") {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), body === undefined ? 8000 : 120000);
  try {
    const config = { signal: controller.signal, headers: { "X-Wardr-Token": token } };
    if (body !== undefined) {
      config.method = "POST";
      config.headers["Content-Type"] = "application/json";
      config.body = JSON.stringify(body);
    }
    const response = await fetch(path, config);
    if (response.ok && format === "blob") return await response.blob();
    const payload = await response.json();
    if (!response.ok) {
      const error = new Error(payload.error || "Cannot reach the Wardr service.");
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    window.clearTimeout(timeout);
  }
}

function refresh() {
  if (state.needsLaunch) {
    connectionError();
    return Promise.resolve();
  }
  if (!refreshRequest) {
    const requestedToken = token;
    const pending = request("/api/status")
      .then((data) => {
        if (requestedToken !== token) return;
        const previous = state.data?.scan;
        renderStatus(data);
        if (previous?.state === "running" && data.scan.state !== "running") {
          setText("announcer", data.scan.error || "Scan complete.");
        }
      })
      .catch((error) => {
        if (requestedToken === token) connectionError(error);
      })
      .finally(() => { if (refreshRequest === pending) refreshRequest = null; });
    refreshRequest = pending;
  }
  return refreshRequest;
}

async function refreshAfterAction() {
  if (refreshRequest) await refreshRequest;
  await refresh();
}

async function poll() {
  window.clearTimeout(pollTimer);
  const generation = ++pollGeneration;
  await refresh();
  if (generation !== pollGeneration || state.needsLaunch) return;
  if (state.view === "defense" && state.connected) await refreshDefense();
  if (element("updates-dialog").open && updateWorking()) await refreshUpdates();
  if (generation !== pollGeneration || state.needsLaunch) return;
  const busy = state.data?.scan.state === "running" || state.data?.intel.state === "running"
    || state.defense?.exposure.running || (element("updates-dialog").open && updateWorking());
  pollTimer = window.setTimeout(poll, document.hidden ? 15000 : busy ? 1200 : 4000);
}

function errorText(error, fallback) {
  if (error.status === 403) {
    connectionError(error);
    return launchInstruction;
  }
  if (error.name === "AbortError" || error instanceof TypeError || error instanceof SyntaxError) return fallback;
  return error.message || fallback;
}

const updateViews = {
  idle: ["", "Check for a signed Wardr release."],
  checking: ["Checking for updates", "Verifying the latest release information."],
  current: ["Wardr is up to date", ""],
  available: ["Update available", "Wardr will verify the download and update this installation."],
  installing: ["Installing update", "Wardr is downloading, verifying, and installing the release."],
  installed: ["Update installed", "Restart Wardr to use the installed version."],
  restarting: ["Restarting Wardr", "Open the new Wardr window or use the launch link printed in your terminal."],
  unavailable: ["Updates unavailable", ""],
  error: ["Update could not complete", ""],
};
const updateProgress = { check: "checking", install: "installing", restart: "restarting" };

function updateWorking() {
  return ["checking", "installing"].includes(state.update?.state);
}

function updateCommand() {
  if (!state.connected || state.pendingUpdate || updateRequest || updateWorking()) return null;
  if (!state.update && state.updateError) return "status";
  if (state.update?.state === "installed" && state.update.can_restart === true) return "restart";
  if (state.data?.offline || state.update?.state === "restarting") return null;
  if (state.update?.state === "available" && state.update.can_update === true && state.update.available_version) return "install";
  return state.update?.can_check === true ? "check" : null;
}

function renderUpdates() {
  element("updates-button").disabled = !state.connected;
  const update = state.update;
  const phase = updateProgress[state.pendingUpdate] || update?.state;
  const [heading, description] = Object.hasOwn(updateViews, phase) ? updateViews[phase] : ["", "Loading update status…"];
  const offline = state.data?.offline && !["installed", "restarting"].includes(phase);
  const target = update?.installed_version || update?.available_version;
  setText("update-current-version", update?.current_version || "—");
  element("update-target").hidden = !target;
  setText("update-target-label", update?.installed_version ? "Installed update" : "Available version");
  setText("update-target-version", target || "");
  setText("update-heading", state.updateError ? "Update action could not complete" : offline ? "Offline mode" : heading);
  setText("update-message", state.updateError || (offline ? "Update checks are paused in offline mode." : "")
    || (state.pendingUpdate ? description : update?.message || description));
  element("update-feedback").dataset.tone = state.updateError || phase === "error" ? "error" : "";

  const command = updateCommand();
  const button = element("update-action");
  button.hidden = !command && !state.pendingUpdate && !updateWorking()
    && (offline || ["installed", "unavailable"].includes(phase));
  button.disabled = !command;
  const actionLabel = {
    status: "Retry",
    install: "Update Wardr",
    restart: "Restart Wardr",
    check: "Check for updates",
  }[command];
  const progressLabel = { checking: "Checking…", installing: "Installing…", restarting: "Restarting…" }[phase];
  setText("update-action", actionLabel || progressLabel || "Check for updates");
}

function refreshUpdates() {
  if (updateRequest) return updateRequest;
  if (state.needsLaunch || !state.connected || state.pendingUpdate || state.update?.state === "restarting") {
    return Promise.resolve();
  }
  const requestedToken = token;
  const pending = request("/api/update")
    .then((update) => {
      if (requestedToken !== token) return;
      state.update = update;
      state.updateError = null;
    })
    .catch((error) => {
      if (requestedToken === token) state.updateError = errorText(error, "Wardr could not read the update status.");
    })
    .finally(() => {
      if (updateRequest !== pending) return;
      updateRequest = null;
      renderUpdates();
    });
  updateRequest = pending;
  renderUpdates();
  return pending;
}

async function runUpdateCommand() {
  const command = updateCommand();
  if (!command) return;
  state.updateError = null;
  if (command === "status") {
    await refreshUpdates();
    return;
  }
  const requestedToken = token;
  const body = command === "install" ? { version: state.update.available_version } : {};
  state.pendingUpdate = command;
  renderUpdates();
  let accepted = false;
  try {
    await request("/api/update/" + command, body);
    if (requestedToken !== token) return;
    state.update = { ...state.update, state: updateProgress[command], message: "" };
    accepted = true;
  } catch (error) {
    if (requestedToken === token) state.updateError = errorText(error, "Wardr could not start the update action. Try again.");
  } finally {
    if (requestedToken === token) {
      state.pendingUpdate = null;
      renderUpdates();
      if (accepted && command !== "restart") {
        await refreshUpdates();
        poll();
      }
    }
  }
}

async function openReport(event) {
  const report = event.currentTarget.dataset.report;
  state.pendingReport = true;
  state.actionNotice = null;
  renderControls();
  renderNotice();
  try {
    const blob = await request(report, undefined, "blob");
    const url = URL.createObjectURL(blob);
    if (report.endsWith(".html")) {
      window.location.assign(url);
    } else {
      const download = make("a");
      download.href = url;
      download.download = report.startsWith("/plan.") ? "wardr-plan.json" : "wardr-report.json";
      download.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 30000);
      setText("announcer", "Report downloaded.");
    }
  } catch (error) {
    state.actionNotice = { error: true, text: errorText(error, "Wardr could not open the report.") };
  } finally {
    state.pendingReport = false;
    renderNotice();
    renderControls();
  }
}

async function startScan() {
  state.pendingScan = true;
  state.actionNotice = null;
  renderControls();
  renderNotice();
  try {
    await request("/api/scan", {});
    setText("announcer", "Scan started.");
  } catch (error) {
    state.actionNotice = { error: true, text: errorText(error, "Wardr could not start the scan. Check the local connection and try again.") };
  } finally {
    await refreshAfterAction();
    state.pendingScan = false;
    renderNotice();
    renderControls();
  }
}

async function refreshIntel() {
  state.pendingIntel = true;
  state.actionNotice = null;
  renderControls();
  renderNotice();
  try {
    await request("/api/intel/refresh", {});
    setText("announcer", "Advisory refresh started.");
  } catch (error) {
    state.actionNotice = { error: true, text: errorText(error, "Wardr could not start the advisory refresh.") };
  } finally {
    await refreshAfterAction();
    state.pendingIntel = false;
    renderNotice();
    renderControls();
  }
}

function showFix(id) {
  const check = state.data?.scan.checks.find((result) => result.id === id);
  if (!check?.can_fix || check.status !== "fail") return;
  state.fixId = id;
  setText("fix-title", "Apply fix for “" + check.title + "”?");
  setText("fix-effect", check.fix_description || check.remediation || "Wardr will update this security setting on the local device.");
  element("fix-error").hidden = true;
  renderControls();
  element("fix-dialog").showModal();
  element("cancel-fix").focus();
}

async function confirmFix() {
  if (state.pendingFix || !state.fixId) return;
  state.pendingFix = true;
  state.actionNotice = null;
  element("fix-error").hidden = true;
  element("cancel-fix").disabled = true;
  setText("confirm-fix", "Applying…");
  renderNotice();
  renderControls();
  try {
    const result = await request("/api/fix", { id: state.fixId });
    if (!result.ok) throw new Error(result.message || "Wardr could not apply this fix.");
    element("fix-dialog").close();
    state.actionNotice = { error: false, text: result.message || "Fix applied." };
  } catch (error) {
    setText("fix-error", errorText(error, "Wardr could not confirm the fix. Run a new scan to verify the setting."));
    element("fix-error").hidden = false;
  } finally {
    await refreshAfterAction();
    state.pendingFix = false;
    element("cancel-fix").disabled = false;
    setText("confirm-fix", "Apply fix");
    renderNotice();
    renderControls();
  }
}

const defensePriorities = {
  urgent: ["Review now", "critical"], high: ["Prioritize", "high"],
  scheduled: ["Schedule", "medium"], verify: ["Verify", "unknown"],
};
const exposureScopes = { wildcard: "All interfaces", interface: "Specific interface", loopback: "Loopback" };
const softwareLimit = 12 * 1024 * 1024;

function defenseNotice(text, error = false) {
  state.defenseNotice = text ? { text, error } : null;
  const notice = element("defense-notice");
  notice.hidden = !text;
  notice.dataset.tone = error ? "error" : "ok";
  setText("defense-notice", state.defenseNotice?.text || "");
}

function renderDefenseControls() {
  const collecting = state.pendingExposure || state.defense?.exposure.running;
  const assessing = state.pendingSoftware || state.defense?.software.running;
  element("exposure-refresh").disabled = !state.connected || collecting;
  setText("exposure-refresh", collecting ? "Collecting…" : "Refresh exposure");
  for (const id of ["software-sbom", "software-osv"]) element(id).disabled = assessing === true;
  element("software-assess").disabled = !state.connected || assessing
    || !element("software-sbom").files.length || !element("software-osv").files.length;
  setText("software-assess", assessing ? "Assessing…" : "Assess software");
  element("local-model-check").disabled = !state.connected || state.pendingModel;
  element("local-model-review").disabled = !state.connected || state.pendingModel
    || !state.model?.model_ready || !state.defense?.plan.tasks.length;
}

function metricList(id, values) {
  const target = element(id);
  target.hidden = !values.length;
  replaceWhenChanged(id, values, () => {
    target.replaceChildren(...values.map(([label, count, tone]) => {
      const tile = make("div", "defense-metric");
      tile.dataset.tone = tone || "unknown";
      tile.append(make("span", null, label), make("strong", null, numberFormat.format(count)));
      return tile;
    }));
  });
}

function listBlock(label, values) {
  const block = make("div");
  const list = make("ul", "defense-evidence");
  list.append(...values.map((value) => make("li", null, value)));
  block.append(make("h3", null, label), list);
  return block;
}

function defenseFinding(row, title, meta, badge, body) {
  const card = make("details", "finding");
  card.dataset.defenseId = row.id;
  const summary = make("summary");
  const heading = make("span", "finding-heading");
  heading.append(make("span", "finding-title", title), make("span", "finding-category", meta));
  summary.append(heading, statusBadge(...badge));
  const content = make("div", "finding-body");
  content.append(...body.filter(Boolean));
  card.append(summary, content);
  return card;
}

function defenseList(name, rows, factory, fallback) {
  const id = name + "-list";
  const target = element(id);
  const limit = state.defenseLimits[name] ?? rows.length;
  const shown = rows.slice(0, limit);
  replaceWhenChanged(id, [shown, fallback], () => {
    const open = new Set(Array.from(target.querySelectorAll("details[open]"), (row) => row.dataset.defenseId));
    const focus = target.contains(document.activeElement) ? document.activeElement.closest("details")?.dataset.defenseId : null;
    const cards = shown.map(factory);
    for (const card of cards) card.open = open.has(card.dataset.defenseId);
    target.replaceChildren(...(cards.length ? cards : [make("p", "empty", fallback)]));
    if (focus) cards.find((card) => card.dataset.defenseId === focus)?.querySelector("summary")?.focus({ preventScroll: true });
  });
  const more = element(name + "-more");
  if (more) more.hidden = limit >= rows.length;
}

function renderPlan(plan) {
  metricList("plan-counts", Object.entries(defensePriorities).map(([key, [label, tone]]) => [label, plan.counts[key] || 0, tone]));
  element("plan-coverage").hidden = !plan.sources.length;
  replaceWhenChanged("plan-sources", plan.sources, () => {
    element("plan-sources").replaceChildren(...plan.sources.map((source) => {
      const row = make("li");
      row.append(make("strong", null, source.label), " — " + source.detail);
      return row;
    }));
  });
  defenseList("plan", plan.tasks, (task) => defenseFinding(
    task, task.title, task.source, defensePriorities[task.priority], [
      task.rationale && detailBlock("Why it matters", task.rationale),
      task.evidence.length && listBlock("Evidence", task.evidence),
      task.steps.length && listBlock("Actions", task.steps),
      detailBlock("Verify the change", task.verification),
      referencesBlock([{ url: task.source_url, label: "Published advisory" }]),
    ],
  ), "The available evidence produced no remediation tasks. Open Sources and coverage to review what Wardr assessed.");
  renderModelReview(plan);
}

function renderExposure(exposure) {
  const result = exposure.result;
  const checked = humanDate(result?.collected_at);
  const depth = { complete: "Collection complete", partial: "Partial collection", unavailable: "Socket tables unavailable" };
  const status = [result ? depth[result.state] : "", checked ? "Collected " + checked : ""].filter(Boolean).join(" · ");
  setText("exposure-status", [
    exposure.running ? "Collecting local socket tables" : "",
    exposure.error || status || (exposure.running ? "" : "Refresh exposure to collect local socket tables"),
  ].filter(Boolean).join(" · "));
  metricList("exposure-counts", result && result.state !== "unavailable"
    ? Object.entries(exposureScopes).map(([key, label]) => [label, result.summary[key] || 0]) : []);
  const sources = result?.coverage || [];
  element("exposure-coverage").hidden = !sources.length;
  replaceWhenChanged("exposure-sources", sources, () => {
    element("exposure-sources").replaceChildren(...sources.map(coverageRow));
  });
  const listeners = result?.listeners || [];
  element("exposure-table").hidden = !listeners.length;
  element("exposure-more").hidden = state.defenseLimits.exposure >= listeners.length;
  const shown = listeners.slice(0, state.defenseLimits.exposure);
  replaceWhenChanged("exposure-list", shown, () => {
    element("exposure-list").replaceChildren(...shown.map((listener) => {
      const row = make("tr");
      const address = listener.address.includes(":") ? "[" + listener.address + "]" : listener.address;
      const owner = [listener.process, listener.pid && "PID " + listener.pid,
        Number.isInteger(listener.uid) && "UID " + listener.uid].filter(Boolean);
      row.append(make("td", "socket-endpoint", listener.protocol.toUpperCase() + " " + address + ":" + listener.port),
        make("td", null, exposureScopes[listener.scope] || "Unclassified"), make("td", null, owner.join(" · ") || "Unavailable"));
      return row;
    }));
  });
}

function renderHunting(hunting) {
  const sampled = plural(hunting.events_considered, "record") + " reviewed over " + plural(hunting.lookback_hours, "hour");
  const omitted = hunting.alerts_omitted ? plural(hunting.alerts_omitted, "additional alert") + " omitted." : "";
  setText("hunting-status", [sampled + ".", hunting.coverage_note, omitted].filter(Boolean).join(" "));
  element("hunting-coverage").hidden = !hunting.coverage.length;
  replaceWhenChanged("hunting-sources", hunting.coverage, () => {
    element("hunting-sources").replaceChildren(...hunting.coverage.map(coverageRow));
  });
  defenseList("hunting", hunting.alerts, (alert) => defenseFinding(
    alert, alert.title, [capitalized(alert.confidence) + " confidence", humanDate(alert.last_seen)].filter(Boolean).join(" · "),
    [capitalized(alert.severity), alert.severity], [
      alert.summary && detailBlock("Why it was flagged", alert.summary),
      alert.evidence.length && listBlock("Recorded evidence", alert.evidence.map((event) =>
        [humanDate(event.at), event.source, event.title, event.detail].filter(Boolean).join(" · "))),
      alert.actions.length && listBlock("Investigate", alert.actions),
    ],
  ), "No hunting rules matched the available event history.");
}

function renderSoftware(software) {
  const result = software.result;
  const checked = humanDate(result?.assessed_at);
  const catalog = {
    full: "Prioritized using the cached CISA catalog.",
    recent_only: "Prioritization covers only the recent entries in the cached CISA catalog.",
    unavailable: "CISA prioritization requires a downloaded catalog.",
  };
  setText("software-status", software.running ? "Matching the supplied software versions…" : checked
    ? "Assessed " + checked + ". " + (catalog[software.catalog_coverage] || "") : "An assessment covers the supplied files.");
  const totals = result?.summary;
  metricList("software-counts", totals ? [
    ["Published matches", totals.matched_findings],
    ["Packages in inventory", result.inventory.identified_packages],
    ["Coverage gaps", totals.coverage_gaps],
  ] : []);
  element("software-coverage").hidden = !result;
  if (result) {
    const notes = [
      result.scope,
      plural(result.advisories.input_records, "advisory record") + " supplied · "
        + plural(result.inventory.skipped_components, "component") + " skipped.",
      plural(totals.packages_without_advisory_entries, "package") + " had no matching entry in this import.",
      result.advisories.invalid_records && plural(result.advisories.invalid_records, "invalid record") + " skipped.",
      result.advisories.unidentified_affected_entries
        && plural(result.advisories.unidentified_affected_entries, "unidentified affected entry", "unidentified affected entries") + ".",
      totals.omitted_findings && plural(totals.omitted_findings, "additional finding") + " outside the display limit.",
      totals.omitted_coverage_gaps && plural(totals.omitted_coverage_gaps, "additional coverage gap") + " outside the display limit.",
      ...result.coverage_gaps.slice(0, 10).map((gap) =>
        gap.package + " " + gap.version + " · " + gap.advisory_id + " — " + gap.reason),
    ].filter(Boolean);
    if (result.coverage_gaps.length > 10) notes.push("Additional coverage gaps are available in the command-line JSON assessment.");
    replaceWhenChanged("software-sources", notes, () => {
      element("software-sources").replaceChildren(...notes.map((note) => make("li", null, note)));
    });
  }
  defenseList("software", result?.findings || [], (finding) => defenseFinding(
    finding, finding.package + " " + finding.version, finding.advisory_id + " · " + finding.ecosystem,
    finding.known_exploited ? ["CISA listed", "critical"]
      : [finding.severity === "unknown" ? "Unrated" : capitalized(finding.severity), finding.severity], [
      detailBlock("Published finding", finding.title),
      detailBlock("Version evidence", finding.evidence),
      detailBlock("Recommended action", finding.remediation),
      referencesBlock([{ url: finding.source_url, label: "Open advisory in OSV" }]),
    ],
  ), result ? "No versions matched the imported advisories. Review Assessment coverage." : "Choose an inventory and advisory export to start.");
}

function renderModelReview(plan) {
  const review = state.modelReview;
  if (!review) return;
  const tasks = new Map(plan.tasks.map((task) => [task.id, task.title]));
  const selections = review.selections.map((batch) => ({
    ...batch, titles: batch.item_ids.map((id) => tasks.get(id)).filter(Boolean),
  })).filter((batch) => batch.titles.length === batch.item_ids.length);
  replaceWhenChanged("local-model-results", selections, () => {
    const list = element("local-model-results");
    list.replaceChildren(...selections.map((batch, index) => defenseFinding(
      { id: "batch-" + index }, batch.source + " review", plural(batch.titles.length, "plan item"), defensePriorities[batch.priority],
      [detailBlock("Review focus", batch.explanation), listBlock("Plan items", batch.titles)],
    )));
  });
}

function renderDefense() {
  if (!state.defense || state.view !== "defense") return;
  switch (state.defenseTab) {
    case "plan": renderPlan(state.defense.plan); break;
    case "exposure": renderExposure(state.defense.exposure); break;
    case "hunting": renderHunting(state.defense.hunting); break;
    case "software": renderSoftware(state.defense.software); break;
  }
  renderControls();
}

function refreshDefense(force = false) {
  if (state.needsLaunch || !state.connected) return Promise.resolve();
  if (defenseRequest) return defenseRequest;
  if (!force && !state.defense?.exposure.running && Date.now() - defenseRefreshed < 8000) return Promise.resolve();
  const access = token;
  const pending = request("/api/defense")
    .then((data) => {
      if (access !== token) return;
      if (!state.defense && state.defenseNotice?.error) defenseNotice("");
      state.defense = data;
      defenseRefreshed = Date.now();
      renderDefense();
    })
    .catch((error) => {
      if (access === token && !state.defense) defenseNotice(errorText(error, "Wardr could not load the defense tools."), true);
    })
    .finally(() => { if (defenseRequest === pending) defenseRequest = null; });
  defenseRequest = pending;
  return pending;
}

async function collectExposure() {
  state.pendingExposure = true;
  defenseNotice("");
  renderControls();
  try {
    await request("/api/exposure", {});
    setText("announcer", "Local exposure collection started.");
    if (defenseRequest) await defenseRequest;
    await refreshDefense(true);
  } catch (error) {
    defenseNotice(errorText(error, "Wardr could not refresh exposure."), true);
  } finally {
    state.pendingExposure = false;
    renderControls();
    poll();
  }
}

async function assessSoftware(event) {
  event.preventDefault();
  const sbom = element("software-sbom").files[0];
  const advisories = element("software-osv").files[0];
  if (!sbom || !advisories || state.pendingSoftware) return;
  if (sbom.size + advisories.size > softwareLimit) {
    defenseNotice("Choose files with a combined size under 12 MiB.", true);
    return;
  }
  state.pendingSoftware = true;
  defenseNotice("");
  renderControls();
  try {
    const documents = await Promise.all([sbom, advisories].map(async (file) => {
      try {
        return JSON.parse(await file.text());
      } catch {
        throw new Error("Check that " + file.name + " is a readable JSON file.");
      }
    }));
    await request("/api/software/assess", { sbom: documents[0], advisories: documents[1] });
    if (defenseRequest) await defenseRequest;
    state.defenseLimits.software = 12;
    await refreshDefense(true);
    defenseNotice("Software assessment completed.");
  } catch (error) {
    defenseNotice(errorText(error, "Wardr could not assess the supplied files."), true);
  } finally {
    state.pendingSoftware = false;
    renderControls();
  }
}

async function runModelAction(review) {
  state.pendingModel = true;
  setText("local-model-status", review ? "Reviewing plan items on this device…" : "Checking the local model…");
  renderControls();
  try {
    if (review) {
      state.modelReview = await request("/api/local-ai/review", {});
      const reviewed = state.modelReview.reviewed_count;
      setText("local-model-status", reviewed ? "Reviewed " + plural(reviewed, "plan item") + "." : "No plan items were available to review.");
      renderModelReview(state.defense.plan);
    } else {
      state.model = await request("/api/local-ai");
      setText("local-model-status", state.model.message);
    }
  } catch (error) {
    setText("local-model-status", errorText(error, "Wardr could not reach the local model."));
  } finally {
    state.pendingModel = false;
    renderControls();
  }
}

const defenseTabs = [...document.querySelectorAll("[data-defense-tab]")];

function selectDefenseTab(tab, focus = false) {
  state.defenseTab = tab.dataset.defenseTab;
  defenseNotice("");
  for (const button of defenseTabs) {
    const selected = button === tab;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
    element(button.getAttribute("aria-controls")).hidden = !selected;
  }
  renderDefense();
  if (focus) tab.focus();
}

for (const [index, tab] of defenseTabs.entries()) {
  tab.addEventListener("click", () => selectDefenseTab(tab));
  tab.addEventListener("keydown", (event) => {
    const last = defenseTabs.length - 1;
    const next = { ArrowRight: (index + 1) % defenseTabs.length, ArrowLeft: (index + last) % defenseTabs.length,
      Home: 0, End: last }[event.key];
    if (!Number.isInteger(next)) return;
    event.preventDefault();
    selectDefenseTab(defenseTabs[next], true);
  });
}
for (const name of Object.keys(state.defenseLimits)) {
  element(name + "-more").addEventListener("click", () => {
    state.defenseLimits[name] += name === "exposure" ? 20 : 12;
    renderDefense();
  });
}
element("exposure-refresh").addEventListener("click", collectExposure);
element("software-form").addEventListener("submit", assessSoftware);
for (const id of ["software-sbom", "software-osv"]) element(id).addEventListener("change", renderControls);
element("local-model-check").addEventListener("click", () => runModelAction(false));
element("local-model-review").addEventListener("click", () => runModelAction(true));

element("scan-button").addEventListener("click", startScan);
element("intel-button").addEventListener("click", refreshIntel);
element("updates-button").addEventListener("click", () => {
  element("updates-dialog").showModal();
  refreshUpdates();
});
element("close-updates").addEventListener("click", () => element("updates-dialog").close());
element("update-action").addEventListener("click", runUpdateCommand);
for (const button of document.querySelectorAll("[data-report]")) {
  button.addEventListener("click", openReport);
}
element("check-filter").addEventListener("change", () => {
  if (state.data) showScan(state.data.scan);
  renderControls();
});
element("cancel-fix").addEventListener("click", () => element("fix-dialog").close());
element("confirm-fix").addEventListener("click", confirmFix);
element("fix-dialog").addEventListener("close", () => { state.fixId = null; });
element("fix-dialog").addEventListener("cancel", (event) => {
  if (state.pendingFix) event.preventDefault();
});
const heroMark = element("hero-mark");
heroMark.addEventListener("error", () => { heroMark.hidden = true; });
if (heroMark.complete && !heroMark.naturalWidth) heroMark.hidden = true;
window.addEventListener("hashchange", () => {
  if (new URLSearchParams(window.location.hash.slice(1)).has("access")) {
    token = launchToken();
    state.needsLaunch = !token;
    refreshRequest = null;
    defenseRequest = null;
    updateRequest = null;
    state.update = null;
    state.updateError = null;
    state.pendingUpdate = null;
    element("updates-dialog").close();
    state.defense = null;
    state.model = null;
    state.modelReview = null;
    element("local-model-results").replaceChildren();
    setText("local-model-status", "Check whether the local model is ready.");
    defenseRefreshed = 0;
    poll();
  }
  selectView(true);
  if (state.view === "defense") {
    renderDefense();
    refreshDefense();
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) poll();
});
selectView();
poll();
