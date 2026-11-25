"use strict";

const element = (id) => document.getElementById(id);
let pendingBootstrapNonce = null;
let token = launchToken();
const launchInstruction = "Open the launch link printed by Wardr to access this dashboard.";
const views = {
  overview: ["Overview", "Real-time protection, active threats, and security checklist for this device."],
  checklist: ["Checklist", "Visual status of every check Wardr can verify and secure on this device."],
  defense: ["Defense", "See exactly what Wardr protects against, run safe self-pen-tests, and inspect local evidence."],
  events: ["Events", "Live activity and changes observed by Wardr's continuous scanner."],
  reports: ["Reports", "View or export your Red / Amber / Green security report and checklist."],
};
const severities = ["critical", "high", "medium", "low"];
function initialAudienceMode() {
  try {
    return window.localStorage.getItem("wardr-audience-mode") === "technical" ? "technical" : "plain";
  } catch {
    return "plain";
  }
}
function initialTheme() {
  try {
    return window.localStorage.getItem("wardr-theme") === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}
function applyTheme(theme) {
  const mode = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = mode;
  try {
    window.localStorage.setItem("wardr-theme", mode);
  } catch {
    /* ignore */
  }
  const btn = element("theme-toggle-button");
  if (btn) {
    btn.textContent = mode === "dark" ? "☀ Light" : "☾ Dark";
    btn.setAttribute("aria-label", mode === "dark" ? "Switch to light mode" : "Switch to dark mode");
    btn.setAttribute("aria-pressed", String(mode === "dark"));
  }
}
const state = {
  theme: initialTheme(),
  data: null,
  view: "overview",
  overviewFilter: "all",
  defense: null,
  defenseTab: "matrix",
  audienceMode: initialAudienceMode(),
  defenseLimits: { plan: 12, exposure: 20, software: 12 },
  defenseNotice: null,
  pendingExposure: false,
  pendingSoftware: false,
  pendingSupplyChain: false,
  pendingPentest: false,
  pendingPentestFix: false,
  pentestUi: { mode: "scan", activeId: null, revealed: 0, timer: null },
  pendingModel: false,
  authMode: "register",
  pendingAuth: false,
  awaitingSso: false,
  pendingTelemetrySync: false,
  legalData: null,
  legalTab: "privacy",
  whatsNewAutoShown: false,
  model: null,
  modelReview: null,
  update: null,
  updateError: null,
  pendingUpdate: null,
  connected: false,
  pendingScan: false,
  selectedScanProfile: "medium",
  pendingTriage: false,
  pendingAiSave: false,
  aiConfigData: null,
  pendingIntel: false,
  pendingFix: false,
  pendingBatchFix: false,
  pendingScriptTarget: null,
  openGreenChecklistAfterFix: false,
  greenSelectedIds: new Set(),
  pendingGreenApply: false,
  workflow: {
    mode: null,
    activeId: null,
    revealed: 0,
    timer: null,
    dismissed: false,
  },
  pendingReport: false,
  needsLaunch: !token && !pendingBootstrapNonce,
  actionNotice: null,
  fixId: null,
  reportTarget: null,
  reportDraft: null,
  pendingIssueReport: false,
  rendered: new Map(),
};
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const timeFormat = new Intl.DateTimeFormat(undefined, { timeStyle: "medium" });
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
    pendingBootstrapNonce = null;
    try { return sessionStorage.getItem(key); } catch { return null; }
  }
  window.history.replaceState(null, "", "#overview");
  if (!/^[A-Za-z0-9_-]{43}$/.test(supplied)) {
    pendingBootstrapNonce = null;
    return null;
  }
  pendingBootstrapNonce = supplied;
  return null;
}

async function ensureSessionToken() {
  if (token) return true;
  if (!pendingBootstrapNonce) return false;
  const nonce = pendingBootstrapNonce;
  pendingBootstrapNonce = null;
  try {
    const response = await fetch("/api/auth/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce }),
    });
    if (!response.ok) {
      state.needsLaunch = true;
      return false;
    }
    const payload = await response.json();
    if (typeof payload.token === "string" && payload.token.length >= 32) {
      token = payload.token;
      state.needsLaunch = false;
      try { sessionStorage.setItem("wardr-launch-token", token); } catch { /* ignore */ }
      return true;
    }
  } catch {
    /* fall through */
  }
  state.needsLaunch = true;
  return false;
}

function setText(id, value) {
  const node = element(id);
  if (node && node.textContent !== value) node.textContent = value;
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

function humanTime(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "" : timeFormat.format(date);
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
  element("header-actions").hidden = selected === "overview" || selected === "defense";
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
  element("live-radar-pill").dataset.active = "false";
  element("live-radar-pill").dataset.scanning = "false";
  setText("live-radar-label", "Continuous radar offline");
  element("sidebar-guard").dataset.active = "false";
  setText("sidebar-guard-title", "Disconnected");
  setText("sidebar-guard-sub", "Local service unreachable");
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
  const fixing = state.pendingFix || state.pendingBatchFix || scan?.fix_running === true;
  const refreshing = state.pendingIntel || intel?.state === "running";
  const scanDisabled = !state.connected || scanning || fixing;
  element("checklist-fix-all").disabled = scanDisabled;
  element("workflow-fix-all").disabled = scanDisabled;
  element("hero-fix-button").disabled = scanDisabled;
  element("hero-scan-depth").disabled = scanDisabled;
  const activeProfile = scan?.profile_label || "scan";
  const ragLevel = state.data?.posture?.level || "pending";
  const urgentScan = ragLevel === "red" || ragLevel === "amber";
  const depthLabels = { light: "Light", medium: "Medium", heavy: "Heavy" };
  setText("hero-scan-depth-label", "Depth: " + (depthLabels[state.selectedScanProfile] || "Medium") + " ▾");
  element("scan-button").disabled = scanDisabled;
  element("scan-button").dataset.running = String(scanning);
  setText("scan-label", scanning ? "Running " + activeProfile.toLowerCase() + "…" : "Run scan");
  element("hero-scan-button").disabled = scanDisabled;
  element("hero-scan-button").dataset.running = String(scanning);
  setText("hero-scan-label", scanning
    ? "Running " + activeProfile.toLowerCase() + "…"
    : urgentScan ? "Run scan now" : "Run scan");
  setText("hero-report-label", ragLevel === "green" ? "Open visual report" : "Visual report");
  element("posture-hero").dataset.scanning = String(scanning);
  element("live-radar-pill").dataset.scanning = String(scanning);
  const ai = state.data?.ai;
  const aiRunning = state.pendingTriage || ai?.running === true;
  const canTriage = Boolean(
    state.connected && !aiRunning && ai && (
      (ai.active_tier === "cloud" && ai.tier2?.ready)
      || (ai.active_tier === "local" && ai.tier3?.ready)
    )
  );
  element("whats-new-button").disabled = !state.connected;
  element("account-button").disabled = !state.connected;
  element("sidebar-account-btn").disabled = !state.connected;
  element("ai-config-button").disabled = !state.connected || state.pendingAiSave;
  element("ai-triage-button").disabled = !canTriage;
  setText("ai-triage-button", aiRunning ? "Analyzing…" : "Run AI triage");
  element("confirm-scan-dialog").disabled = !state.connected || scanning || fixing;
  element("intel-button").disabled = !state.connected || refreshing || state.data?.offline === true;
  setText("intel-button", state.data?.offline ? "Offline mode" : refreshing ? "Refreshing…" : "Refresh catalog");
  for (const button of document.querySelectorAll("[data-fix]")) {
    button.disabled = !state.connected || scanning || fixing;
  }
  for (const button of document.querySelectorAll("[data-disposition]")) {
    button.disabled = !state.connected || scanning || fixing;
  }
  const current = scan?.checks?.find((check) => check.id === state.fixId);
  element("confirm-fix").disabled = !state.connected || scanning || fixing || !current?.can_fix || current.status !== "fail";
  for (const button of document.querySelectorAll("[data-report]")) {
    const ready = button.dataset.report.startsWith("/plan.") ? state.defense?.plan : scan?.updated_at;
    button.disabled = !state.connected || !ready || state.pendingReport;
  }
  for (const button of document.querySelectorAll("[data-visual-report]")) {
    button.disabled = !state.connected || !scan?.updated_at;
  }
  element("mission-fix-all").disabled = !state.connected || scanning || fixing;
  element("vrep-fix-all").disabled = !state.connected || scanning || fixing;
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

function isPendingUpdateCheck(check) {
  return String(check?.id || "").endsWith("-pending-updates");
}

function isHandledCheck(check) {
  const kind = check?.disposition?.kind;
  if (check?.status === "unknown" && kind === "acknowledged") return true;
  if (check?.status === "fail" && isPendingUpdateCheck(check) && kind === "queued") return true;
  return false;
}

function isAcceptedRiskCheck(check) {
  return check?.status === "fail" && !isPendingUpdateCheck(check) && check?.disposition?.kind === "acknowledged";
}

function openActionableChecks(scan) {
  return sortedChecks(scan?.checks || []).filter(
    (c) => (c.status === "fail" || c.status === "unknown") && !isHandledCheck(c),
  );
}

function isUpdateCheck(check) {
  return String(check?.id || "").includes("update") || String(check?.category || "").toLowerCase() === "updates";
}

function dispositionMeta(check) {
  if (isPendingUpdateCheck(check)) {
    return {
      kind: "queued",
      shortLabel: "Mark queued",
      actionLabel: "Mark queued (pending restart)",
      badgeLabel: "Queued · Pending restart",
    };
  }
  if (check?.status === "unknown") {
    return {
      kind: "acknowledged",
      shortLabel: "Mark verified",
      actionLabel: "Mark verified manually",
      badgeLabel: "Verified manually",
    };
  }
  return {
    kind: "acknowledged",
    shortLabel: "Accept risk",
    actionLabel: "Acknowledge as accepted risk",
    badgeLabel: "Accepted risk",
  };
}

function checkStatus(check) {
  if (isHandledCheck(check)) {
    return check.disposition.kind === "queued"
      ? ["Queued · Pending restart", "queued"]
      : ["Verified manually", "queued"];
  }
  if (isAcceptedRiskCheck(check)) {
    return ["Accepted risk", "medium"];
  }
  if (check.status === "fail") {
    const severity = severities.includes(check.severity) ? check.severity : "unknown";
    return [severity === "unknown" ? "Needs attention" : capitalized(severity) + " risk", severity];
  }
  if (check.status === "pass") return ["Secured", "pass"];
  if (check.status === "not_applicable") return ["Not applicable", "neutral"];
  return ["Unable to verify", "unknown"];
}

function checkVisual(check) {
  if (check.status === "pass" || isHandledCheck(check)) return ["pass", "✓"];
  if (isAcceptedRiskCheck(check)) return ["amber", "!"];
  if (check.status === "fail") {
    return check.severity === "critical" || check.severity === "high" ? ["red", "!"] : ["amber", "!"];
  }
  if (check.status === "unknown") return ["amber", "?"];
  return ["neutral", "–"];
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

function shortSnippet(text, max = 110) {
  if (!text) return "";
  const clean = String(text).replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max - 1) + "…" : clean;
}

function findingCard(check, open) {
  const [visualState, glyphChar] = checkVisual(check);
  const card = make("details", "finding");
  card.dataset.checkId = check.id;
  card.dataset.visual = visualState;
  card.open = open;

  const summary = make("summary");
  const glyph = make("span", "check-glyph", glyphChar);
  glyph.dataset.state = visualState;
  glyph.setAttribute("aria-hidden", "true");

  const heading = make("span", "finding-heading");
  heading.append(make("span", "finding-title", check.title));
  const subParts = [check.category, shortSnippet(check.evidence, 96)].filter(Boolean);
  if (subParts.length) heading.append(make("span", "finding-category", subParts.join(" · ")));

  const handled = isHandledCheck(check);
  const acceptedRisk = isAcceptedRiskCheck(check);
  const hasDisposition = handled || acceptedRisk;
  const dispMeta = dispositionMeta(check);
  const right = make("span", "finding-summary-right");
  if (hasDisposition) {
    const undoBtn = make("button", "button button-secondary button-small button-undo-disp", "Undo");
    undoBtn.type = "button";
    undoBtn.dataset.disposition = check.id;
    undoBtn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      setCheckDisposition(check.id, "clear");
    });
    right.append(undoBtn);
  } else if (check.status === "fail") {
    if (check.can_fix === true) {
      const quickFix = make("button", "button button-fix button-small", "Auto-fix");
      quickFix.type = "button";
      quickFix.dataset.fix = check.id;
      quickFix.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        startBatchFix([check.id], false);
      });
      right.append(quickFix);
    } else if (check.action_guide?.can_script_fix) {
      const scriptQuick = make("button", "button button-script button-small", check.action_guide.script_label || "Fix via script");
      scriptQuick.type = "button";
      scriptQuick.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        promptScriptFixes([check]);
      });
      right.append(scriptQuick);
    }
    if (check.action_guide?.can_open_settings) {
      const settingsQuick = make("button", "button button-settings button-small", (check.action_guide.settings_label || "Open Settings") + " ↗");
      settingsQuick.type = "button";
      settingsQuick.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openCheckSettings(check.id);
      });
      right.append(settingsQuick);
    }
    if (check.can_fix !== true) {
      const markBtn = make("button", "button button-ack button-small", dispMeta.shortLabel);
      markBtn.type = "button";
      markBtn.dataset.disposition = check.id;
      markBtn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        setCheckDisposition(check.id, dispMeta.kind);
      });
      right.append(markBtn);
    }
  }
  right.append(statusBadge(...checkStatus(check)));

  summary.append(glyph, heading, right);

  const body = make("div", "finding-body");
  if (hasDisposition) {
    const markedAt = humanDate(check.disposition.at);
    const statusText = check.disposition.kind === "queued"
      ? "Marked queued (pending restart)" + (markedAt ? " on " + markedAt : "")
        + ". Wardr counts this item as addressed until your restart completes, and will automatically re-verify on future scans or re-alert immediately if a newer update appears."
      : acceptedRisk
        ? "Acknowledged as accepted risk" + (markedAt ? " on " + markedAt : "")
          + ". This security control is still failing on your OS, so device posture stays Amber until you fix it and re-scan."
        : "Confirmed manually" + (markedAt ? " on " + markedAt : "")
          + ". Wardr will automatically re-alert if a future scan detects new or changed evidence.";
    body.append(detailBlock("Status", statusText));
  }
  if (check.risk && check.status === "fail" && !handled) body.append(detailBlock("Risk", check.risk));
  if (check.evidence) body.append(detailBlock("What Wardr found", check.evidence));
  if (check.remediation && check.status !== "pass") body.append(detailBlock("Recommended action", check.remediation));
  const references = referencesBlock(check.references);
  if (references) body.append(references);

  const actions = make("div", "finding-actions");
  if (hasDisposition) {
    const restoreBtn = make("button", "button button-secondary button-small", "Restore to Needs action");
    restoreBtn.type = "button";
    restoreBtn.dataset.disposition = check.id;
    restoreBtn.addEventListener("click", () => setCheckDisposition(check.id, "clear"));
    actions.append(restoreBtn);
  } else {
    if (check.can_fix === true && check.status === "fail") {
      const button = make("button", "button button-primary button-small", "Review & apply fix");
      button.type = "button";
      button.dataset.fix = check.id;
      button.addEventListener("click", () => showFix(check.id));
      actions.append(button);
    }
    if ((check.status === "fail" || check.status === "unknown") && check.action_guide?.can_open_settings) {
      const sBtn = make("button", "button button-settings button-small", (check.action_guide.settings_label || "Open Settings") + " ↗");
      sBtn.type = "button";
      sBtn.addEventListener("click", () => openCheckSettings(check.id));
      actions.append(sBtn);
    }
    if (check.status === "fail" && check.action_guide?.can_script_fix) {
      const scBtn = make("button", "button button-script button-small", check.action_guide.script_label || "Fix via script");
      scBtn.type = "button";
      scBtn.addEventListener("click", () => promptScriptFixes([check]));
      actions.append(scBtn);
    }
    if ((check.status === "fail" && check.can_fix !== true) || check.status === "unknown") {
      const ackBtn = make("button", "button button-ack button-small", dispMeta.actionLabel);
      ackBtn.type = "button";
      ackBtn.dataset.disposition = check.id;
      ackBtn.addEventListener("click", () => setCheckDisposition(check.id, dispMeta.kind));
      actions.append(ackBtn);
    }
    if (check.status === "fail") {
      const reportBtn = make("button", "button button-secondary button-small", "Report to Wardr");
      reportBtn.type = "button";
      reportBtn.addEventListener("click", () => openIssueReport("finding", check.id));
      actions.append(reportBtn);
    }
  }
  if (actions.childElementCount) body.append(actions);
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
  function rank(check) {
    if (isHandledCheck(check)) return 2;
    if (check.status === "fail") return 0;
    if (check.status === "unknown") return 1;
    if (check.status === "pass") return 3;
    return 4;
  }
  function priority(check) {
    const index = severities.indexOf(check.severity);
    return index < 0 ? severities.length : index;
  }
  return [...checks].sort((a, b) => rank(a) - rank(b)
    || priority(a) - priority(b) || String(a.title).localeCompare(b.title));
}

function fallbackPosture(scan) {
  const checks = scan?.checks || [];
  const attention = checks.filter((c) => c.status === "fail" && !isHandledCheck(c));
  const handled = checks.filter((c) => isHandledCheck(c));
  const passed = checks.filter((c) => c.status === "pass");
  const addressed = passed.length + handled.length;
  const unknown = checks.filter((c) => c.status === "unknown" && !isHandledCheck(c));
  const securable = addressed + attention.length + unknown.length;
  const ready = Boolean(scan?.updated_at);
  const red = attention.some((c) => c.severity === "critical" || c.severity === "high");
  const level = !ready ? "pending" : red ? "red" : (attention.length || unknown.length) ? "amber" : addressed ? "green" : "amber";
  return {
    level,
    label: level === "green" ? "Protected" : level === "red" ? "At risk" : level === "amber" ? "Needs attention" : "Scanning",
    headline: !ready ? "Running initial protection scan"
      : level === "green" ? "You are protected"
      : level === "red" ? "Action required to protect this device" : "Almost fully protected",
    summary: !ready ? "Wardr is checking everything it can secure on this device."
      : `${addressed} of ${securable} securable items are addressed.`,
    as_safe_as_possible: level === "green",
    secured: passed.length,
    handled: handled.length,
    queued: handled.filter((c) => c.disposition?.kind === "queued").length,
    acknowledged: handled.filter((c) => c.disposition?.kind === "acknowledged").length,
    addressed,
    failed: attention.length,
    unverified: unknown.length,
    securable_total: securable,
    fixable: attention.filter((c) => c.can_fix === true).length,
    coverage_pct: securable ? Math.round((100 * addressed) / securable) : null,
  };
}

function showPosture(data) {
  const scan = data.scan;
  const posture = data.posture || fallbackPosture(scan);
  const monitor = data.monitoring || {};
  const threats = data.threats || { status: "clear", count: 0 };
  const ready = Boolean(scan.updated_at);
  const level = posture.level || "pending";

  const hero = element("posture-hero");
  hero.dataset.rag = level;
  hero.dataset.monitoring = String(Boolean(monitor.running));
  hero.dataset.scanning = String(state.pendingScan || scan.state === "running");

  setText("rag-label", posture.label || "Scanning");
  setText("posture-headline", posture.headline || "Waiting for results");
  setText("posture-description", posture.summary || "Complete a device scan to see your security status.");

  const meter = element("protection-meter");
  const securable = posture.securable_total || 0;
  const secured = posture.secured || 0;
  const handled = posture.handled || 0;
  const addressed = posture.addressed ?? (secured + handled);
  meter.max = Math.max(securable, 1);
  meter.value = ready ? addressed : 0;

  if (ready && securable > 0) {
    setText("coverage-meter-value", numberFormat.format(addressed) + " of " + numberFormat.format(securable)
      + (handled > 0 ? " addressed (" : " secured (") + (posture.coverage_pct ?? 0) + "%)");
    if (posture.as_safe_as_possible) {
      if ((posture.queued || 0) > 0) {
        setText("protection-verdict", "All items verified or queued for restart — Wardr will auto-verify once you reboot.");
      } else if (handled > 0) {
        setText("protection-verdict", "All securable items are verified or acknowledged with zero active threats.");
      } else {
        setText("protection-verdict", "Everything Wardr can secure on this device is verified secure.");
      }
    } else if (threats.status === "threat") {
      setText("protection-verdict", "Active threat detected right now — review the alert panel below immediately.");
    } else if (posture.failed > 0) {
      const fixText = posture.fixable > 0 ? " (" + plural(posture.fixable, "automatic fix") + " ready)" : "";
      setText("protection-verdict", plural(posture.failed, "item") + " still need attention" + fixText + " to maximize protection.");
    } else if (posture.unverified > 0) {
      setText("protection-verdict", plural(posture.unverified, "check") + " could not be verified automatically.");
    } else if ((posture.accepted_risks || 0) > 0) {
      setText("protection-verdict", plural(posture.accepted_risks, "failing check") + " acknowledged as accepted risk — fix and re-scan to reach Green.");
    } else {
      setText("protection-verdict", "Continuous scanning is paused — restart Wardr to resume real-time monitoring.");
    }
  } else {
    setText("coverage-meter-value", scan.state === "running" ? "Scanning…" : "—");
    setText("protection-verdict", scan.state === "running"
      ? "Verifying firewall, disk encryption, system patches, and permissions…"
      : "Run a scan to verify everything Wardr can secure.");
  }

  // One-click Fix-to-Green CTA directly on the Overview hero card whenever device is not Green
  const heroFixBtn = element("hero-fix-button");
  const openItems = openActionableChecks(scan);
  const autoFixable = openItems.filter((c) => c.status === "fail" && (c.can_fix === true || c.action_guide?.can_script_fix === true));
  if (!ready || openItems.length === 0) {
    heroFixBtn.hidden = true;
    heroFixBtn.dataset.mode = "";
    heroFixBtn.dataset.settingsId = "";
  } else {
    heroFixBtn.hidden = false;
    heroFixBtn.dataset.mode = "green-flow";
    heroFixBtn.dataset.settingsId = "";
    const count = openItems.length;
    setText(
      "hero-fix-label",
      autoFixable.length > 0
        ? (count === 1 ? "Fix 1 item → Go Green" : "Fix All (" + numberFormat.format(count) + ") → Go Green")
        : (count === 1 ? "Fix 1 item → Go Green" : "Fix All (" + numberFormat.format(count) + ") → Go Green"),
    );
  }

  // Last scan depth summary on Hero
  const depthNode = element("scan-depth-summary");
  const mods = scan.modules || {};
  const depthParts = [];
  if (ready && scan.profile_label) depthParts.push(scan.profile_label);
  if (Number.isInteger(mods.posture_checks)) depthParts.push(plural(mods.posture_checks, "posture check"));
  if (Number.isInteger(mods.sockets_inspected)) depthParts.push(plural(mods.sockets_inspected, "socket"));
  if (mods.fim_status === "pass") depthParts.push("FIM intact (" + (mods.fim_tracked || 0) + " files)");
  else if (mods.fim_status === "fail") depthParts.push("FIM detected " + plural(mods.fim_changes || 1, "change"));
  if (Number.isInteger(mods.packages_discovered)) depthParts.push(plural(mods.packages_discovered, "package"));
  if (mods.ai_triage) depthParts.push("AI triaged");
  depthNode.hidden = depthParts.length === 0;
  setText("scan-depth-summary", depthParts.join(" · "));

  // Update Reports tab live RAG preview
  const preview = element("report-rag-preview");
  preview.dataset.rag = level;
  setText("report-rag-label", ready ? posture.label : "Pending scan");
  setText("report-rag-headline", ready ? posture.headline : "Waiting for scan results");
  setText("report-rag-summary", ready ? posture.summary : "Run a scan to generate your Red / Amber / Green security report.");
  const stats = ready ? [
    addressed + " of " + securable + (handled > 0 ? " addressed" : " secured"),
    ...(handled > 0 ? [plural(handled, "queued / handled")] : []),
    plural(posture.failed || 0, "open item"),
    threats.count ? plural(threats.count, "active threat") : "0 active threats",
  ] : [];
  replaceWhenChanged("report-rag-stats", stats, () => {
    element("report-rag-stats").replaceChildren(...stats.map((text) => make("span", "report-rag-stat", text)));
  });

  // Update sidebar guard RAG tone
  const guard = element("sidebar-guard");
  guard.dataset.rag = level;
}

function showThreats(threats, monitor) {
  const panel = element("threat-panel");
  const status = threats?.status || "clear";
  const alerts = threats?.alerts || [];
  const count = threats?.count || 0;
  panel.dataset.threatState = status;

  const checkedTime = humanTime(threats?.checked_at || monitor?.last_poll);
  const sourcesActive = threats?.sources_active ?? 0;
  const sourcesTotal = threats?.sources_total ?? (monitor?.coverage?.length || 0);

  if (status === "threat") {
    setText("threat-headline", plural(count, "active threat") + " detected right now");
    setText("threat-subtitle", "Wardr's continuous radar flagged high-priority activity in the last "
      + plural(threats.lookback_hours || 24, "hour") + ". Review and investigate immediately.");
    setText("threat-pill", "Active threat");
  } else if (status === "warning") {
    setText("threat-headline", plural(count, "suspicious pattern") + " detected");
    setText("threat-subtitle", "Continuous monitoring observed unusual activity worth confirming."
      + (checkedTime ? " Last checked " + checkedTime + "." : ""));
    setText("threat-pill", "Review needed");
  } else {
    setText("threat-headline", "No active threats happening right now");
    const sensorNote = sourcesTotal > 0
      ? "Watching " + numberFormat.format(sourcesActive) + " of " + plural(sourcesTotal, "live sensor")
      : "Continuous telemetry ready";
    const timeNote = checkedTime ? "Last swept " + checkedTime : "Completing first live sweep";
    setText("threat-subtitle", sensorNote + " · " + timeNote + " · 0 threats detected in the last "
      + plural(threats?.lookback_hours || 24, "hour") + ".");
    setText("threat-pill", "All clear");
  }

  const list = element("threat-list");
  list.hidden = alerts.length === 0;
  if (alerts.length > 0) {
    replaceWhenChanged("threat-list", alerts, () => {
      list.replaceChildren(...alerts.map((alert) => {
        const item = make("div", "threat-item");
        const main = make("div", "threat-item-main");
        main.append(make("h3", null, alert.title));
        if (alert.summary) main.append(make("p", null, alert.summary));
        const meta = [capitalized(alert.confidence) + " confidence", humanDate(alert.last_seen)].filter(Boolean).join(" · ");
        if (meta) main.append(make("p", "threat-item-meta", meta));

        const actions = make("div", "threat-item-actions");
        actions.append(statusBadge(capitalized(alert.severity) || "High", alert.severity || "high"));
        const inspect = make("button", "button button-secondary button-small", "Inspect");
        inspect.type = "button";
        inspect.addEventListener("click", () => {
          window.location.hash = "#defense";
          const huntingTab = element("defense-tab-hunting");
          if (huntingTab) selectDefenseTab(huntingTab);
        });
        const reportBtn = make("button", "button button-secondary button-small", "Report");
        reportBtn.type = "button";
        reportBtn.addEventListener("click", () => openIssueReport("alert", alert.id));
        actions.append(inspect, reportBtn);

        item.append(main, actions);
        return item;
      }));
    });
  }
}

function showScan(scan) {
  const checks = sortedChecks(scan.checks);
  const securable = checks.filter((check) => check.status !== "not_applicable");
  const attention = checks.filter((check) => check.status === "fail" && !isHandledCheck(check));
  const handled = checks.filter((check) => isHandledCheck(check));
  const unknown = checks.filter((check) => check.status === "unknown" && !isHandledCheck(check));
  const passed = checks.filter((check) => check.status === "pass");
  const addressed = [...handled, ...passed];
  const repairable = attention.filter((check) => check.can_fix === true || check.action_guide?.can_script_fix === true);
  const ready = Boolean(scan.updated_at);
  const scanDate = humanDate(scan.updated_at);
  const waiting = scan.state === "running" ? "Device scan is running…" : "Run a scan to verify this device.";

  setText("risk-secured", ready ? numberFormat.format(addressed.length) : "–");
  for (const severity of severities) {
    setText("risk-" + severity, ready ? numberFormat.format(attention.filter((check) => check.severity === severity).length) : "–");
  }

  // Overview filter pill counts
  setText("pill-count-all", numberFormat.format(securable.length));
  setText("pill-count-attention", numberFormat.format(attention.length));
  setText("pill-count-secured", numberFormat.format(addressed.length));
  setText("pill-count-unknown", numberFormat.format(unknown.length));

  const handledSuffix = handled.length ? " · " + plural(handled.length, "queued / handled") : "";
  const openTotal = attention.length + unknown.length;
  setText("overview-checklist-subtitle", ready
    ? numberFormat.format(passed.length) + " of " + plural(securable.length, "securable check") + " verified secure"
      + handledSuffix
      + (openTotal ? " · " + plural(openTotal, "item") + " left to reach Green" : " · Everything securable is addressed")
    : waiting);

  const fixAllBtn = element("checklist-fix-all");
  fixAllBtn.hidden = !(ready && openTotal > 0);
  if (openTotal > 0) {
    setText("checklist-fix-all-label", openTotal === 1
      ? "Fix 1 item → Go Green"
      : "Fix All (" + numberFormat.format(openTotal) + ") → Go Green");
  }
  if (ready && repairable.length > 0) {
    setText("overview-fixable-note", plural(repairable.length, "issue") + " can be fixed & protected right now with one click.");
  } else if (ready && attention.length === 0 && unknown.length === 0 && addressed.length > 0) {
    setText("overview-fixable-note", handled.length > 0
      ? "All securable checks are verified or queued/handled — click Undo on any queued item to restore it."
      : "All securable checks passed — no manual changes needed.");
  } else if (ready) {
    setText("overview-fixable-note", "Use the action buttons to jump to Settings, or mark a queued update / manual fix as handled.");
  } else {
    setText("overview-fixable-note", "");
  }

  const overviewShown = state.overviewFilter === "attention" ? attention
    : state.overviewFilter === "secured" ? addressed
    : state.overviewFilter === "unknown" ? unknown
    : securable;
  const overviewEmpty = state.overviewFilter === "attention" ? "Every check is secured or queued — nothing needs action."
    : state.overviewFilter === "secured" ? "No checks are marked secured yet."
    : state.overviewFilter === "unknown" ? "All applicable checks were verified."
    : "No securable checks were recorded in this scan.";
  renderFindings("priority-list", overviewShown, ready ? overviewEmpty : waiting);

  setText("checklist-subtitle", ready
    ? plural(passed.length, "secured")
      + (handled.length ? " · " + plural(handled.length, "queued / handled") : "")
      + " · " + plural(attention.length, "open finding") + " · " + plural(unknown.length, "unverified")
    : waiting);
  setText("last-scan", scanDate ? "Last full scan " + scanDate : "No scan recorded");
  setText("report-detail", scanDate
    ? "Visual Red / Amber / Green report based on the scan completed " + scanDate + "."
    : "Complete a device scan to generate your visual Red / Amber / Green report.");

  const filter = element("check-filter").value;
  const shown = filter === "attention" ? attention
    : filter === "secured" ? addressed
    : filter === "unknown" ? unknown
    : checks;
  const empty = filter === "attention" ? "No checks flagged for action in this scan."
    : filter === "secured" ? "No checks are marked secured yet."
    : filter === "unknown" ? "No checks are marked unable to verify."
    : "No checks were recorded in this scan.";
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

function sensorRow(item) {
  const row = make("li");
  const name = make("span", "sensor-name");
  const markState = item.available === true ? "ok" : item.available === false ? "warn" : "pending";
  const glyph = item.available === true ? "✓" : item.available === false ? "!" : "·";
  const mark = make("span", "sensor-mark", glyph);
  mark.dataset.state = markState;
  mark.setAttribute("aria-hidden", "true");
  name.append(mark, String(item.label || item.id || "Local sensor"));
  const stateLabel = item.available === true ? "Watching" : item.available === false ? "Limited" : "Starting";
  row.append(name, make("span", "sensor-state", stateLabel));
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

function showMonitoring(monitor, scan) {
  const checked = humanDate(monitor.last_poll);
  const checkedTime = humanTime(monitor.last_poll);
  const running = Boolean(monitor.running);
  const scanning = state.pendingScan || scan?.state === "running";
  const interval = monitor.interval > 0 ? Math.round(monitor.interval) : 30;
  const sweeps = Number.isInteger(monitor.poll_count) ? monitor.poll_count : 0;
  const coverage = monitor.coverage || [];
  const available = coverage.filter((item) => item.available === true).length;

  // Top live scanning pill & sidebar guard
  const livePill = element("live-radar-pill");
  livePill.dataset.active = String(running);
  livePill.dataset.scanning = String(scanning);
  const sweepSuffix = sweeps > 0 ? " · Sweep #" + numberFormat.format(sweeps) : "";
  setText("live-radar-label", scanning
    ? "Full device scan sweeping now…"
    : running
      ? "Constantly scanning · Every " + interval + "s" + sweepSuffix
      : "Continuous scanning paused");

  const guard = element("sidebar-guard");
  guard.dataset.active = String(running);
  setText("sidebar-guard-title", scanning ? "Scanning now…" : running ? "Constantly scanning" : "Radar paused");
  setText("sidebar-guard-sub", running
    ? (checkedTime ? "Swept " + checkedTime : "Every " + interval + "s") + (sweeps ? " · #" + numberFormat.format(sweeps) : "")
    : "Monitoring inactive");

  // Hero radar caption & cadence
  setText("posture-cadence", running
    ? "Constantly scanning every " + interval + "s" + (checkedTime ? " · Last sweep " + checkedTime : "")
    : "Continuous radar is paused");
  setText("radar-caption-text", scanning
    ? "Full security scan in progress…"
    : running
      ? "Live radar · " + numberFormat.format(available) + "/" + numberFormat.format(coverage.length) + " sensors" + sweepSuffix
      : "Real-time radar inactive");

  const label = running ? "Constantly scanning" : "Paused";
  const message = checked
    ? "Last swept " + checked + (sweeps ? " (sweep #" + numberFormat.format(sweeps) + ")." : ".")
    : "Waiting for the first live sweep.";
  setText("monitor-label", label);
  setText("monitor-detail", message + (running ? " Sweeps automatically every " + interval + " seconds." : ""));
  element("monitor-status").dataset.running = String(running);
  setText("events-status", running ? "Active" : "Inactive");
  element("events-status").dataset.tone = running ? "pass" : "unknown";
  setText("events-detail", message + (running ? " Checks every " + interval + " seconds." : ""));

  const coverageSummary = checked && coverage.length
    ? numberFormat.format(available) + " of " + plural(coverage.length, "live sensor") + " active"
    : "";
  setText("monitor-coverage", coverageSummary);
  element("monitor-coverage").hidden = !coverageSummary;
  element("monitor-sensors").hidden = coverage.length === 0;
  replaceWhenChanged("monitor-sensors", coverage, () => {
    element("monitor-sensors").replaceChildren(...coverage.map(sensorRow));
  });

  setText("history-detail", monitor.history_detail || "");
  element("history-detail").hidden = !monitor.history_detail;
  element("events-coverage").hidden = coverage.length === 0;
  replaceWhenChanged("coverage-list", coverage, () => {
    element("coverage-list").replaceChildren(...coverage.map(coverageRow));
  });

  const events = monitor.events || [];
  const empty = checked ? "No unexpected changes recorded by the continuous scanner." : "Events will appear here when Wardr detects a change.";
  replaceWhenChanged("event-list", [events, empty], () => {
    element("event-list").replaceChildren(...(events.length ? events.map(eventCard) : [make("p", "empty", empty)]));
  });
}

function showIntel(intel) {
  const date = humanDate(intel.refreshed_at);
  const label = state.data?.offline ? (intel.available
    ? "Offline mode uses the downloaded catalog." : "No downloaded catalog is available in offline mode.")
    : intel.state === "running" ? "Fetching the CISA catalog…"
    : intel.error || (intel.available && Number.isInteger(intel.count) ? plural(intel.count, "known exploited advisory", "known exploited advisories")
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

function showAITiers(ai) {
  if (!ai) return;
  const active = ai.active_tier || "radar";
  const t2 = ai.tier2 || {};
  const t3 = ai.tier3 || {};
  const ramNote = ai.host_ram_gb ? ai.host_ram_gb + " GB RAM detected" : "RAM auto-detect";

  element("tier-box-radar").dataset.active = String(active === "radar");
  element("tier-box-radar").dataset.ready = "true";
  setText("tier1-state", active === "radar" ? "Active tier" : "Always on (base)");

  element("tier-box-cloud").dataset.active = String(active === "cloud");
  element("tier-box-cloud").dataset.ready = String(Boolean(t2.ready));
  setText("tier2-state", ai.offline ? "Paused (offline)"
    : active === "cloud" && t2.ready ? "Active"
    : t2.ready ? "Ready"
    : t2.has_api_key ? "Key saved" : "Add free key");
  setText("tier2-meta", t2.ready
    ? "Zero local CPU · " + (t2.model || "Cloud model") + " · Redacted"
    : "Zero local CPU/RAM · HF / Groq / OpenRouter");

  element("tier-box-local").dataset.active = String(active === "local");
  element("tier-box-local").dataset.ready = String(Boolean(t3.ready));
  setText("tier3-state", active === "local" && t3.ready ? "Active (offline)"
    : t3.ready ? "Ready in Ollama"
    : t3.ollama_available ? "Model not pulled" : "Ollama not running");
  setText("tier3-meta", (t3.model_label || "Foundation-Sec-8B") + " · " + ramNote);

  setText("tiers-subtitle", active === "cloud"
    ? "Tier 1 local radar + Tier 2 Free Cloud AI Offload (zero local CPU/RAM load, redacted locally)."
    : active === "local"
      ? "Tier 1 local radar + Tier 3 Heavy Local AI (" + (t3.model_label || "local model") + ", 100% offline)."
      : "Tier 1 local radar active. Add Tier 2 (free cloud offload) or Tier 3 (local heavy AI) anytime.");

  const errNode = element("ai-triage-error");
  errNode.hidden = !ai.triage_error;
  setText("ai-triage-error", ai.triage_error || "");

  const box = element("ai-triage-box");
  const triage = ai.triage;
  box.hidden = !triage;
  if (triage) {
    setText("ai-triage-badge", (triage.tier_label || "AI Triage") + " · " + (triage.model || ""));
    setText("ai-triage-summary", triage.summary || "");
    setText("ai-triage-verdict", triage.threat_verdict || "");
    const actions = triage.top_actions || [];
    replaceWhenChanged("ai-triage-actions", actions, () => {
      element("ai-triage-actions").replaceChildren(...actions.map((step) => make("li", null, step)));
    });
    const metaParts = [
      triage.analyzed_at ? "Analyzed " + humanDate(triage.analyzed_at) : "",
      triage.redactions_applied ? plural(triage.redactions_applied, "local identifier") + " stripped before analysis" : "Redacted summary analyzed",
    ].filter(Boolean);
    setText("ai-triage-meta", metaParts.join(" · "));
  }
}

function scheduleWorkflowTick() {
  window.clearTimeout(state.workflow.timer);
  state.workflow.timer = window.setTimeout(() => {
    state.workflow.timer = null;
    if (state.data) renderWorkflowStage(state.data);
  }, 360);
}

function buildWorkflowStepRow(step, mode) {
  const row = make("li", "workflow-step");
  row.dataset.status = step.status;
  const badgeGlyph = step.status === "done" ? "✓"
    : step.status === "fixed" ? "✓"
    : step.status === "warn" ? "!"
    : step.status === "failed" ? "!"
    : step.status === "running" ? ""
    : "·";
  const badge = make("span", "step-badge", badgeGlyph);
  badge.setAttribute("aria-hidden", "true");

  const body = make("div", "step-body");
  body.append(make("span", "step-label", step.label));
  if (step.detail) body.append(make("span", "step-detail", step.detail));

  const tagLabel = step.status === "running" ? (mode === "fix" ? "Protecting…" : "Checking…")
    : step.status === "done" ? "Verified"
    : step.status === "fixed" ? "Protected"
    : step.status === "warn" ? "Identified"
    : step.status === "failed" ? "Needs review"
    : "Queued";
  row.append(badge, body, make("span", "step-tag", tagLabel));
  return row;
}

function buildTodoActionButtons(check) {
  const wrap = make("div", "todo-item-actions");
  if (isHandledCheck(check) || isAcceptedRiskCheck(check)) {
    const undoBtn = make("button", "button button-secondary button-small button-undo-disp", "Undo / Restore");
    undoBtn.type = "button";
    undoBtn.dataset.disposition = check.id;
    undoBtn.addEventListener("click", () => setCheckDisposition(check.id, "clear"));
    wrap.append(undoBtn);
    return wrap;
  }
  if (check.can_fix === true) {
    const autoBtn = make("button", "button button-fix button-small", "Auto-fix now");
    autoBtn.type = "button";
    autoBtn.addEventListener("click", () => startBatchFix([check.id], false));
    wrap.append(autoBtn);
  }
  if (check.action_guide?.can_open_settings) {
    const openBtn = make("button", "button button-settings button-small", (check.action_guide.settings_label || "Open Settings") + " ↗");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => openCheckSettings(check.id));
    wrap.append(openBtn);
  }
  if (check.action_guide?.can_script_fix) {
    const scriptBtn = make("button", "button button-script button-small", check.action_guide.script_label || "Fix via script");
    scriptBtn.type = "button";
    scriptBtn.addEventListener("click", () => promptScriptFixes([check]));
    wrap.append(scriptBtn);
  }
  if (check.status === "fail" && check.can_fix !== true) {
    const dispMeta = dispositionMeta(check);
    const ackBtn = make("button", "button button-ack button-small", dispMeta.actionLabel);
    ackBtn.type = "button";
    ackBtn.dataset.disposition = check.id;
    ackBtn.addEventListener("click", () => setCheckDisposition(check.id, dispMeta.kind));
    wrap.append(ackBtn);
  }
  return wrap.childElementCount ? wrap : null;
}

function buildTodoRow(check) {
  const li = make("li", "workflow-todo-item");
  const textWrap = make("div");
  textWrap.append(make("strong", null, check.title));
  const detail = (!check.can_fix && !check.action_guide?.can_script_fix && check.action_guide?.script_note)
    ? check.action_guide.script_note
    : (check.remediation || check.evidence);
  textWrap.append(make("span", null, shortSnippet(detail, 170)));
  const buttons = buildTodoActionButtons(check);
  if (buttons) textWrap.append(buttons);
  const badges = make("div", "workflow-todo-badges");
  badges.append(statusBadge(...checkStatus(check)));
  li.append(textWrap, badges);
  return li;
}

function renderWorkflowStage(data) {
  const stage = element("workflow-stage");
  const wf = state.workflow;
  const scan = data.scan || {};
  const batch = data.fix_batch;

  // Auto-surface when a scan or batch fix is actively running unless dismissed
  if (!wf.mode && !wf.dismissed) {
    if (batch?.state === "running") {
      wf.mode = "fix";
      wf.activeId = batch.id;
      wf.revealed = 0;
    } else if (scan.state === "running" && (scan.steps || []).length) {
      wf.mode = "scan";
      wf.activeId = scan.id;
      wf.revealed = 0;
    }
  }

  if (!wf.mode || wf.dismissed) {
    stage.hidden = true;
    return;
  }

  const isFix = wf.mode === "fix";
  const rawSteps = isFix
    ? (batch?.steps || []).map((s) => ({
      id: s.id,
      label: s.title,
      status: s.status,
      detail: s.message,
    }))
    : (scan.steps || []);

  if (!rawSteps.length) {
    stage.hidden = true;
    return;
  }

  const backendDone = isFix ? batch?.state === "complete" : scan.state !== "running";
  const readyCount = rawSteps.filter((s) => ["done", "warn", "fixed", "failed"].includes(s.status)).length;
  if (wf.revealed < readyCount) {
    wf.revealed += 1;
    scheduleWorkflowTick();
  }

  const allRevealed = backendDone && wf.revealed >= rawSteps.length;
  stage.hidden = false;
  stage.dataset.mode = isFix ? "fix" : "scan";
  stage.dataset.phase = allRevealed ? "complete" : "running";

  const displaySteps = rawSteps.map((step, index) => {
    if (index < wf.revealed) return step;
    if (index === wf.revealed && !allRevealed) {
      return {
        ...step,
        status: "running",
        detail: isFix ? "Applying rollback-safe protection…" : "Inspecting this security area…",
      };
    }
    return { ...step, status: "pending", detail: "Waiting…" };
  });

  const pct = allRevealed ? 100
    : Math.min(96, Math.max(8, Math.round(100 * (wf.revealed + 0.45) / rawSteps.length)));
  element("workflow-progress").value = pct;
  setText("workflow-pct", pct + "%");
  element("workflow-dismiss").hidden = !allRevealed;

  if (isFix) {
    const succeeded = batch?.succeeded || 0;
    const total = batch?.total || rawSteps.length;
    setText("workflow-title", allRevealed
      ? "Protection applied — " + plural(succeeded, "area") + " shielded & verified"
      : "Fixing & protecting your device…");
    setText("workflow-subtitle", allRevealed
      ? "Rollback snapshots were saved automatically for every change."
      : "Hardening " + numberFormat.format(total) + " identified security " + (total === 1 ? "area" : "areas") + " with verification…");
  } else {
    const label = scan.profile_label || "Security scan";
    const checks = sortedChecks(scan.checks || []);
    const open = checks.filter((c) => c.status === "fail" && !isHandledCheck(c));
    setText("workflow-title", allRevealed
      ? label + " complete"
      : "Running " + label.toLowerCase() + "…");
    setText("workflow-subtitle", allRevealed
      ? (open.length
        ? "Identified " + plural(open.length, "item") + " that need attention."
        : "Everything checked is verified or queued.")
      : "Scanning each layer of your device and verifying protections…");
  }

  replaceWhenChanged("workflow-steps", [wf.mode, displaySteps], () => {
    element("workflow-steps").replaceChildren(...displaySteps.map((s) => buildWorkflowStepRow(s, wf.mode)));
  });

  const panel = element("workflow-actions-panel");
  const failing = openActionableChecks(scan);
  const fixable = failing.filter((c) => c.status === "fail" && c.can_fix === true);
  const scriptFixable = failing.filter((c) => c.status === "fail" && c.can_fix !== true && c.action_guide?.can_script_fix === true);
  const repairable = [...fixable, ...scriptFixable];
  const manualOnly = failing.filter((c) => !repairable.includes(c));

  renderMissionModal(data, isFix, displaySteps, allRevealed, pct, failing, repairable, manualOnly);
  stage.hidden = element("mission-dialog").open;

  if (!allRevealed) {
    panel.hidden = true;
    return;
  }

  // If auto-fix just completed and manual items still remain, open the guided checklist automatically.
  if (isFix && state.openGreenChecklistAfterFix && failing.length > 0 && !element("green-checklist-dialog").open) {
    state.openGreenChecklistAfterFix = false;
    if (element("mission-dialog").open) element("mission-dialog").close();
    openGreenChecklistModal();
  }

  panel.hidden = false;
  const fixBtn = element("workflow-fix-all");
  const fixingNow = state.pendingBatchFix || state.pendingFix || scan.fix_running === true;
  fixBtn.hidden = failing.length === 0;
  fixBtn.disabled = !state.connected || fixingNow || scan.state === "running";
  if (failing.length > 0) {
    setText("workflow-fix-all-label", failing.length === 1
      ? "Fix 1 item → Go Green"
      : "Fix All (" + numberFormat.format(failing.length) + ") → Go Green");
  }

  if (failing.length === 0) {
    setText("workflow-actions-title", "Everything Wardr can secure is protected");
    setText("workflow-actions-note", "All securable checks are verified or handled with zero remaining open items.");
  } else if (repairable.length > 0) {
    setText("workflow-actions-title", plural(failing.length, "item") + " left to reach Green");
    setText("workflow-actions-note", "Click Fix All to auto-fix eligible issues and walk through any remaining manual items.");
  } else {
    setText("workflow-actions-title", plural(manualOnly.length, "manual step") + " left to reach Green");
    setText("workflow-actions-note", "Click Fix All to open the guided checklist with quick Settings links and one-click sign-off.");
  }

  const todoSignature = failing.map((c) => [c.id, c.title, c.severity, c.can_fix, c.disposition?.kind, c.action_guide?.can_open_settings, c.action_guide?.can_script_fix]);
  replaceWhenChanged("workflow-todo-list", todoSignature, () => {
    const list = element("workflow-todo-list");
    list.hidden = failing.length === 0;
    list.replaceChildren(...failing.map(buildTodoRow));
  });
}

function renderMissionModal(data, isFix, displaySteps, allRevealed, pct, failing, repairable, manualOnly) {
  const modal = element("mission-dialog");
  if (!modal.open) return;
  const scan = data.scan || {};
  const batch = data.fix_batch;
  const posture = data.posture || fallbackPosture(scan);
  const completedCount = displaySteps.filter((s) => ["done", "warn", "fixed", "failed"].includes(s.status)).length;
  const runningStep = displaySteps.find((s) => s.status === "running");

  modal.dataset.mode = isFix ? "fix" : "scan";
  modal.dataset.phase = allRevealed ? "complete" : "running";
  modal.dataset.rag = isFix && allRevealed ? "green" : (posture.level || "pending");

  setText("mission-badge-text", isFix
    ? (allRevealed ? "Protection locked in" : "Active protection")
    : (allRevealed ? (scan.profile_label || "Scan") + " complete" : (scan.profile_label || "Security scan")));
  setText("mission-counter", numberFormat.format(completedCount) + " / " + numberFormat.format(displaySteps.length)
    + (isFix ? " protected" : " layers"));
  setText("mission-pct", pct + "%");
  setText("mission-pct-label", isFix ? "PROTECTING" : "SCANNING");
  element("mission-progress").value = pct;

  if (isFix) {
    const succeeded = batch?.succeeded || 0;
    setText("mission-title", allRevealed
      ? plural(succeeded, "security area") + " protected & verified"
      : "Hardening & protecting your device…");
    setText("mission-ticker", allRevealed
      ? "Every completed fix was verified against your live system state."
      : (runningStep ? runningStep.label + " — " + runningStep.detail : "Applying protections…"));
  } else {
    setText("mission-title", allRevealed
      ? (failing.length === 0 && posture.level === "green"
        ? "Your device is protected"
        : posture.headline || "Almost fully protected")
      : "Sweeping " + (scan.profile_label || "device scan").toLowerCase() + "…");
    setText("mission-ticker", allRevealed
      ? (posture.summary || plural(posture.secured || 0, "check") + " verified secure.")
      : (runningStep ? runningStep.label + " — " + runningStep.detail : "Scanning active security layers…"));
  }

  replaceWhenChanged("mission-steps", [modal.dataset.mode, displaySteps], () => {
    element("mission-steps").replaceChildren(...displaySteps.map((s) => buildWorkflowStepRow(s, modal.dataset.mode)));
  });

  const panel = element("mission-actions-panel");
  panel.hidden = !allRevealed;
  element("mission-open-report").hidden = !allRevealed;
  setText("close-mission-dialog", allRevealed ? "Done" : "Run in background");

  if (!allRevealed) return;

  const fixBtn = element("mission-fix-all");
  const fixingNow = state.pendingBatchFix || state.pendingFix || scan.fix_running === true;
  fixBtn.hidden = failing.length === 0;
  fixBtn.disabled = !state.connected || fixingNow || scan.state === "running";
  if (failing.length > 0) {
    fixBtn.dataset.mode = "green-flow";
    fixBtn.dataset.settingsId = "";
    setText(
      "mission-fix-all-label",
      failing.length === 1
        ? "FIX 1 ITEM → GO GREEN"
        : "FIX ALL (" + numberFormat.format(failing.length) + ") → GO GREEN",
    );
  }

  if (failing.length === 0) {
    setText("mission-actions-title", "All securable checks passed");
    setText("mission-actions-note", "Everything Wardr can secure on this device is locked down and continuously monitored.");
  } else if (repairable.length > 0) {
    setText("mission-actions-title", plural(failing.length, "item") + " left to reach 100% Green");
    setText("mission-actions-note", "Click FIX ALL to automatically fix eligible issues and walk through any remaining manual steps.");
  } else {
    setText("mission-actions-title", plural(manualOnly.length, "manual step") + " left to reach 100% Green");
    setText("mission-actions-note", "Click FIX ALL to open the guided checklist—jump right to Settings or check off verified items in seconds.");
  }

  const todoSignature = failing.map((c) => [c.id, c.title, c.severity, c.can_fix, c.disposition?.kind, c.action_guide?.can_open_settings, c.action_guide?.can_script_fix]);
  replaceWhenChanged("mission-todo-list", todoSignature, () => {
    const list = element("mission-todo-list");
    list.hidden = failing.length === 0;
    list.replaceChildren(...failing.map(buildTodoRow));
  });
}

function renderVisualReportModal(data) {
  if (!data) return;
  const scan = data.scan || {};
  const posture = data.posture || fallbackPosture(scan);
  const threats = data.threats || { status: "clear", count: 0 };
  const monitor = data.monitoring || {};
  const level = posture.level || "pending";
  const checks = sortedChecks(scan.checks || []);
  const securable = checks.filter((c) => c.status !== "not_applicable");
  const repairable = securable.filter((c) => c.status === "fail" && !isHandledCheck(c) && (c.can_fix === true || c.action_guide?.can_script_fix === true));

  element("visual-report-dialog").dataset.rag = level;
  element("vrep-hero").dataset.rag = level;
  setText("vrep-rag-label", posture.label || "Scanning");
  setText("vrep-score-pill", (posture.coverage_pct ?? 0) + ((posture.handled || 0) > 0 ? "% addressed" : "% secured"));
  setText("vrep-title", posture.headline || "Security Protection Report");
  setText("vrep-summary", posture.summary || "");
  const hostLine = [
    data.host?.name,
    [data.host?.os, data.host?.version].filter(Boolean).join(" "),
    scan.updated_at ? "Scanned " + humanDate(scan.updated_at) : "",
  ].filter(Boolean).join(" · ");
  setText("vrep-meta", hostLine);

  const totalSec = posture.securable_total || 0;
  const addressed = posture.addressed ?? ((posture.secured || 0) + (posture.handled || 0));
  element("vrep-meter").max = Math.max(totalSec, 1);
  element("vrep-meter").value = addressed;
  setText("vrep-meter-text", numberFormat.format(addressed) + " of " + numberFormat.format(totalSec) + " (" + (posture.coverage_pct ?? 0) + "%)");

  const tBar = element("vrep-threat-bar");
  tBar.dataset.threatState = threats.status || "clear";
  setText("vrep-threat-title", threats.count
    ? plural(threats.count, "active threat") + " detected right now"
    : "No active threats happening right now");
  const cadence = monitor.running && monitor.interval
    ? "Continuous radar sweeping every " + Math.round(monitor.interval) + "s" + (monitor.poll_count ? " · Sweep #" + numberFormat.format(monitor.poll_count) : "")
    : "Continuous radar paused";
  setText("vrep-threat-detail", cadence + " · " + numberFormat.format(threats.sources_active || 0) + " of "
    + plural(threats.sources_total || 0, "live sensor") + " watching");

  setText("vrep-count-secured", numberFormat.format(addressed));
  setText("vrep-count-action", numberFormat.format(posture.failed || 0));
  setText("vrep-count-unverified", numberFormat.format(posture.unverified || 0));
  setText("vrep-count-threats", numberFormat.format(threats.count || 0));
  element("vrep-tile-threats").dataset.clear = String((threats.count || 0) === 0);

  const openVrepItems = openActionableChecks(scan);
  const vrepFix = element("vrep-fix-all");
  vrepFix.hidden = openVrepItems.length === 0;
  if (openVrepItems.length > 0) {
    setText("vrep-fix-all-label", openVrepItems.length === 1
      ? "Fix 1 item → Go Green"
      : "Fix All (" + numberFormat.format(openVrepItems.length) + ") → Go Green");
  }

  replaceWhenChanged("vrep-checklist", securable, () => {
    element("vrep-checklist").replaceChildren(...securable.map((check) => {
      const [visual, glyphChar] = checkVisual(check);
      const handled = isHandledCheck(check);
      const row = make("div", "vrep-row");
      row.dataset.visual = visual;
      const glyph = make("span", "check-glyph", glyphChar);
      glyph.dataset.state = visual;
      glyph.setAttribute("aria-hidden", "true");
      const info = make("div");
      info.append(make("strong", null, check.title));
      const detailText = check.status === "pass"
        ? (check.evidence || "Verified secure.")
        : handled
          ? (check.disposition.kind === "queued"
            ? "Queued (pending restart) — will auto-verify after reboot. " + (check.evidence || "")
            : "Manually fixed / acknowledged. " + (check.evidence || ""))
          : (check.remediation || check.evidence || "Review this setting.");
      info.append(make("p", null, detailText));
      if (check.status === "fail") {
        const btns = buildTodoActionButtons(check);
        if (btns) info.append(btns);
      }
      row.append(glyph, info, statusBadge(...checkStatus(check)));
      return row;
    }));
  });
}

function openVisualReportModal() {
  if (!state.data?.scan?.updated_at) return;
  renderVisualReportModal(state.data);
  const modal = element("visual-report-dialog");
  if (!modal.open) modal.showModal();
}

function renderStatus(data) {
  state.connected = true;
  state.data = data;
  element("connection-error").hidden = true;
  renderConnection();
  setText("device-name", data.host.name || "This device");
  setText("device-os", [data.host.os, data.host.version].filter(Boolean).join(" "));
  setText("workspace-mode", data.offline ? "Offline mode" : "Local protection");
  showPosture(data);
  renderWorkflowStage(data);
  if (element("visual-report-dialog").open) renderVisualReportModal(data);
  showThreats(data.threats, data.monitoring);
  showScan(data.scan);
  showAITiers(data.ai);
  showMonitoring(data.monitoring, data.scan);
  showIntel(data.intel);
  renderAccount(data.account);
  renderWhatsNew(data.whats_new, data.account);
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

async function refresh() {
  if (!token && pendingBootstrapNonce) {
    await ensureSessionToken();
  }
  if (state.needsLaunch || !token) {
    connectionError();
    return;
  }
  if (!refreshRequest) {
    const requestedToken = token;
    const pending = request("/api/status")
      .then((data) => {
        if (requestedToken !== token) return;
        const previous = state.data?.scan;
        try {
          renderStatus(data);
        } catch (renderErr) {
          console.error("Wardr UI render error:", renderErr);
          return;
        }
        if (previous?.state === "running" && data.scan.state !== "running") {
          setText("announcer", data.scan.error || "Scan complete.");
        }
      }, (error) => {
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
  const pentestActive = Boolean(
    state.defense?.pentest?.running || state.pendingPentest
    || state.defense?.pentest?.fix_running || state.pendingPentestFix
  );
  if (state.view === "defense" && state.connected) await refreshDefense(pentestActive);
  if (element("updates-dialog").open && updateWorking()) await refreshUpdates();
  if (generation !== pollGeneration || state.needsLaunch) return;
  const busy = state.awaitingSso
    || state.data?.scan.state === "running" || state.data?.intel.state === "running"
    || state.data?.fix_batch?.state === "running"
    || pentestActive
    || state.defense?.exposure.running || (element("updates-dialog").open && updateWorking());
  const delay = state.awaitingSso ? 600 : document.hidden ? 25000 : busy ? 450 : 8000;
  pollTimer = window.setTimeout(poll, delay);
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
  restarting: [
    "Restarting Wardr",
    window.__WARDR_DESKTOP__
      ? "Wardr is restarting and will reconnect automatically."
      : "Open the new Wardr window or use the launch link printed in your terminal.",
  ],
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
      download.download = report.startsWith("/plan.")
        ? (report.includes(".html") ? "wardr-plan.html" : "wardr-plan.json")
        : (report.includes(".html") ? "wardr-report.html" : "wardr-report.json");
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

const fallbackScanProfiles = [
  {
    id: "light", label: "Light scan", duration: "~2–5 sec", cpu_level: "Minimal CPU", recommended: false,
    checks_included: ["OS firewall, encryption, and security update posture", "SSH, credential, and local AI tool permissions"],
    benefit: "Near-instant results with virtually zero CPU or battery impact — safe to run anytime.",
    warning: "Skips live network port inspection, config file integrity hashing, and installed software CVE checks.",
  },
  {
    id: "medium", label: "Medium scan", duration: "~10–25 sec", cpu_level: "Moderate CPU", recommended: true,
    checks_included: ["All Light scan OS & credential posture checks", "Local network exposure (listening TCP/UDP sockets & owners)", "File Integrity Monitoring (SHA-256 baseline check)"],
    benefit: "Best everyday balance — verifies OS security, catches exposed ports, and detects tampered security configs.",
    warning: "Brief moderate CPU and disk activity while inspecting sockets and hashing files; skips full package SBOM matching and AI deep review.",
  },
  {
    id: "heavy", label: "Heavy / Deep scan", duration: "~30–90+ sec", cpu_level: "High CPU & RAM", recommended: false,
    checks_included: ["All Medium scan posture, socket & file-integrity checks", "Full installed software discovery (SBOM) & advisory matching", "Attack-surface & loopback TLS hygiene audit", "AI Threat & Posture Triage (via Tier 2 Cloud or Tier 3 Local AI if enabled)"],
    benefit: "Maximum depth — audits installed packages, risky exposed services, local TLS, and correlates findings with AI.",
    warning: "Noticeably higher CPU, disk, and memory load (especially if Tier 3 Local AI is active); fans may spin up and battery drains faster.",
  },
];

function renderScanDialog() {
  const profiles = state.data?.scan_profiles?.length ? state.data.scan_profiles : fallbackScanProfiles;
  const container = element("scan-options");
  container.replaceChildren(...profiles.map((profile) => {
    const selected = state.selectedScanProfile === profile.id;
    const card = make("label", "scan-option");
    card.dataset.selected = String(selected);
    const radio = make("input");
    radio.type = "radio";
    radio.name = "scan-profile";
    radio.value = profile.id;
    radio.checked = selected;
    radio.addEventListener("change", () => {
      state.selectedScanProfile = profile.id;
      renderScanDialog();
    });

    const body = make("div");
    const head = make("div", "scan-option-head");
    const titleWrap = make("span", "scan-option-title", profile.label);
    if (profile.recommended) titleWrap.append(make("span", "scan-rec-badge", "Recommended"));
    const pills = make("span", "scan-option-pills");
    pills.append(make("span", "scan-pill", profile.duration));
    const cpuPill = make("span", "scan-pill", profile.cpu_level);
    cpuPill.dataset.cpu = profile.id === "heavy" ? "high" : profile.id === "medium" ? "medium" : "low";
    pills.append(cpuPill);
    head.append(titleWrap, pills);

    const list = make("ul", "scan-checks");
    for (const item of profile.checks_included || []) list.append(make("li", null, item));

    const tradeoffs = make("div", "scan-tradeoffs");
    const benefit = make("div", "scan-callout scan-callout-benefit");
    benefit.append(make("strong", null, "Benefit: "), profile.benefit);
    const warning = make("div", "scan-callout scan-callout-warning");
    if (profile.id === "heavy") warning.dataset.severity = "high";
    warning.append(make("strong", null, "Trade-off: "), profile.warning);
    tradeoffs.append(benefit, warning);

    body.append(head, list, tradeoffs);
    card.append(radio, body);
    return card;
  }));
  const chosen = profiles.find((p) => p.id === state.selectedScanProfile) || profiles[1];
  setText("confirm-scan-dialog", "Start " + chosen.label);
}

function openScanDialog() {
  element("scan-dialog-error").hidden = true;
  renderScanDialog();
  element("scan-dialog").showModal();
}

async function startScan(profile = "medium") {
  state.pendingScan = true;
  state.actionNotice = null;
  renderControls();
  renderNotice();
  try {
    const started = await request("/api/scan", { profile });
    if (element("scan-dialog").open) element("scan-dialog").close();
    window.clearTimeout(state.workflow.timer);
    state.workflow.mode = "scan";
    state.workflow.activeId = started.scan_id || null;
    state.workflow.revealed = 0;
    state.workflow.dismissed = false;
    const mission = element("mission-dialog");
    mission.dataset.mode = "scan";
    mission.dataset.phase = "running";
    mission.dataset.rag = "pending";
    if (!mission.open) mission.showModal();
    const label = (state.data?.scan_profiles || fallbackScanProfiles).find((p) => p.id === profile)?.label || "Scan";
    setText("mission-badge-text", label);
    setText("mission-title", "Sweeping " + label.toLowerCase() + "…");
    setText("mission-pct", "5%");
    element("mission-progress").value = 5;
    element("mission-actions-panel").hidden = true;
    element("mission-open-report").hidden = true;
    setText("announcer", label + " started.");
    poll();
  } catch (error) {
    const msg = errorText(error, "Wardr could not start the scan. Check the local connection and try again.");
    if (element("scan-dialog").open) {
      setText("scan-dialog-error", msg);
      element("scan-dialog-error").hidden = false;
    } else {
      state.actionNotice = { error: true, text: msg };
    }
  } finally {
    await refreshAfterAction();
    state.pendingScan = false;
    renderNotice();
    renderControls();
  }
}

async function openCheckSettings(id) {
  state.actionNotice = null;
  try {
    const result = await request("/api/action/open-settings", { id });
    state.actionNotice = { error: false, text: result.message || "Opened System Settings." };
    setText("announcer", state.actionNotice.text);
  } catch (error) {
    state.actionNotice = { error: true, text: errorText(error, "Could not open System Settings automatically.") };
  } finally {
    renderNotice();
  }
}

async function setCheckDisposition(id, kind, note = "") {
  state.actionNotice = null;
  try {
    await request("/api/check/disposition", { id, kind, note });
    const msg = kind === "queued"
      ? "Marked queued (pending restart) — Wardr will automatically verify once you reboot."
      : kind === "acknowledged"
        ? "Marked handled — Wardr will re-alert automatically if new findings appear."
        : "Restored item to Needs action.";
    state.actionNotice = { error: false, text: msg };
    setText("announcer", msg);
  } catch (error) {
    state.actionNotice = { error: true, text: errorText(error, "Could not update check status.") };
  } finally {
    await refreshAfterAction();
    renderNotice();
    renderControls();
  }
}

function promptScriptFixes(checksToFix) {
  const list = (checksToFix || []).filter((c) => c.status === "fail" && (c.can_fix === true || c.action_guide?.can_script_fix === true));
  if (!list.length) return;
  const hasScripts = list.some((c) => c.can_fix !== true && c.action_guide?.can_script_fix === true);
  if (!hasScripts) {
    startBatchFix(list.map((c) => c.id), false);
    return;
  }
  state.pendingScriptTarget = { ids: list.map((c) => c.id), includeScripts: true };
  setText("script-dialog-title", list.length === 1
    ? "Fix “" + list[0].title + "” via script?"
    : "Fix & protect " + plural(list.length, "issue") + " now?");
  element("script-dialog-error").hidden = true;
  element("script-cmd-list").replaceChildren(...list.map((check) => {
    const item = make("li");
    item.append(make("strong", null, check.title));
    if (check.can_fix === true) {
      item.append(make("small", null, "Automatic rollback-safe permission repair (no password prompt needed)."));
    } else if (check.action_guide?.script_preview) {
      item.append(make("div", "script-cmd-code", check.action_guide.script_preview));
      if (check.action_guide.script_note) item.append(make("small", null, check.action_guide.script_note));
    }
    return item;
  }));
  element("script-confirm-dialog").showModal();
}

function renderGreenChecklistModal() {
  const items = openActionableChecks(state.data?.scan);
  const validIds = new Set(items.map((c) => c.id));
  for (const id of Array.from(state.greenSelectedIds)) {
    if (!validIds.has(id)) state.greenSelectedIds.delete(id);
  }
  const list = element("green-checklist-items");
  if (!items.length) {
    if (element("green-checklist-dialog").open) element("green-checklist-dialog").close();
    return;
  }

  setText(
    "green-dialog-title",
    items.length === 1
      ? "1 step left to reach 100% Green"
      : numberFormat.format(items.length) + " steps left to reach 100% Green",
  );
  setText(
    "green-select-all-label",
    "Select all (" + numberFormat.format(items.length) + ")",
  );

  const selectedCount = state.greenSelectedIds.size;
  const selectAllBox = element("green-select-all");
  selectAllBox.checked = selectedCount === items.length && items.length > 0;
  selectAllBox.indeterminate = selectedCount > 0 && selectedCount < items.length;
  setText("green-selected-counter", numberFormat.format(selectedCount) + " of " + numberFormat.format(items.length) + " checked");

  const applyBtn = element("green-mark-fixed-btn");
  applyBtn.disabled = state.pendingGreenApply || selectedCount === 0;
  if (state.pendingGreenApply) {
    setText("green-mark-fixed-btn", "Verifying…");
  } else if (selectedCount === items.length && selectedCount > 0) {
    setText("green-mark-fixed-btn", "Verify all → Go Green");
  } else if (selectedCount > 0) {
    setText("green-mark-fixed-btn", "Verify " + numberFormat.format(selectedCount) + " selected");
  } else {
    setText("green-mark-fixed-btn", "Verify & Confirm");
  }

  list.replaceChildren(...items.map((check) => {
    const checked = state.greenSelectedIds.has(check.id);
    const row = make("li", "green-item");
    row.dataset.checked = String(checked);

    const checkbox = make("input", "green-item-check");
    checkbox.type = "checkbox";
    checkbox.id = "green-chk-" + check.id;
    checkbox.checked = checked;
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.greenSelectedIds.add(check.id);
      else state.greenSelectedIds.delete(check.id);
      renderGreenChecklistModal();
    });

    const content = make("div", "green-item-content");
    const head = make("div", "green-item-head");
    const titleLabel = make("label", "green-item-title", check.title);
    titleLabel.htmlFor = checkbox.id;
    const badge = make(
      "span",
      "status-label",
      check.status === "unknown" ? "Manual check" : "Needs action",
    );
    badge.dataset.tone = check.status === "unknown" ? "unknown" : check.severity;
    head.append(titleLabel, badge);

    const stepText = check.remediation || check.action_guide?.script_note || "Verify this setting on your device, then check the box once confirmed.";
    const step = make("p", "green-item-step", stepText);
    const evidence = make("p", "green-item-evidence", check.evidence || "");

    const actions = make("div", "green-item-actions");
    if (check.status === "fail" && (check.can_fix === true || check.action_guide?.can_script_fix === true)) {
      const autoBtn = make("button", "button button-protect button-small", "Auto-fix now");
      autoBtn.type = "button";
      autoBtn.addEventListener("click", () => {
        if (element("green-checklist-dialog").open) element("green-checklist-dialog").close();
        promptScriptFixes([check]);
      });
      actions.append(autoBtn);
    }
    if (check.action_guide?.can_open_settings) {
      const settingsBtn = make(
        "button",
        "button button-settings button-small",
        (check.action_guide.settings_label || "Open System Settings") + " ↗",
      );
      settingsBtn.type = "button";
      settingsBtn.addEventListener("click", () => openCheckSettings(check.id));
      actions.append(settingsBtn);
    }
    if (check.reference?.url) {
      const guideLink = make("a", "button button-secondary button-small", (check.reference.label || "How-to guide") + " ↗");
      guideLink.href = check.reference.url;
      guideLink.target = "_blank";
      guideLink.rel = "noopener noreferrer";
      actions.append(guideLink);
    }

    content.append(head, step);
    if (check.evidence) content.append(evidence);
    if (actions.childElementCount) content.append(actions);
    row.append(checkbox, content);
    return row;
  }));
}

function openGreenChecklistModal() {
  const items = openActionableChecks(state.data?.scan);
  if (!items.length) return;
  state.greenSelectedIds = new Set();
  element("green-dialog-error").hidden = true;
  if (element("mission-dialog").open) element("mission-dialog").close();
  if (element("visual-report-dialog").open) element("visual-report-dialog").close();
  renderGreenChecklistModal();
  const dialog = element("green-checklist-dialog");
  if (!dialog.open) dialog.showModal();
}

async function applyGreenChecklistSelection() {
  const ids = Array.from(state.greenSelectedIds);
  if (!ids.length || state.pendingGreenApply) return;
  const currentChecks = state.data?.scan?.checks || [];
  const byId = new Map(currentChecks.map((c) => [c.id, c]));
  const verifiableFailIds = [];
  const dispositionIds = [];
  for (const id of ids) {
    const check = byId.get(id);
    if (!check) continue;
    if (check.status === "fail" && !isPendingUpdateCheck(check)) {
      verifiableFailIds.push(id);
    } else if (check.status === "unknown" || isPendingUpdateCheck(check)) {
      dispositionIds.push(id);
    }
  }
  state.pendingGreenApply = true;
  element("green-dialog-error").hidden = true;
  renderGreenChecklistModal();
  try {
    if (dispositionIds.length > 0) {
      await request("/api/check/disposition/batch", {
        ids: dispositionIds,
        kind: "acknowledged",
        note: "Confirmed or queued via Wardr Guided Checklist.",
      });
    }
    let stillFailing = [];
    if (verifiableFailIds.length > 0) {
      await request("/api/scan", { profile: "light" });
      for (let attempt = 0; attempt < 60; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 350));
        await refreshAfterAction();
        if (state.data?.scan?.state !== "running") break;
      }
      const updatedById = new Map((state.data?.scan?.checks || []).map((c) => [c.id, c]));
      stillFailing = verifiableFailIds.filter((id) => updatedById.get(id)?.status === "fail");
    } else {
      await refreshAfterAction();
    }
    state.greenSelectedIds = new Set(stillFailing);
    const remaining = openActionableChecks(state.data?.scan);
    if (stillFailing.length > 0) {
      setText(
        "green-dialog-error",
        "Wardr re-scanned your OS and confirmed "
          + plural(stillFailing.length, "item")
          + " still failing. Complete the change in System Settings, then click Re-scan to verify.",
      );
      element("green-dialog-error").hidden = false;
      renderGreenChecklistModal();
    } else if (remaining.length === 0) {
      if (element("green-checklist-dialog").open) element("green-checklist-dialog").close();
      state.actionNotice = { error: false, text: "All checks verified secure or queued — your device is now Green Protected!" };
      renderNotice();
    } else {
      renderGreenChecklistModal();
    }
  } catch (error) {
    setText("green-dialog-error", errorText(error, "Could not verify selected checks."));
    element("green-dialog-error").hidden = false;
  } finally {
    state.pendingGreenApply = false;
    if (element("green-checklist-dialog").open) renderGreenChecklistModal();
  }
}

function triggerFixAll() {
  const openItems = openActionableChecks(state.data?.scan);
  if (!openItems.length) return;
  const repairable = openItems.filter(
    (c) => c.status === "fail" && (c.can_fix === true || c.action_guide?.can_script_fix === true),
  );
  const remainingManual = openItems.filter((c) => !repairable.includes(c));
  if (repairable.length > 0) {
    state.openGreenChecklistAfterFix = remainingManual.length > 0;
    promptScriptFixes(repairable);
  } else {
    state.openGreenChecklistAfterFix = false;
    openGreenChecklistModal();
  }
}

async function startBatchFix(ids = null, includeScripts = false) {
  if (state.pendingBatchFix || state.pendingFix) return;
  state.pendingBatchFix = true;
  state.actionNotice = null;
  renderControls();
  renderNotice();
  try {
    const body = {};
    if (Array.isArray(ids) && ids.length) body.ids = ids;
    if (includeScripts) body.include_scripts = true;
    const started = await request("/api/fix/batch", body);
    if (element("script-confirm-dialog").open) element("script-confirm-dialog").close();
    if (element("visual-report-dialog").open) element("visual-report-dialog").close();
    window.clearTimeout(state.workflow.timer);
    state.workflow.mode = "fix";
    state.workflow.activeId = started.batch_id || null;
    state.workflow.revealed = 0;
    state.workflow.dismissed = false;
    const mission = element("mission-dialog");
    mission.dataset.mode = "fix";
    mission.dataset.phase = "running";
    mission.dataset.rag = "green";
    if (!mission.open) mission.showModal();
    setText("mission-badge-text", "Active protection");
    setText("mission-title", "Hardening & protecting your device…");
    setText("mission-pct", "5%");
    element("mission-progress").value = 5;
    element("mission-actions-panel").hidden = true;
    element("mission-open-report").hidden = true;
    setText("announcer", "Applying fixes and protections.");
    poll();
  } catch (error) {
    const msg = errorText(error, "Wardr could not start automatic protection.");
    if (element("script-confirm-dialog").open) {
      setText("script-dialog-error", msg);
      element("script-dialog-error").hidden = false;
    } else {
      state.actionNotice = { error: true, text: msg };
    }
  } finally {
    await refreshAfterAction();
    state.pendingBatchFix = false;
    renderNotice();
    renderControls();
  }
}

function populateAiDialog(ai) {
  state.aiConfigData = ai;
  const active = ai.active_tier || "radar";
  for (const radio of document.querySelectorAll('input[name="ai-active-tier"]')) {
    radio.checked = radio.value === active;
  }
  const t2 = ai.tier2 || {};
  const presetSelect = element("ai-cloud-preset");
  presetSelect.replaceChildren(...(t2.presets || []).map((preset) => {
    const opt = make("option", null, preset.label);
    opt.value = preset.id;
    return opt;
  }));
  presetSelect.value = t2.preset || "huggingface";
  element("ai-cloud-endpoint").value = t2.endpoint || "";
  element("ai-cloud-model").value = t2.model || "";
  element("ai-cloud-key").value = "";
  setText("ai-key-status", t2.has_api_key ? "(saved " + (t2.key_hint || "") + " — leave blank to keep)" : "(not set)");

  const t3 = ai.tier3 || {};
  const ramText = ai.host_ram_gb
    ? "Detected " + ai.host_ram_gb + " GB RAM on this device. " + (t3.ollama_available ? "Ollama is running locally." : "Start Ollama locally to use Tier 3 models.")
    : (t3.ollama_available ? "Ollama is running locally." : "Install and start Ollama to run Tier 3 models offline.");
  setText("ai-ram-note", ramText);

  const list = element("ai-local-list");
  list.replaceChildren(...(t3.profiles || []).map((profile) => {
    const card = make("label", "ai-model-card");
    const radio = make("input");
    radio.type = "radio";
    radio.name = "ai-local-profile";
    radio.value = profile.id;
    radio.checked = profile.id === (t3.profile || ai.recommended_local_profile);

    const body = make("div");
    const head = make("div", "ai-model-head");
    head.append(make("strong", null, profile.label));
    const badges = make("span", "ai-model-badges");
    badges.append(make("span", "scan-pill", profile.size_label + " · " + profile.license));
    if (profile.recommended) badges.append(make("span", "scan-rec-badge", "Recommended"));
    if (profile.installed) badges.append(statusBadge("Installed", "pass"));
    else if (!profile.fits_ram) badges.append(statusBadge("Needs " + profile.min_ram_gb + " GB+ RAM", "medium"));
    head.append(badges);

    body.append(head, make("p", "ai-model-desc", profile.summary));
    if (!profile.installed) {
      body.append(make("div", "ai-pull-cmd", "ollama pull " + profile.ollama_tag));
    }
    card.append(radio, body);
    return card;
  }));
}

async function openAiDialog() {
  element("ai-dialog-error").hidden = true;
  if (state.data?.ai) populateAiDialog(state.data.ai);
  element("ai-dialog").showModal();
  try {
    const fresh = await request("/api/ai");
    populateAiDialog(fresh);
  } catch {
    /* Fall back to cached status already populated. */
  }
}

async function saveAiConfig(event) {
  event.preventDefault();
  if (state.pendingAiSave) return;
  state.pendingAiSave = true;
  element("ai-dialog-error").hidden = true;
  element("save-ai-dialog").disabled = true;
  setText("save-ai-dialog", "Saving…");
  try {
    const activeTier = document.querySelector('input[name="ai-active-tier"]:checked')?.value || "radar";
    const localProfile = document.querySelector('input[name="ai-local-profile"]:checked')?.value;
    const payload = {
      active_tier: activeTier,
      cloud_preset: element("ai-cloud-preset").value,
      cloud_endpoint: element("ai-cloud-endpoint").value.trim(),
      cloud_model: element("ai-cloud-model").value.trim(),
    };
    const key = element("ai-cloud-key").value.trim();
    if (key) payload.cloud_api_key = key;
    if (localProfile) payload.local_profile = localProfile;
    await request("/api/ai/config", payload);
    element("ai-dialog").close();
    state.actionNotice = { error: false, text: "AI protection tier settings saved." };
    await refreshAfterAction();
  } catch (error) {
    setText("ai-dialog-error", errorText(error, "Could not save AI protection settings."));
    element("ai-dialog-error").hidden = false;
  } finally {
    state.pendingAiSave = false;
    element("save-ai-dialog").disabled = false;
    setText("save-ai-dialog", "Save AI settings");
    renderNotice();
    renderControls();
  }
}

async function runAiTriage() {
  if (state.pendingTriage) return;
  state.pendingTriage = true;
  element("ai-triage-error").hidden = true;
  renderControls();
  try {
    await request("/api/ai/triage", {});
    setText("announcer", "AI protection analysis complete.");
  } catch (error) {
    setText("ai-triage-error", errorText(error, "AI triage could not complete."));
    element("ai-triage-error").hidden = false;
  } finally {
    state.pendingTriage = false;
    await refreshAfterAction();
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

async function showFix(id) {
  const check = state.data?.scan.checks.find((result) => result.id === id);
  if (!check?.can_fix || check.status !== "fail") return;
  state.fixId = id;
  setText("fix-title", "Apply fix for “" + check.title + "”?");
  setText("fix-effect", check.fix_description || check.remediation || "Wardr will update this security setting on the local device.");
  const preview = element("fix-preview");
  preview.replaceChildren();
  preview.hidden = true;
  element("fix-error").hidden = true;
  renderControls();
  element("fix-dialog").showModal();
  element("cancel-fix").focus();
  try {
    const dryRun = await request("/api/fix/preview", { id });
    if (state.fixId !== id) return;
    if (Array.isArray(dryRun.changes) && dryRun.changes.length) {
      preview.replaceChildren(...dryRun.changes.map((c) =>
        make("li", null, c.target + ": " + c.current_mode + " → " + c.target_mode + " (rollback snapshot saved)")
      ));
      preview.hidden = false;
    }
  } catch {
    /* Preview is best-effort; confirmation remains protected server-side. */
  }
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
  const testing = state.pendingPentest || state.defense?.pentest?.running === true;
  const hardening = state.pendingPentestFix || state.defense?.pentest?.fix_running === true;
  const pentestBusy = testing || hardening;
  element("run-pentest-top").disabled = !state.connected || pentestBusy;
  setText("run-pentest-top", hardening ? "Hardening…" : testing ? "Simulating attacks…" : "Run Self-Pen-Test");
  element("run-pentest-full").disabled = !state.connected || pentestBusy;
  setText("run-pentest-full", hardening ? "Hardening…" : testing ? "Simulating attacks…" : "Run Full Self-Pen-Test (6 Probes)");
  element("pentest-fix-all").disabled = !state.connected || pentestBusy;
  element("pentest-lab-fix-all").disabled = !state.connected || pentestBusy;
  for (const btn of document.querySelectorAll("[data-pentest-module], [data-pentest-fix], [data-pentest-disp]")) {
    btn.disabled = !state.connected || pentestBusy;
  }
  element("exposure-refresh").disabled = !state.connected || collecting;
  setText("exposure-refresh", collecting ? "Collecting…" : "Refresh exposure");
  for (const id of ["software-sbom", "software-osv"]) element(id).disabled = assessing === true;
  element("software-auto-scan").disabled = !state.connected || assessing === true;
  setText("software-auto-scan", assessing ? "Scanning…" : "Auto-scan installed software");
  const scRunning = state.pendingSupplyChain || state.defense?.supply_chain?.running === true;
  element("supply-chain-scan-btn").disabled = !state.connected || scRunning;
  setText("supply-chain-scan-btn", scRunning ? "Scanning repos & packages…" : "Scan Local Repos & Packages");
  element("software-assess").disabled = !state.connected || assessing
    || !element("software-sbom").files.length || !element("software-osv").files.length;
  setText("software-assess", assessing ? "Assessing…" : "Assess software");
  element("local-model-check").disabled = !state.connected || state.pendingModel;
  element("local-model-review").disabled = !state.connected || state.pendingModel
    || !state.model?.model_ready || !state.defense?.plan.tasks.length;
}

function isHandledPentest(test) {
  return (test?.outcome === "warning" || test?.outcome === "exposed") && test?.disposition?.kind === "acknowledged";
}

function collectPentestFixIds(tests) {
  const ids = [];
  for (const test of tests || []) {
    if (isHandledPentest(test)) continue;
    for (const f of test.findings || []) {
      if (f.can_fix === true && f.fix_id && !ids.includes(f.fix_id)) ids.push(f.fix_id);
    }
  }
  return ids;
}

function buildPentestActionButtons(test) {
  const wrap = make("div", "todo-item-actions");
  if (isHandledPentest(test)) {
    const undoBtn = make("button", "button button-secondary button-small button-undo-disp", "Undo / Restore");
    undoBtn.type = "button";
    undoBtn.dataset.pentestDisp = test.id;
    undoBtn.addEventListener("click", () => setPentestDisposition(test.id, "clear"));
    wrap.append(undoBtn);
    return wrap;
  }
  for (const f of test.findings || []) {
    if (f.can_fix === true && f.fix_id) {
      const cls = f.fix_kind === "script" ? "button button-script button-small" : "button button-fix button-small";
      const btn = make("button", cls, f.fix_label || "Auto-fix now");
      btn.type = "button";
      btn.dataset.pentestFix = f.fix_id;
      btn.addEventListener("click", () => startPentestFix([f.fix_id]));
      wrap.append(btn);
    }
    if (f.settings_check_id) {
      const sBtn = make("button", "button button-settings button-small", "Open Firewall Settings ↗");
      sBtn.type = "button";
      sBtn.addEventListener("click", () => openCheckSettings(f.settings_check_id));
      wrap.append(sBtn);
    }
  }
  if (test.outcome === "warning" || test.outcome === "exposed") {
    const ackBtn = make("button", "button button-ack button-small", "Mark handled");
    ackBtn.type = "button";
    ackBtn.dataset.pentestDisp = test.id;
    ackBtn.addEventListener("click", () => setPentestDisposition(test.id, "acknowledged"));
    wrap.append(ackBtn);
  }
  return wrap.childElementCount ? wrap : null;
}

function buildPentestTodoRow(test) {
  const li = make("li", "workflow-todo-item");
  const textWrap = make("div");
  const primaryFinding = (test.findings || [])[0];
  textWrap.append(make("strong", null, primaryFinding?.title || test.title));
  textWrap.append(make("span", null, shortSnippet(primaryFinding?.detail || test.remediation || test.plain_summary, 180)));
  const buttons = buildPentestActionButtons(test);
  if (buttons) textWrap.append(buttons);
  const badges = make("div", "workflow-todo-badges");
  badges.append(statusBadge(
    test.outcome === "exposed" ? "Exposed" : "Warning",
    test.outcome === "exposed" ? "critical" : "medium",
  ));
  li.append(textWrap, badges);
  return li;
}

function renderDefenseMatrix(matrix) {
  if (!matrix) return;
  const tech = state.audienceMode === "technical";
  setText("matrix-subtitle", tech
    ? "Technical mode — MITRE ATT&CK techniques, active controls, telemetry sensors, and self-pen-test proof."
    : "Everyday mode — plain-English view of real-world threats and how Wardr stops them.");

  const summaryPills = [
    [matrix.defended_domains + " of " + matrix.total_domains + " threat domains defended",
      matrix.defended_domains === matrix.total_domains ? "green" : "amber"],
    [matrix.proven_domains > 0
      ? matrix.proven_domains + " of " + matrix.total_domains + " proven via self-pen-test"
      : "Self-pen-test ready to run",
      matrix.proven_domains > 0 ? "green" : "neutral"],
  ];
  replaceWhenChanged("matrix-summary-pills", summaryPills, () => {
    element("matrix-summary-pills").replaceChildren(...summaryPills.map(([label, tone]) => {
      const pill = make("span", "matrix-summary-pill", label);
      pill.dataset.tone = tone;
      return pill;
    }));
  });

  const domains = matrix.domains || [];
  replaceWhenChanged("matrix-grid", [state.audienceMode, domains], () => {
    element("matrix-grid").replaceChildren(...domains.map((domain) => {
      const card = make("article", "matrix-card");
      card.dataset.level = domain.level || "green";

      const head = make("div", "matrix-card-head");
      const titleRow = make("div", "matrix-card-title-row");
      const glyphState = domain.level === "green" ? "pass" : domain.level === "red" ? "red" : "amber";
      const glyph = make("span", "check-glyph", domain.level === "green" ? "✓" : "!");
      glyph.dataset.state = glyphState;
      glyph.setAttribute("aria-hidden", "true");
      titleRow.append(glyph, make("h3", null, domain.title));

      const badgeTone = domain.level === "green" ? "pass" : domain.level === "red" ? "critical" : "medium";
      head.append(titleRow, statusBadge(domain.status_label, badgeTone));

      const body = make("div", "matrix-body");
      if (tech) {
        const mitreWrap = make("div", "mitre-tags");
        for (const tag of domain.technical?.mitre || []) {
          mitreWrap.append(make("span", "mitre-tag", tag));
        }
        body.append(mitreWrap);

        const ctrlBlock = make("div", "matrix-block matrix-block-defense");
        ctrlBlock.append(make("strong", null, "Active Controls & Sensors"));
        const ul = make("ul", "tech-list");
        for (const item of [...(domain.technical?.controls || []), ...(domain.technical?.sensors || [])].slice(0, 6)) {
          ul.append(make("li", null, item));
        }
        ctrlBlock.append(ul);
        body.append(ctrlBlock);

        const evBlock = make("div", "matrix-block");
        evBlock.append(make("strong", null, "Live Telemetry Evidence"), make("p", null, domain.technical?.evidence || ""));
        body.append(evBlock);
      } else {
        const threatBlock = make("div", "matrix-block");
        threatBlock.append(make("strong", null, "What attackers try"), make("p", null, domain.plain?.attacker_goal || ""));
        const defBlock = make("div", "matrix-block matrix-block-defense");
        defBlock.append(make("strong", null, "How Wardr protects you"), make("p", null, domain.plain?.how_wardr_defends || ""));
        body.append(threatBlock, defBlock, make("p", "matrix-live-note", domain.plain?.live_note || ""));
      }

      const footer = make("div", "matrix-card-footer");
      const proof = make("span", "pentest-proof-pill", domain.pentest_label || "Not simulated yet");
      proof.dataset.state = domain.pentest_status || "untested";
      const testBtn = make("button", "button button-secondary button-small", "Test this defense");
      testBtn.type = "button";
      testBtn.dataset.pentestModule = domain.pentest_id;
      testBtn.addEventListener("click", () => startPentest([domain.pentest_id]));
      footer.append(proof, testBtn);

      card.append(head, body, footer);
      return card;
    }));
  });
}

function renderPentestLab(pentest) {
  if (!pentest) return;
  const result = pentest.result;
  const tech = state.audienceMode === "technical";
  const hero = element("pentest-hero");
  const fixIds = collectPentestFixIds(result?.tests || []);
  const labFixBtn = element("pentest-lab-fix-all");
  labFixBtn.hidden = fixIds.length === 0;
  if (fixIds.length > 0) {
    setText("pentest-lab-fix-all-label", "Fix & Harden All (" + numberFormat.format(fixIds.length) + ")");
  }

  if (result) {
    const addressed = result.addressed_count ?? ((result.defended_count || 0) + (result.handled_count || 0));
    hero.dataset.verdict = result.verdict || "resilient";
    setText("pentest-verdict-title", result.verdict_headline || "Self-Pen-Test Complete");
    setText("pentest-verdict-summary", result.scope_notice || "");
    setText("pentest-score-val", (result.score_pct ?? 0) + "%");
    setText("pentest-score-sub", addressed + " of " + result.total_tests + (result.handled_count ? " addressed · " : " blocked · ") + (result.verdict_label || ""));
    setText("pentest-ran-at", result.ran_at ? "Last simulated " + humanDate(result.ran_at) + " (" + result.duration_ms + " ms)" : "");
  } else {
    hero.dataset.verdict = "idle";
    setText("pentest-verdict-title", "Authorized Local Attack Simulator");
    setText("pentest-verdict-summary", "Safely probes your own device across 6 real attacker techniques (Wi-Fi port exposure, infostealer secret harvest, startup backdoors, PATH hijacks, firewall boundaries, and a live tamper canary) to prove your defenses hold.");
    setText("pentest-score-val", "—");
    setText("pentest-score-sub", "Run to prove defenses");
    setText("pentest-ran-at", "Not run yet on this device");
  }

  const paths = result?.attack_paths || [];
  element("attack-paths-section").hidden = paths.length === 0;
  replaceWhenChanged("attack-path-grid", [state.audienceMode, paths], () => {
    element("attack-path-grid").replaceChildren(...paths.map((path) => {
      const card = make("article", "attack-path-card");
      card.dataset.status = path.status;
      const head = make("div", "attack-path-head");
      head.append(
        make("h4", null, path.title),
        statusBadge(path.status_label, path.status === "blocked" ? "pass" : "critical"),
      );
      const list = make("ol", "attack-steps");
      for (const step of path.steps || []) {
        const li = make("li", "attack-step");
        li.dataset.result = step.result;
        const mark = make("span", "attack-step-mark", step.result === "blocked" ? "✓" : "!");
        mark.setAttribute("aria-hidden", "true");
        const content = make("div");
        content.append(
          make("strong", null, step.stage + (tech && step.mitre ? " · " + step.mitre : "")),
          make("span", null, step.note),
        );
        li.append(mark, content);
        list.append(li);
      }
      card.append(head, make("p", null, path.plain_scenario), list);
      return card;
    }));
  });

  const tests = result?.tests || [];
  replaceWhenChanged("pentest-list", [state.audienceMode, tests], () => {
    const target = element("pentest-list");
    if (!tests.length) {
      target.replaceChildren(make("p", "empty", "Click “Run Full Self-Pen-Test” above to safely simulate all 6 real attacker techniques against this device."));
      return;
    }
    target.replaceChildren(...tests.map((test) => {
      const handled = isHandledPentest(test);
      const visual = (test.outcome === "defended" || handled) ? "pass" : test.outcome === "exposed" ? "red" : "amber";
      const glyphChar = (test.outcome === "defended" || handled) ? "✓" : "!";
      const card = make("details", "finding");
      card.dataset.visual = visual;
      card.open = test.outcome !== "defended" && !handled;

      const summary = make("summary");
      const glyph = make("span", "check-glyph", glyphChar);
      glyph.dataset.state = visual;
      glyph.setAttribute("aria-hidden", "true");

      const heading = make("span", "finding-heading");
      heading.append(
        make("span", "finding-title", test.title),
        make("span", "finding-category", tech ? (test.technical_summary || test.plain_summary) : test.plain_summary),
      );

      const right = make("span", "finding-summary-right");
      if (handled) {
        const undoBtn = make("button", "button button-secondary button-small button-undo-disp", "Undo");
        undoBtn.type = "button";
        undoBtn.dataset.pentestDisp = test.id;
        undoBtn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          setPentestDisposition(test.id, "clear");
        });
        right.append(undoBtn);
      } else if (test.outcome !== "defended") {
        const firstFix = (test.findings || []).find((f) => f.can_fix === true && f.fix_id);
        if (firstFix) {
          const fCls = firstFix.fix_kind === "script" ? "button button-script button-small" : "button button-fix button-small";
          const fBtn = make("button", fCls, firstFix.fix_label || "Auto-fix");
          fBtn.type = "button";
          fBtn.dataset.pentestFix = firstFix.fix_id;
          fBtn.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            startPentestFix([firstFix.fix_id]);
          });
          right.append(fBtn);
        }
        const ackQuick = make("button", "button button-ack button-small", "Mark handled");
        ackQuick.type = "button";
        ackQuick.dataset.pentestDisp = test.id;
        ackQuick.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          setPentestDisposition(test.id, "acknowledged");
        });
        right.append(ackQuick);
      }

      const rerunBtn = make("button", "button button-secondary button-small", "Re-test");
      rerunBtn.type = "button";
      rerunBtn.dataset.pentestModule = test.id;
      rerunBtn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        startPentest([test.id]);
      });
      const badgeLabel = handled ? "Acknowledged"
        : test.outcome === "defended" ? "Blocked ✓"
        : test.outcome === "exposed" ? "Exposed" : "Warning";
      const badgeTone = handled ? "queued"
        : test.outcome === "defended" ? "pass"
        : test.outcome === "exposed" ? "critical" : "medium";
      right.append(rerunBtn, statusBadge(badgeLabel, badgeTone));
      summary.append(glyph, heading, right);

      const body = make("div", "finding-body");
      if (handled) {
        const markedAt = humanDate(test.disposition?.at);
        body.append(detailBlock("Status", "Marked acknowledged" + (markedAt ? " on " + markedAt : "")
          + ". Wardr will automatically re-alert if a future simulation detects new or different exposures."));
      }
      if (tech) {
        const mitreWrap = make("div", "mitre-tags");
        for (const m of test.mitre || []) {
          mitreWrap.append(make("span", "mitre-tag", m.id + " · " + m.name));
        }
        body.append(mitreWrap);
        body.append(detailBlock("Technical verdict (" + test.duration_ms + " ms)", test.technical_summary));
        if ((test.probes_run || []).length) {
          const probeBlock = make("div");
          const ul = make("ul", "probe-list");
          for (const p of test.probes_run) ul.append(make("li", null, p));
          probeBlock.append(make("h3", null, "Safe local probes executed"), ul);
          body.append(probeBlock);
        }
      } else {
        body.append(
          detailBlock("What we simulated", test.plain_what_tested),
          detailBlock("How your defenses responded", test.plain_how_defended),
        );
      }
      if ((test.findings || []).length) {
        body.append(listBlock("Findings", test.findings.map((f) => f.title + " — " + f.detail)));
      }
      if (test.remediation) {
        body.append(detailBlock("Recommended hardening", test.remediation));
      }
      const actionRow = buildPentestActionButtons(test);
      if (actionRow) body.append(actionRow);
      card.append(summary, body);
      return card;
    }));
  });
}

function schedulePentestTick() {
  window.clearTimeout(state.pentestUi.timer);
  state.pentestUi.timer = window.setTimeout(() => {
    state.pentestUi.timer = null;
    if (state.defense?.pentest) renderPentestModal(state.defense.pentest);
  }, 320);
}

function renderPentestModal(pentest) {
  const modal = element("pentest-dialog");
  if (!modal.open || !pentest) return;
  const ui = state.pentestUi;
  const isFix = ui.mode === "fix";
  const batch = pentest.fix_batch;
  const rawSteps = isFix
    ? (batch?.steps || []).map((s) => ({ id: s.id, label: s.label, status: s.status, detail: s.detail }))
    : (pentest.steps || []);
  if (!rawSteps.length) return;

  const backendDone = isFix
    ? (!pentest.fix_running && !state.pendingPentestFix && batch?.state === "complete")
    : (!pentest.running && !state.pendingPentest);
  const doneStatuses = isFix ? ["fixed", "failed"] : ["done", "warn", "exposed"];
  const readyCount = rawSteps.filter((s) => doneStatuses.includes(s.status)).length;
  if (ui.revealed < readyCount) {
    ui.revealed += 1;
    schedulePentestTick();
  }
  const allRevealed = backendDone && ui.revealed >= rawSteps.length;

  const displaySteps = rawSteps.map((step, index) => {
    if (index < ui.revealed) {
      return { ...step, status: step.status === "exposed" ? "failed" : step.status };
    }
    if (index === ui.revealed && !allRevealed) {
      return {
        ...step,
        status: "running",
        detail: isFix ? "Applying hardening fix & re-testing live…" : "Simulating attack vector safely on localhost…",
      };
    }
    return { ...step, status: "pending", detail: "Queued…" };
  });

  const pct = allRevealed ? 100
    : Math.min(95, Math.max(8, Math.round(100 * (ui.revealed + 0.45) / rawSteps.length)));
  const runningStep = displaySteps.find((s) => s.status === "running");
  const result = pentest.result;
  const modalRag = !allRevealed ? "pending"
    : result?.verdict === "resilient" ? "green"
    : result?.verdict === "vulnerable" ? "red" : "amber";

  modal.dataset.mode = isFix ? "fix" : "scan";
  modal.dataset.phase = allRevealed ? "complete" : "running";
  modal.dataset.rag = isFix && allRevealed && result?.verdict === "resilient" ? "green" : modalRag;

  setText("pentest-modal-badge", isFix
    ? (allRevealed ? "Hardening Complete" : "Hardening & Re-Verifying")
    : (allRevealed ? "Self-Pen-Test Complete" : "Self-Pen-Test Running"));
  setText("pentest-modal-counter", numberFormat.format(Math.min(ui.revealed, rawSteps.length)) + " / " + numberFormat.format(rawSteps.length)
    + (isFix ? " hardened" : " probes"));
  setText("pentest-modal-pct", pct + "%");
  setText("pentest-modal-pct-label", isFix ? "HARDENING" : "PROBING");
  element("pentest-modal-progress").value = pct;

  if (isFix) {
    const succeeded = batch?.succeeded || 0;
    setText("pentest-modal-title", allRevealed
      ? (result?.verdict === "resilient"
        ? "Hardened & verified — " + (result?.verdict_headline || "Resilient")
        : plural(succeeded, "hardening fix") + " applied & re-tested")
      : "Hardening exposures & re-running probes…");
    setText("pentest-modal-ticker", allRevealed
      ? (result ? "Live resilience score: " + result.score_pct + "% (" + (result.addressed_count ?? result.defended_count) + " of " + result.total_tests + " addressed)." : "Re-verification complete.")
      : (runningStep ? runningStep.label + " — " + runningStep.detail : "Applying allowlisted hardening…"));
  } else {
    setText("pentest-modal-title", allRevealed
      ? (result?.verdict_headline || "Attack simulation complete")
      : "Testing your defenses against real attacks…");
    setText("pentest-modal-ticker", allRevealed
      ? (result?.scope_notice || "All simulated probes completed safely.")
      : (runningStep ? runningStep.label + " — " + runningStep.detail : "Running non-destructive local probes…"));
  }

  replaceWhenChanged("pentest-modal-steps", [modal.dataset.mode, displaySteps], () => {
    element("pentest-modal-steps").replaceChildren(...displaySteps.map((step) => {
      const row = make("li", "workflow-step");
      row.dataset.status = step.status;
      const glyph = (step.status === "done" || step.status === "fixed") ? "✓"
        : (step.status === "warn" || step.status === "failed") ? "!"
        : step.status === "running" ? "" : "·";
      const badge = make("span", "step-badge", glyph);
      badge.setAttribute("aria-hidden", "true");
      const body = make("div", "step-body");
      body.append(make("span", "step-label", step.label));
      if (step.detail) body.append(make("span", "step-detail", step.detail));
      const tag = step.status === "running" ? (isFix ? "Hardening…" : "Probing…")
        : step.status === "fixed" ? "Hardened ✓"
        : step.status === "done" ? "Blocked ✓"
        : step.status === "warn" ? "Warning"
        : step.status === "failed" ? (isFix ? "Needs manual step" : "Exposed !")
        : "Queued";
      row.append(badge, body, make("span", "step-tag", tag));
      return row;
    }));
  });

  const panel = element("pentest-actions-panel");
  panel.hidden = !allRevealed;
  element("view-pentest-results").hidden = !allRevealed;
  setText("close-pentest-dialog", allRevealed ? "Done" : "Run in background");

  if (!allRevealed) return;

  const openTests = (result?.tests || []).filter((t) => (t.outcome === "warning" || t.outcome === "exposed") && !isHandledPentest(t));
  const fixIds = collectPentestFixIds(openTests);
  const fixBtn = element("pentest-fix-all");
  fixBtn.hidden = fixIds.length === 0;
  if (fixIds.length > 0) {
    setText("pentest-fix-all-label", "FIX & HARDEN ALL (" + numberFormat.format(fixIds.length) + ")");
  }

  if (openTests.length === 0) {
    setText("pentest-actions-title", "All simulated attacks blocked — 100% Resilient");
    setText("pentest-actions-note", "Every tested attack path is locked down or acknowledged with live verification.");
  } else if (fixIds.length > 0) {
    setText("pentest-actions-title", plural(openTests.length, "simulated weakness", "simulated weaknesses") + " ready to harden");
    setText("pentest-actions-note", "Click FIX & HARDEN ALL to close exposures and re-test automatically, or handle items individually below.");
  } else {
    setText("pentest-actions-title", plural(openTests.length, "remaining item") + " to review");
    setText("pentest-actions-note", "Apply the guided hardening step or click Mark handled if this configuration is intentional.");
  }

  const sig = openTests.map((t) => [t.id, t.outcome, t.disposition?.kind, (t.findings || []).map((f) => f.title)]);
  replaceWhenChanged("pentest-todo-list", sig, () => {
    const list = element("pentest-todo-list");
    list.hidden = openTests.length === 0;
    list.replaceChildren(...openTests.map(buildPentestTodoRow));
  });
}

async function startPentest(ids = null) {
  if (state.pendingPentest || state.defense?.pentest?.running || state.pendingPentestFix || state.defense?.pentest?.fix_running) return;
  state.pendingPentest = true;
  defenseNotice("");
  window.clearTimeout(state.pentestUi.timer);
  state.pentestUi.mode = "scan";
  state.pentestUi.revealed = 0;

  const modal = element("pentest-dialog");
  modal.dataset.mode = "scan";
  modal.dataset.phase = "running";
  modal.dataset.rag = "pending";
  setText("pentest-modal-badge", "Self-Pen-Test Running");
  setText("pentest-modal-title", "Launching safe local attack simulations…");
  setText("pentest-modal-ticker", "Strictly local, non-destructive probes — zero external hosts contacted.");
  setText("pentest-modal-pct", "6%");
  setText("pentest-modal-pct-label", "PROBING");
  element("pentest-modal-progress").value = 6;
  element("pentest-actions-panel").hidden = true;
  element("view-pentest-results").hidden = true;
  if (!modal.open) modal.showModal();
  renderControls();

  try {
    const payload = Array.isArray(ids) && ids.length ? { ids } : {};
    const started = await request("/api/pentest/run", payload);
    state.pentestUi.activeId = started.pentest_id || null;
    setText("announcer", "Self-pen-test simulation started.");
    if (defenseRequest) await defenseRequest;
    await refreshDefense(true);
  } catch (error) {
    if (modal.open) modal.close();
    defenseNotice(errorText(error, "Wardr could not start the self-pen-test simulation."), true);
  } finally {
    state.pendingPentest = false;
    await refreshDefense(true);
    renderControls();
    poll();
  }
}

async function startPentestFix(fixIds = null) {
  if (state.pendingPentestFix || state.defense?.pentest?.fix_running || state.pendingPentest || state.defense?.pentest?.running) return;
  state.pendingPentestFix = true;
  defenseNotice("");
  window.clearTimeout(state.pentestUi.timer);
  state.pentestUi.mode = "fix";
  state.pentestUi.revealed = 0;

  const modal = element("pentest-dialog");
  modal.dataset.mode = "fix";
  modal.dataset.phase = "running";
  modal.dataset.rag = "pending";
  setText("pentest-modal-badge", "Hardening & Re-Verifying");
  setText("pentest-modal-title", "Hardening exposures & re-running probes…");
  setText("pentest-modal-ticker", "Applying allowlisted local fixes and re-testing live…");
  setText("pentest-modal-pct", "8%");
  setText("pentest-modal-pct-label", "HARDENING");
  element("pentest-modal-progress").value = 8;
  element("pentest-actions-panel").hidden = true;
  element("view-pentest-results").hidden = true;
  if (!modal.open) modal.showModal();
  renderControls();

  try {
    const payload = Array.isArray(fixIds) && fixIds.length ? { fix_ids: fixIds } : {};
    const started = await request("/api/pentest/fix", payload);
    state.pentestUi.activeId = started.batch_id || null;
    setText("announcer", "Hardening fixes started.");
    if (defenseRequest) await defenseRequest;
    await refreshDefense(true);
  } catch (error) {
    if (modal.open) modal.close();
    defenseNotice(errorText(error, "Wardr could not apply the pen-test hardening fixes."), true);
  } finally {
    state.pendingPentestFix = false;
    await refreshDefense(true);
    renderControls();
    poll();
  }
}

async function setPentestDisposition(moduleId, kind, note = "") {
  defenseNotice("");
  try {
    await request("/api/pentest/disposition", { id: moduleId, kind, note });
    const msg = kind === "acknowledged"
      ? "Marked pen-test item handled — Wardr will re-alert automatically if exposures change."
      : "Restored pen-test item to active review.";
    defenseNotice(msg, false);
    setText("announcer", msg);
  } catch (error) {
    defenseNotice(errorText(error, "Could not update pen-test item status."), true);
  } finally {
    await refreshDefense(true);
    renderControls();
  }
}

function setAudienceMode(mode) {
  state.audienceMode = mode === "technical" ? "technical" : "plain";
  try {
    window.localStorage.setItem("wardr-audience-mode", state.audienceMode);
  } catch {
    /* ignore storage restrictions */
  }
  for (const pill of document.querySelectorAll("[data-audience]")) {
    pill.setAttribute("aria-pressed", String(pill.dataset.audience === state.audienceMode));
  }
  renderDefense();
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
  const card = make("details", "finding finding-plain");
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
  defenseList("hunting", hunting.alerts, (alert) => {
    const reportBtn = make("button", "button button-secondary button-small", "Report to Wardr");
    reportBtn.type = "button";
    reportBtn.addEventListener("click", () => openIssueReport("alert", alert.id));
    const actionWrap = make("div", "finding-actions");
    actionWrap.append(reportBtn);
    return defenseFinding(
      alert, alert.title, [capitalized(alert.confidence) + " confidence", humanDate(alert.last_seen)].filter(Boolean).join(" · "),
      [capitalized(alert.severity), alert.severity], [
        alert.summary && detailBlock("Why it was flagged", alert.summary),
        alert.evidence.length && listBlock("Recorded evidence", alert.evidence.map((event) =>
          [humanDate(event.at), event.source, event.title, event.detail].filter(Boolean).join(" · "))),
        alert.actions.length && listBlock("Investigate", alert.actions),
        actionWrap,
      ],
    );
  }, "No hunting rules matched the available event history.");
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
  if (!state.defense) return;
  if (element("pentest-dialog").open && state.defense.pentest) {
    renderPentestModal(state.defense.pentest);
  }
  if (state.view !== "defense") return;
  switch (state.defenseTab) {
    case "matrix": renderDefenseMatrix(state.defense.defense_matrix); break;
    case "pentest": renderPentestLab(state.defense.pentest); break;
    case "plan": renderPlan(state.defense.plan); break;
    case "exposure": renderExposure(state.defense.exposure); break;
    case "hunting": renderHunting(state.defense.hunting); break;
    case "software":
      renderSupplyChain(state.defense.supply_chain);
      renderSoftware(state.defense.software);
      break;
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

const overviewFilterButtons = [...document.querySelectorAll("[data-overview-filter]")];
for (const button of overviewFilterButtons) {
  button.addEventListener("click", () => {
    state.overviewFilter = button.dataset.overviewFilter;
    for (const pill of overviewFilterButtons) {
      pill.setAttribute("aria-pressed", String(pill === button));
    }
    if (state.data) {
      showScan(state.data.scan);
      renderControls();
    }
  });
}

for (const name of Object.keys(state.defenseLimits)) {
  element(name + "-more").addEventListener("click", () => {
    state.defenseLimits[name] += name === "exposure" ? 20 : 12;
    renderDefense();
  });
}

async function autoScanSoftware() {
  if (state.pendingSoftware) return;
  state.pendingSoftware = true;
  defenseNotice("");
  renderControls();
  try {
    const result = await request("/api/inventory/scan", {});
    if (defenseRequest) await defenseRequest;
    state.defenseLimits.software = 12;
    await refreshDefense(true);
    const inv = result.inventory || {};
    defenseNotice("Auto-discovered " + plural(inv.component_count || 0, "installed package")
      + " (" + (inv.sources?.join(", ") || "local") + ").");
  } catch (error) {
    defenseNotice(errorText(error, "Wardr could not auto-scan installed software."), true);
  } finally {
    state.pendingSoftware = false;
    renderControls();
  }
}

async function refreshIssuePreview() {
  if (!state.reportTarget) return;
  const target = state.reportTarget;
  element("report-error").hidden = true;
  element("download-report").disabled = true;
  element("submit-report").disabled = true;
  setText("report-preview", "Redacting local identifiers…");
  try {
    const draft = await request("/api/report/preview", {
      kind: target.kind,
      id: target.id,
      notes: element("report-notes").value || "",
      suspected_zero_day: element("report-zero-day").checked,
    });
    if (state.reportTarget !== target) return;
    state.reportDraft = draft;
    setText("report-redactions", plural(draft.redaction_total || 0, "local identifier")
      + " automatically stripped · Fingerprint " + draft.payload.fingerprint);
    setText("report-preview", JSON.stringify(draft.payload, null, 2));
    element("download-report").disabled = false;
    element("submit-report").disabled = state.data?.offline === true || state.pendingIssueReport;
  } catch (error) {
    setText("report-error", errorText(error, "Could not build the redacted report preview."));
    element("report-error").hidden = false;
    setText("report-preview", "");
  }
}

function openIssueReport(kind, id) {
  state.reportTarget = { kind, id };
  state.reportDraft = null;
  element("report-zero-day").checked = kind === "alert";
  element("report-notes").value = "";
  element("report-error").hidden = true;
  setText("report-redactions", "");
  element("report-dialog").showModal();
  refreshIssuePreview();
}

function downloadIssueReport() {
  if (!state.reportDraft?.payload) return;
  const blob = new Blob([JSON.stringify(state.reportDraft.payload, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = make("a");
  link.href = url;
  link.download = "wardr-sanitized-report-" + state.reportDraft.payload.fingerprint.slice(0, 12) + ".json";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 30000);
}

async function submitIssueReport() {
  if (!state.reportDraft?.payload || state.pendingIssueReport) return;
  state.pendingIssueReport = true;
  element("report-error").hidden = true;
  element("submit-report").disabled = true;
  setText("submit-report", "Submitting…");
  try {
    const result = await request("/api/report/submit", { payload: state.reportDraft.payload });
    element("report-dialog").close();
    state.actionNotice = { error: false, text: "Sanitized report submitted (Case " + (result.receipt?.case_id || "recorded") + ")." };
    renderNotice();
  } catch (error) {
    setText("report-error", errorText(error, "Could not reach Wardr central intake. You can download the redacted JSON instead."));
    element("report-error").hidden = false;
  } finally {
    state.pendingIssueReport = false;
    setText("submit-report", "Submit to Wardr");
    element("submit-report").disabled = !state.reportDraft?.payload || state.data?.offline === true;
  }
}

function renderSupplyChain(sc) {
  if (!sc) return;
  const result = sc.result;
  const checked = humanDate(result?.scanned_at);
  if (sc.running || state.pendingSupplyChain) {
    setText("supply-chain-status", "Scanning local repositories, npm lockfiles, global modules & runtimes…");
  } else if (sc.error) {
    setText("supply-chain-status", sc.error);
  } else if (result) {
    const phpNote = result.php_runtime?.installed ? " · PHP " + result.php_runtime.version : "";
    setText("supply-chain-status", "Scanned " + checked + " (" + result.duration_ms + " ms) across "
      + (result.roots?.join(", ") || "local folders") + phpNote + ".");
  } else {
    setText("supply-chain-status", "Click “Scan Local Repos & Packages” to check for compromised npm packages, malicious postinstall hooks, React2Shell, PHP2Shell & Log4Shell.");
  }

  metricList("supply-chain-counts", result ? [
    ["Repos scanned", result.repos_detected || 0, "pass"],
    ["Manifests", result.manifests_scanned || 0, "pass"],
    ["Packages checked", result.packages_checked || 0, "pass"],
    ["Threat signatures", result.signatures_count || 0, "pass"],
    ["Findings", result.total_findings || 0, (result.total_findings || 0) > 0 ? "critical" : "pass"],
  ] : []);

  const findings = result?.findings || [];
  replaceWhenChanged("supply-chain-list", [result?.scanned_at, findings], () => {
    const target = element("supply-chain-list");
    if (!result) {
      target.replaceChildren();
      return;
    }
    if (!findings.length) {
      target.replaceChildren(make("p", "empty", "Clean — 0 compromised npm packages, malicious postinstall hooks, React2Shell, PHP2Shell, or Log4Shell exposures detected across "
        + numberFormat.format(result.packages_checked || 0) + " checked packages."));
      return;
    }
    target.replaceChildren(...findings.map((item) => defenseFinding(
      item,
      item.title,
      item.location + " · " + (item.cve || "Supply Chain") + (item.mitre ? " · " + item.mitre : ""),
      [capitalized(item.severity), item.severity],
      [
        detailBlock("What Wardr found", item.plain_summary),
        detailBlock("Package / version", (item.package || "local") + " @ " + (item.version || "unknown")),
        detailBlock("Recommended remediation", item.remediation),
      ],
    )));
  });
}

async function runSupplyChainScan() {
  if (state.pendingSupplyChain) return;
  state.pendingSupplyChain = true;
  defenseNotice("");
  renderControls();
  try {
    const customPath = element("supply-chain-path").value.trim();
    const payload = customPath ? { path: customPath } : {};
    const result = await request("/api/supply-chain/scan", payload);
    if (defenseRequest) await defenseRequest;
    await refreshDefense(true);
    const msg = result.total_findings > 0
      ? "Supply-chain scan found " + plural(result.total_findings, "compromised package or exploit risk") + "."
      : "Supply-chain scan clean — checked " + plural(result.packages_checked || 0, "package")
        + " across " + plural(result.manifests_scanned || 0, "manifest") + ".";
    defenseNotice(msg, result.total_findings > 0);
  } catch (error) {
    defenseNotice(errorText(error, "Could not complete supply-chain scan."), true);
  } finally {
    state.pendingSupplyChain = false;
    renderControls();
  }
}

function renderWhatsNew(whatsNew, accountInfo) {
  if (!whatsNew?.latest) return;
  const latest = whatsNew.latest;
  setText("whats-new-version", "Wardr v" + latest.version + (latest.date ? " · " + latest.date : ""));
  setText("whats-new-title", latest.title || "What’s New in Wardr");
  setText("whats-new-summary", latest.summary || "");
  replaceWhenChanged("whats-new-list", latest.highlights || [], () => {
    element("whats-new-list").replaceChildren(...(latest.highlights || []).map((item) => {
      const li = make("li", "whats-new-item");
      const tag = make("span", "whats-new-tag", item.tag || "New");
      tag.dataset.kind = String(item.tag || "new").toLowerCase();
      const body = make("div");
      body.append(make("strong", null, item.title), make("p", null, item.detail));
      li.append(tag, body);
      return li;
    }));
  });
  const authBlocked = Boolean(accountInfo?.auth_required);
  const dialog = element("whats-new-dialog");
  if (whatsNew.should_show && !authBlocked && !state.whatsNewAutoShown && !dialog.open && !element("auth-gate-dialog").open) {
    state.whatsNewAutoShown = true;
    dialog.showModal();
  }
}

async function dismissWhatsNew() {
  element("whats-new-dialog").close();
  try {
    await request("/api/whats-new/seen", {});
    await refreshAfterAction();
  } catch {
    /* ignore */
  }
}

function showAuthError(message) {
  const errorEl = element("auth-error");
  setText("auth-error", message);
  errorEl.hidden = false;
  errorEl.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function clearAuthError() {
  element("auth-error").hidden = true;
  element("auth-legal-box").classList.remove("needs-attention");
}

function requireLegalAgreement() {
  if (state.authMode === "login" || element("auth-accept-legal").checked) {
    element("auth-legal-box").classList.remove("needs-attention");
    return true;
  }
  const legalBox = element("auth-legal-box");
  legalBox.classList.add("needs-attention");
  legalBox.scrollIntoView({ block: "nearest", behavior: "smooth" });
  element("auth-accept-legal").focus();
  showAuthError("Please check the Privacy Policy and Terms of Use box above to continue.");
  return false;
}

function setAuthMode(mode) {
  state.authMode = mode === "login" ? "login" : "register";
  for (const pill of document.querySelectorAll("[data-auth-mode]")) {
    pill.setAttribute("aria-pressed", String(pill.dataset.authMode === state.authMode));
  }
  const isReg = state.authMode === "register";
  element("auth-name-wrap").hidden = !isReg;
  element("auth-legal-box").hidden = !isReg;
  element("auth-consent-box").hidden = !isReg;
  element("auth-password").minLength = isReg ? 10 : 1;
  element("auth-password").autocomplete = isReg ? "new-password" : "current-password";
  setText("auth-password-hint", isReg ? "(10+ characters)" : "");
  setText("auth-submit-btn", isReg ? "Create Wardr account" : "Sign in");
  clearAuthError();
}

function accountInitials(name, email) {
  const src = String(name || email || "").trim();
  if (!src) return "?";
  const parts = src.split(/[\s@._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return src.slice(0, 2).toUpperCase();
}

function openAccountOrAuth() {
  const acct = state.data?.account;
  if (acct?.signed_in) {
    element("account-dialog-error").hidden = true;
    element("telemetry-preview-box").hidden = true;
    element("account-dialog").showModal();
  } else if (!acct?.offline) {
    setAuthMode(state.authMode);
    element("auth-gate-dialog").showModal();
  }
}

function renderAccount(acct) {
  if (!acct) return;
  const chip = element("account-button");
  const signedIn = Boolean(acct.signed_in && acct.account);
  chip.dataset.signedIn = String(signedIn);
  if (acct.offline && !signedIn) {
    setText("account-button-label", "Offline mode");
    setText("top-account-avatar", "OF");
    setText("sidebar-account-avatar", "OF");
    setText("sidebar-account-name", "Offline mode");
    setText("sidebar-account-email", "Air-gapped local session");
  } else if (signedIn) {
    const user = acct.account;
    const displayName = user.name || user.email;
    const initials = accountInitials(user.name, user.email);
    setText("account-button-label", displayName);
    setText("top-account-avatar", initials);
    setText("sidebar-account-avatar", initials);
    setText("sidebar-account-name", displayName);
    setText("sidebar-account-email", user.email || "Signed in");
  } else {
    setText("account-button-label", "Sign in");
    setText("top-account-avatar", "?");
    setText("sidebar-account-avatar", "?");
    setText("sidebar-account-name", "Sign in");
    setText("sidebar-account-email", "Account & privacy");
  }

  const providers = Array.isArray(acct.sso_providers) ? acct.sso_providers : [];
  let configuredSsoCount = 0;
  for (const btn of document.querySelectorAll("[data-sso]")) {
    const match = providers.find((item) => item.id === btn.dataset.sso);
    const enabled = match ? Boolean(match.configured) : true;
    btn.hidden = !enabled;
    if (enabled) configuredSsoCount += 1;
  }
  const ssoGroup = element("sso-buttons");
  if (ssoGroup) {
    ssoGroup.hidden = configuredSsoCount === 0;
    ssoGroup.dataset.count = String(configuredSsoCount);
  }
  const authDivider = element("auth-divider");
  if (authDivider) {
    authDivider.hidden = configuredSsoCount === 0;
  }

  const gate = element("auth-gate-dialog");
  if (signedIn && state.awaitingSso) {
    state.awaitingSso = false;
    setText("announcer", "Signed in to Wardr.");
  }
  if (acct.auth_required && !gate.open && !element("legal-dialog").open) {
    setAuthMode(state.authMode);
    gate.showModal();
  } else if (!acct.auth_required && gate.open) {
    gate.close();
  }

  if (signedIn) {
    const user = acct.account;
    setText("acct-display-name", user.name || "—");
    setText("acct-display-email", user.email || "—");
    setText("acct-display-server", user.server_url || acct.server_url || "https://api.getwardr.com");
    const provLabel = user.provider === "google" ? "Google" : user.provider === "microsoft" ? "Microsoft" : "Email account";
    setText("account-provider-pill", provLabel);
    const prefs = user.preferences || {};
    element("pref-diagnostics").checked = Boolean(prefs.share_system_diagnostics);
    element("pref-threats").checked = Boolean(prefs.share_threat_intelligence);
    element("pref-updates").checked = prefs.auto_check_updates !== false;
    setText("acct-sync-status", user.last_telemetry_status
      ? user.last_telemetry_status + (user.last_telemetry_sync ? " (" + humanDate(user.last_telemetry_sync) + ")" : "")
      : "No diagnostics synced yet. Telemetry is strictly opt-in.");
  }
}

async function submitAuthForm(event) {
  event.preventDefault();
  if (state.pendingAuth) return;
  if (!requireLegalAgreement()) return;
  state.pendingAuth = true;
  clearAuthError();
  element("auth-submit-btn").disabled = true;
  try {
    const email = element("auth-email").value.trim();
    const password = element("auth-password").value;
    if (state.authMode === "register") {
      await request("/api/account/register", {
        name: element("auth-name").value.trim(),
        email,
        password,
        accepted_legal: element("auth-accept-legal").checked,
        share_system_diagnostics: element("auth-opt-diagnostics").checked,
        share_threat_intelligence: element("auth-opt-threats").checked,
      });
    } else {
      await request("/api/account/login", { email, password });
    }
    element("auth-password").value = "";
    element("auth-gate-dialog").close();
    await refreshAfterAction();
    setText("announcer", "Signed in to Wardr.");
  } catch (error) {
    showAuthError(errorText(error, "Sign-in could not complete."));
  } finally {
    state.pendingAuth = false;
    element("auth-submit-btn").disabled = false;
  }
}

async function triggerSso(provider) {
  clearAuthError();
  if (!requireLegalAgreement()) return;
  try {
    const result = await request("/api/account/sso/start", {
      provider,
      accepted_legal: state.authMode === "login" ? true : element("auth-accept-legal").checked,
    });
    if (result.authorize_url) {
      state.awaitingSso = true;
      window.open(result.authorize_url, "_blank", "noopener,noreferrer");
      showAuthError(
        window.__WARDR_DESKTOP__
          ? "Finish signing in with " + capitalized(provider) + " in your browser — Wardr will unlock and pop back automatically."
          : "Finish signing in with " + capitalized(provider) + " in your browser — Wardr will unlock automatically.",
      );
      poll();
    }
  } catch (error) {
    showAuthError(errorText(error, "Could not start sign-in."));
  }
}

async function saveAccountPreferences() {
  element("account-dialog-error").hidden = true;
  try {
    await request("/api/account/preferences", {
      share_system_diagnostics: element("pref-diagnostics").checked,
      share_threat_intelligence: element("pref-threats").checked,
      auto_check_updates: element("pref-updates").checked,
    });
    await refreshAfterAction();
  } catch (error) {
    setText("account-dialog-error", errorText(error, "Could not save telemetry preferences."));
    element("account-dialog-error").hidden = false;
  }
}

async function previewTelemetry() {
  element("account-dialog-error").hidden = true;
  const box = element("telemetry-preview-box");
  box.hidden = false;
  setText("telemetry-preview-box", "Building redacted telemetry preview…");
  try {
    const data = await request("/api/account/telemetry/preview");
    setText("telemetry-preview-box", JSON.stringify(data, null, 2));
  } catch (error) {
    setText("account-dialog-error", errorText(error, "Could not build redacted preview."));
    element("account-dialog-error").hidden = false;
    box.hidden = true;
  }
}

async function syncTelemetryNow() {
  if (state.pendingTelemetrySync) return;
  state.pendingTelemetrySync = true;
  element("account-dialog-error").hidden = true;
  element("sync-telemetry-btn").disabled = true;
  setText("sync-telemetry-btn", "Syncing…");
  try {
    const res = await request("/api/account/telemetry/sync", {});
    setText("acct-sync-status", res.message || "Diagnostics synced.");
    await refreshAfterAction();
  } catch (error) {
    setText("account-dialog-error", errorText(error, "Could not sync diagnostics."));
    element("account-dialog-error").hidden = false;
  } finally {
    state.pendingTelemetrySync = false;
    element("sync-telemetry-btn").disabled = false;
    setText("sync-telemetry-btn", "Sync diagnostics now");
  }
}

async function signOutAccount() {
  try {
    await request("/api/account/logout", {});
    element("account-dialog").close();
    await refreshAfterAction();
  } catch (error) {
    setText("account-dialog-error", errorText(error, "Could not sign out."));
    element("account-dialog-error").hidden = false;
  }
}

function renderLegalDialog() {
  const data = state.legalData;
  if (!data) return;
  setText("legal-dialog-meta", "Policy version " + data.policy_version + " · Effective " + data.effective_date);
  for (const pill of document.querySelectorAll("[data-legal-tab]")) {
    pill.setAttribute("aria-pressed", String(pill.dataset.legalTab === state.legalTab));
  }
  const sections = state.legalTab === "terms" ? (data.terms || []) : (data.privacy || []);
  element("legal-content").replaceChildren(...sections.map((sec) => {
    const div = make("div", "legal-section");
    div.append(make("h3", null, sec.heading), make("p", null, sec.body));
    return div;
  }));
}

async function openLegalDialog(tab = "privacy") {
  state.legalTab = tab === "terms" ? "terms" : "privacy";
  const dialog = element("legal-dialog");
  if (!dialog.open) dialog.showModal();
  if (!state.legalData) {
    element("legal-content").replaceChildren(make("p", "empty", "Loading policy…"));
    try {
      state.legalData = await request("/api/legal");
    } catch {
      element("legal-content").replaceChildren(make("p", "empty", "Could not load Privacy Policy / Terms of Use."));
      return;
    }
  }
  renderLegalDialog();
}

element("exposure-refresh").addEventListener("click", collectExposure);
element("supply-chain-scan-btn").addEventListener("click", runSupplyChainScan);
element("whats-new-button").addEventListener("click", () => element("whats-new-dialog").showModal());
element("dismiss-whats-new").addEventListener("click", dismissWhatsNew);
element("account-button").addEventListener("click", openAccountOrAuth);
element("sidebar-account-btn").addEventListener("click", openAccountOrAuth);
element("close-account-dialog").addEventListener("click", () => element("account-dialog").close());
element("account-signout-btn").addEventListener("click", signOutAccount);
element("auth-form").addEventListener("submit", submitAuthForm);
element("pref-diagnostics").addEventListener("change", saveAccountPreferences);
element("pref-threats").addEventListener("change", saveAccountPreferences);
element("pref-updates").addEventListener("change", saveAccountPreferences);
element("preview-telemetry-btn").addEventListener("click", previewTelemetry);
element("sync-telemetry-btn").addEventListener("click", syncTelemetryNow);
element("auth-gate-dialog").addEventListener("cancel", (event) => {
  if (state.data?.account?.auth_required) event.preventDefault();
});
for (const pill of document.querySelectorAll("[data-auth-mode]")) {
  pill.addEventListener("click", () => setAuthMode(pill.dataset.authMode));
}
for (const btn of document.querySelectorAll("[data-sso]")) {
  btn.addEventListener("click", () => triggerSso(btn.dataset.sso));
}
element("auth-accept-legal").addEventListener("change", () => {
  if (element("auth-accept-legal").checked) clearAuthError();
});
for (const btn of document.querySelectorAll("[data-open-legal]")) {
  btn.addEventListener("click", () => openLegalDialog(btn.dataset.openLegal));
}
for (const pill of document.querySelectorAll("[data-legal-tab]")) {
  pill.addEventListener("click", () => {
    state.legalTab = pill.dataset.legalTab;
    renderLegalDialog();
  });
}
element("close-legal-dialog").addEventListener("click", () => element("legal-dialog").close());
element("run-pentest-top").addEventListener("click", () => startPentest(null));
element("run-pentest-full").addEventListener("click", () => startPentest(null));
element("pentest-fix-all").addEventListener("click", () => startPentestFix(null));
element("pentest-lab-fix-all").addEventListener("click", () => startPentestFix(null));
element("close-pentest-dialog").addEventListener("click", () => element("pentest-dialog").close());
element("view-pentest-results").addEventListener("click", () => {
  element("pentest-dialog").close();
  const ptTab = element("defense-tab-pentest");
  if (ptTab) selectDefenseTab(ptTab);
});
for (const pill of document.querySelectorAll("[data-audience]")) {
  pill.setAttribute("aria-pressed", String(pill.dataset.audience === state.audienceMode));
  pill.addEventListener("click", () => setAudienceMode(pill.dataset.audience));
}
element("software-auto-scan").addEventListener("click", autoScanSoftware);
element("software-form").addEventListener("submit", assessSoftware);
element("cancel-report").addEventListener("click", () => element("report-dialog").close());
element("download-report").addEventListener("click", downloadIssueReport);
element("submit-report").addEventListener("click", submitIssueReport);
element("report-zero-day").addEventListener("change", refreshIssuePreview);
element("report-notes").addEventListener("change", refreshIssuePreview);
element("report-dialog").addEventListener("close", () => { state.reportTarget = null; state.reportDraft = null; });
for (const id of ["software-sbom", "software-osv"]) element(id).addEventListener("change", renderControls);
element("local-model-check").addEventListener("click", () => runModelAction(false));
element("local-model-review").addEventListener("click", () => runModelAction(true));

element("theme-toggle-button").addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  applyTheme(state.theme);
});
applyTheme(state.theme);
element("scan-button").addEventListener("click", () => startScan(state.selectedScanProfile));
element("hero-scan-button").addEventListener("click", () => startScan(state.selectedScanProfile));
element("hero-scan-depth").addEventListener("click", openScanDialog);
element("hero-fix-button").addEventListener("click", triggerFixAll);
element("close-green-dialog").addEventListener("click", () => element("green-checklist-dialog").close());
element("green-select-all").addEventListener("change", () => {
  const items = openActionableChecks(state.data?.scan);
  if (element("green-select-all").checked) {
    state.greenSelectedIds = new Set(items.map((c) => c.id));
  } else {
    state.greenSelectedIds.clear();
  }
  renderGreenChecklistModal();
});
element("green-mark-fixed-btn").addEventListener("click", applyGreenChecklistSelection);
element("green-rescan-btn").addEventListener("click", () => {
  if (element("green-checklist-dialog").open) element("green-checklist-dialog").close();
  startScan(state.selectedScanProfile);
});
window.__wardrOnFocus = () => {
  if (state.connected) refresh();
};
window.addEventListener("focus", () => {
  if (state.connected && (state.awaitingSso || element("auth-gate-dialog").open)) {
    refresh();
  }
});
element("cancel-scan-dialog").addEventListener("click", () => element("scan-dialog").close());
element("confirm-scan-dialog").addEventListener("click", () => startScan(state.selectedScanProfile));
element("workflow-fix-all").addEventListener("click", triggerFixAll);
element("checklist-fix-all").addEventListener("click", triggerFixAll);
element("mission-fix-all").addEventListener("click", triggerFixAll);
element("vrep-fix-all").addEventListener("click", triggerFixAll);
element("cancel-script-dialog").addEventListener("click", () => element("script-confirm-dialog").close());
element("confirm-script-dialog").addEventListener("click", () => {
  const target = state.pendingScriptTarget;
  if (!target) return;
  startBatchFix(target.ids, target.includeScripts);
});
element("close-mission-dialog").addEventListener("click", () => {
  element("mission-dialog").close();
  if (state.data) renderWorkflowStage(state.data);
});
element("mission-open-report").addEventListener("click", () => {
  element("mission-dialog").close();
  openVisualReportModal();
});
element("close-vrep-dialog").addEventListener("click", () => element("visual-report-dialog").close());
for (const button of document.querySelectorAll("[data-visual-report]")) {
  button.addEventListener("click", openVisualReportModal);
}
element("workflow-dismiss").addEventListener("click", () => {
  window.clearTimeout(state.workflow.timer);
  state.workflow.dismissed = true;
  state.workflow.mode = null;
  element("workflow-stage").hidden = true;
});
element("ai-config-button").addEventListener("click", openAiDialog);
element("ai-triage-button").addEventListener("click", runAiTriage);
element("cancel-ai-dialog").addEventListener("click", () => element("ai-dialog").close());
element("ai-config-form").addEventListener("submit", saveAiConfig);
element("ai-cloud-preset").addEventListener("change", () => {
  const presets = state.aiConfigData?.tier2?.presets || state.data?.ai?.tier2?.presets || [];
  const match = presets.find((item) => item.id === element("ai-cloud-preset").value);
  if (match && match.id !== "custom") {
    element("ai-cloud-endpoint").value = match.endpoint;
    element("ai-cloud-model").value = match.default_model;
  }
});
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

window.addEventListener("hashchange", () => {
  if (new URLSearchParams(window.location.hash.slice(1)).has("access")) {
    token = launchToken();
    state.needsLaunch = !token && !pendingBootstrapNonce;
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
  document.body.dataset.hidden = String(document.hidden);
  if (!document.hidden) poll();
});
document.body.dataset.hidden = String(document.hidden);
selectView();
poll();
