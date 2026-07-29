/* app.js — SOAR Console frontend
 * Talks to the Flask mock API (dashboard/api/routes.py). Falls back to
 * embedded mock data if the API isn't running yet (e.g. opening
 * index.html directly), so the UI is always demoable.
 */

const FALLBACK = {
  metrics: {
    mttr_avg_seconds: 4.2,
    mttr_target_seconds: 5.0,
    alerts_ingested_24h: 412,
    cases_auto_contained_24h: 37,
    analyst_hours_saved_24h: 18.5,
  },
  cases: [
    { id: "CASE-1001", title: "Suspicious outbound traffic to known C2 IP", severity: "critical", status: "contained", ioc: "185.220.101.7", mttr_seconds: 3.8 },
    { id: "CASE-1002", title: "Credential-stuffing pattern on VPN gateway", severity: "high", status: "in_progress", ioc: "45.83.64.22", mttr_seconds: null },
    { id: "CASE-1003", title: "Malicious hash matched on endpoint", severity: "medium", status: "resolved_auto", ioc: "d41d8cd98f00b204e9800998ecf8427e", mttr_seconds: 4.6 },
  ],
  alerts: [
    { id: "ALRT-88231", rule: "Outbound connection to Tor exit node", severity: "critical", ioc_value: "185.220.101.7", source: "Splunk SIEM", enrichment_status: "complete" },
    { id: "ALRT-88240", rule: "Repeated auth failures across 40 accounts", severity: "high", ioc_value: "45.83.64.22", source: "QRadar SIEM", enrichment_status: "in_progress" },
    { id: "ALRT-88261", rule: "Port scan detected from internal host", severity: "low", ioc_value: "192.0.2.44", source: "Palo Alto Firewall", enrichment_status: "queued" },
  ],
  playbooks: [
    { id: "isolate-ec2-and-block-ip", name: "Isolate EC2 + Block IP", trigger: "risk_score >= 85 and ioc_type == 'ip'", actions: ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"], avg_exec_seconds: 3.9 },
    { id: "block-ip-firewall", name: "Block IP at Perimeter Firewall", trigger: "risk_score >= 60 and ioc_type == 'ip'", actions: ["block_ip_edge_firewall", "notify_slack"], avg_exec_seconds: 2.1 },
    { id: "quarantine-endpoint", name: "Quarantine Endpoint (EDR)", trigger: "risk_score >= 50 and ioc_type == 'hash'", actions: ["isolate_host_edr", "notify_slack"], avg_exec_seconds: 4.6 },
  ],
  integrations: [
    { id: "splunk", name: "Splunk SIEM", type: "alert_source", status: "connected", last_event: "8s ago" },
    { id: "abuseipdb", name: "AbuseIPDB", type: "enrichment", status: "connected", last_event: "6s ago" },
    { id: "virustotal", name: "VirusTotal", type: "enrichment", status: "connected", last_event: "6s ago" },
    { id: "aws-sdk", name: "AWS SDK (EC2 isolation)", type: "orchestration", status: "connected", last_event: "14m ago" },
    { id: "palo-alto", name: "Palo Alto Firewall API", type: "orchestration", status: "degraded", last_event: "2h ago" },
    { id: "slack", name: "Slack notifications", type: "notification", status: "connected", last_event: "3m ago" },
  ],
};

// ---------- Session / auth guard ----------

function getSession() {
  try {
    return JSON.parse(localStorage.getItem("soar_session"));
  } catch (e) {
    return null;
  }
}

function requireSession() {
  const session = getSession();
  if (!session) {
    window.location.href = "login.html";
    return null;
  }
  return session;
}

function initials(name) {
  return name.split(" ").map((p) => p[0]).join("").slice(0, 2).toUpperCase();
}

function renderUserCard(session) {
  document.getElementById("user-avatar").textContent = initials(session.name || session.username);
  document.getElementById("user-name").textContent = session.name || session.username;
  document.getElementById("user-role").textContent = session.role_label || session.role;
  document.getElementById("role-badge").textContent = session.role_label || session.role;

  document.getElementById("logout-btn").addEventListener("click", () => {
    localStorage.removeItem("soar_session");
    window.location.href = "login.html";
  });
}

// ---------- Fetch helpers ----------

async function fetchJSON(path, fallback, options = {}) {
  try {
    const res = await fetch(path, options);
    if (!res.ok) throw new Error("bad response");
    return await res.json();
  } catch (e) {
    return fallback;
  }
}

// ---------- KPI / MTTR rendering ----------

function renderMTTR(metrics) {
  const value = metrics.mttr_avg_seconds;
  const target = metrics.mttr_target_seconds || 5;
  document.getElementById("mttr-value").textContent = value.toFixed(1);

  const circumference = 377; // 2 * PI * r(60)
  const ratio = Math.min(value / (target * 1.6), 1);
  const offset = circumference * (1 - ratio);
  const ring = document.getElementById("mttr-ring-progress");
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = value <= target ? "var(--green)" : "var(--red)";
}

function renderKPIs(metrics) {
  document.getElementById("kpi-ingested").textContent = metrics.alerts_ingested_24h;
  document.getElementById("kpi-contained").textContent = metrics.cases_auto_contained_24h;
  document.getElementById("kpi-hours").textContent = `${metrics.analyst_hours_saved_24h}h`;
}

function renderStats(cases) {
  const total = cases.length;
  const critical = cases.filter((c) => c.severity === "critical").length;
  const autoResolved = cases.filter((c) => c.status === "resolved_auto" || c.status === "contained").length;
  const pending = cases.filter((c) => c.status === "open" || c.status === "in_progress").length;

  document.getElementById("stat-total").textContent = total;
  document.getElementById("stat-critical").textContent = critical;
  document.getElementById("stat-resolved").textContent = autoResolved;
  document.getElementById("stat-pending").textContent = pending;
}

// ---------- Row templates ----------

function caseRow(c) {
  const mttr = c.mttr_seconds ? `${c.mttr_seconds}s` : "—";
  return `
    <div class="case-row" data-case-id="${c.id}">
      <span class="case-id">${c.id}</span>
      <div>
        <div class="case-title">${c.title}</div>
        <div class="case-ioc">${c.ioc}</div>
      </div>
      <span class="chip ${c.severity}">${c.severity}</span>
      <span class="status-tag ${c.status}">${c.status.replace("_", " ")} · MTTR ${mttr}</span>
    </div>`;
}

function alertRow(a) {
  return `
    <div class="alert-row" data-alert-id="${a.id}">
      <div class="alert-main">
        <span class="alert-rule">${a.rule}</span>
        <span class="alert-meta">${a.source} · ${a.ioc_value}</span>
      </div>
      <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px;">
        <span class="chip ${a.severity}">${a.severity}</span>
        <span class="enrich-tag">${a.enrichment_status}</span>
      </div>
    </div>`;
}
function timeAgo(iso) {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.round(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  return `${Math.round(mins / 60)}h ago`;
}

let CAN_APPROVE = false; // set in init() from the session's permissions
let LAST_METRICS = null; // cached metrics, used by renderStatCards on re-renders

function incidentRow(c) {
  const canAck = c.status === "open" || c.status === "in_progress";
  const needsApproval = c.status === "pending_approval";
  return `
    <tr data-case-id="${c.id}" data-ioc="${c.ioc || ""}">
      <td class="id-cell">
        ${c.id}
        <div class="id-cell-ioc">${c.ioc || ""}</div>
      </td>
      <td class="time-cell">${timeAgo(c.created_at || c.opened_at)}</td>
      <td>${(c.ioc_type || "—").toUpperCase()}</td>
      <td><span class="chip ${c.severity}">${c.severity}</span></td>
      <td><span class="status-tag ${c.status}">${c.status.replace("_", " ")}</span></td>
      <td class="row-actions">
        <button data-view-case="${c.id}">View</button>
        ${canAck ? `<button data-ack-case="${c.id}">Acknowledge</button>` : ""}
        ${needsApproval && CAN_APPROVE ? `
          <button class="approve-btn" data-approve-case="${c.id}">Approve</button>
          <button class="reject-btn" data-reject-case="${c.id}">Reject</button>` : ""}
      </td>
    </tr>`;
}

function renderApprovalBanner(cases) {
  const banner = document.getElementById("approval-banner");
  if (!banner) return;
  const pending = cases.filter((c) => c.status === "pending_approval");

  if (!CAN_APPROVE || pending.length === 0) {
    banner.hidden = true;
    return;
  }
  document.getElementById("approval-banner-count").textContent =
    `${pending.length} incident${pending.length === 1 ? "" : "s"}`;
  banner.hidden = false;
}



function playbookCard(p, canEdit) {
  const editBtn = canEdit
    ? `<button class="btn-edit" data-edit-playbook="${p.id}">Edit playbook</button>`
    : "";
  return `
    <div class="playbook-card">
      <h3>${p.name}</h3>
      <code class="playbook-trigger">${p.trigger}</code>
      <ul class="playbook-actions">
        ${p.actions.map((a) => `<li>${a}</li>`).join("")}
      </ul>
      <div class="playbook-foot">
        <span class="playbook-exec">avg exec: ${p.avg_exec_seconds}s</span>
        ${editBtn}
      </div>
    </div>`;
}

function integrationCard(i) {
  return `
    <div class="integration-card">
      <div class="integration-head">
        <span class="integration-name">${i.name}</span>
        <span class="dot ${i.status}"></span>
      </div>
      <span class="integration-type">${i.type.replace("_", " ")}</span>
      <span class="integration-status ${i.status}">${i.status}</span>
      <span class="integration-event">last event: ${i.last_event}</span>
    </div>`;
}

// ---------- Modals ----------

function openModal(overlayId, bodyId, html) {
  document.getElementById(bodyId).innerHTML = html;
  document.getElementById(overlayId).classList.add("is-open");
}

function closeAllModals() {
  document.querySelectorAll(".modal-overlay").forEach((el) => el.classList.remove("is-open"));
}


function countryFlag(geo) {
  if (!geo) return "";
  const match = geo.match(/,\s*([A-Z]{2})$/); // e.g. "Bucharest, RO" -> "RO"
  if (!match) return "";
  const code = match[1];
  const codePoints = [...code].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function riskBarColor(score) {
  if (score >= 80) return "var(--severity-critical)";
  if (score >= 60) return "var(--severity-high)";
  if (score >= 40) return "var(--severity-medium)";
  return "var(--severity-low)";
}

// Each timeline step type gets its own color, so the chain of
// custody reads at a glance rather than as a wall of identical text.
const TIMELINE_STEP_COLORS = {
  "Ingested": "var(--cyan)",
  "Enriched": "#a78bfa",
  "Risk Scored": "var(--severity-medium)",
  "Playbook Triggered": "var(--severity-high)",
  "Contained": "var(--severity-low)",
};

function timelineStepColor(step) {
  return TIMELINE_STEP_COLORS[step] || "var(--text-muted)";
}
function caseDetailHTML(c) {
  const enrichment = c.enrichment || {};
  const timeline = c.timeline || [];
  const flag = countryFlag(enrichment.geo);
  const riskColor = riskBarColor(c.risk_score || 0);

  return `
    <div class="modal-head">
      <span class="case-id">${c.id}</span>
      <span class="chip ${c.severity}">${c.severity}</span>
    </div>
    <h2>${c.title}</h2>

    <div class="kv-grid detail-grid">
      <div><span>Alert type</span><strong>${(c.ioc_type || "—").toUpperCase()}</strong></div>
      <div><span>Source IP / IOC</span><strong>${c.ioc}</strong></div>
      <div><span>Country</span><strong>${flag ? `${flag} ` : ""}${enrichment.geo || "—"}</strong></div>
      <div><span>Status</span><strong>${c.status.replace("_", " ")}</strong></div>
    </div>

    <h3>Risk score</h3>
    <div class="risk-bar-track">
      <div class="risk-bar-fill" style="width:${c.risk_score || 0}%; background:${riskColor};"></div>
    </div>
    <span class="risk-bar-label" style="color:${riskColor};">${c.risk_score || 0}/100</span>

    <h3>Enrichment</h3>
    <div class="kv-grid">
      ${enrichment.abuseipdb_confidence != null ? `<div><span>AbuseIPDB confidence</span><strong>${enrichment.abuseipdb_confidence}%</strong></div>` : ""}
      ${enrichment.virustotal_malicious_votes ? `<div><span>VirusTotal votes</span><strong>${enrichment.virustotal_malicious_votes}</strong></div>` : ""}
      ${enrichment.asn ? `<div><span>ASN</span><strong>${enrichment.asn}</strong></div>` : ""}
      ${enrichment.first_seen_in_feeds ? `<div><span>First seen</span><strong>${enrichment.first_seen_in_feeds}</strong></div>` : ""}
    </div>

    <h3>Actions taken timeline</h3>
    <div class="timeline">
      ${timeline.map((t) => `
        <div class="timeline-step">
          <span class="timeline-offset" style="color:${timelineStepColor(t.step)};">T+${t.offset_seconds}s</span>
          <div>
            <strong style="color:${timelineStepColor(t.step)};">${t.step}</strong>
            <p>${t.detail}</p>
          </div>
        </div>`).join("")}
    </div>`;
}

function alertDetailHTML(a) {
  return `
    <div class="modal-head">
      <span class="case-id">${a.id}</span>
      <span class="chip ${a.severity}">${a.severity}</span>
    </div>
    <h2>${a.rule}</h2>
    <p class="modal-sub">from <strong>${a.source}</strong> · enrichment: <strong>${a.enrichment_status}</strong></p>
    <h3>Raw indicator</h3>
    <div class="kv-grid">
      <div><span>IOC type</span><strong>${a.ioc_type || "—"}</strong></div>
      <div><span>IOC value</span><strong>${a.ioc_value}</strong></div>
      <div><span>Received</span><strong>${a.received_at ? new Date(a.received_at).toLocaleString() : "—"}</strong></div>
    </div>
    <p class="modal-note">This alert is queued for enrichment. Once AbuseIPDB / VirusTotal lookups
    complete and a risk score is assigned, it will open a case automatically if it crosses threshold.</p>`;
}

function playbookEditorHTML(p) {
  return `
    <h2>Edit playbook</h2>
    <p class="modal-sub">${p.name}</p>
    <label class="field-label" for="edit-trigger">Trigger condition</label>
    <textarea id="edit-trigger" class="code-input" rows="2">${p.trigger}</textarea>

    <label class="field-label" for="edit-actions">Actions (one per line, executed in order)</label>
    <textarea id="edit-actions" class="code-input" rows="4">${p.actions.join("\n")}</textarea>

    <div class="modal-actions">
      <button class="btn-primary" id="save-playbook-btn" data-playbook-id="${p.id}">Save changes</button>
      <span class="save-note">Changes require peer review before publishing (Day 18)</span>
    </div>`;
}

// ---------- Live incident feed (auto-refresh every 5s) ----------

async function fetchIncidents(cases, onUpdate) {
  const spinner = document.getElementById("incidents-spinner");
  if (spinner) spinner.hidden = false;

  try {
    const latest = await fetchJSON("/api/incidents", null);
    if (latest) {
      const knownIds = new Set(cases.map((c) => c.id));
      const newOnes = latest.filter((c) => !knownIds.has(c.id));

      if (newOnes.length) {
        // Newest first, at the top of the list.
        cases.unshift(...newOnes);
        onUpdate(newOnes.map((c) => c.id));
      }
    }
  } catch (e) {
    // Silently skip this poll cycle — next interval tick will retry.
  } finally {
    if (spinner) spinner.hidden = true;
  }
}

function renderStatCards(cases, metrics) {
  const mttrEl = document.getElementById("statcard-mttr");
  const autoResolvedEl = document.getElementById("statcard-autoresolved");
  const criticalEl = document.getElementById("statcard-critical");
  if (!mttrEl) return; // Cases view not in the DOM yet

  const mttr = metrics && typeof metrics.mttr_avg_seconds === "number"
    ? metrics.mttr_avg_seconds.toFixed(1)
    : "—";
  mttrEl.textContent = mttr;

  const total = cases.length;
  const autoResolved = cases.filter((c) => c.status === "resolved_auto" || c.status === "contained").length;
  autoResolvedEl.textContent = total ? `${Math.round((autoResolved / total) * 100)}%` : "—";

  const criticalOpen = cases.filter(
    (c) => c.severity === "critical" && c.status !== "closed" && c.status !== "closed_false_positive"
  ).length;
  criticalEl.textContent = criticalOpen;
}

// Severity filter + search state (Day 12/13)
let ACTIVE_SEVERITY = "all";
let SEARCH_QUERY = "";

function applyIncidentFilters() {
  const rows = document.querySelectorAll("#incidents-table-body tr");
  const query = SEARCH_QUERY.trim().toLowerCase();

  rows.forEach((row) => {
    const severity = row.querySelector(".chip")?.classList[1] || "";
    const rowText = row.textContent.toLowerCase();

    const matchesSeverity = ACTIVE_SEVERITY === "all" || severity === ACTIVE_SEVERITY;
    const matchesSearch = !query || rowText.includes(query);

    row.classList.toggle("is-filtered-out", !(matchesSeverity && matchesSearch));
  });
}

function renderIncidentsTable(cases, newIds = [], metrics = null) {
  document.getElementById("incidents-table-body").innerHTML = cases.map(incidentRow).join("");
  newIds.forEach((id) => {
    const row = document.querySelector(`#incidents-table-body tr[data-case-id="${id}"]`);
    if (row) row.classList.add("is-new");
  });
  renderStats(cases);
  renderApprovalBanner(cases);
  renderStatCards(cases, metrics || LAST_METRICS);
  applyIncidentFilters();
}


// ---------- View switching ----------

function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("is-active", section.id === `view-${view}`);
  });
  const titles = {
    dashboard: "SOC Overview",
    cases: "All Cases",
    alerts: "Alert Queue",
    playbooks: "Containment Playbooks",
    integrations: "Connected Systems",
  };
  document.getElementById("view-title").textContent = titles[view] || "SOC Overview";
}

// ---------- Init ----------

async function init() {
  const session = requireSession();
  if (!session) return; // redirected to login

 renderUserCard(session);
  const canEditPlaybooks = (session.permissions || []).includes("edit");
  CAN_APPROVE = (session.permissions || []).includes("approve");
  document.getElementById("playbook-edit-hint").textContent = canEditPlaybooks
    ? "editable — playbook changes require peer review"
    : "read-only for your role";

  const [metrics, cases, alerts, playbooks, integrations] = await Promise.all([
    fetchJSON("/api/metrics", FALLBACK.metrics),
    fetchJSON("/api/cases", FALLBACK.cases),
    fetchJSON("/api/alerts", FALLBACK.alerts),
    fetchJSON("/api/playbooks", FALLBACK.playbooks),
    fetchJSON("/api/integrations", FALLBACK.integrations),
  ]);

renderMTTR(metrics);
  renderKPIs(metrics);
  LAST_METRICS = metrics;

  const casesHTML = cases.map(caseRow).join("");
  document.getElementById("cases-table").innerHTML = casesHTML;
  renderIncidentsTable(cases, [], metrics);

  const alertsHTML = alerts.map(alertRow).join("");
  document.getElementById("alerts-list").innerHTML = alertsHTML;
  document.getElementById("alerts-list-full").innerHTML = alertsHTML;

  document.getElementById("playbooks-grid").innerHTML =
    playbooks.map((p) => playbookCard(p, canEditPlaybooks)).join("");

  document.getElementById("integrations-grid").innerHTML =
    integrations.map(integrationCard).join("");

// Nav
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });
document.getElementById("approval-banner").addEventListener("click", (e) => {
    const link = e.target.closest("[data-view]");
    if (link) switchView(link.dataset.view);
  });

  // Severity filter buttons (Day 12)
  document.getElementById("severity-filter").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-severity]");
    if (!btn) return;
    ACTIVE_SEVERITY = btn.dataset.severity;
    document.querySelectorAll("#severity-filter .filter-btn").forEach((b) => {
      b.classList.toggle("is-active", b === btn);
    });
    applyIncidentFilters();
  });

  // Incident search bar (Day 13) — search by IP, type, or case ID
  document.getElementById("incident-search").addEventListener("input", (e) => {
    SEARCH_QUERY = e.target.value;
    applyIncidentFilters();
  });
  // Case row -> detail modal
  document.body.addEventListener("click", async (e) => {
    const viewBtn = e.target.closest("[data-view-case]");
    if (viewBtn) {
      const detail = await fetchJSON(
        `/api/cases/${viewBtn.dataset.viewCase}`,
        cases.find((c) => c.id === viewBtn.dataset.viewCase)
      );
      openModal("case-modal-overlay", "case-modal-body", caseDetailHTML(detail));
      return;
    }

const ackBtn = e.target.closest("[data-ack-case]");
    if (ackBtn) {
      const id = ackBtn.dataset.ackCase;
      const updated = await fetchJSON(`/api/cases/${id}/ack`, null, { method: "POST" });
      const idx = cases.findIndex((c) => c.id === id);
      if (idx > -1) cases[idx].status = (updated && updated.status) || "acknowledged";
renderIncidentsTable(cases);
      return;
    }

    const approveBtn = e.target.closest("[data-approve-case]");
    if (approveBtn) {
      const id = approveBtn.dataset.approveCase;
      const updated = await fetchJSON(`/api/approve/${id}`, null, {
        method: "POST",
        headers: { "X-Role": session.role },
      });
      const idx = cases.findIndex((c) => c.id === id);
      if (idx > -1 && updated) cases[idx] = { ...cases[idx], ...updated };
      document.getElementById("incidents-table-body").innerHTML = cases.map(incidentRow).join("");
      renderStats(cases);
      renderApprovalBanner(cases);
      return;
    }

    const rejectBtn = e.target.closest("[data-reject-case]");
    if (rejectBtn) {
      const id = rejectBtn.dataset.rejectCase;
      const updated = await fetchJSON(`/api/reject/${id}`, null, {
        method: "POST",
        headers: { "X-Role": session.role },
      });
      const idx = cases.findIndex((c) => c.id === id);
      if (idx > -1 && updated) cases[idx] = { ...cases[idx], ...updated };
      document.getElementById("incidents-table-body").innerHTML = cases.map(incidentRow).join("");
      renderStats(cases);
      renderApprovalBanner(cases);
      return;
    }
    const caseEl = e.target.closest("[data-case-id]");
    if (caseEl) {
      const detail = await fetchJSON(
        `/api/cases/${caseEl.dataset.caseId}`,
        cases.find((c) => c.id === caseEl.dataset.caseId)
      );
      openModal("case-modal-overlay", "case-modal-body", caseDetailHTML(detail));
      return;
    }

    const alertEl = e.target.closest("[data-alert-id]");
    if (alertEl) {
      const detail = alerts.find((a) => a.id === alertEl.dataset.alertId);
      openModal("alert-modal-overlay", "alert-modal-body", alertDetailHTML(detail));
      return;
    }

    const editBtn = e.target.closest("[data-edit-playbook]");
    if (editBtn) {
      const pb = playbooks.find((p) => p.id === editBtn.dataset.editPlaybook);
      openModal("playbook-modal-overlay", "playbook-modal-body", playbookEditorHTML(pb));
      return;
    }

    const saveBtn = e.target.closest("#save-playbook-btn");
    if (saveBtn) {
      const id = saveBtn.dataset.playbookId;
      const trigger = document.getElementById("edit-trigger").value.trim();
      const actions = document.getElementById("edit-actions").value
        .split("\n").map((s) => s.trim()).filter(Boolean);

      const updated = await fetchJSON(`/api/playbooks/${id}`, { ...FALLBACK.playbooks.find(p => p.id === id), trigger, actions }, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Role": session.role },
        body: JSON.stringify({ trigger, actions }),
      });

      const idx = playbooks.findIndex((p) => p.id === id);
      if (idx > -1) playbooks[idx] = { ...playbooks[idx], ...updated };
      document.getElementById("playbooks-grid").innerHTML =
        playbooks.map((p) => playbookCard(p, canEditPlaybooks)).join("");
      closeAllModals();
      return;
    }

    if (e.target.closest("[data-close-modal]") || e.target.classList.contains("modal-overlay")) {
      closeAllModals();
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAllModals();
  });

  // Live incident feed: poll for new incidents every 5 seconds.
  setInterval(() => {
    fetchIncidents(cases, (newIds) => renderIncidentsTable(cases, newIds));
  }, 5000);
}
  


document.addEventListener("DOMContentLoaded", init);
