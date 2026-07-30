/**
 * SOARVault Cases View Component (views/cases.js)
 * High-tech Cases table, Threat Intel enrichment preview, Risk Score meter, and Detail Drawer.
 */

const CasesView = {
  renderRiskMeter(score) {
    const s = Math.min(Math.max(score || 0, 0), 100);
    let color = "var(--cyber-emerald)";
    if (s >= 80) color = "var(--cyber-crimson)";
    else if (s >= 60) color = "var(--sev-high)";
    else if (s >= 40) color = "var(--cyber-amber)";

    return `
      <div class="risk-meter" title="Composite Risk Score: ${s}/100">
        <div class="risk-bar-track">
          <div class="risk-bar-fill" style="width: ${s}%; background: ${color};"></div>
        </div>
        <span class="risk-score-num" style="color: ${color};">${s}</span>
      </div>
    `;
  },

  renderCaseRow(c) {
    const mttr = c.mttr_seconds ? `${c.mttr_seconds}s` : "—";
    const iocVal = c.ioc || (c.iocs && c.iocs[0] ? c.iocs[0].value : "N/A");
    const riskScore = c.risk_score || (c.enrichment ? c.enrichment.risk_score : 0);

    return `
      <tr class="table-row" onclick="CasesView.openDetail('${c.id}')">
        <td class="case-id-cell">${c.id}</td>
        <td>
          <div class="case-title-cell">${c.title}</div>
          <div class="ioc-subtext">${iocVal}</div>
        </td>
        <td>
          <span class="badge-sev ${c.severity}">${c.severity}</span>
        </td>
        <td>
          ${this.renderRiskMeter(riskScore)}
        </td>
        <td>
          <span class="status-tag ${c.status}">${c.status.replace("_", " ")}</span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-muted);">
          ${mttr}
        </td>
      </tr>
    `;
  },

  async openDetail(caseId) {
    const backdrop = document.getElementById("drawer-backdrop");
    const body = document.getElementById("drawer-body");
    if (!backdrop || !body) return;

    body.innerHTML = `<div style="color: var(--text-muted); font-size: 13px;">Loading incident details for ${caseId}...</div>`;
    backdrop.classList.add("is-open");

    const caseData = await SOAR_API.fetch(`/api/cases/${caseId}`, null);
    if (!caseData) {
      body.innerHTML = `<div style="color: var(--cyber-crimson)">Failed to load case data.</div>`;
      return;
    }

    const enrichment = caseData.enrichment || {};
    const timeline = caseData.timeline || [];

    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 24px;">
        <div>
          <span class="case-id-cell">${caseData.id}</span>
          <h2 style="font-family: var(--font-header); font-size: 20px; font-weight: 700; color: #fff; margin-top: 4px;">${caseData.title}</h2>
        </div>
        <span class="badge-sev ${caseData.severity}">${caseData.severity}</span>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px;">
        <div class="glass-panel" style="padding: 16px;">
          <span style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">AbuseIPDB Score</span>
          <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--cyber-cyan); margin-top: 4px;">
            ${enrichment.abuse_score !== undefined ? enrichment.abuse_score + '/100' : (enrichment.abuseipdb_confidence ? enrichment.abuseipdb_confidence + '%' : 'N/A')}
          </div>
        </div>

        <div class="glass-panel" style="padding: 16px;">
          <span style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Geo / Location</span>
          <div style="font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: #fff; margin-top: 6px;">
            ${enrichment.geo_country || enrichment.geo || 'Unknown Location'}
          </div>
          <div style="font-size: 11px; color: var(--text-dim);">${enrichment.geo_asn_org || enrichment.asn || ''}</div>
        </div>
      </div>

      <h3 style="font-family: var(--font-header); font-size: 15px; color: #fff; margin-bottom: 12px;">Containment Execution Timeline</h3>
      <div class="timeline-container">
        ${timeline.map(t => `
          <div class="timeline-step">
            <div class="timeline-dot"></div>
            <div class="timeline-step-title">
              <span>${t.step || t.action}</span>
              <span class="timeline-step-time">${t.ts ? t.ts.slice(11, 19) : (t.offset_seconds !== undefined ? '+' + t.offset_seconds + 's' : '')}</span>
            </div>
            <div class="timeline-step-detail">${t.detail || ''}</div>
          </div>
        `).join('')}
      </div>

      ${caseData.status === "pending_approval" ? `
        <div style="margin-top: 32px; padding: 16px; background: rgba(255, 184, 0, 0.1); border: 1px solid var(--cyber-amber); border-radius: 12px; display:flex; justify-content:space-between; align-items:center;">
          <div style="font-size: 12.5px; color: var(--cyber-amber);">Manual authorization required to execute EC2 quarantine action.</div>
          <button onclick="CasesView.approve('${caseData.id}')" style="background: var(--cyber-amber); color: #000; font-weight: 700; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer;">Approve Execution</button>
        </div>
      ` : ''}
    `;
  },

  async approve(caseId) {
    const res = await SOAR_API.fetch(`/api/approve/${caseId}`, null, { method: "POST" });
    if (res && !res.error) {
      this.openDetail(caseId);
      window.SOAR_APP.refresh();
    } else {
      alert(res ? res.error : "Failed to authorize playbook execution.");
    }
  },

  closeDetail() {
    const backdrop = document.getElementById("drawer-backdrop");
    if (backdrop) backdrop.classList.remove("is-open");
  },

  renderTable(cases) {
    const container = document.getElementById("cases-table-body");
    if (!container) return;

    if (!cases || cases.length === 0) {
      container.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No active incidents reported.</td></tr>`;
      return;
    }

    container.innerHTML = cases.map(c => this.renderCaseRow(c)).join('');
  }
};
