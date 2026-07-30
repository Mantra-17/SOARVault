/**
 * SOARVault Alert Queue Component (views/queue.js)
 * Real-time SIEM alert stream pre-enrichment.
 */

const QueueView = {
  renderAlertItem(alert) {
    const rule = alert.rule || alert.title || alert.rule_id || "Unclassified Detection";
    const src = alert.source || alert.source_siem || "Generic SIEM";
    const ioc = alert.ioc_value || alert.ioc || (alert.network ? alert.network.src_ip : "N/A");
    const status = alert.enrichment_status || alert.status || "queued";

    return `
      <div class="alert-feed-item">
        <div class="alert-feed-info">
          <div class="alert-rule-title">${rule}</div>
          <div class="alert-source-meta">${src} · <span style="font-family: var(--font-mono); color: var(--cyber-cyan);">${ioc}</span></div>
        </div>
        <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 4px;">
          <span class="badge-sev ${alert.severity}">${alert.severity}</span>
          <span style="font-size: 10.5px; font-family: var(--font-mono); color: var(--text-dim); text-transform: uppercase;">${status}</span>
        </div>
      </div>
    `;
  },

  render(alerts) {
    const container = document.getElementById("alerts-feed-container");
    if (!container) return;

    if (!alerts || alerts.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 24px;">Alert queue is empty.</div>`;
      return;
    }

    container.innerHTML = alerts.map(a => this.renderAlertItem(a)).join('');
  }
};
