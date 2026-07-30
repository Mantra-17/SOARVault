/**
 * SOARVault Integrations View Component (views/integrations.js)
 * SIEM alert sources, Threat Intel enrichment providers, and Orchestration APIs matrix.
 */

const IntegrationsView = {
  renderCard(item) {
    const isConnected = item.status === "connected";
    const statusColor = isConnected ? "var(--cyber-emerald)" : "var(--cyber-amber)";

    return `
      <div class="integration-card">
        <div class="integration-icon">🌐</div>
        <div class="integration-meta" style="flex:1;">
          <div class="integration-name">${item.name}</div>
          <div class="integration-type">${item.type.replace("_", " ")}</div>
        </div>
        <span style="font-size: 10.5px; font-family: var(--font-mono); color: ${statusColor}; background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 6px; text-transform: uppercase;">
          ${item.status}
        </span>
      </div>
    `;
  },

  render(integrations) {
    const container = document.getElementById("integrations-grid-container");
    if (!container) return;

    if (!integrations || integrations.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted);">No integrations configured.</div>`;
      return;
    }

    container.innerHTML = integrations.map(i => this.renderCard(i)).join('');
  }
};
