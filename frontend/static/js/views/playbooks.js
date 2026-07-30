/**
 * SOARVault Playbooks View Component (views/playbooks.js)
 * Visualizes configured containment playbooks, trigger conditions, and action sequences.
 */

const PlaybooksView = {
  renderCard(pb) {
    const actions = pb.actions || [];

    return `
      <div class="playbook-card">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
            <div class="playbook-card-title">${pb.name || pb.id}</div>
            <span style="font-size: 11px; color: var(--cyber-emerald); font-family: var(--font-mono);">ACTIVE</span>
          </div>
          <div class="playbook-trigger-code">${pb.trigger}</div>
        </div>

        <div>
          <span style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; display:block; margin-bottom: 6px;">Automated Action Chain</span>
          <div class="action-chips-list">
            ${actions.map(a => `<span class="action-chip">⚡ ${a}</span>`).join('')}
          </div>
        </div>
      </div>
    `;
  },

  render(playbooks) {
    const container = document.getElementById("playbooks-grid-container");
    if (!container) return;

    if (!playbooks || playbooks.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted);">No playbooks registered.</div>`;
      return;
    }

    container.innerHTML = playbooks.map(p => this.renderCard(p)).join('');
  }
};
