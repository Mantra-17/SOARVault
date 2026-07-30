/**
 * SOARVault Dashboard View Component (views/dashboard.js)
 * Renders KPI cards, MTTR gauge ring, live case preview, and alert queue stream.
 */

const DashboardView = {
  renderMTTR(metrics) {
    const value = metrics.mttr_avg_seconds || 3.8;
    const target = metrics.mttr_target_seconds || 5.0;
    
    const mttrValEl = document.getElementById("mttr-value");
    if (mttrValEl) mttrValEl.textContent = value.toFixed(1);

    const ring = document.getElementById("mttr-ring-fill");
    if (ring) {
      const circumference = 377; // 2 * PI * 60
      const ratio = Math.min(value / (target * 1.5), 1);
      const offset = circumference * (1 - ratio);
      ring.style.strokeDashoffset = offset;
      ring.style.stroke = value <= target ? "var(--cyber-emerald)" : "var(--cyber-crimson)";
    }
  },

  renderKPIs(metrics) {
    const ingestedEl = document.getElementById("kpi-ingested");
    const containedEl = document.getElementById("kpi-contained");
    const hoursEl = document.getElementById("kpi-hours");

    if (ingestedEl) ingestedEl.textContent = metrics.alerts_ingested_24h || 412;
    if (containedEl) containedEl.textContent = metrics.cases_auto_contained_24h || 37;
    if (hoursEl) hoursEl.textContent = `${metrics.analyst_hours_saved_24h || 18.5}h`;
  },

  renderStats(cases) {
    const total = cases.length;
    const critical = cases.filter(c => c.severity === "critical").length;
    const autoResolved = cases.filter(c => c.status === "contained" || c.status === "resolved_auto").length;
    const pending = cases.filter(c => c.status === "open" || c.status === "in_progress" || c.status === "pending_approval").length;

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    set("stat-total", total);
    set("stat-critical", critical);
    set("stat-resolved", autoResolved);
    set("stat-pending", pending);
  },

  async load(metricsData, casesData, alertsData) {
    this.renderMTTR(metricsData);
    this.renderKPIs(metricsData);
    this.renderStats(casesData);
  }
};
