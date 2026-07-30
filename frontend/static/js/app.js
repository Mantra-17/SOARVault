/**
 * SOARVault Core Application Orchestrator (app.js)
 * Master SPA router, active state manager, navigation handler, and live refresh engine.
 */

window.SOAR_APP = {
  currentView: "dashboard",

  init() {
    const session = SOAR_API.requireSession();
    if (!session) return;

    this.renderUser(session);
    this.setupNavigation();
    this.refresh();

    // Live auto-refresh polling loop (every 5 seconds)
    setInterval(() => this.refresh(true), 5000);
  },

  renderUser(session) {
    const avatarEl = document.getElementById("user-avatar");
    const nameEl = document.getElementById("user-name");
    const roleEl = document.getElementById("user-role");
    const badgeEl = document.getElementById("role-badge");

    const initials = (session.name || session.username || "AN").slice(0, 2).toUpperCase();

    if (avatarEl) avatarEl.textContent = initials;
    if (nameEl) nameEl.textContent = session.name || session.username;
    if (roleEl) roleEl.textContent = session.role_label || session.role;
    if (badgeEl) badgeEl.textContent = session.role_label || session.role;

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => {
        localStorage.removeItem("soar_session");
        window.location.href = "login.html";
      });
    }
  },

  setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item[data-view]");
    navItems.forEach(item => {
      item.addEventListener("click", (e) => {
        const view = e.currentTarget.getAttribute("data-view");
        this.switchView(view);
      });
    });
  },

  switchView(viewName) {
    this.currentView = viewName;

    // Update Sidebar Navigation buttons
    document.querySelectorAll(".nav-item").forEach(item => {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("is-active");
      } else {
        item.classList.remove("is-active");
      }
    });

    // Update Visible View Section
    document.querySelectorAll(".view-section").forEach(sec => {
      if (sec.id === `view-${viewName}`) {
        sec.classList.add("is-active");
      } else {
        sec.classList.remove("is-active");
      }
    });

    // Update Header Title
    const titleEl = document.getElementById("view-title");
    const titles = {
      dashboard: "SOC Overview Command Center",
      cases: "Incident & Case Management",
      alerts: "Live SIEM Ingestion Queue",
      playbooks: "Playbook Orchestration Engine",
      integrations: "SIEM & Security Tools Integrations",
    };
    if (titleEl) titleEl.textContent = titles[viewName] || "SOAR Operations";

    this.refresh();
  },

  async refresh(silent = false) {
    const metrics = await SOAR_API.fetch("/api/metrics", "metrics");
    const cases = await SOAR_API.fetch("/api/cases", "cases");
    const alerts = await SOAR_API.fetch("/api/alerts", "alerts");

    if (metrics && cases) {
      DashboardView.load(metrics, cases, alerts);
    }

    if (cases) {
      CasesView.renderTable(cases);
      
      // Update pending approval banner
      const pendingApprovalCases = cases.filter(c => c.status === "pending_approval");
      const banner = document.getElementById("approval-banner");
      const countEl = document.getElementById("approval-banner-count");
      if (banner && countEl) {
        if (pendingApprovalCases.length > 0) {
          countEl.textContent = `${pendingApprovalCases.length} incident${pendingApprovalCases.length > 1 ? 's' : ''}`;
          banner.hidden = false;
        } else {
          banner.hidden = true;
        }
      }
    }

    if (alerts) {
      QueueView.render(alerts);
    }

    if (this.currentView === "playbooks") {
      const playbooks = await SOAR_API.fetch("/api/playbooks", "playbooks");
      PlaybooksView.render(playbooks);
    }

    if (this.currentView === "integrations") {
      const integrations = await SOAR_API.fetch("/api/integrations", "integrations");
      IntegrationsView.render(integrations);
    }
  }
};

document.addEventListener("DOMContentLoaded", () => {
  SOAR_APP.init();
});
