/**
 * SOARVault API & Session Manager (api.js)
 * Modular API client layer for fetch handling and fallback demo state.
 */

const SOAR_API = {
  FALLBACK: {
    metrics: {
      mttr_avg_seconds: 3.8,
      mttr_target_seconds: 5.0,
      alerts_ingested_24h: 412,
      cases_auto_contained_24h: 37,
      analyst_hours_saved_24h: 18.5,
    },
    cases: [
      { id: "CASE-1001", title: "Suspicious outbound traffic to known C2 IP", severity: "critical", status: "contained", ioc: "185.220.101.7", risk_score: 92, mttr_seconds: 3.8 },
      { id: "CASE-1002", title: "Credential-stuffing pattern on VPN gateway", severity: "high", status: "in_progress", ioc: "45.83.64.22", risk_score: 78, mttr_seconds: null },
      { id: "CASE-1003", title: "Malicious hash matched on endpoint", severity: "medium", status: "resolved_auto", ioc: "d41d8cd98f00b204e9800998ecf8427e", risk_score: 55, mttr_seconds: 4.6 },
    ],
    alerts: [
      { id: "ALRT-88231", rule: "Outbound connection to Tor exit node", severity: "critical", ioc_value: "185.220.101.7", source: "Splunk SIEM", enrichment_status: "complete" },
      { id: "ALRT-88240", rule: "Repeated auth failures across 40 accounts", severity: "high", ioc_value: "45.83.64.22", source: "QRadar SIEM", enrichment_status: "in_progress" },
    ],
    playbooks: [
      { id: "isolate-ec2-and-block-ip", name: "Isolate EC2 + Block IP", trigger: "risk_score >= 80 and ioc_type == 'ip'", actions: ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"] },
      { id: "block-ip-firewall", name: "Block IP at Perimeter Firewall", trigger: "risk_score >= 60 and ioc_type == 'ip'", actions: ["block_ip_edge_firewall", "notify_slack"] },
    ],
    integrations: [
      { id: "splunk", name: "Splunk SIEM", type: "alert_source", status: "connected", last_event: "8s ago" },
      { id: "abuseipdb", name: "AbuseIPDB", type: "enrichment", status: "connected", last_event: "6s ago" },
      { id: "virustotal", name: "VirusTotal", type: "enrichment", status: "connected", last_event: "6s ago" },
    ]
  },

  getSession() {
    try {
      return JSON.parse(localStorage.getItem("soar_session"));
    } catch (e) {
      return null;
    }
  },

  requireSession() {
    const session = this.getSession();
    if (!session) {
      window.location.href = "login.html";
      return null;
    }
    return session;
  },

  async fetch(path, fallbackKey, options = {}) {
    const session = this.getSession();
    const headers = { ...options.headers };
    if (session && session.role) {
      headers["X-Role"] = session.role;
    }

    try {
      const res = await fetch(path, { ...options, headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`API path ${path} unavailable, using fallback for ${fallbackKey}`);
      return fallbackKey ? this.FALLBACK[fallbackKey] : null;
    }
  }
};
