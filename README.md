# SOAR Incident Containment Engine — Frontend (Rohit)

This is the **frontend + mock API** slice of the team's Project 3: Enterprise
Cloud / MSSP SOAR Incident Containment Engine. It's built so it runs
standalone with fake data today, and plugs into the real ingestion /
enrichment / orchestration modules (teammates' side) later — the API
endpoints and JSON shapes are the contract between the two.

## What's here

```
dashboard/
  app.py            Flask entrypoint — serves static/ and mounts the API
  rbac.py           Role definitions (SOC Analyst vs Security Engineer)
  case_manager.py   In-memory case store, incl. enrichment + kill-chain timeline
  api/
    routes.py       /api/auth/login, /metrics, /cases (+detail), /alerts,
                     /playbooks (+edit), /integrations
  static/
    login.html      Sign-in page (session stored in localStorage)
    index.html      Dashboard shell — sidebar nav, KPI strip, 5 views, 3 modals
    css/styles.css  Ops-console dark theme
    js/auth.js      Login page logic
    js/app.js       Auth guard, view routing, modals, playbook editor
```

## Pages / views

- **Login** (`login.html`) — demo accounts below; stores role + permissions in session
- **Dashboard** — MTTR ring, KPI strip, Active Cases + Alert Queue previews
- **Cases** — full case list; click a row for a detail modal with enrichment
  data (AbuseIPDB/VirusTotal) and the containment kill-chain timeline
- **Alert Queue** — full alert list; click a row for raw indicator detail
- **Playbooks** — trigger/action cards; Security Engineers see an **Edit
  playbook** button that opens an editor and saves via `PUT /api/playbooks/<id>`
  (SOC Analysts get a 403 if they try the API directly — enforced in `rbac.py`)
- **Integrations** — connection status for SIEM sources, enrichment APIs,
  and orchestration targets (Splunk, QRadar, CrowdStrike, AbuseIPDB,
  VirusTotal, AWS SDK, Palo Alto firewall API, Slack)

## Run it

```bash
pip install -r requirements.txt
python -m dashboard.app
```

Then open http://127.0.0.1:5000 — you'll land on the login page first.

**Demo accounts:**
| Username | Password | Role |
|---|---|---|
| `asha.soc` | `demo123` | SOC Analyst |
| `rohit.eng` | `demo123` | Security Engineer |

If you just open `dashboard/static/index.html` directly in a browser (no
Flask running), the frontend falls back to embedded mock data so it's
still demoable — the login page's fallback credentials match the table above.

## Git workflow

Working on branch `rohit`, committing daily as pieces land. See
`ROADMAP.md` for the day-by-day plan.

```bash
git checkout -b rohit
git add .
git commit -m "day 1: scaffold dashboard app + folder structure"
git push -u origin rohit
```

## Ingestion & Orchestration Backend (Mantra)

The backend orchestration engine is responsible for receiving raw SIEM alerts, normalizing them, and orchestrating threat enrichment.

### Architecture

Read the full backend design document here: [ORCHESTRATOR_DESIGN.md](docs/ORCHESTRATOR_DESIGN.md).

### Run the API

```bash
uvicorn ingestion.main:app --reload
```

The API will be available at http://127.0.0.1:8000.

### Testing & Benchmarking

To test the orchestration engine under load, use the provided benchmarking tool:

```bash
# Send 100 requests with a concurrency of 10
python benchmark.py -n 100 -c 10
```
