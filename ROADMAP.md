# 25-Day Roadmap — Frontend (branch: `rohit`)

Each day = one focused chunk of work = one commit. Adjust dates to your
actual sprint, but keep the order — later days depend on earlier ones.
Commit message format suggestion: `day N: <what changed>`.

## Week 1 — Scaffold & static shell
- **Day 1** — Create folder structure (`dashboard/`, `static/`, `api/`), empty stub files, initial `README.md`.
- **Day 2** — Flask entrypoint (`app.py`) serving a placeholder `index.html`.
- **Day 3** — Base `index.html` shell: sidebar nav + topbar, no styling yet.
- **Day 4** — `styles.css` v1: color tokens, layout grid, sidebar styling.
- **Day 5** — Style the topbar + KPI card row (static numbers, no data yet).
- **Day 6** — Build the MTTR ring SVG and get it rendering (hardcoded value).
- **Day 7** — Responsive pass: mobile breakpoint, sidebar collapse.

## Week 2 — Mock data & interactivity
- **Day 8** — `case_manager.py` with in-memory `MOCK_CASES`.
- **Day 9** — `api/routes.py`: `/api/cases` + `/api/metrics` endpoints.
- **Day 10** — `app.js`: fetch cases, render the Active Cases panel.
- **Day 11** — Wire `/api/metrics` into the MTTR ring + KPI cards (live values, animated).
- **Day 12** — Add `/api/alerts` endpoint + render the Alert Queue panel.
- **Day 13** — Severity chips (`critical/high/medium/low`) styling + status tags.
- **Day 14** — Nav view-switching (Dashboard / Cases / Alerts / Playbooks) without page reload.

## Week 3 — Playbooks, RBAC, polish
- **Day 15** — `rbac.py`: role definitions (SOC Analyst vs Security Engineer).
- **Day 16** — `login.html` + `auth.js`: real sign-in page, session stored client-side, protected pages redirect here if no session.
- **Day 17** — `/api/playbooks` endpoint + Playbooks grid view.
- **Day 18** — Playbook editor modal for Security Engineer role (`PUT /api/playbooks/<id>`), 403 enforced server-side for other roles.
- **Day 19** — Case detail modal (enrichment + kill-chain timeline) and Alert detail modal.
- **Day 20** — `/api/integrations` endpoint + Integrations view (SIEM/enrichment/orchestration connection status).
- **Day 21** — Accessibility pass: keyboard focus states, color contrast check, `alt`/`aria` labels.

## Week 4 — Integration & handoff
- **Day 22** — Wire an "Acknowledge case" button to `POST /api/cases/<id>/ack`.
- **Day 23** — Loading states (skeletons/spinners) while API calls are in flight.
- **Day 24** — Integration pass with teammates' real ingestion/enrichment endpoints once available (swap mock URLs for real ones).
- **Day 25** — Final polish: cross-browser check, README updated with setup steps, demo walkthrough for the team.

## Notes for daily commits
- Commit only what actually changed that day — small, real diffs read
  better in review than one giant commit split artificially.
- If a day's task is genuinely done early, pull the next day's task
  forward rather than committing a no-op.
- Open a PR from `rohit` → `main` (or your team's integration branch)
  once Week 2 is stable, then keep pushing to the same branch/PR daily.
