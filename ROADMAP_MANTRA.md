# 30-Day Engineering Roadmap: Mantra (Alert Ingestion & Orchestration)

This document outlines the detailed 30-day engineering roadmap for Mantra. Mantra is responsible for Alert Ingestion, Data Normalization, FastAPI API, Orchestrator, Integration between modules, Performance Optimization, Benchmarking, Audit Logging, Docker Integration, Final Pipeline Connection, and related Documentation.

## Day 1
### Goal
Initialize the repository, setup the project structure, and configure the base FastAPI application.

### Files to Create
- `README.md`
- `requirements.txt`
- `.env.example`
- `.gitignore`
- `ingestion/__init__.py`
- `ingestion/schema.py`
- `ingestion/normalizer.py`
- `ingestion/main.py`
- `ingestion/simulator.py`

### Files to Modify
- None

### Detailed Tasks
- Initialize the git repository.
- Setup basic `FastAPI` app in `main.py` with standard Uvicorn configurations.
- Create base package structure for `ingestion` and empty files for future days.
- Define `requirements.txt` containing `fastapi`, `uvicorn`, `pydantic`, `requests`, etc.
- Create `sample_alerts/` directory to store mock JSON alerts.

### Expected Output
A running FastAPI base app (`/docs` reachable) with project scaffolded and dependencies installed.

### Dependencies
None.

### Testing
- Verify server starts successfully.
- Check swagger UI at `/docs`.

### Deliverables
Project skeleton and base configurations.

### Git Commit
`chore(project): initialize repository and base FastAPI structure`

---

## Day 2
### Goal
Implement Pydantic data schemas for raw and normalized alerts.

### Files to Create
- None

### Files to Modify
- `ingestion/schema.py`

### Detailed Tasks
- Implement `RawAlert` Pydantic model for incoming webhooks.
- Implement `NormalizedAlert` Pydantic model for internal orchestration.
- Implement `IOC` (Indicator of Compromise) model.
- Define Enums: `Severity` (Critical, High, Medium, Low), `AlertStatus` (New, Processing, Resolved, Ignored), `AttackType` (Brute Force, Malware, DDoS, Insider Threat, Data Exfiltration).
- Implement basic Pydantic validation (e.g., valid IP format).

### Expected Output
Strict validation models ready to accept structured dictionary inputs.

### Dependencies
None.

### Testing
- Unit tests for Pydantic models (success and failure scenarios).

### Deliverables
Completed `schema.py` with full Pydantic models and Enums.

### Git Commit
`feat(ingestion): implement normalized alert schema and validation models`

---

## Day 3
### Goal
Implement the data normalization logic for various SIEM vendor formats.

### Files to Create
- None

### Files to Modify
- `ingestion/normalizer.py`

### Detailed Tasks
- Create `normalize_alert()` function to handle raw to normalized conversion.
- Implement helper functions: `extract_source_ip()`, `extract_destination_ip()`, `normalize_timestamp()`.
- Add mapping dictionaries to handle severity and attack type translations.
- Include robust error handling for missing fields and type mismatches.

### Expected Output
A module that safely takes a `RawAlert` and outputs a `NormalizedAlert`.

### Dependencies
None.

### Testing
- Unit tests validating normalization rules with missing/malformed inputs.

### Deliverables
Completed `normalizer.py` with standard mapping logic.

### Git Commit
`feat(ingestion): implement alert normalization logic and mapping`

---

## Day 4
### Goal
Expose ingestion logic through FastAPI endpoints.

### Files to Create
- None

### Files to Modify
- `ingestion/main.py`

### Detailed Tasks
- Create `POST /webhook/alert` endpoint to receive alerts.
- Create `GET /health` endpoint for readiness probes.
- Create `GET /alerts` endpoint for retrieving recently processed alerts.
- Implement input validation and error handling using Pydantic and `HTTPException`.
- Add structured logging to log incoming payloads and errors.

### Expected Output
API server ready to receive and validate POST requests on `/webhook/alert`.

### Dependencies
None.

### Testing
- API tests using `TestClient` for valid/invalid payloads.

### Deliverables
Functional FastAPI endpoints with validation and error logging.

### Git Commit
`feat(api): create webhook ingestion and health check endpoints`

---

## Day 5
### Goal
Implement an alert simulator to generate realistic mock data.

### Files to Create
- None

### Files to Modify
- `ingestion/simulator.py`

### Detailed Tasks
- Create classes or functions to generate distinct types of alerts.
- Support generating: Brute Force, Malware, DDoS, Insider Threat, Data Exfiltration.
- Introduce slight randomness (IPs, timestamps, usernames) for realism.

### Expected Output
A runnable script that generates diverse, randomized SIEM alerts on demand.

### Dependencies
None.

### Testing
- Manual run to ensure valid JSON outputs that pass `schema.py` validation.

### Deliverables
A comprehensive simulator script to test the ingestion pipeline.

### Git Commit
`feat(simulator): implement dynamic SIEM alert generation script`

---

## Day 6
### Goal
Create static sample alerts representing complex edge cases.

### Files to Create
- `ingestion/sample_alerts/alert_1.json` to `alert_10.json` (various)
- `ingestion/sample_alerts/malformed_timestamp.json`

### Files to Modify
- None

### Detailed Tasks
- Create 10 static JSON sample alerts representing different SIEM vendors (e.g., Splunk, QRadar, Sentinel).
- Create payloads with malformed timestamps, IPv6 addresses, missing fields, and nested structures to test system resilience.

### Expected Output
A directory populated with test payloads that simulate real-world SIEM complexities.

### Dependencies
None.

### Testing
- Run test payloads through `/webhook/alert` to verify graceful failure or successful parsing.

### Deliverables
Static JSON alert test suite.

### Git Commit
`test(data): add complex and malformed sample JSON alerts`

---

## Day 7
### Goal
Finalize Week 1 documentation and ensure testing coverage.

### Files to Create
- None

### Files to Modify
- `README.md`
- `tests/test_ingestion.py` (if created)

### Detailed Tasks
- Update `README.md` with instructions on how to start the API and use the simulator.
- Refine existing unit tests for normalizer and schema validation.
- Prepare the repository for the Week 1 pull request.

### Expected Output
Fully documented and tested Week 1 milestone.

### Dependencies
None.

### Testing
- Complete execution of the unit test suite (`pytest`).

### Deliverables
Updated README and Week 1 Pull Request.

### Git Commit
`docs(readme): document API setup and ingestion testing`

---

## Day 8
### Goal
Implement the core asynchronous orchestrator pipeline.

### Files to Create
- `ingestion/orchestrator.py`

### Files to Modify
- `ingestion/main.py`

### Detailed Tasks
- Create `AlertOrchestrator` class to manage the pipeline flow.
- Implement the pipeline: Raw Alert -> Normalizer -> Enrichment (Mock/Import).
- Integrate `orchestrator.py` into `main.py` to route webhook data.
- Import teammate's enrichment module (e.g., `from enrichment.enricher import enrich_alert`) without implementing their logic.

### Expected Output
An orchestrator that directs data through normalization and enrichment stages.

### Dependencies
Requires the interface of the `enrichment` module built by a teammate.

### Testing
- Integration tests ensuring data flows correctly from Webhook -> Normalizer -> Orchestrator.

### Deliverables
Functional orchestration pipeline linking normalization and enrichment.

### Git Commit
`feat(orchestrator): implement base alert pipeline and enrichment integration`

---

## Day 9
### Goal
Refine the webhook response to include enriched data and pipeline timing.

### Files to Create
- None

### Files to Modify
- `ingestion/main.py`
- `ingestion/orchestrator.py`

### Detailed Tasks
- Modify the orchestrator to track timing metrics for the pipeline execution.
- Ensure the webhook endpoint returns the final `NormalizedAlert`, mock `Threat Intel`, and `Risk Score` in a structured JSON format.

### Expected Output
API responses that show the fully enriched context and processing time.

### Dependencies
Relies on the `enrichment` module returning expected intel and risk scores.

### Testing
- API tests validating the structure of the JSON response.

### Deliverables
Enhanced API endpoints with detailed response data and latency tracking.

### Git Commit
`feat(api): return enriched alert data and pipeline metrics in webhook`

---

## Day 10
### Goal
Implement high-throughput batch endpoints and deduplication logic.

### Files to Create
- None

### Files to Modify
- `ingestion/main.py`
- `ingestion/orchestrator.py`

### Detailed Tasks
- Add `POST /webhook/alerts/batch` for processing multiple alerts simultaneously.
- Add `GET /stats` endpoint for retrieving pipeline health metrics.
- Implement basic `Alert Deduplication` in the orchestrator (e.g., using a local cache or in-memory set based on source IP and attack type within a time window).

### Expected Output
System capable of handling arrays of alerts and filtering out redundant signals.

### Dependencies
None.

### Testing
- API batch testing and deduplication unit tests.

### Deliverables
Batch endpoint and deduplication filter.

### Git Commit
`feat(ingestion): add batch processing endpoint and alert deduplication`

---

## Day 11
### Goal
Enhance the orchestrator with asynchronous concurrency.

### Files to Create
- None

### Files to Modify
- `ingestion/orchestrator.py`

### Detailed Tasks
- Refactor the orchestrator to use `asyncio.gather` for parallel execution of multiple enrichment tasks (e.g., VirusTotal + AbuseIPDB).
- Ensure thread-safety and proper async handling for I/O bound operations.

### Expected Output
Significantly faster processing times for enrichment via parallel execution.

### Dependencies
Depends on the async nature of the enrichment teammate's modules.

### Testing
- Load testing to verify asynchronous efficiency.

### Deliverables
Fully asynchronous orchestrator capable of parallel task execution.

### Git Commit
`refactor(orchestrator): implement parallel asynchronous enrichment execution`

---

## Day 12
### Goal
Conduct performance optimization and latency profiling.

### Files to Create
- None

### Files to Modify
- `ingestion/normalizer.py`
- `ingestion/orchestrator.py`

### Detailed Tasks
- Profile the pipeline to identify bottlenecks.
- Optimize regex patterns or loop constructs in the normalizer.
- Optimize memory usage in the deduplication cache.

### Expected Output
Reduced overhead in data parsing and normalization.

### Dependencies
None.

### Testing
- Benchmark comparison before and after optimizations.

### Deliverables
Optimized codebase.

### Git Commit
`perf(ingestion): optimize normalization logic and reduce latency`

---

## Day 13
### Goal
Implement a dedicated benchmarking script to measure system limits.

### Files to Create
- `benchmark.py`

### Files to Modify
- None

### Detailed Tasks
- Create a load testing script targeting the batch API.
- Calculate and log performance metrics: Average, P95 (95th percentile latency), Min, and Max.
- Generate high volumes of mock data using the `simulator.py`.

### Expected Output
A standalone tool for verifying the performance SLA of the pipeline.

### Dependencies
None.

### Testing
- Run `benchmark.py` against a local Uvicorn instance.

### Deliverables
Benchmarking utility script.

### Git Commit
`test(benchmark): create load testing script for latency metrics (P95, Avg)`

---

## Day 14
### Goal
Draft architecture documentation for the ingestion and orchestration layer.

### Files to Create
- `docs/architecture.md` (or similar)

### Files to Modify
- `README.md`

### Detailed Tasks
- Document the sequence flow: Raw -> Normalizer -> Orchestrator -> Enrichment -> Playbooks.
- Detail the deduplication strategy and asynchronous design.
- Update `README.md` with pointers to the new documentation.

### Expected Output
Clear, enterprise-grade technical documentation.

### Dependencies
None.

### Testing
- Review documentation for clarity and accuracy.

### Deliverables
Architectural design document.

### Git Commit
`docs(architecture): add sequence flow and orchestration documentation`

---

## Day 15
### Goal
Connect the complete end-to-end orchestration pipeline.

### Files to Create
- None

### Files to Modify
- `ingestion/orchestrator.py`

### Detailed Tasks
- Connect the full pipeline: Raw Alert -> Normalize -> Enrich -> Playbook -> Dashboard.
- Import modules from the playbooks and dashboard teammates.
- Utilize interfaces cleanly, catching exceptions from external modules to ensure pipeline resilience.

### Expected Output
A cohesive pipeline where an ingested alert flows seamlessly to mitigation and visualization.

### Dependencies
Requires stable interfaces from both the Playbooks and Dashboard teammates.

### Testing
- End-to-end integration tests verifying the full flow.

### Deliverables
Fully integrated orchestrator.

### Git Commit
`feat(orchestrator): integrate playbooks and dashboard into final pipeline`

---

## Day 16
### Goal
Execute formal performance testing against the SLA.

### Files to Create
- None

### Files to Modify
- None

### Detailed Tasks
- Run the `benchmark.py` tool.
- Target goal: Process an alert End-to-End in < 5 seconds.
- Log results and identify any remaining bottlenecks in the integration layer.

### Expected Output
Benchmark report confirming the SLA is met.

### Dependencies
None.

### Testing
- Extensive benchmark testing.

### Deliverables
Confirmed performance results.

### Git Commit
`test(perf): execute full pipeline benchmark and validate <5s SLA`

---

## Day 17
### Goal
Apply final pipeline optimizations based on Day 16 results.

### Files to Create
- None

### Files to Modify
- `ingestion/orchestrator.py`

### Detailed Tasks
- Fine-tune async timeouts or connection pools.
- Address any performance issues found during benchmarking (e.g., adding fast-fail logic).

### Expected Output
A highly tuned, production-ready pipeline.

### Dependencies
None.

### Testing
- Re-run benchmarks to confirm improvements.

### Deliverables
Final performance-optimized orchestrator.

### Git Commit
`perf(pipeline): tune async timeouts and optimize integration boundaries`

---

## Day 18
### Goal
Implement a structured audit logging mechanism.

### Files to Create
- `ingestion/audit.py`

### Files to Modify
- `ingestion/orchestrator.py`

### Detailed Tasks
- Create an `audit_logger` class in `audit.py`.
- Ensure logs capture critical orchestration decisions, playbook executions, and deduplication events.
- Format logs as structured JSON for easy ingest into external monitoring tools.

### Expected Output
Comprehensive, structured tracking of all automated actions.

### Dependencies
None.

### Testing
- Unit tests verifying the structure and storage of audit logs.

### Deliverables
Audit logging module.

### Git Commit
`feat(audit): implement structured JSON audit logging`

---

## Day 19
### Goal
Expose the audit logs via the API.

### Files to Create
- None

### Files to Modify
- `ingestion/main.py`

### Detailed Tasks
- Create `GET /audit-log` endpoint.
- Implement pagination or limit parameters.
- Secure the endpoint (conceptually, or rely on teammate's RBAC).

### Expected Output
An API endpoint for security operators to review historical actions.

### Dependencies
None.

### Testing
- API tests retrieving the logs.

### Deliverables
Audit log API endpoint.

### Git Commit
`feat(api): expose structured audit logs via GET endpoint`

---

## Day 20
### Goal
Finalize API and Architecture documentation.

### Files to Create
- `docs/api/ingestion_api.md`

### Files to Modify
- `docs/architecture.md`

### Detailed Tasks
- Document all endpoints, request/response payloads, and status codes.
- Ensure Swagger/OpenAPI spec is accurate via FastAPI docstrings.

### Expected Output
Polished developer documentation.

### Dependencies
None.

### Testing
- Review Swagger UI for completeness.

### Deliverables
Finalized API documentation.

### Git Commit
`docs(api): finalize OpenAPI spec and detailed endpoint documentation`

---

## Day 21
### Goal
Merge Week 3 progress and conduct PR reviews.

### Files to Create
- None

### Files to Modify
- None

### Detailed Tasks
- Review teammates' PRs.
- Address PR feedback on the orchestration and ingestion modules.
- Ensure main branch remains stable.

### Expected Output
Merged codebase for Week 3.

### Dependencies
Collaboration with the entire engineering team.

### Testing
- CI pipeline passes on `main`.

### Deliverables
Approved and merged PRs.

### Git Commit
`chore(merge): review and merge Week 3 orchestrator features`

---

## Day 22
### Goal
Perform final integration and resolve any merge conflicts.

### Files to Create
- None

### Files to Modify
- Any files requiring conflict resolution.

### Detailed Tasks
- Pull the latest `main`.
- Fix any breaking changes introduced by other modules (e.g., changed enrichment schemas).
- Ensure the pipeline functions end-to-end flawlessly.

### Expected Output
A unified, conflict-free repository ready for containerization.

### Dependencies
All teammates' final modules must be in `main`.

### Testing
- Full end-to-end regression testing.

### Deliverables
Stable, integrated application.

### Git Commit
`fix(integration): resolve merge conflicts and stabilize pipeline`

---

## Day 23
### Goal
Implement Docker deployment configurations.

### Files to Create
- `Dockerfile`
- `docker-compose.yml`

### Files to Modify
- None

### Detailed Tasks
- Create a multi-stage `Dockerfile` for the Python FastAPI application.
- Define a `docker-compose.yml` to spin up the application (and potentially a mock DB/Redis if utilized).
- Follow Docker best practices (e.g., non-root user, minimal base image).

### Expected Output
A containerized application that can be run with a single command.

### Dependencies
None.

### Testing
- `docker build` and `docker-compose up` to verify successful containerization.

### Deliverables
Docker configurations.

### Git Commit
`chore(docker): create Dockerfile and docker-compose configurations`

---

## Day 24
### Goal
Conduct rigorous testing in the Docker environment.

### Files to Create
- None

### Files to Modify
- `Dockerfile` (if fixes are needed)

### Detailed Tasks
- Test all endpoints while running inside the Docker container.
- Verify environment variable injection and network configurations.

### Expected Output
Verified container behavior matching local development.

### Dependencies
None.

### Testing
- Run integration tests against the Docker instance.

### Deliverables
Tested and verified Docker setup.

### Git Commit
`test(docker): validate API and pipeline within Docker container`

---

## Day 25
### Goal
Write the comprehensive technical report for the SOAR engine.

### Files to Create
- `SOAR_TECHNICAL_REPORT.md`

### Files to Modify
- None

### Detailed Tasks
- Detail the architecture, design patterns used (SOLID, Clean Architecture), challenges faced, and performance benchmarks achieved.
- Provide a summary of the ingestion and orchestration modules.

### Expected Output
A professional, enterprise-grade engineering report.

### Dependencies
None.

### Testing
- Review document for clarity and professional tone.

### Deliverables
Technical report document.

### Git Commit
`docs(report): draft SOAR vault technical report and performance summary`

---

## Day 26
### Goal
Prepare the environment and data for the final demonstration.

### Files to Create
- None

### Files to Modify
- `ingestion/simulator.py` (if specific demo scenarios are needed)

### Detailed Tasks
- Script a perfect "golden path" demonstration scenario.
- Ensure the simulator generates predictable data that highlights the platform's strengths.

### Expected Output
A reproducible, polished demo workflow.

### Dependencies
Playbooks and Dashboards must be ready to receive demo data.

### Testing
- Dry-run the demonstration multiple times.

### Deliverables
Demo preparation.

### Git Commit
`chore(demo): script golden-path demo scenarios in simulator`

---

## Day 27
### Goal
Finalize the main project README.

### Files to Create
- None

### Files to Modify
- `README.md`

### Detailed Tasks
- Include Quickstart instructions, Docker usage, Architecture overview, and links to detailed docs.
- Ensure it is pristine for external evaluation.

### Expected Output
A beautiful, comprehensive GitHub README.

### Dependencies
None.

### Testing
- Render markdown to verify formatting.

### Deliverables
Final `README.md`.

### Git Commit
`docs(readme): finalize project documentation and quickstart guide`

---

## Day 28
### Goal
Execute code cleanup, linting, and a security review.

### Files to Create
- None

### Files to Modify
- Various `.py` files

### Detailed Tasks
- Run `flake8`, `black`, or `ruff` to ensure consistent formatting.
- Perform a manual security review (e.g., checking for hardcoded secrets, injection vulnerabilities).

### Expected Output
Clean, secure, and idiomatic Python codebase.

### Dependencies
None.

### Testing
- Automated linting and security scanning (e.g., `bandit`).

### Deliverables
Linted and secured code.

### Git Commit
`style(cleanup): format code, run linters, and apply security fixes`

---

## Day 29
### Goal
Conduct final system-wide end-to-end testing.

### Files to Create
- None

### Files to Modify
- None

### Detailed Tasks
- Run the full test suite.
- Execute a final benchmark test.
- Verify everything works seamlessly in Docker.

### Expected Output
100% confidence in the release candidate.

### Dependencies
All teammate modules must be finalized.

### Testing
- Full regression suite.

### Deliverables
Test sign-off.

### Git Commit
`test(regression): execute final end-to-end system test suite`

---

## Day 30
### Goal
Release v1.0.0.

### Files to Create
- None

### Files to Modify
- None

### Detailed Tasks
- Tag the repository with `v1.0.0`.
- Create a formal GitHub Release with changelog notes.

### Expected Output
The first official release of the SOARVault Ingestion Engine.

### Dependencies
None.

### Testing
- Verify release artifacts.

### Deliverables
v1.0.0 Release.

### Git Commit
`chore(release): tag and publish v1.0.0`
