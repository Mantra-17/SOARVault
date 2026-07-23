# Implementation Plan: Ingestion API & Async Orchestrator (Days 4-12)

This plan covers the completion of Day 4 through Day 12 of the SOARVault engineering roadmap for the `ingestion` module. This includes building the FastAPI webhook server, the asynchronous pipeline orchestrator, the event simulator, and comprehensive testing.

## User Review Required

> [!IMPORTANT]
> **Enrichment Synchronization:** The current `enrichment/enricher.py` module exposes synchronous functions (`enrich_alert`). To fulfill the Day 11 requirement of an asynchronous orchestration pipeline, I will wrap the call to `enrich_alert` in `asyncio.to_thread()` so it doesn't block the FastAPI event loop during I/O operations (like fetching from VirusTotal or AbuseIPDB).

## Open Questions

> [!WARNING]
> **RawAlert Model:** In checking `schema.py`, the canonical `NormalizedAlert` model exists, but `RawAlert` does not. I will accept an arbitrary JSON dictionary (`Dict[str, Any]`) as the payload for `POST /webhook/alert` representing the `RawAlert` since SIEM payloads are highly unstructured. Is this acceptable, or would you prefer I explicitly define a loosely-typed `RawAlert` Pydantic model in `schema.py`?

## Proposed Changes

### 1. REST API
#### [MODIFY] [main.py](file:///c:/Users/jashj/OneDrive/Desktop/SOARVault/SOARVault/ingestion/main.py)
- Initialize FastAPI app instance.
- Add `POST /webhook/alert` endpoint to ingest single raw SIEM alerts.
- Add `POST /webhook/alerts/batch` for high-throughput batch ingestion.
- Add `GET /health` for readiness probes.
- Add `GET /alerts` and `GET /stats` to fetch recent alerts and metrics.
- Implement a global exception handler for graceful `500` error responses.

### 2. Async Orchestrator
#### [NEW] [orchestrator.py](file:///c:/Users/jashj/OneDrive/Desktop/SOARVault/SOARVault/ingestion/orchestrator.py)
- Build the `AlertOrchestrator` class responsible for managing state and pipeline flow.
- Implement the async pipeline: `Raw Payload -> Normalizer -> Enrichment`.
- Incorporate deduplication by generating a SHA-256 hash of the alert's core contents and silently dropping duplicates.
- Measure pipeline execution latency using `time.perf_counter()` and append the timings to the enriched response payload.

### 3. Simulation & Mock Data
#### [MODIFY] [simulator.py](file:///c:/Users/jashj/OneDrive/Desktop/SOARVault/SOARVault/ingestion/simulator.py)
- Create an `AlertSimulator` class that randomly generates SIEM payloads mimicking: Brute Force, Malware, DDoS, Insider Threat, and Data Exfiltration.

#### [NEW] sample_alerts/alert_*.json
- Generate 10 distinct JSON files representing diverse payloads with edge cases.

### 4. Testing & Optimization
#### [NEW] [tests/test_ingestion.py](file:///c:/Users/jashj/OneDrive/Desktop/SOARVault/SOARVault/tests/test_ingestion.py)
- Unit tests for the FastAPI endpoints using `fastapi.testclient.TestClient`.
- Integration tests ensuring the Orchestrator successfully passes normalized data to the mock Enrichment module.

#### [MODIFY] [normalizer.py](file:///c:/Users/jashj/OneDrive/Desktop/SOARVault/SOARVault/ingestion/normalizer.py)
- Optimize regex patterns by compiling them at the module level.
- Add `@functools.lru_cache` for repeated parsing operations.

## Verification Plan

### Automated Tests
- Run `pytest tests/test_ingestion.py -v` to ensure components are functionally correct.

### Manual Verification
- Start the API server and run `python ingestion/simulator.py` to blast the server and observe the asynchronous pipeline behavior and latency metrics.
