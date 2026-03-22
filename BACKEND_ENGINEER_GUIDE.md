# SentinelFuzz AI Engine Backend Integration Guide

This is the single integration document for backend engineers.

## 1) What this engine does

Given an authorized target URL, the engine:

1. Crawls the target (links, forms, parameters).
2. Runs DAST-style fuzzing payloads against discovered inputs.
3. Detects high-signal vulnerability indicators from responses.
4. Scores findings with a CVSS-inspired severity model.
5. Generates remediation text (offline templates or AI provider).
6. Returns a structured JSON report your backend can store and send to frontend.

## 2) Safety model (must understand)

- You must pass `authorized: true`, otherwise scan is blocked.
- Private/local targets are blocked by default.
- Payload set is non-destructive by default.
- Use only on systems where you have explicit legal permission to test.

## 3) Runtime requirements

Minimum:

- Python 3.11+ (tested on Python 3.12)
- OS: Windows/Linux/macOS
- Network access from engine to scan target

Optional AI providers:

- Offline mode (default): no extra install, no API key
- Ollama local free models:
  - Install Ollama
  - Pull model (example): `ollama pull llama3.1:8b`
- Hugging Face Inference:
  - `HF_API_TOKEN` required
  - Free-tier model endpoint supported

## 4) Install and run

```bat
cd /d f:\Hackathon\SentinelFuzz\AI_Engine
python -m venv .venv
.venv\Scripts\activate
python run_server.py
```

Server defaults:

- Host: `127.0.0.1`
- Port: `8787`

Health check:

```bash
GET http://127.0.0.1:8787/health
```

## 5) Environment variables

Use `.env.example` as reference:

- `SENTINEL_HOST=127.0.0.1`
- `SENTINEL_PORT=8787`
- `SENTINEL_AI_PROVIDER=offline|ollama|huggingface`
- `SENTINEL_OLLAMA_URL=http://127.0.0.1:11434`
- `SENTINEL_OLLAMA_MODEL=llama3.1:8b`
- `SENTINEL_HF_MODEL=mistralai/Mistral-7B-Instruct-v0.2`
- `HF_API_TOKEN=...`

## 6) API contract for Node.js backend

### Option A: Async workflow (recommended)

#### 1. Start scan

`POST /v1/scans`

Request:

```json
{
  "target_url": "http://testphp.vulnweb.com",
  "authorized": true,
  "max_depth": 2,
  "max_pages": 30,
  "max_payloads_per_param": 18,
  "delay_ms": 100,
  "include_header_scan": true,
  "allow_private_targets": false,
  "enable_spa_api_discovery": true,
  "max_js_files": 8,
  "guess_common_params": true
}
```

Response `202`:

```json
{
  "job": {
    "job_id": "uuid",
    "status": "queued"
  },
  "status_url": "/v1/scans/{job_id}"
}
```

#### 2. Poll status

`GET /v1/scans/{job_id}`

Response `200`:

```json
{
  "job": {
    "job_id": "uuid",
    "status": "running"
  },
  "poll_after_ms": 1500
}
```

Statuses: `queued`, `running`, `completed`, `failed`

#### 3. Get final result

`GET /v1/scans/{job_id}/result`

- `200`: final scan JSON
- `202`: still in progress
- `409`: job failed (error payload included)

### Option B: Sync workflow

`POST /v1/scan` returns full result directly (blocking request).

Use only for short scans or internal tooling.

## 7) Response schema (important fields)

Top-level:

- `scan_id`
- `target_url`
- `started_at`, `completed_at`, `duration_ms`
- `stats.endpoints_discovered`
- `stats.requests_sent`
- `stats.findings_count`
- `findings[]`
- `errors[]`

Per finding:

- `finding_id`
- `vulnerability_type`
- `severity`
- `score`
- `confidence`
- `url`, `method`, `parameter`
- `payload`
- `evidence`
- `recommendation`
- `references[]`

## 8) Node.js backend integration pattern

Recommended backend flow:

1. Frontend submits target URL to your backend.
2. Backend validates user/session/authorization for scan request.
3. Backend calls `POST /v1/scans`.
4. Backend stores `job_id` and returns it to frontend immediately.
5. Frontend polls backend `/scan-status/:jobId`.
6. Backend polls engine status/result and stores final report.
7. Backend serves normalized findings to frontend dashboard.

Use this example adapter as a base:

- `examples/node_client.js`

## 9) Production checklist

1. Run engine behind internal network boundary.
2. Add backend auth + tenant ownership checks before starting scans.
3. Add request rate limiting at backend and engine gateway.
4. Persist scan/job/finding data in backend database.
5. Add queue + worker layer if running many scans concurrently.
6. Add audit logs (who started scan, target, timestamps, outcome).
7. Restrict outbound egress if your security policy requires it.
