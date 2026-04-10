# Backend (FastAPI)

This folder provides HTTP APIs for audits, benchmarking, and vulnerability submissions.

## Tech Stack

- FastAPI
- Pydantic schemas
- Async SSE streaming for audit progress
- Supabase integration for shared persistence

## Folder Structure

```text
backend/
├── app/
│   ├── main.py                           # FastAPI app, CORS, router registration
│   ├── api/routes/
│   │   ├── audits.py                     # Audit create/snapshot/SSE stream
│   │   ├── benchmark.py                  # Benchmark load/run/LLM check
│   │   └── vulnerabilities.py            # Vulnerability submission endpoint
│   ├── schemas/
│   │   ├── audit.py                      # Audit request/response/event models
│   │   ├── benchmark.py                  # Benchmark request/response models
│   │   └── vulnerability_submission.py   # Submission models
│   └── services/
│       ├── audit_service.py              # Audit orchestration logic
│       ├── benchmark_service.py          # Benchmark logic
│       ├── sse_manager.py                # SSE queue/subscription manager
│       ├── audit_repository.py           # Supabase-backed audit persistence
│       └── vulnerability_submission_service.py # Supabase submission writes
└── tests/
    └── test_audits_sse.py                # SSE behavior tests
```

## Run Locally

From repository root:

```bash
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Or from `backend/` folder:

```bash
../.venv/bin/python -m uvicorn app.main:app --port 8000
```

## API Endpoints

### Health

- `GET /healthz`

### Audits

- `POST /api/v1/audits`
- `GET /api/v1/audits/{audit_id}`
- `GET /api/v1/audits/{audit_id}/stream` (SSE)

### Benchmark

- `GET /api/v1/benchmark/contracts`
- `GET /api/v1/benchmark/llm-check`
- `POST /api/v1/benchmark/run`

### Vulnerability Submissions

- `POST /api/v1/vulnerabilities/submissions`

## Environment Variables

Common variables used by backend services:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` or `SUPABASE_KEY`
- `SUPABASE_VULNERABILITY_SUBMISSIONS_TABLE` (default: `flagged_contract_submissions`)
- `DATA_BACKEND` (for parts of the project that can use local vs shared DB)

## Supabase Notes

- `vulnerability_submission_service.py` supports simplified schema writes and
  includes compatibility logic for legacy table layouts.
- Schema and migration scripts are under `supabase/` in repository root.

## Testing

From repository root:

```bash
pytest backend/tests -q
```

If your tests depend on external services, ensure required env vars are configured.
