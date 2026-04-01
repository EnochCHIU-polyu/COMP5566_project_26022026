from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.schemas.vulnerability_submission import (
    VulnerabilitySubmissionRequest,
    VulnerabilitySubmissionResponse,
)
from app.services.vulnerability_submission_service import vulnerability_submission_service

# Make project root importable when backend is run from backend/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase2_llm_engine.vulnerability_store import get_vulnerability_catalog_meta

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


@router.get("/catalog")
async def get_vulnerability_catalog() -> dict[str, object]:
    meta = get_vulnerability_catalog_meta()
    return {
        "count": meta["count"],
        "names": meta["names"],
        "source": meta["source"],
        "raw_row_count": meta.get("raw_row_count"),
        "table": meta.get("table"),
        "data_backend": meta.get("data_backend"),
    }


@router.post("/submissions", response_model=VulnerabilitySubmissionResponse)
async def submit_vulnerability(
    req: VulnerabilitySubmissionRequest,
) -> VulnerabilitySubmissionResponse:
    try:
        return vulnerability_submission_service.submit(req)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store submission: {exc}") from exc
