from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.vulnerability_submission import (
    VulnerabilitySubmissionRequest,
    VulnerabilitySubmissionResponse,
)
from app.services.vulnerability_submission_service import vulnerability_submission_service

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


@router.post("/submissions", response_model=VulnerabilitySubmissionResponse)
async def submit_vulnerability(
    req: VulnerabilitySubmissionRequest,
) -> VulnerabilitySubmissionResponse:
    try:
        return vulnerability_submission_service.submit(req)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store submission: {exc}") from exc
