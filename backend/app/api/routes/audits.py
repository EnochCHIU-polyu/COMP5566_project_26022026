from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.schemas.audit import AuditCreateRequest, AuditCreateResponse, AuditSnapshot
from app.services.audit_service import audit_service
from app.services.sse_manager import sse_manager

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _load_runtime_metrics(limit: int = 100) -> dict:
    metrics_path = Path(
        os.getenv("RUNTIME_AUDIT_METRICS_FILE", "data/runtime_metrics/audit_metrics.jsonl")
    )
    if not metrics_path.exists():
        return {
            "summary": {
                "total_runs": 0,
                "completed_runs": 0,
                "failed_runs": 0,
                "avg_duration_seconds": 0.0,
                "avg_risk_score": 0.0,
                "total_other_findings": 0,
                "avg_other_findings_per_completed_run": 0.0,
            },
            "records": [],
            "source": str(metrics_path),
        }

    records: list[dict] = []
    try:
        with metrics_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return {
            "summary": {
                "total_runs": 0,
                "completed_runs": 0,
                "failed_runs": 0,
                "avg_duration_seconds": 0.0,
                "avg_risk_score": 0.0,
                "total_other_findings": 0,
                "avg_other_findings_per_completed_run": 0.0,
            },
            "records": [],
            "source": str(metrics_path),
        }

    total = len(records)
    completed = [r for r in records if str(r.get("status", "")).lower() == "completed"]
    failed = [r for r in records if str(r.get("status", "")).lower() == "failed"]

    def _avg(nums: list[float]) -> float:
        if not nums:
            return 0.0
        return round(sum(nums) / len(nums), 3)

    durations = [float(r.get("duration_seconds", 0.0) or 0.0) for r in completed]
    risks = [float(r.get("risk_score", 0.0) or 0.0) for r in completed]
    other_counts = [max(0, int(r.get("other_count", 0) or 0)) for r in completed]

    recent = records[-max(1, limit) :]
    recent.reverse()
    return {
        "summary": {
            "total_runs": total,
            "completed_runs": len(completed),
            "failed_runs": len(failed),
            "avg_duration_seconds": _avg(durations),
            "avg_risk_score": _avg(risks),
            "total_other_findings": int(sum(other_counts)),
            "avg_other_findings_per_completed_run": _avg([float(x) for x in other_counts]),
        },
        "records": recent,
        "source": str(metrics_path),
    }


@router.post("", response_model=AuditCreateResponse)
async def create_audit(req: AuditCreateRequest) -> AuditCreateResponse:
    audit_id = str(uuid.uuid4())
    sse_manager.create_audit(audit_id)
    asyncio.create_task(audit_service.run_audit(audit_id, req))
    return AuditCreateResponse(audit_id=audit_id, status="queued")


@router.get("/{audit_id}", response_model=AuditSnapshot)
async def get_audit_snapshot(audit_id: str) -> AuditSnapshot:
    if not sse_manager.exists(audit_id):
        raise HTTPException(status_code=404, detail="Audit not found")
    snap = sse_manager.snapshot(audit_id)
    return snap


@router.get("/{audit_id}/stream")
async def stream_audit_events(audit_id: str) -> StreamingResponse:
    if not sse_manager.exists(audit_id):
        raise HTTPException(status_code=404, detail="Audit not found")

    queue = await sse_manager.subscribe(audit_id)

    async def event_stream():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield _sse_format(event.event, event.model_dump(mode="json"))
                    if event.event in {"audit_completed", "audit_failed"}:
                        break
                except asyncio.TimeoutError:
                    heartbeat = {
                        "audit_id": audit_id,
                        "event": "ping",
                        "stage": "queued",
                        "seq": -1,
                        "payload": {},
                    }
                    yield _sse_format("ping", heartbeat)
        finally:
            await sse_manager.unsubscribe(audit_id, queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/metrics/runtime")
async def get_runtime_metrics(limit: int = 100) -> dict:
    return _load_runtime_metrics(limit=limit)
