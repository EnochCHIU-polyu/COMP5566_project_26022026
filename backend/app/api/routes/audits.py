from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.schemas.audit import (
    AuditCreateRequest,
    AuditCreateResponse,
    AuditFeedbackRequest,
    AuditSnapshot,
)
from app.services.audit_service import audit_service
from app.services.sse_manager import sse_manager

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _load_runtime_metrics(limit: int = 100) -> dict:
    metrics_path = Path(
        os.getenv("RUNTIME_AUDIT_METRICS_FILE", "data/runtime_metrics/audit_metrics.jsonl")
    )
    feedback_path = Path(
        os.getenv("RUNTIME_AUDIT_FEEDBACK_FILE", "data/runtime_metrics/audit_feedback.jsonl")
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
                "feedback_true_count": 0,
                "feedback_response_count": 0,
                "feedback_true_rate": None,
            },
            "records": [],
            "source": str(metrics_path),
            "feedback_source": str(feedback_path),
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
                "feedback_true_count": 0,
                "feedback_response_count": 0,
                "feedback_true_rate": None,
            },
            "records": [],
            "source": str(metrics_path),
            "feedback_source": str(feedback_path),
        }

    feedback_state_by_audit: dict[str, dict[str, bool]] = {}
    if feedback_path.exists():
        try:
            with feedback_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    aid = str(obj.get("audit_id", "")).strip()
                    if not aid:
                        continue
                    vuln_name = str(obj.get("vuln_name", "")).strip()
                    if not vuln_name:
                        continue
                    bucket = feedback_state_by_audit.setdefault(aid, {})
                    if bool(obj.get("clear", False)):
                        bucket.pop(vuln_name, None)
                        continue
                    bucket[vuln_name] = bool(obj.get("is_true", False))
        except OSError:
            feedback_state_by_audit = {}

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

    feedback_true_count = 0
    feedback_response_count = 0
    for rec in records:
        aid = str(rec.get("audit_id", "")).strip()
        state = feedback_state_by_audit.get(aid, {})
        t_cnt = int(sum(1 for v in state.values() if v))
        r_cnt = int(len(state))
        rec["feedback_true_count"] = t_cnt
        rec["feedback_response_count"] = r_cnt
        rec["feedback_true_rate"] = (round(t_cnt / r_cnt, 4) if r_cnt > 0 else None)
        feedback_true_count += t_cnt
        feedback_response_count += r_cnt

    feedback_true_rate = (
        round(feedback_true_count / feedback_response_count, 4)
        if feedback_response_count > 0
        else None
    )

    return {
        "summary": {
            "total_runs": total,
            "completed_runs": len(completed),
            "failed_runs": len(failed),
            "avg_duration_seconds": _avg(durations),
            "avg_risk_score": _avg(risks),
            "total_other_findings": int(sum(other_counts)),
            "avg_other_findings_per_completed_run": _avg([float(x) for x in other_counts]),
            "feedback_true_count": feedback_true_count,
            "feedback_response_count": feedback_response_count,
            "feedback_true_rate": feedback_true_rate,
        },
        "records": recent,
        "source": str(metrics_path),
        "feedback_source": str(feedback_path),
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


@router.post("/{audit_id}/feedback")
async def submit_audit_feedback(audit_id: str, req: AuditFeedbackRequest) -> dict:
    feedback_path = Path(
        os.getenv("RUNTIME_AUDIT_FEEDBACK_FILE", "data/runtime_metrics/audit_feedback.jsonl")
    )
    feedback_path.parent.mkdir(parents=True, exist_ok=True)

    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "audit_id": audit_id,
        "vuln_name": req.vuln_name,
        "is_true": bool(req.is_true),
    }
    try:
        with feedback_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to persist feedback: {exc}") from exc

    return {"ok": True}


@router.delete("/{audit_id}/feedback")
async def clear_audit_feedback(audit_id: str, vuln_name: str = Query(min_length=1, max_length=200)) -> dict:
    feedback_path = Path(
        os.getenv("RUNTIME_AUDIT_FEEDBACK_FILE", "data/runtime_metrics/audit_feedback.jsonl")
    )
    feedback_path.parent.mkdir(parents=True, exist_ok=True)

    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "audit_id": audit_id,
        "vuln_name": vuln_name,
        "clear": True,
    }
    try:
        with feedback_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to clear feedback: {exc}") from exc

    return {"ok": True}
