from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.schemas.audit import AuditCreateRequest, AuditCreateResponse, AuditSnapshot
from app.services.audit_service import audit_service
from app.services.sse_manager import sse_manager

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


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
