from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


AuditStage = Literal["queued", "slither", "llm", "completed", "failed"]
AuditEventType = Literal[
    "audit_started",
    "slither_progress",
    "slither_result",
    "llm_progress",
    "llm_chunk",
    "audit_completed",
    "audit_failed",
    "ping",
]


class AuditCreateRequest(BaseModel):
    contract_name: str = Field(min_length=1, max_length=200)
    source_code: str = Field(min_length=1)
    model: str = "deepseek-v3.2"
    mode: str = "non_binary"
    pipeline: str = "standard"
    temperature: float = 0.0
    batch_size: int = 8


class AuditCreateResponse(BaseModel):
    audit_id: str
    status: str


class AuditEvent(BaseModel):
    audit_id: str
    event: AuditEventType
    stage: AuditStage
    seq: int
    ts: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class AuditSnapshot(BaseModel):
    audit_id: str
    stage: AuditStage
    status: str
    events: list[AuditEvent] = Field(default_factory=list)
