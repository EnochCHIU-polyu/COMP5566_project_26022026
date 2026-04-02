from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.schemas.audit import AuditEvent, AuditSnapshot
from app.services.audit_repository import audit_repository


@dataclass
class AuditState:
    stage: str = "queued"
    status: str = "queued"
    seq: int = 0
    events: List[AuditEvent] = field(default_factory=list)


class SSEManager:
    def __init__(self) -> None:
        self._queues: Dict[str, List[asyncio.Queue[AuditEvent]]] = defaultdict(list)
        self._state: Dict[str, AuditState] = defaultdict(AuditState)
        self._known_ids: set[str] = set()

    def create_audit(self, audit_id: str) -> None:
        _ = self._state[audit_id]
        self._known_ids.add(audit_id)
        audit_repository.upsert_run(
            audit_id=audit_id,
            status="queued",
            stage="queued",
            metadata={},
        )

    def exists(self, audit_id: str) -> bool:
        if audit_id in self._known_ids:
            return True
        if audit_repository.enabled:
            snap = audit_repository.load_snapshot(audit_id)
            return snap is not None
        return False

    async def subscribe(self, audit_id: str) -> asyncio.Queue[AuditEvent]:
        queue: asyncio.Queue[AuditEvent] = asyncio.Queue()
        self._queues[audit_id].append(queue)
        return queue

    async def unsubscribe(self, audit_id: str, queue: asyncio.Queue[AuditEvent]) -> None:
        if audit_id in self._queues and queue in self._queues[audit_id]:
            self._queues[audit_id].remove(queue)

    async def publish(
        self,
        audit_id: str,
        event: str,
        stage: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        state = self._state[audit_id]
        state.seq += 1
        entry = AuditEvent(
            audit_id=audit_id,
            event=event,  # type: ignore[arg-type]
            stage=stage,  # type: ignore[arg-type]
            seq=state.seq,
            ts=datetime.now(timezone.utc),
            payload=payload or {},
        )

        state.stage = stage
        state.status = "completed" if event == "audit_completed" else state.status
        if event == "audit_failed":
            state.status = "failed"
        elif state.status not in {"completed", "failed"}:
            state.status = "running"

        state.events.append(entry)

        audit_repository.insert_event(entry)
        audit_repository.upsert_run(
            audit_id=audit_id,
            status=state.status,
            stage=state.stage,
            metadata={},
        )

        for queue in self._queues.get(audit_id, []):
            await queue.put(entry)

        return entry

    def snapshot(self, audit_id: str) -> AuditSnapshot:
        db_snapshot = audit_repository.load_snapshot(audit_id)
        if db_snapshot is not None:
            return db_snapshot

        state = self._state[audit_id]
        return AuditSnapshot(
            audit_id=audit_id,
            stage=state.stage,  # type: ignore[arg-type]
            status=state.status,
            events=list(state.events),
        )


sse_manager = SSEManager()
