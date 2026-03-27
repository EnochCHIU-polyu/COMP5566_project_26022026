from __future__ import annotations

import logging
import os
from typing import Any

from app.schemas.audit import AuditEvent, AuditSnapshot

logger = logging.getLogger(__name__)


class AuditRepository:
    """Supabase-backed persistence for audit runs and events."""

    def __init__(self) -> None:
        self._enabled = os.getenv("DATA_BACKEND", "supabase").strip().lower() == "supabase"
        self._url = os.getenv("SUPABASE_URL", "")
        self._key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "") or os.getenv("SUPABASE_KEY", "")
        self._runs_table = os.getenv("SUPABASE_AUDITS_TABLE", "audit_runs")
        self._events_table = os.getenv("SUPABASE_AUDIT_EVENTS_TABLE", "audit_events")
        self._client = None

        if not self._enabled:
            return
        if not self._url or not self._key:
            logger.warning("Supabase audit repository disabled: missing URL/key")
            self._enabled = False
            return

        try:
            from supabase import create_client

            self._client = create_client(self._url, self._key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Supabase audit repository init failed: %s", exc)
            self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled and self._client is not None

    def upsert_run(
        self,
        audit_id: str,
        status: str,
        stage: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        try:
            payload = {
                "id": audit_id,
                "status": status,
                "stage": stage,
                "metadata": metadata or {},
            }
            self._client.table(self._runs_table).upsert(payload).execute()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Supabase upsert_run failed for %s: %s", audit_id, exc)

    def insert_event(self, event: AuditEvent) -> None:
        if not self.enabled:
            return
        try:
            payload = {
                "audit_id": event.audit_id,
                "event": event.event,
                "stage": event.stage,
                "seq": event.seq,
                "ts": event.ts.isoformat(),
                "payload": event.payload,
            }
            self._client.table(self._events_table).insert(payload).execute()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Supabase insert_event failed for %s: %s", event.audit_id, exc)

    def load_snapshot(self, audit_id: str) -> AuditSnapshot | None:
        if not self.enabled:
            return None

        try:
            run_resp = (
                self._client.table(self._runs_table)
                .select("id,status,stage")
                .eq("id", audit_id)
                .limit(1)
                .execute()
            )
            run_rows = getattr(run_resp, "data", None) or []
            if not run_rows:
                return None
            run_row = run_rows[0]

            event_resp = (
                self._client.table(self._events_table)
                .select("audit_id,event,stage,seq,ts,payload")
                .eq("audit_id", audit_id)
                .order("seq")
                .execute()
            )
            event_rows = getattr(event_resp, "data", None) or []
            events = [AuditEvent.model_validate(row) for row in event_rows]

            return AuditSnapshot(
                audit_id=audit_id,
                stage=run_row.get("stage", "queued"),
                status=run_row.get("status", "queued"),
                events=events,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Supabase load_snapshot failed for %s: %s", audit_id, exc)
            return None


audit_repository = AuditRepository()
