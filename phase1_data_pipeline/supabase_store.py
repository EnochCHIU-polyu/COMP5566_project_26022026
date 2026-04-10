"""
Shared Supabase storage helpers for datasets and user submissions.

All functions are optional-safe: if Supabase is not configured, callers can
fallback to local filesystem data without raising hard failures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Optional

from config import (
    SUPABASE_CONTRACTS_TABLE,
    SUPABASE_KEY,
    SUPABASE_SUBMISSIONS_TABLE,
    SUPABASE_URL,
)


def is_supabase_enabled() -> bool:
    """Return True when URL and key are present."""
    return bool(SUPABASE_URL and SUPABASE_KEY)


@lru_cache(maxsize=1)
def _get_client():
    """Build a cached Supabase client lazily."""
    if not is_supabase_enabled():
        return None

    try:
        from supabase import create_client

        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception:
        return None


def fetch_contracts(source: Optional[str] = None, limit: Optional[int] = None) -> list[dict[str, Any]]:
    """
    Fetch contracts from Supabase contracts table.

    Expected table columns:
    - name (text)
    - source_code (text)
    - labels (json/jsonb)
    - source (text)
    """
    client = _get_client()
    if client is None:
        return []

    query = client.table(SUPABASE_CONTRACTS_TABLE).select("name,source_code,labels,source")
    if source:
        query = query.eq("source", source)
    if limit:
        query = query.limit(int(limit))

    try:
        response = query.execute()
    except Exception:
        return []

    rows = getattr(response, "data", None) or []
    contracts = []
    for row in rows:
        contracts.append(
            {
                "name": row.get("name", ""),
                "source_code": row.get("source_code", "") or "",
                "labels": row.get("labels", []) or [],
            }
        )
    return contracts


def create_flagged_submission(payload: dict[str, Any]) -> bool:
    """Insert a user-flagged contract submission into Supabase."""
    client = _get_client()
    if client is None:
        return False

    data = {
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }

    try:
        client.table(SUPABASE_SUBMISSIONS_TABLE).insert(data).execute()
        return True
    except Exception:
        return False


def list_pending_submissions(limit: int = 50) -> list[dict[str, Any]]:
    """Return pending submissions for reviewer moderation UI."""
    client = _get_client()
    if client is None:
        return []

    try:
        response = (
            client.table(SUPABASE_SUBMISSIONS_TABLE)
            .select("id,created_at,reporter_name,reporter_email,contract_name,suspected_vulnerability,status")
            .eq("status", "pending")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
    except Exception:
        return []

    return getattr(response, "data", None) or []


def get_submission(submission_id: str) -> dict[str, Any] | None:
    """Fetch one flagged submission by id."""
    client = _get_client()
    if client is None:
        return None

    try:
        response = (
            client.table(SUPABASE_SUBMISSIONS_TABLE)
            .select("*")
            .eq("id", submission_id)
            .limit(1)
            .execute()
        )
    except Exception:
        return None

    rows = getattr(response, "data", None) or []
    return rows[0] if rows else None


def set_submission_status(submission_id: str, status: str, reviewer_notes: str = "") -> bool:
    """Update moderation status for a submission."""
    client = _get_client()
    if client is None:
        return False

    if status not in {"pending", "under_review", "approved", "rejected", "needs_info"}:
        return False

    payload = {
        "status": status,
        "reviewer_notes": reviewer_notes.strip() or None,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        (
            client.table(SUPABASE_SUBMISSIONS_TABLE)
            .update(payload)
            .eq("id", submission_id)
            .execute()
        )
        return True
    except Exception:
        return False


def publish_submission_to_contracts(submission_id: str) -> bool:
    """
    Publish an approved submission into the shared contracts table.

    The inserted contract uses source='vulnerable' and split='community'.
    """
    client = _get_client()
    if client is None:
        return False

    row = get_submission(submission_id)
    if not row:
        return False

    suspected = row.get("suspected_vulnerability", [])
    labels = []
    if isinstance(suspected, list):
        for vuln_name in suspected:
            if isinstance(vuln_name, str) and vuln_name.strip():
                labels.append(
                    {
                        "vuln_type": vuln_name.strip(),
                        "swc_id": None,
                        "severity": row.get("severity_claim", "medium"),
                        "lines": [],
                        "function": None,
                        "description": "Community-flagged and moderator-approved submission",
                    }
                )

    contract_payload = {
        "name": row.get("contract_name", "Unnamed Submission"),
        "source_code": row.get("source_code", ""),
        "labels": labels,
        "source": "vulnerable",
        "split": "community",
        "compiler_version": "unknown",
    }

    try:
        client.table(SUPABASE_CONTRACTS_TABLE).insert(contract_payload).execute()
        return True
    except Exception:
        return False
