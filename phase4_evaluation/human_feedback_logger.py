"""
Phase 4 – Evaluation: Human feedback persistence.

Persists TP/FP/TN/FN verdicts from the Human-in-the-Loop UI to disk
for later use in fine-tuning, RAG, or evaluation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

FEEDBACK_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "human_feedback")
FEEDBACK_FILE = os.path.join(FEEDBACK_DIR, "feedback.jsonl")


def _contract_hash(source_code: str, length: int = 16) -> str:
    """Compute a short hash of the contract source for deduplication."""
    return hashlib.sha256(source_code.encode("utf-8")).hexdigest()[:length]


def _source_snippet(source_code: str, max_chars: int = 500) -> str:
    """Extract a truncated snippet of the source for context."""
    if not source_code:
        return ""
    return source_code[:max_chars].replace("\n", " ") + ("..." if len(source_code) > max_chars else "")


def log_feedback(
    verdict: str,
    vuln_name: str,
    llm_response: str,
    source_code: str,
    contract_name: str = "",
) -> None:
    """
    Append a single human feedback record to the feedback log.

    Parameters
    ----------
    verdict : str
        One of "TP", "FP", "TN", "FN".
    vuln_name : str
        Vulnerability type name.
    llm_response : str
        The LLM's raw response (truncated if long).
    source_code : str
        Full contract source (used for hash and snippet).
    contract_name : str, optional
        Human-readable contract identifier.
    """
    if verdict not in ("TP", "FP", "TN", "FN"):
        logger.warning("Invalid verdict '%s', skipping log", verdict)
        return

    os.makedirs(FEEDBACK_DIR, exist_ok=True)

    record = {
        "contract_hash": _contract_hash(source_code),
        "contract_name": contract_name,
        "vuln_name": vuln_name,
        "verdict": verdict,
        "llm_response": llm_response[:1000],
        "source_snippet": _source_snippet(source_code),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with open(FEEDBACK_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        logger.info("Logged feedback: %s for %s", verdict, vuln_name)
    except OSError as exc:
        logger.error("Failed to write feedback: %s", exc)


def load_feedback(limit: Optional[int] = None) -> list[dict]:
    """
    Load feedback records from the log file.

    Parameters
    ----------
    limit : int, optional
        Maximum number of records to return (most recent first).

    Returns
    -------
    list[dict]
        List of feedback records.
    """
    if not os.path.exists(FEEDBACK_FILE):
        return []

    records = []
    with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if limit:
        records = records[-limit:][::-1]
    else:
        records = records[::-1]

    return records
