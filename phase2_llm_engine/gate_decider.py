"""
Phase 2 gate decider.

Runs a contract-level YES/NO decision after Slither pre-scan to determine whether
full detailed vulnerability auditing should continue.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from phase2_llm_engine.llm_client import query_llm


def _parse_gate_response(raw: str) -> tuple[bool | None, float, str]:
    cleaned = (raw or "").strip()
    if not cleaned:
        return None, 0.0, "Empty LLM response"

    json_match = re.search(r"\{[\s\S]*\}", cleaned)
    if json_match:
        snippet = json_match.group(0)
        try:
            parsed = json.loads(snippet)
            verdict = str(parsed.get("verdict", "")).strip().upper()
            confidence = parsed.get("confidence", 0.0)
            reason = str(parsed.get("reason", "")).strip()
            if verdict in {"YES", "NO"}:
                return verdict == "YES", float(confidence or 0.0), reason
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    first = cleaned.splitlines()[0].strip().upper()
    if first.startswith("YES"):
        return True, 0.6, "Fallback verdict parsing from first line"
    if first.startswith("NO"):
        return False, 0.6, "Fallback verdict parsing from first line"
    return None, 0.0, "Unable to parse gate verdict"


def decide_contract_gate(
    source_code: str,
    slither_result: dict[str, Any],
    model: str,
    temperature: Optional[float] = None,
) -> dict[str, Any]:
    """
    Return gate decision after Slither pre-scan.

    Output:
      {
        "has_vulnerability": bool,
        "confidence": float,
        "reason": str,
        "raw_response": str,
      }
    """
    findings = slither_result.get("findings", []) if isinstance(slither_result, dict) else []
    summary = str(slither_result.get("summary", "")) if isinstance(slither_result, dict) else ""

    system = (
        "You are a strict smart-contract triage gate. "
        "Decide if this contract likely has any real vulnerability that deserves detailed audit. "
        "Output valid JSON only."
    )
    user = (
        "Use Slither pre-scan and code context to decide a contract-level gate verdict.\n"
        "Return exactly this JSON schema:\n"
        "{\"verdict\":\"YES|NO\",\"confidence\":0.0,\"reason\":\"...\"}\n"
        "Rules:\n"
        "1) YES means likely vulnerable, continue detailed audit.\n"
        "2) NO means no clear vulnerability signal, skip detailed audit.\n"
        "3) Be conservative but avoid obvious false positives from static analysis.\n\n"
        f"Slither summary:\n{summary}\n\n"
        f"Slither findings count: {len(findings)}\n"
        f"Contract source (truncated):\n{source_code[:8000]}"
    )

    raw = query_llm(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        model=model,
        temperature=temperature,
    )

    parsed_verdict, confidence, reason = _parse_gate_response(raw)
    if parsed_verdict is None:
        high_impact_hits = 0
        for item in findings:
            impact = str(item.get("impact", "")).upper()
            if impact in {"HIGH", "CRITICAL"}:
                high_impact_hits += 1
        parsed_verdict = high_impact_hits > 0
        confidence = 0.45
        reason = "Fallback to Slither impact threshold due to unparseable gate response"

    return {
        "has_vulnerability": bool(parsed_verdict),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "reason": reason,
        "raw_response": raw,
    }
