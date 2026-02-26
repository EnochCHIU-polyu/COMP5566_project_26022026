"""
Phase 2 – LLM Engine: Chain-of-Thought analyzer.

Implements the CoT looping script that:
1. Extracts all function names from a contract.
2. Queries the LLM to review each function individually.
3. Also iterates through all 38 vulnerability types, injecting definitions.
"""

from __future__ import annotations

import logging
from typing import Optional, Callable

from phase2_llm_engine.prompt_builder import (
    build_prompt,
    build_cot_function_prompt,
    build_multi_vuln_prompt,
    extract_function_names,
)
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
from phase2_llm_engine.llm_client import query_llm
from config import CLASSIFICATION_MODE

logger = logging.getLogger(__name__)


def _build_structured_result(vuln_results: list[dict], function_results: list[dict]) -> dict:
    """Convert raw vuln/function results into a structured summary dict."""
    findings = []
    for vr in vuln_results:
        response = vr.get("response", "")
        is_vuln = (
            response.strip().upper().startswith("YES")
            or "YES" in response[:20].upper()
        )
        if is_vuln:
            findings.append({
                "vuln_type": vr["vuln_name"],
                "severity": "HIGH",
                "confidence": 0.7,
                "description": response[:200].strip(),
            })
    return {"findings": findings}


def analyze_contract(
    source_code: str,
    contract_name: str = "Unknown",
    mode: Optional[str] = None,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    verify: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> dict:
    """
    Run a full audit of *source_code* using all 38 vulnerability types and
    a Chain-of-Thought pass over every function.

    Parameters
    ----------
    source_code : str
        Pre-processed Solidity source.
    contract_name : str
        Human-readable name for logging / report.
    mode : str, optional
        Classification mode: ``"binary"``, ``"non_binary"``, ``"cot"``,
        or ``"multi_vuln"``.  Defaults to the value in config.
    model : str, optional
        LLM model to use.
    temperature : float, optional
        Temperature override.
    verify : bool
        If True, run a self-check verification pass on findings and add
        a ``"verified_findings"`` key to the result.
    progress_callback : callable, optional
        Called as ``callback(current, total, message)`` after each LLM call.

    Returns
    -------
    dict
        ``{
            "contract_name": str,
            "vuln_results": [{"vuln_name": str, "response": str}, ...],
            "function_results": [{"function_name": str, "response": str}, ...],
        }``
        When ``verify=True``, also includes ``"verified_findings"`` key.
    """
    effective_mode = mode or CLASSIFICATION_MODE
    logger.info("Auditing '%s' | mode=%s | model=%s", contract_name, effective_mode, model)

    # ── multi_vuln mode: single call for all vulns ────────────────────────
    if effective_mode == "multi_vuln":
        messages = build_multi_vuln_prompt(source_code, VULNERABILITY_TYPES)
        response = query_llm(messages, model=model, temperature=temperature)
        if progress_callback:
            progress_callback(1, 1, "multi_vuln batch complete")
        result = {
            "contract_name": contract_name,
            "vuln_results": [{"vuln_name": "multi_vuln", "response": response}],
            "function_results": [],
        }
        if verify:
            result["verified_findings"] = []
        return result

    # ── Phase A: iterate over all 38 vulnerability types ─────────────────────
    vuln_results = []
    total_vulns = len(VULNERABILITY_TYPES)
    for idx, vuln in enumerate(VULNERABILITY_TYPES):
        logger.debug("  Checking vulnerability: %s", vuln["name"])
        messages = build_prompt(
            source_code=source_code,
            vuln_name=vuln["name"],
            vuln_description=vuln["description"],
            mode=effective_mode,
        )
        response = query_llm(messages, model=model, temperature=temperature)
        vuln_results.append({"vuln_name": vuln["name"], "response": response})
        if progress_callback:
            progress_callback(idx + 1, total_vulns, vuln["name"])

    # ── Phase B: Chain-of-Thought per function ────────────────────────────────
    function_names = extract_function_names(source_code)
    function_results = []
    for fn_name in function_names:
        logger.debug("  CoT review of function: %s()", fn_name)
        messages = build_cot_function_prompt(source_code, fn_name)
        response = query_llm(messages, model=model, temperature=temperature)
        function_results.append({"function_name": fn_name, "response": response})

    result = {
        "contract_name": contract_name,
        "vuln_results": vuln_results,
        "function_results": function_results,
    }

    # ── Phase C (optional): self-check verification ───────────────────────────
    if verify:
        try:
            from phase2_llm_engine.output_parser import AuditResult, Finding, parse_audit_response
            from phase2_llm_engine.self_checker import self_check_audit

            # Build a minimal AuditResult from vuln_results
            findings = []
            for vr in vuln_results:
                response = vr.get("response", "")
                is_vuln = (
                    response.strip().upper().startswith("YES")
                    or "YES" in response[:20].upper()
                )
                if is_vuln:
                    findings.append(Finding(
                        vuln_type=vr["vuln_name"],
                        description=response[:200],
                    ))
            initial = AuditResult(findings=findings, raw_response="")
            verified = self_check_audit(
                initial, source_code, query_llm, model=model, temperature=temperature or 0.0
            )
            result["verified_findings"] = [
                {
                    "vuln_type": vf.finding.vuln_type,
                    "verified": vf.verified,
                    "confidence": vf.verification_confidence,
                    "reasoning": vf.verification_reasoning,
                }
                for vf in verified
            ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Self-check verification failed: %s", exc)
            result["verified_findings"] = []

    return result
