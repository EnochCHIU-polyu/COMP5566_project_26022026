"""
Phase 2 – LLM Engine: Chain-of-Thought analyzer.

Implements the CoT looping script that:
1. Extracts all function names from a contract.
2. Queries the LLM to review each function individually.
3. Also iterates through all 38 vulnerability types, injecting definitions.
"""

from __future__ import annotations

import logging
from typing import Optional

from phase2_llm_engine.prompt_builder import (
    build_prompt,
    build_cot_function_prompt,
    extract_function_names,
)
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
from phase2_llm_engine.llm_client import query_llm
from config import CLASSIFICATION_MODE

logger = logging.getLogger(__name__)


def analyze_contract(
    source_code: str,
    contract_name: str = "Unknown",
    mode: Optional[str] = None,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
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
        Classification mode: ``"binary"``, ``"non_binary"``, or ``"cot"``.
        Defaults to the value in config.
    model : str, optional
        LLM model to use.
    temperature : float, optional
        Temperature override.

    Returns
    -------
    dict
        ``{
            "contract_name": str,
            "vuln_results": [{"vuln_name": str, "response": str}, ...],
            "function_results": [{"function_name": str, "response": str}, ...],
        }``
    """
    effective_mode = mode or CLASSIFICATION_MODE
    logger.info("Auditing '%s' | mode=%s | model=%s", contract_name, effective_mode, model)

    # ── Phase A: iterate over all 38 vulnerability types ─────────────────────
    vuln_results = []
    for vuln in VULNERABILITY_TYPES:
        logger.debug("  Checking vulnerability: %s", vuln["name"])
        messages = build_prompt(
            source_code=source_code,
            vuln_name=vuln["name"],
            vuln_description=vuln["description"],
            mode=effective_mode,
        )
        response = query_llm(messages, model=model, temperature=temperature)
        vuln_results.append({"vuln_name": vuln["name"], "response": response})

    # ── Phase B: Chain-of-Thought per function ────────────────────────────────
    function_names = extract_function_names(source_code)
    function_results = []
    for fn_name in function_names:
        logger.debug("  CoT review of function: %s()", fn_name)
        messages = build_cot_function_prompt(source_code, fn_name)
        response = query_llm(messages, model=model, temperature=temperature)
        function_results.append({"function_name": fn_name, "response": response})

    return {
        "contract_name": contract_name,
        "vuln_results": vuln_results,
        "function_results": function_results,
    }
