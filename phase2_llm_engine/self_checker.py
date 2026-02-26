"""
Phase 2 – LLM Engine: Self-consistency verification pass.

Implements a two-pass audit architecture:
  Pass 1 (Detect):  Run standard audit → get candidate findings
  Pass 2 (Verify):  For each finding, use a skeptical prompt to verify
  Pass 3 (Merge):   Keep only confirmed findings above confidence threshold
"""

from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

from phase2_llm_engine.output_parser import AuditResult, Finding, parse_audit_response

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.6


@dataclass
class VerifiedFinding:
    finding: Finding
    verified: bool
    verification_confidence: float
    verification_reasoning: str


def _build_verification_prompt(finding: Finding, source_code: str) -> list[dict]:
    """Build a skeptical verification prompt for a single finding."""
    lines_str = (
        ", ".join(f"L{ln}" for ln in finding.lines) if finding.lines else "unspecified lines"
    )
    system = (
        "You are a critical security reviewer tasked with verifying audit findings. "
        "Your job is to be skeptical and only confirm genuine vulnerabilities."
    )
    user = (
        f"A security auditor claims this contract has a {finding.vuln_type} vulnerability "
        f"at {lines_str}.\n\n"
        f"The auditor's description: {finding.description}\n\n"
        f"Contract source:\n{source_code}\n\n"
        "Critically evaluate this claim. Is this a genuine vulnerability or a false positive?\n"
        'Respond with JSON: {"verified": true/false, "confidence": 0.0-1.0, "reasoning": "..."}'
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def verify_finding(
    finding: Finding,
    source_code: str,
    query_fn,
    model: Optional[str] = None,
    temperature: float = 0.0,
) -> VerifiedFinding:
    """
    Verify a single finding using a skeptical second-pass prompt.

    Parameters
    ----------
    finding : Finding
        The finding to verify.
    source_code : str
        Contract source code.
    query_fn : callable
        Function matching signature query_llm(messages, model, temperature).
    model : str, optional
        LLM model to use for verification.
    temperature : float
        Temperature for verification pass (recommend 0.0 for consistency).

    Returns
    -------
    VerifiedFinding
    """
    messages = _build_verification_prompt(finding, source_code)
    try:
        raw = query_fn(messages, model=model, temperature=temperature)
        json_match = re.search(r'\{.*?\}', raw, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            verified = bool(data.get("verified", False))
            confidence = float(data.get("confidence", 0.5))
            reasoning = str(data.get("reasoning", ""))
        else:
            verified = (
                "true" in raw.lower()
                or "genuine" in raw.lower()
                or "confirmed" in raw.lower()
            )
            confidence = 0.7 if verified else 0.3
            reasoning = raw[:200]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Verification failed for %s: %s", finding.vuln_type, exc)
        verified = True  # Don't suppress on error
        confidence = finding.confidence
        reasoning = f"Verification error: {exc}"

    return VerifiedFinding(
        finding=finding,
        verified=verified,
        verification_confidence=confidence,
        verification_reasoning=reasoning,
    )


def self_check_audit(
    initial_result: AuditResult,
    source_code: str,
    query_fn,
    model: Optional[str] = None,
    temperature: float = 0.0,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> list[VerifiedFinding]:
    """
    Run Pass 2 (verification) on all findings from Pass 1.

    Findings below the confidence threshold are demoted to INFO severity.

    Parameters
    ----------
    initial_result : AuditResult
        Output from Pass 1 (detect phase).
    source_code : str
        Contract source code.
    query_fn : callable
        LLM query function.
    model : str, optional
        Model for verification pass.
    temperature : float
        Temperature for verification.
    confidence_threshold : float
        Minimum confidence to keep a finding at its original severity.

    Returns
    -------
    list[VerifiedFinding]
    """
    verified_findings = []
    for finding in initial_result.findings:
        vf = verify_finding(finding, source_code, query_fn, model, temperature)
        if not vf.verified or vf.verification_confidence < confidence_threshold:
            finding.severity = "INFO"
            finding.confidence = vf.verification_confidence
        verified_findings.append(vf)

    confirmed = sum(1 for vf in verified_findings if vf.verified)
    logger.info(
        "Self-check: %d/%d findings verified (threshold=%.2f)",
        confirmed, len(verified_findings), confidence_threshold,
    )
    return verified_findings
