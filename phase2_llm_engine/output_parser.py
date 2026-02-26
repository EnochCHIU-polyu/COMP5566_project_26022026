"""
Phase 2 – LLM Engine: Structured output parser.

Parses LLM audit responses into structured finding objects.
"""

from __future__ import annotations
import json
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CERTAINTY_MARKERS = {
    "definitely": 0.95, "certainly": 0.95, "clearly": 0.90,
    "likely": 0.75, "probably": 0.70, "possibly": 0.50,
    "might": 0.45, "could": 0.40, "unlikely": 0.25,
}


@dataclass
class Finding:
    vuln_type: str
    severity: str = "MEDIUM"
    confidence: float = 0.5
    lines: list[int] = field(default_factory=list)
    function: Optional[str] = None
    description: str = ""
    recommendation: str = ""


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0
    raw_response: str = ""


def extract_confidence(response: str) -> float:
    """Heuristically assign confidence based on language certainty markers."""
    text = response.lower()
    for marker, score in sorted(CERTAINTY_MARKERS.items(), key=lambda x: -x[1]):
        if marker in text:
            return score
    return 0.5


def parse_audit_response(raw: str) -> AuditResult:
    """
    Parse raw LLM response into AuditResult.

    Handles clean JSON, markdown-wrapped JSON, and partial/malformed JSON.
    Falls back to regex extraction.
    """
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if json_match:
        raw_json = json_match.group(1)
    else:
        raw_json = raw.strip()

    # Try direct JSON parse
    try:
        data = json.loads(raw_json)
        return _parse_json_result(data, raw)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try to find any JSON object in the response
    brace_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if brace_match:
        try:
            data = json.loads(brace_match.group(0))
            return _parse_json_result(data, raw)
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: regex extraction
    return _regex_fallback(raw)


def _parse_json_result(data: dict, raw: str) -> AuditResult:
    """Parse a dict (from JSON) into AuditResult."""
    findings = []
    for f in data.get("findings", []):
        severity = str(f.get("severity", "MEDIUM")).upper()
        if severity not in SEVERITY_LEVELS:
            severity = "MEDIUM"
        finding = Finding(
            vuln_type=str(f.get("vuln_type", "Unknown")),
            severity=severity,
            confidence=float(f.get("confidence", 0.5)),
            lines=[int(x) for x in f.get("lines", []) if isinstance(x, (int, float)) and int(x) >= 0],
            function=f.get("function"),
            description=str(f.get("description", "")),
            recommendation=str(f.get("recommendation", "")),
        )
        findings.append(finding)
    return AuditResult(
        findings=findings,
        summary=str(data.get("summary", "")),
        risk_score=float(data.get("risk_score", 0.0)),
        raw_response=raw,
    )


def _regex_fallback(raw: str) -> AuditResult:
    """Use regex to extract vulnerability mentions and line numbers."""
    findings = []
    vuln_pattern = re.compile(
        r'(?:vulnerability|vuln|issue|finding)[\s:]+([A-Za-z\s/\-]+?)(?:\s+at\s+line|\s+\(line|\n|$)',
        re.IGNORECASE,
    )
    line_pattern = re.compile(r'\bL?(?:ine\s*)?(\d+)\b')

    for match in vuln_pattern.finditer(raw):
        vuln_type = match.group(1).strip()
        if len(vuln_type) > 3:
            lines = [
                int(m.group(1))
                for m in line_pattern.finditer(raw[match.start():match.start() + 200])
            ]
            confidence = extract_confidence(raw[max(0, match.start() - 100):match.start() + 200])
            findings.append(Finding(
                vuln_type=vuln_type,
                confidence=confidence,
                lines=lines[:10],
                description=raw[match.start():match.start() + 200].strip(),
            ))

    return AuditResult(findings=findings, raw_response=raw)
