"""
Phase 2 Slither integration helpers.

Runs Slither as a static pre-scan and converts detector output into
compact references that can be fed to LLM prompts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def is_slither_available() -> bool:
    """Return True if the slither CLI is available in PATH."""
    return shutil.which("slither") is not None


def _extract_json_blob(text: str) -> dict[str, Any] | None:
    cleaned = (text or "").strip()
    if not cleaned:
        return None

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            return None
    return None


def _normalize_detector(det: dict[str, Any]) -> dict[str, Any]:
    lines: set[int] = set()
    for el in det.get("elements", []) or []:
        src = (el or {}).get("source_mapping", {}) or {}
        for ln in src.get("lines", []) or []:
            if isinstance(ln, int):
                lines.add(ln)

    return {
        "check": str(det.get("check", "unknown")).strip() or "unknown",
        "impact": str(det.get("impact", "Unknown")).strip() or "Unknown",
        "confidence": str(det.get("confidence", "Unknown")).strip() or "Unknown",
        "description": str(det.get("description", "")).strip(),
        "lines": sorted(lines),
    }


def run_slither_analysis(
    source_code: str,
    file_name: str = "Contract.sol",
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """
    Run Slither on source code and return normalized detector findings.

    Returns
    -------
    dict
        {
            "ok": bool,
            "error": str,
            "findings": list[dict],
            "summary": str,
            "raw": dict|None,
        }
    """
    if not source_code.strip():
        return {
            "ok": False,
            "error": "Empty source code.",
            "findings": [],
            "summary": "",
            "raw": None,
        }

    if not is_slither_available():
        return {
            "ok": False,
            "error": "Slither CLI not found in PATH. Install with `pip install slither-analyzer`.",
            "findings": [],
            "summary": "",
            "raw": None,
        }

    safe_name = Path(file_name).name or "Contract.sol"
    with tempfile.TemporaryDirectory(prefix="slither_scan_") as tmpdir:
        target = Path(tmpdir) / safe_name
        target.write_text(source_code, encoding="utf-8")

        cmd = ["slither", str(target), "--json", "-"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "error": f"Slither execution failed: {exc}",
                "findings": [],
                "summary": "",
                "raw": None,
            }

    payload = _extract_json_blob(proc.stdout) or _extract_json_blob(proc.stderr)
    if payload is None:
        err = (proc.stderr or proc.stdout or "No output from Slither").strip()
        return {
            "ok": False,
            "error": f"Slither output parse failed: {err[:600]}",
            "findings": [],
            "summary": "",
            "raw": None,
        }

    detectors = (((payload or {}).get("results") or {}).get("detectors") or [])
    findings = [_normalize_detector(d) for d in detectors if isinstance(d, dict)]

    if not findings:
        summary = "Slither found no detector alerts."
    else:
        top = findings[:5]
        summary_lines = [f"Slither findings: {len(findings)} detector alert(s)."]
        for item in top:
            line_txt = ", ".join(f"L{ln}" for ln in item.get("lines", [])[:5]) or "no lines"
            summary_lines.append(
                f"- {item['check']} | impact={item['impact']} | confidence={item['confidence']} | lines={line_txt}"
            )
        summary = "\n".join(summary_lines)

    return {
        "ok": True,
        "error": "",
        "findings": findings,
        "summary": summary,
        "raw": payload,
    }


def format_slither_reference(
    slither_result: dict[str, Any] | None,
    max_items: int = 12,
) -> str:
    """Format Slither output into compact prompt context for LLM reference."""
    if not slither_result or not slither_result.get("ok"):
        return ""

    findings = slither_result.get("findings", []) or []
    if not findings:
        return "Slither pre-scan found no detector alerts."

    lines = ["Slither pre-scan findings (may include false positives):"]
    for item in findings[: max(1, max_items)]:
        line_txt = ", ".join(f"L{ln}" for ln in (item.get("lines") or [])[:6]) or "none"
        desc = str(item.get("description", "")).replace("\n", " ").strip()
        if len(desc) > 220:
            desc = desc[:217] + "..."
        lines.append(
            f"- detector={item.get('check')} impact={item.get('impact')} confidence={item.get('confidence')} lines={line_txt} detail={desc}"
        )
    return "\n".join(lines)
