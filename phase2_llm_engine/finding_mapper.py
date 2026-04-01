"""
Phase 2 finding mapper.

Maps Slither findings to vulnerability catalog entries loaded from Supabase/local
with an OTHER fallback for unmapped findings.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from phase2_llm_engine.llm_client import query_llm


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _keyword_score(finding_text: str, vuln: dict[str, Any]) -> float:
    score = 0.0
    keys = vuln.get("detection_keywords", []) or []
    for kw in keys:
        k = _norm(str(kw))
        if k and k in finding_text:
            score += 1.0

    vuln_name = _norm(str(vuln.get("name", "")))
    for token in vuln_name.split():
        if token and token in finding_text:
            score += 0.4

    desc_tokens = _norm(str(vuln.get("description", ""))).split()[:20]
    for token in desc_tokens:
        if len(token) >= 6 and token in finding_text:
            score += 0.1

    return score


def _llm_judge_map(
    finding: dict[str, Any],
    vuln_names: list[str],
    model: str,
    temperature: float,
) -> tuple[str, float, str]:
    choices = "\n".join(f"- {n}" for n in vuln_names)
    system = "You map security findings to one known vulnerability type or OTHER. Output JSON only."
    user = (
        "Map this finding to one type from the catalog list or OTHER.\n"
        "Return JSON schema: {\"vuln_type\":\"<name|OTHER>\",\"confidence\":0.0,\"reason\":\"...\"}\n\n"
        f"Catalog names:\n{choices}\n\n"
        f"Finding check: {finding.get('check', '')}\n"
        f"Impact: {finding.get('impact', '')}\n"
        f"Confidence: {finding.get('confidence', '')}\n"
        f"Description: {finding.get('detail', '')}\n"
    )
    raw = query_llm(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        model=model,
        temperature=temperature,
    )

    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        return "OTHER", 0.35, "LLM mapping parse failed"

    try:
        data = json.loads(m.group(0))
        name = str(data.get("vuln_type", "OTHER")).strip()
        conf = float(data.get("confidence", 0.35) or 0.35)
        reason = str(data.get("reason", "")).strip()
        if name != "OTHER" and name not in vuln_names:
            return "OTHER", 0.35, "LLM mapped to unknown type"
        return name, max(0.0, min(1.0, conf)), reason
    except (json.JSONDecodeError, ValueError, TypeError):
        return "OTHER", 0.35, "LLM mapping parse failed"


def map_findings_to_catalog(
    slither_hits: list[dict[str, Any]],
    vuln_catalog: list[dict[str, Any]],
    model: Optional[str] = None,
    temperature: float = 0.0,
    use_llm_judge: bool = False,
) -> dict[str, Any]:
    """
    Map Slither findings to vulnerability catalog entries.

    Returns dict containing mapped findings and OTHER candidates.
    """
    vuln_names = [str(v.get("name", "")).strip() for v in vuln_catalog if str(v.get("name", "")).strip()]
    mapped: list[dict[str, Any]] = []
    other_candidates: list[dict[str, Any]] = []

    for hit in slither_hits:
        finding_text = _norm(
            f"{hit.get('check', '')} {hit.get('impact', '')} {hit.get('detail', '')}"
        )
        best_name = "OTHER"
        best_score = 0.0

        for vuln in vuln_catalog:
            name = str(vuln.get("name", "")).strip()
            if not name:
                continue
            score = _keyword_score(finding_text, vuln)
            if score > best_score:
                best_score = score
                best_name = name

        confidence = min(0.95, 0.30 + best_score * 0.15)
        reason = "Keyword-based mapping"

        if best_score < 1.0:
            best_name = "OTHER"
            confidence = 0.35
            reason = "No strong keyword match"

        if use_llm_judge and model:
            judged_name, judged_conf, judged_reason = _llm_judge_map(
                finding=hit,
                vuln_names=vuln_names,
                model=model,
                temperature=temperature,
            )
            if judged_name == "OTHER" or judged_conf >= confidence:
                best_name = judged_name
                confidence = judged_conf
                reason = judged_reason or reason

        item = {
            "slither_check": str(hit.get("check", "unknown")),
            "impact": str(hit.get("impact", "Unknown")),
            "lines": hit.get("lines", []),
            "detail": str(hit.get("detail", "")),
            "vuln_type": best_name,
            "confidence": round(confidence, 3),
            "reason": reason,
        }
        mapped.append(item)

        if best_name == "OTHER":
            other_candidates.append(item)

    return {
        "mapped": mapped,
        "other_candidates": other_candidates,
    }


def discover_vulnerability_types_with_llm(
    source_code: str,
    slither_reference: str,
    gate_reason: str,
    vuln_catalog: list[dict[str, Any]],
    model: str,
    temperature: float = 0.0,
) -> dict[str, Any]:
    """
    Discover vulnerability types directly from contract+context against DB names.

    Returns:
    {
      "matched_db_types": list[str],
      "other_findings": [{"name": str, "description": str, "confidence": float}],
      "raw_response": str,
    }
    """
    vuln_names = [
        str(v.get("name", "")).strip()
        for v in vuln_catalog
        if str(v.get("name", "")).strip()
    ]
    catalog_txt = "\n".join(f"- {n}" for n in vuln_names)

    system = (
        "You are a smart-contract vulnerability type classifier. "
        "Map findings to the exact provided DB type names when possible, and use OTHER only if no DB type matches. "
        "Output valid JSON only."
    )
    user = (
        "Classify vulnerability types for this contract using the provided DB type names.\n"
        "Return JSON schema exactly:\n"
        "{\"matched_db_types\":[\"<name>\"],\"other_findings\":[{\"name\":\"...\",\"description\":\"...\",\"confidence\":0.0}],\"reason\":\"...\"}\n"
        "Rules:\n"
        "1) matched_db_types must use exact names from DB list.\n"
        "2) Put in other_findings only when no DB type can represent it.\n"
        "3) Prefer precision over recall; do not guess unrelated types.\n"
        "4) Return empty arrays if none.\n\n"
        f"DB vulnerability type names:\n{catalog_txt}\n\n"
        f"Gate reasoning:\n{gate_reason}\n\n"
        f"Slither reference:\n{slither_reference}\n\n"
        f"Source code:\n{source_code[:12000]}"
    )

    raw = query_llm(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        model=model,
        temperature=temperature,
    )

    matched_db_types: list[str] = []
    other_findings: list[dict[str, Any]] = []

    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            payload = json.loads(m.group(0))
            for n in payload.get("matched_db_types", []) or []:
                name = str(n).strip()
                if name in vuln_names and name not in matched_db_types:
                    matched_db_types.append(name)

            for item in payload.get("other_findings", []) or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "OTHER")).strip() or "OTHER"
                desc = str(item.get("description", "")).strip()
                conf = float(item.get("confidence", 0.4) or 0.4)
                other_findings.append(
                    {
                        "name": name,
                        "description": desc,
                        "confidence": max(0.0, min(1.0, conf)),
                    }
                )
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    return {
        "matched_db_types": matched_db_types,
        "other_findings": other_findings,
        "raw_response": raw,
    }


def shortlist_vulnerability_types(
    mapped: list[dict[str, Any]],
    vuln_catalog: list[dict[str, Any]],
    min_types: int = 3,
    max_types: int = 6,
) -> list[dict[str, Any]]:
    """
    Pick top mapped vulnerability types for detailed audit.
    """
    min_types = max(1, min_types)
    max_types = max(min_types, max_types)

    agg: dict[str, float] = {}
    for item in mapped:
        name = str(item.get("vuln_type", "OTHER")).strip()
        if not name or name == "OTHER":
            continue
        conf = float(item.get("confidence", 0.0) or 0.0)
        impact = str(item.get("impact", "")).upper()
        impact_boost = 0.3 if impact == "HIGH" else 0.15 if impact == "MEDIUM" else 0.0
        agg[name] = agg.get(name, 0.0) + conf + impact_boost

    ranked = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)
    selected_names = [name for name, _ in ranked[:max_types]]

    if len(selected_names) < min_types:
        high_priority = []
        for vuln in vuln_catalog:
            sev = str(vuln.get("severity_default", "")).lower()
            if sev in {"critical", "high"}:
                high_priority.append(str(vuln.get("name", "")).strip())
        for name in high_priority:
            if name and name not in selected_names:
                selected_names.append(name)
            if len(selected_names) >= min_types:
                break

    catalog_by_name = {
        str(v.get("name", "")).strip(): v
        for v in vuln_catalog
        if str(v.get("name", "")).strip()
    }
    out: list[dict[str, Any]] = []
    for name in selected_names[:max_types]:
        vuln = catalog_by_name.get(name)
        if vuln:
            out.append(vuln)
    return out
