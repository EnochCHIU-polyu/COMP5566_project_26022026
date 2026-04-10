from __future__ import annotations

import asyncio
import json
import re
import sys
import logging
import time
from pathlib import Path
from typing import Any

# Make project root importable when backend is run from backend/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase2_llm_engine.cot_analyzer import (
    run_multi_llm_audit,
)
from phase2_llm_engine.llm_client import query_llm
from phase2_llm_engine.slither_runner import (
    format_slither_reference,
    is_slither_available,
    run_slither_analysis,
)
from phase2_llm_engine.vulnerability_store import get_vulnerability_types
from phase2_llm_engine.vulnerability_store import get_vulnerability_catalog_meta
from phase2_llm_engine.gate_decider import decide_contract_gate
from phase2_llm_engine.finding_mapper import (
    discover_vulnerability_types_with_llm,
    map_findings_to_catalog,
)
from phase4_evaluation.runtime_metrics_logger import append_runtime_metric
from config import (
    DATA_BACKEND,
    MAPPING_JUDGE_MODEL,
    MAPPING_USE_LLM_JUDGE,
    RUNTIME_AUDIT_METRICS_FILE,
    SLITHER_GATE_ENABLED,
    SLITHER_GATE_MODEL,
    SUPABASE_KEY,
    SUPABASE_OTHER_VULNERABILITIES_TABLE,
    SUPABASE_SERVICE_ROLE_KEY,
    SUPABASE_URL,
)

from app.schemas.audit import AuditCreateRequest
from app.services.sse_manager import sse_manager
from app.utils.async_compat import to_thread


logger = logging.getLogger(__name__)


LLM_BATCH_TIMEOUT_SECONDS = 120


def _chunk_list(items: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [items]
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def _extract_json_payload(raw_text: str) -> dict[str, Any] | None:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            parsed = json.loads(snippet)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _build_batch_messages(
    source_code: str,
    selected_batch: list[dict[str, Any]],
    mode: str,
    slither_reference: str = "",
) -> list[dict[str, str]]:
    mode_instruction = {
        "binary": "Use YES/NO verdict for each vulnerability, with concise explanation.",
        "non_binary": "Provide detailed explanation for each vulnerability.",
        "cot": "Reason carefully and provide concise final explanations.",
        "multi_vuln": "Audit all listed vulnerabilities together with per-item details.",
    }.get(mode, "Provide detailed explanation for each vulnerability.")

    vuln_block = "\n".join(
        f"- {v['name']}: {v['description']}" for v in selected_batch
    )
    slither_block = (
        "Static analysis reference (Slither, may include false positives):\n"
        f"{slither_reference.strip()}\n\n"
        if slither_reference.strip()
        else ""
    )

    schema = {
        "results": [
            {
                "vuln_name": "<must exactly match one requested vulnerability name>",
                "verdict": "YES|NO|UNCERTAIN",
                "confidence": 0.0,
                "explanation": "<detailed explanation>",
                "evidence_lines": [1, 2],
                "recommendation": "<fix suggestion>",
            }
        ]
    }

    user_prompt = (
        "Audit the smart contract for each selected vulnerability and return ONLY valid JSON.\n\n"
        f"Mode: {mode}\n"
        f"Instruction: {mode_instruction}\n\n"
        "Selected vulnerabilities:\n"
        f"{vuln_block}\n\n"
        f"{slither_block}"
        "Requirements:\n"
        "1) Return one result object for every listed vulnerability.\n"
        "2) Keep vuln_name exactly identical to input names.\n"
        "3) Use verdict YES/NO (UNCERTAIN only if impossible).\n"
        "4) explanation must be specific.\n"
        "5) evidence_lines should contain line numbers when available.\n"
        "6) recommendation should be practical.\n\n"
        f"Output schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Source Code:\n{source_code}"
    )

    return [
        {
            "role": "system",
            "content": "You are a senior smart contract security auditor. Output valid JSON only.",
        },
        {"role": "user", "content": user_prompt},
    ]


def _format_batch_item_as_response(item: dict[str, Any]) -> str:
    verdict = str(item.get("verdict", "UNCERTAIN")).upper()
    explanation = str(item.get("explanation", "")).strip()
    recommendation = str(item.get("recommendation", "")).strip()
    confidence = item.get("confidence", None)
    evidence_lines = item.get("evidence_lines", [])

    line_tokens = [f"L{ln}" for ln in evidence_lines if isinstance(ln, int)]
    lines_text = ", ".join(line_tokens) if line_tokens else "None"
    confidence_text = (
        f"{float(confidence):.2f}"
        if isinstance(confidence, (int, float))
        else "N/A"
    )

    return (
        f"{verdict}\n"
        f"Confidence: {confidence_text}\n"
        f"Explanation: {explanation}\n"
        f"Evidence lines: {lines_text}\n"
        f"Recommendation: {recommendation}"
    )


def _is_positive_finding(response: str) -> bool:
    text = (response or "").strip().upper()
    return text.startswith("YES") or ("YES" in text[:20])


def _build_final_summary(results: list[dict[str, str]]) -> str:
    positives = [r for r in results if _is_positive_finding(r["response"])]
    if not positives:
        return "No clear vulnerabilities were confirmed by the selected pipeline."

    top_lines: list[str] = []
    for item in positives[:5]:
        first_line = item["response"].splitlines()[0] if item["response"] else "YES"
        top_lines.append(f"- {item['vuln_name']}: {first_line}")

    return (
        f"Detected {len(positives)} potential vulnerability findings out of {len(results)} checks.\n"
        + "\n".join(top_lines)
    )


def _severity_rank(severity: str) -> int:
    mapping = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    return mapping.get(str(severity).upper(), 2)


def _risk_score_from_findings(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0.7
    total = 0.0
    for item in findings:
        sev = _severity_rank(str(item.get("severity", "LOW")))
        conf = float(item.get("confidence", 0.5) or 0.5)
        total += sev * max(0.1, min(1.0, conf))
    return round(min(10.0, total / max(1.0, len(findings)) * 1.7), 2)


def _build_structured_report(llm_results: list[dict[str, str]], fallback_summary: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for item in llm_results:
        vuln_name = str(item.get("vuln_name", "unknown"))
        response = str(item.get("response", ""))
        upper = response.strip().upper()
        if not (upper.startswith("YES") or "YES" in upper[:20]):
            continue

        conf_match = re.search(r"Confidence:\s*([0-9]*\.?[0-9]+)", response, re.IGNORECASE)
        explanation_match = re.search(r"Explanation:\s*(.+)", response, re.IGNORECASE)
        recommendation_match = re.search(r"Recommendation:\s*(.+)", response, re.IGNORECASE)
        lines = [int(x) for x in re.findall(r"\bL(\d+)\b", response)]

        confidence = float(conf_match.group(1)) if conf_match else 0.65
        description = explanation_match.group(1).strip() if explanation_match else response[:180].strip()
        recommendation = recommendation_match.group(1).strip() if recommendation_match else "Review and patch the affected logic path."

        severity = "MEDIUM"
        if any(tok in vuln_name.upper() for tok in ["REENTRANCY", "ACCESS CONTROL", "DELEGATE", "SELF-DESTRUCT"]):
            severity = "HIGH"

        findings.append(
            {
                "vuln_type": vuln_name,
                "severity": severity,
                "confidence": max(0.0, min(1.0, confidence)),
                "lines": sorted(set(lines))[:12],
                "function": None,
                "description": description[:240],
                "recommendation": recommendation[:180],
            }
        )

    summary = fallback_summary
    if not findings:
        summary = "No confirmed vulnerabilities were detected in this run. The contract appears safe under current checks."

    return {
        "findings": findings,
        "summary": summary,
        "risk_score": _risk_score_from_findings(findings),
    }


def _store_other_candidates(audit_id: str, candidates: list[dict[str, Any]]) -> None:
    if not candidates:
        return
    if DATA_BACKEND != "supabase":
        return
    api_key = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY
    if not SUPABASE_URL or not api_key:
        return

    payload = []
    for c in candidates:
        payload.append(
            {
                "name": "OTHER",
                "description": str(c.get("detail", ""))[:1000],
                "swc_id": None,
                "severity_default": str(c.get("impact", "medium")).lower(),
                "example_vulnerable": "",
                "example_fixed": "",
                "detection_keywords": [str(c.get("slither_check", "unknown"))],
                "cwe_id": None,
                "source_audit_id": audit_id,
                "source_check": str(c.get("slither_check", "unknown")),
                "mapping_confidence": float(c.get("confidence", 0.0) or 0.0),
                "status": "pending_review",
            }
        )

    try:
        from supabase import create_client

        client = create_client(SUPABASE_URL, api_key)
        client.table(SUPABASE_OTHER_VULNERABILITIES_TABLE).insert(payload).execute()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to store OTHER vulnerability candidates: %s", exc)


def _write_runtime_metrics(record: dict[str, Any]) -> None:
    try:
        append_runtime_metric(record, RUNTIME_AUDIT_METRICS_FILE)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to append runtime audit metrics: %s", exc)


def _build_other_detail_messages(
    source_code: str,
    other_candidate: dict[str, Any],
    slither_reference: str,
) -> list[dict[str, str]]:
    check = str(other_candidate.get("slither_check", "unknown"))
    detail = str(other_candidate.get("detail", ""))
    impact = str(other_candidate.get("impact", "Unknown"))
    lines = other_candidate.get("lines", []) or []
    line_txt = ", ".join(f"L{ln}" for ln in lines if isinstance(ln, int)) or "none"

    user_prompt = (
        "Assess this potential smart-contract vulnerability that is currently NOT in the known DB catalog. "
        "Respond with valid JSON only using schema:\n"
        "{\"verdict\":\"YES|NO|UNCERTAIN\",\"confidence\":0.0,\"description\":\"...\","
        "\"recommendation\":\"...\",\"evidence_lines\":[1,2],\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW|INFO\"}\n\n"
        f"Detector check: {check}\n"
        f"Detector impact: {impact}\n"
        f"Detector lines: {line_txt}\n"
        f"Detector detail: {detail}\n\n"
        f"{slither_reference}\n\n"
        f"Source Code:\n{source_code}"
    )
    return [
        {"role": "system", "content": "You are a senior smart contract security auditor. Output valid JSON only."},
        {"role": "user", "content": user_prompt},
    ]


async def _run_other_detail_checks_streaming(
    audit_id: str,
    source_code: str,
    model: str,
    slither_reference: str,
    other_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(other_candidates, start=1):
        check = str(item.get("slither_check", "unknown"))
        await sse_manager.publish(
            audit_id,
            event="llm_progress",
            stage="llm",
            payload={"message": f"Running OTHER detail audit {idx}/{len(other_candidates)} for {check}"},
        )
        messages = _build_other_detail_messages(source_code, item, slither_reference)
        raw = await asyncio.wait_for(
            to_thread(query_llm, messages, model, 0.0),
            timeout=LLM_BATCH_TIMEOUT_SECONDS,
        )
        payload = _extract_json_payload(raw) or {}
        verdict = str(payload.get("verdict", "UNCERTAIN")).upper()
        confidence = payload.get("confidence", item.get("confidence", 0.35))
        description = str(payload.get("description", item.get("detail", ""))).strip()
        recommendation = str(payload.get("recommendation", "Investigate and patch this non-catalog vulnerability path.")).strip()
        evidence_lines = payload.get("evidence_lines", item.get("lines", []))
        severity = str(payload.get("severity", "MEDIUM")).upper()
        line_tokens = ", ".join(f"L{ln}" for ln in evidence_lines if isinstance(ln, int)) or "None"
        response = (
            f"{verdict}\n"
            f"Confidence: {float(confidence):.2f}\n"
            f"Explanation: {description}\n"
            f"Evidence lines: {line_tokens}\n"
            f"Recommendation: {recommendation}"
        )
        out.append(
            {
                "vuln_name": f"OTHER::{check}",
                "response": response,
                "is_other": True,
                "mapped_from_db": False,
                "severity": severity,
            }
        )
        await sse_manager.publish(
            audit_id,
            event="llm_chunk",
            stage="llm",
            payload={"index": idx, "text": f"[OTHER::{check}] {verdict}"},
        )
    return out


async def _run_standard_batched_checks_streaming(
    audit_id: str,
    source_code: str,
    mode: str,
    model: str,
    batch_size: int,
    slither_reference: str,
    vuln_catalog: list[dict[str, Any]],
) -> list[dict[str, str]]:
    vuln_by_name = {v["name"]: v for v in vuln_catalog}
    selected_names = [v["name"] for v in vuln_catalog]
    chunks = _chunk_list(selected_names, max(1, batch_size))

    results: list[dict[str, str]] = []
    for chunk_idx, chunk_names in enumerate(chunks, start=1):
        await sse_manager.publish(
            audit_id,
            event="llm_progress",
            stage="llm",
            payload={
                "message": f"Running LLM batch {chunk_idx}/{len(chunks)}",
                "batch_index": chunk_idx,
                "batch_total": len(chunks),
            },
        )

        chunk_vulns = [vuln_by_name[name] for name in chunk_names if name in vuln_by_name]
        messages = _build_batch_messages(
            source_code=source_code,
            selected_batch=chunk_vulns,
            mode=mode,
            slither_reference=slither_reference,
        )

        try:
            raw_response = await asyncio.wait_for(
                to_thread(
                    query_llm,
                    messages,
                    model,
                    0.0,
                ),
                timeout=LLM_BATCH_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                f"LLM batch {chunk_idx}/{len(chunks)} timed out after {LLM_BATCH_TIMEOUT_SECONDS}s"
            ) from exc

        payload = _extract_json_payload(raw_response)
        parsed_results = payload.get("results", []) if isinstance(payload, dict) else []
        parsed_by_name = {
            str(item.get("vuln_name", "")).strip(): item
            for item in parsed_results
            if isinstance(item, dict)
        }

        for vuln_name in chunk_names:
            item = parsed_by_name.get(vuln_name)
            if item is None:
                response = f"ERROR: Missing result for {vuln_name}\nRaw: {raw_response[:600]}"
            else:
                response = _format_batch_item_as_response(item)
            result_item = {"vuln_name": vuln_name, "response": response}
            results.append(result_item)

            preview = response.splitlines()[0] if response else "(empty)"
            await sse_manager.publish(
                audit_id,
                event="llm_chunk",
                stage="llm",
                payload={
                    "index": len(results),
                    "text": f"[{vuln_name}] {preview}",
                    "batch_index": chunk_idx,
                },
            )

    return results


class AuditService:
    async def run_audit(self, audit_id: str, req: AuditCreateRequest) -> None:
        started_at = time.time()
        await sse_manager.publish(
            audit_id,
            event="audit_started",
            stage="queued",
            payload={
                "contract_name": req.contract_name,
                "model": req.model,
                "mode": req.mode,
                "pipeline": req.pipeline,
                "batch_size": req.batch_size,
            },
        )

        try:
            await sse_manager.publish(
                audit_id,
                event="slither_progress",
                stage="slither",
                payload={"message": "Running Slither detectors"},
            )

            catalog_meta = await to_thread(get_vulnerability_catalog_meta)
            catalog_count = int(catalog_meta.get("count", 0) or 0)
            catalog_source = str(catalog_meta.get("source", "unknown"))
            logger.info(
                "Audit %s catalog loaded: source=%s count=%d",
                audit_id,
                catalog_source,
                catalog_count,
            )

            vuln_catalog = await to_thread(get_vulnerability_types)
            logger.info(
                "Audit %s using vulnerability snapshot count=%d",
                audit_id,
                len(vuln_catalog),
            )

            preprocessed = await to_thread(
                preprocess_contract,
                req.source_code,
                model=req.model,
            )
            source_for_audit = preprocessed["source_code"]

            if is_slither_available():
                slither_result = await to_thread(
                    run_slither_analysis,
                    source_for_audit,
                    f"{req.contract_name or 'Contract'}.sol",
                )
            else:
                slither_result = {
                    "ok": False,
                    "error": "Slither CLI not found.",
                    "findings": [],
                    "summary": "",
                }

            raw_findings = slither_result.get("findings", []) or []
            slither_hits = [
                {
                    "check": item.get("check", "unknown"),
                    "impact": item.get("impact", "Unknown"),
                    "lines": item.get("lines", []),
                    "detail": item.get("description", ""),
                }
                for item in raw_findings
            ]
            slither_summary = str(slither_result.get("summary", "")).strip()
            slither_reference = format_slither_reference(slither_result)

            await sse_manager.publish(
                audit_id,
                event="slither_result",
                stage="slither",
                payload={"hits": slither_hits, "summary": slither_summary},
            )

            gate = {
                "has_vulnerability": True,
                "confidence": 0.5,
                "reason": "Gate disabled",
                "raw_response": "",
            }
            if SLITHER_GATE_ENABLED:
                gate = await to_thread(
                    decide_contract_gate,
                    source_for_audit,
                    slither_result,
                    SLITHER_GATE_MODEL or req.model,
                    0.0,
                )

            await sse_manager.publish(
                audit_id,
                event="llm_progress",
                stage="llm",
                payload={
                    "message": (
                        f"Gate verdict: {'YES' if gate['has_vulnerability'] else 'NO'} "
                        f"(confidence={gate['confidence']:.2f})"
                    ),
                    "gate": gate,
                },
            )

            if not gate["has_vulnerability"]:
                safe_report = {
                    "findings": [],
                    "summary": "No clear vulnerability signals were detected after Slither pre-scan and LLM gate triage. The contract appears safe for now, but deploy with standard security controls and monitoring.",
                    "risk_score": 0.8,
                }
                await sse_manager.publish(
                    audit_id,
                    event="audit_completed",
                    stage="completed",
                    payload={
                        "verdict": "no-clear-findings",
                        "summary": safe_report["summary"],
                        "results": [],
                        "report": safe_report,
                    },
                )
                _write_runtime_metrics(
                    {
                        "audit_id": audit_id,
                        "status": "completed",
                        "gate_has_vulnerability": False,
                        "gate_confidence": gate["confidence"],
                        "mapped_count": 0,
                        "other_count": 0,
                        "shortlist_count": 0,
                        "llm_result_count": 0,
                        "duration_seconds": round(time.time() - started_at, 3),
                        "model": req.model,
                        "pipeline": req.pipeline,
                        "mode": req.mode,
                    }
                )
                return

            mapping = await to_thread(
                map_findings_to_catalog,
                slither_hits,
                vuln_catalog,
                MAPPING_JUDGE_MODEL or req.model,
                0.0,
                bool(MAPPING_USE_LLM_JUDGE),
            )
            llm_discovery = await to_thread(
                discover_vulnerability_types_with_llm,
                source_for_audit,
                slither_reference,
                str(gate.get("reason", "")),
                vuln_catalog,
                MAPPING_JUDGE_MODEL or req.model,
                0.0,
            )
            mapped = mapping.get("mapped", [])
            other_candidates = mapping.get("other_candidates", [])
            discovered_db_types = [
                str(x).strip() for x in llm_discovery.get("matched_db_types", []) if str(x).strip()
            ]
            discovered_other = llm_discovery.get("other_findings", []) or []

            for item in discovered_other:
                name = str(item.get("name", "OTHER")).strip() or "OTHER"
                desc = str(item.get("description", "")).strip()
                other_candidates.append(
                    {
                        "slither_check": f"llm-other::{name}",
                        "impact": "Unknown",
                        "lines": [],
                        "detail": desc,
                        "vuln_type": "OTHER",
                        "confidence": float(item.get("confidence", 0.4) or 0.4),
                        "reason": "LLM discovery: no DB match",
                    }
                )

            dedup_other: list[dict[str, Any]] = []
            seen_other_keys: set[str] = set()
            for oc in other_candidates:
                key = f"{oc.get('slither_check','')}::{oc.get('detail','')[:160]}"
                if key in seen_other_keys:
                    continue
                seen_other_keys.add(key)
                dedup_other.append(oc)
            other_candidates = dedup_other

            mapped_db_names = sorted(
                {
                    str(item.get("vuln_type", "")).strip()
                    for item in mapped
                    if str(item.get("vuln_type", "")).strip() and str(item.get("vuln_type", "")).strip() != "OTHER"
                }
                | set(discovered_db_types)
            )

            # Prefer contract-level discovered DB types. Use slither-derived mappings only
            # when discovery returns nothing, and filter out low-confidence slither noise.
            slither_only_names = sorted(
                {
                    str(item.get("vuln_type", "")).strip()
                    for item in mapped
                    if (
                        str(item.get("vuln_type", "")).strip()
                        and str(item.get("vuln_type", "")).strip() != "OTHER"
                        and float(item.get("confidence", 0.0) or 0.0) >= 0.6
                    )
                }
            )
            effective_names = sorted(set(discovered_db_types)) if discovered_db_types else slither_only_names

            await to_thread(_store_other_candidates, audit_id, other_candidates)

            await sse_manager.publish(
                audit_id,
                event="llm_progress",
                stage="llm",
                payload={
                    "message": (
                        f"Mapped findings: slither_map={len(mapped)} llm_db_types={len(discovered_db_types)} other={len(other_candidates)} db_types={len(mapped_db_names)}"
                    ),
                    "mapping": {
                        "mapped_count": len(mapped),
                        "other_count": len(other_candidates),
                        "mapped_db_types": mapped_db_names,
                        "discovered_db_types": discovered_db_types,
                        "effective_db_types": effective_names,
                        "selection_source": "llm_discovery" if discovered_db_types else "slither_map",
                    },
                },
            )

            await sse_manager.publish(
                audit_id,
                event="llm_progress",
                stage="llm",
                payload={"message": "LLM auditing started"},
            )

            effective_catalog = [v for v in vuln_catalog if v["name"] in set(effective_names)]

            if req.pipeline == "multi_llm" and effective_names:
                model_pool = [req.model, "deepseek-v3.2"]
                # Keep order but remove duplicates.
                unique_models = list(dict.fromkeys(model_pool))
                multi_result = await asyncio.wait_for(
                    to_thread(
                        run_multi_llm_audit,
                        source_for_audit,
                        req.contract_name,
                        unique_models,
                        req.mode,
                        0.0,
                        "majority",
                        None,
                        effective_names,
                        False,
                        None,
                        False,
                        slither_reference,
                    ),
                    timeout=600,
                )
                llm_results = multi_result.get("vuln_results", [])
                for idx, item in enumerate(llm_results, start=1):
                    vuln_name = str(item.get("vuln_name", "unknown"))
                    response = str(item.get("response", ""))
                    preview = response.splitlines()[0] if response else "(empty)"
                    await sse_manager.publish(
                        audit_id,
                        event="llm_chunk",
                        stage="llm",
                        payload={"index": idx, "text": f"[{vuln_name}] {preview}"},
                    )
            elif effective_names:
                llm_results = await _run_standard_batched_checks_streaming(
                    audit_id,
                    source_for_audit,
                    req.mode,
                    req.model,
                    min(req.batch_size, max(1, len(effective_catalog))),
                    slither_reference,
                    effective_catalog,
                )
            else:
                llm_results = []

            other_results = await _run_other_detail_checks_streaming(
                audit_id,
                source_for_audit,
                req.model,
                slither_reference,
                other_candidates,
            )
            llm_results = [*llm_results, *other_results]

            summary = _build_final_summary(
                [
                    {
                        "vuln_name": str(i.get("vuln_name", "unknown")),
                        "response": str(i.get("response", "")),
                    }
                    for i in llm_results
                ]
            )
            verdict = "vulnerable" if "potential vulnerability" in summary.lower() else "no-clear-findings"
            structured_report = _build_structured_report(llm_results, summary)

            await sse_manager.publish(
                audit_id,
                event="audit_completed",
                stage="completed",
                payload={
                    "verdict": verdict,
                    "summary": summary,
                    "results": llm_results,
                    "report": structured_report,
                    "mapping": {
                        "db_types": effective_names,
                        "other_count": len(other_candidates),
                        "mapped_count": len(mapped),
                        "other_candidates": other_candidates,
                        "discovered_db_types": discovered_db_types,
                        "selection_source": "llm_discovery" if discovered_db_types else "slither_map",
                    },
                },
            )
            _write_runtime_metrics(
                {
                    "audit_id": audit_id,
                    "status": "completed",
                    "gate_has_vulnerability": True,
                    "gate_confidence": gate["confidence"],
                    "mapped_count": len(mapped),
                    "other_count": len(other_candidates),
                    "shortlist_count": len(effective_names),
                    "llm_result_count": len(llm_results),
                    "duration_seconds": round(time.time() - started_at, 3),
                    "model": req.model,
                    "pipeline": req.pipeline,
                    "mode": req.mode,
                    "risk_score": structured_report.get("risk_score", 0.0),
                }
            )
        except Exception as exc:  # noqa: BLE001
            _write_runtime_metrics(
                {
                    "audit_id": audit_id,
                    "status": "failed",
                    "error": str(exc),
                    "duration_seconds": round(time.time() - started_at, 3),
                    "model": req.model,
                    "pipeline": req.pipeline,
                    "mode": req.mode,
                }
            )
            await sse_manager.publish(
                audit_id,
                event="audit_failed",
                stage="failed",
                payload={"error": str(exc)},
            )


audit_service = AuditService()
