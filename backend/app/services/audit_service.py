from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

# Make project root importable when backend is run from backend/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase2_llm_engine.cot_analyzer import (
    analyze_contract_cascade,
    run_multi_llm_audit,
)
from phase2_llm_engine.llm_client import query_llm
from phase2_llm_engine.slither_runner import (
    format_slither_reference,
    is_slither_available,
    run_slither_analysis,
)
from phase2_llm_engine.vulnerability_store import get_vulnerability_names, get_vulnerability_types

from app.schemas.audit import AuditCreateRequest
from app.services.sse_manager import sse_manager


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


async def _run_standard_batched_checks_streaming(
    audit_id: str,
    source_code: str,
    mode: str,
    model: str,
    temperature: float,
    batch_size: int,
    slither_reference: str,
) -> list[dict[str, str]]:
    vuln_catalog = get_vulnerability_types()
    vuln_by_name = {v["name"]: v for v in vuln_catalog}
    selected_names = get_vulnerability_names()
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
                asyncio.to_thread(
                    query_llm,
                    messages,
                    model,
                    temperature,
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
        await sse_manager.publish(
            audit_id,
            event="audit_started",
            stage="queued",
            payload={
                "contract_name": req.contract_name,
                "model": req.model,
                "mode": req.mode,
                "pipeline": req.pipeline,
                "temperature": req.temperature,
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

            preprocessed = await asyncio.to_thread(
                preprocess_contract,
                req.source_code,
                model=req.model,
            )
            source_for_audit = preprocessed["source_code"]

            if is_slither_available():
                slither_result = await asyncio.to_thread(
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

            await sse_manager.publish(
                audit_id,
                event="llm_progress",
                stage="llm",
                payload={"message": "LLM auditing started"},
            )

            if req.pipeline == "cascade":
                cascade_result = await asyncio.wait_for(
                    asyncio.to_thread(
                        analyze_contract_cascade,
                        source_for_audit,
                        req.contract_name,
                        "deepseek-v3.2",
                        req.model,
                        req.temperature,
                        False,
                        False,
                        None,
                        None,
                        slither_reference,
                    ),
                    timeout=600,
                )
                llm_results = cascade_result.get("vuln_results", [])
            elif req.pipeline == "multi_llm":
                model_pool = [req.model, "deepseek-v3.2"]
                # Keep order but remove duplicates.
                unique_models = list(dict.fromkeys(model_pool))
                multi_result = await asyncio.wait_for(
                    asyncio.to_thread(
                        run_multi_llm_audit,
                        source_for_audit,
                        req.contract_name,
                        unique_models,
                        req.mode,
                        req.temperature,
                        "majority",
                        None,
                        get_vulnerability_names(),
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
            else:
                llm_results = await _run_standard_batched_checks_streaming(
                    audit_id,
                    source_for_audit,
                    req.mode,
                    req.model,
                    req.temperature,
                    req.batch_size,
                    slither_reference,
                )

            if req.pipeline == "cascade":
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

            await sse_manager.publish(
                audit_id,
                event="audit_completed",
                stage="completed",
                payload={
                    "verdict": verdict,
                    "summary": summary,
                    "results": llm_results,
                },
            )
        except Exception as exc:  # noqa: BLE001
            await sse_manager.publish(
                audit_id,
                event="audit_failed",
                stage="failed",
                payload={"error": str(exc)},
            )


audit_service = AuditService()
