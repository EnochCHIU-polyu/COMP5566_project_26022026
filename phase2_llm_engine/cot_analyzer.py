"""
Phase 2 – LLM Engine: Contract analyzer.

Default path: batched JSON over vulnerability types (chunked by ``BATCH_VULNS_PER_PROMPT``),
one model response listing ``results[]`` per type — code maps ``vuln_name`` to rows.

Optional ``sequential_vuln_audit=True`` restores per-type LLM calls plus per-function CoT.
"""

from __future__ import annotations

import json
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable, Sequence

from phase2_llm_engine.prompt_builder import (
    build_prompt,
    build_cot_function_prompt,
    build_multi_vuln_prompt,
    build_agent_reflection_prompt,
    build_batch_audit_prompt,
    extract_function_names,
)
from phase2_llm_engine.vulnerability_store import get_vulnerability_types
from phase2_llm_engine.llm_client import query_llm
from config import BATCH_VULNS_PER_PROMPT, CLASSIFICATION_MODE

logger = logging.getLogger(__name__)


def _chunk_vuln_names(names: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [names]
    return [names[i : i + chunk_size] for i in range(0, len(names), chunk_size)]


def _parse_batch_json_response(raw: str, vuln_names: list[str]) -> list[dict]:
    """Parse batch JSON response into vuln_results format."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end > start:
            try:
                data = json.loads(cleaned[start:end + 1])
            except json.JSONDecodeError:
                return [{"vuln_name": n, "response": f"ERROR: Failed to parse JSON\n{raw[:200]}"} for n in vuln_names]
        else:
            return [{"vuln_name": n, "response": f"ERROR: No JSON in response\n{raw[:200]}"} for n in vuln_names]
    parsed = {str(r.get("vuln_name", "")).strip(): r for r in data.get("results", []) if isinstance(r, dict)}
    results = []
    for n in vuln_names:
        r = parsed.get(n)
        if r:
            verdict = str(r.get("verdict", "UNCERTAIN")).upper()
            expl = str(r.get("explanation", "")).strip()
            conf = r.get("confidence")
            lines = r.get("evidence_lines", [])
            rec = str(r.get("recommendation", "")).strip()
            conf_txt = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "N/A"
            line_txt = ", ".join(f"L{x}" for x in lines if isinstance(x, int))
            results.append({
                "vuln_name": n,
                "response": f"{verdict}\nConfidence: {conf_txt}\nExplanation: {expl}\nEvidence lines: {line_txt}\nRecommendation: {rec}",
            })
        else:
            results.append({"vuln_name": n, "response": f"ERROR: Missing in batch output\n{raw[:300]}"})
    return results


def _run_batch_audit_for_model(
    source_code: str,
    contract_name: str,
    model: Optional[str],
    mode: str,
    temperature: Optional[float],
    vuln_filter: Sequence[str],
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    slither_reference: str = "",
) -> dict:
    """
    **Canonical multi-class audit:** one structured JSON per chunk; rows matched by ``vuln_name``.

    Flow: ``build_batch_audit_prompt`` → ``query_llm`` → ``_parse_batch_json_response``
    (each ``results[]`` item must reuse the exact catalog name). Chunk size:
    ``BATCH_VULNS_PER_PROMPT``.
    """
    vulnerability_types = get_vulnerability_types()
    catalog_by_name = {str(v.get("name", "")).strip(): v for v in vulnerability_types if str(v.get("name", "")).strip()}
    vuln_set = {str(x).strip() for x in vuln_filter if str(x).strip()}
    ordered: list[str] = []
    seen: set[str] = set()
    for n in vuln_filter:
        key = str(n).strip()
        if key in catalog_by_name and key not in seen:
            ordered.append(key)
            seen.add(key)
    for key in sorted(vuln_set - seen):
        if key in catalog_by_name:
            ordered.append(key)

    chunk_size = max(1, int(BATCH_VULNS_PER_PROMPT) or 8)
    chunks = _chunk_vuln_names(ordered, chunk_size)
    vuln_results: list[dict] = []
    total_chunks = len(chunks)

    for ci, chunk in enumerate(chunks):
        selected = [catalog_by_name[n] for n in chunk]
        messages = build_batch_audit_prompt(
            source_code,
            selected,
            mode,
            slither_reference=slither_reference,
        )
        raw = query_llm(messages, model=model, temperature=temperature)
        vuln_results.extend(_parse_batch_json_response(raw, chunk))
        if progress_callback:
            progress_callback(ci + 1, total_chunks, f"batch_json_chunk_{ci + 1}/{total_chunks}")

    return {
        "contract_name": contract_name,
        "vuln_results": vuln_results,
        "function_results": [],
    }


# Public alias — benchmark / services should rely on this pattern only for list-of-types audits.
run_batched_vulnerability_audit = _run_batch_audit_for_model


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
    verify_with_rag: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    agent_mode: bool = False,
    agent_judge_model: Optional[str] = None,
    vuln_filter: Optional[Sequence[str]] = None,
    sequential_vuln_audit: bool = False,
    slither_reference: str = "",
) -> dict:
    """
    Run a vulnerability-type audit of *source_code* using the catalog (or a filter).

    By default uses **batched JSON**: the model returns a ``results`` array;
    the parser aligns each row to ``vuln_name`` (chunked via ``BATCH_VULNS_PER_PROMPT``).
    ``function_results`` is empty unless ``sequential_vuln_audit=True``.

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
    verify_with_rag : bool
        If True and ``verify=True``, verification uses TF-IDF retrieved context (single LLM call).
    progress_callback : callable, optional
        Called as ``callback(current, total, message)`` after each LLM call.
    agent_mode : bool
        If True, use 2-step agent reasoning: analyze → reflect/judge.
    agent_judge_model : str, optional
        Model for reflection step (default: same as model). Use a different
        model for cross-checking (e.g. analyzer=gpt-4o, judge=claude).
    vuln_filter : sequence of str, optional
        If provided, only these names are requested; otherwise **all** catalog types.
    sequential_vuln_audit : bool
        If True, use one LLM call per type and run per-function CoT (legacy).
        Ignored when ``agent_mode`` or ``verify`` is True (those paths stay sequential).

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
    logger.info(
        "Auditing '%s' | mode=%s | model=%s | agent_mode=%s",
        contract_name,
        effective_mode,
        model,
        agent_mode,
    )

    # ── multi_vuln mode: single call for all vulns ────────────────────────
    vulnerability_types = get_vulnerability_types()

    if effective_mode == "multi_vuln":
        messages = build_multi_vuln_prompt(
            source_code,
            vulnerability_types,
            slither_reference=slither_reference,
        )
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

    # ── Batched JSON: all catalog types or ``vuln_filter`` (chunked) ───────────
    if not agent_mode and not verify and not sequential_vuln_audit:
        if vuln_filter:
            names_for_batch: Sequence[str] = vuln_filter
        else:
            names_for_batch = [
                str(v["name"])
                for v in vulnerability_types
                if str(v.get("name", "")).strip()
            ]
        return run_batched_vulnerability_audit(
            source_code=source_code,
            contract_name=contract_name,
            model=model,
            mode=effective_mode,
            temperature=temperature,
            vuln_filter=names_for_batch,
            progress_callback=progress_callback,
            slither_reference=slither_reference,
        )

    # ── Phase A: sequential per-type (agent / verify / sequential_vuln_audit) ──
    vulns_to_check = vulnerability_types
    if vuln_filter:
        vuln_set = set(vuln_filter)
        vulns_to_check = [v for v in vulnerability_types if v["name"] in vuln_set]
    vuln_results = []
    total_vulns = len(vulns_to_check)
    judge_model = agent_judge_model or model

    for idx, vuln in enumerate(vulns_to_check):
        logger.debug("  Checking vulnerability: %s", vuln["name"])
        messages = build_prompt(
            source_code=source_code,
            vuln_name=vuln["name"],
            vuln_description=vuln["description"],
            mode=effective_mode,
            example_vulnerable=vuln.get("example_vulnerable", ""),
            example_fixed=vuln.get("example_fixed", ""),
            slither_reference=slither_reference,
        )
        response = query_llm(messages, model=model, temperature=temperature)

        if agent_mode:
            # Step 2: Reflection/judgment – second LLM reviews the analysis
            if progress_callback:
                progress_callback(idx + 1, total_vulns * 2, f"{vuln['name']} (reflect)")
            reflect_messages = build_agent_reflection_prompt(
                source_code=source_code,
                vuln_name=vuln["name"],
                vuln_description=vuln["description"],
                initial_analysis=response,
                slither_reference=slither_reference,
            )
            reflection = query_llm(
                reflect_messages,
                model=judge_model,
                temperature=temperature or 0.0,
            )
            # Extract final verdict from reflection for scoring compatibility
            ref_upper = reflection.strip().upper()
            final_verdict = "YES" if (
                ref_upper.startswith("YES") or "YES" in ref_upper[:30]
            ) else "NO"
            # Prefix with verdict so infer_verdict_for_scoring works; keep full chain
            response = (
                f"{final_verdict}\n\n"
                f"[Agent Step 1 - Analysis]\n{response}\n\n"
                f"[Agent Step 2 - Reflection/Judge]\n{reflection}"
            )

        vuln_results.append({"vuln_name": vuln["name"], "response": response})
        if progress_callback and not agent_mode:
            progress_callback(idx + 1, total_vulns, vuln["name"])
        elif progress_callback and agent_mode:
            progress_callback((idx + 1) * 2, total_vulns * 2, vuln["name"])

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
                initial,
                source_code,
                query_llm,
                model=model,
                temperature=temperature or 0.0,
                use_rag=verify_with_rag,
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


def _cascade_small_clear_no(small_response: str) -> bool:
    """True if cheap binary pass clearly says NO (safe to skip expensive model)."""
    t = small_response.strip().upper()
    if t.startswith("NO"):
        return True
    if t.startswith("YES"):
        return False
    first = small_response.split("\n")[0].strip().upper()
    return first.startswith("NO") or ("NO" in first[:40] and "YES" not in first[:25])


def analyze_contract_cascade(
    source_code: str,
    contract_name: str = "Unknown",
    small_model: str = "gpt-4o-mini",
    large_model: str = "gpt-4o",
    temperature: Optional[float] = None,
    verify: bool = False,
    verify_with_rag: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    vuln_filter: Optional[Sequence[str]] = None,
    slither_reference: str = "",
) -> dict:
    """
    Two-tier audit without ``vuln_filter``: per-type small→large, then CoT per function.

    With ``vuln_filter`` and ``verify`` False: **only batched JSON** — binary batch on
    ``small_model``, then ``non_binary`` batch on ``large_model`` for types not clearly NO
    (same ``vuln_name`` alignment as :func:`run_batched_vulnerability_audit`).
    """
    logger.info(
        "Cascade audit '%s' | small=%s large=%s",
        contract_name,
        small_model,
        large_model,
    )

    if vuln_filter and not verify:
        small_batch = run_batched_vulnerability_audit(
            source_code=source_code,
            contract_name=contract_name,
            model=small_model,
            mode="binary",
            temperature=temperature,
            vuln_filter=vuln_filter,
            progress_callback=progress_callback,
            slither_reference=slither_reference,
        )
        large_by: dict[str, str] = {}
        need_names = [
            vr["vuln_name"]
            for vr in small_batch["vuln_results"]
            if not _cascade_small_clear_no(vr.get("response", ""))
        ]
        if need_names:
            large_batch = run_batched_vulnerability_audit(
                source_code=source_code,
                contract_name=contract_name,
                model=large_model,
                mode="non_binary",
                temperature=temperature,
                vuln_filter=need_names,
                progress_callback=progress_callback,
                slither_reference=slither_reference,
            )
            large_by = {vr["vuln_name"]: vr["response"] for vr in large_batch["vuln_results"]}

        merged: list[dict] = []
        for vr in small_batch["vuln_results"]:
            name = vr["vuln_name"]
            resp = vr.get("response", "")
            if _cascade_small_clear_no(resp):
                merged.append({
                    "vuln_name": name,
                    "response": (
                        f"NO\n\n[Cascade: {small_model} binary — {large_model} skipped]\n\n{resp}"
                    ),
                })
            else:
                lg = large_by.get(name, "ERROR: Missing deep batch result for this type")
                merged.append({
                    "vuln_name": name,
                    "response": (
                        f"[Cascade: {small_model} → {large_model}]\n\n"
                        f"--- Cheap pass ---\n{resp}\n\n--- Deep pass ---\n{lg}"
                    ),
                })
        return {
            "contract_name": contract_name,
            "vuln_results": merged,
            "function_results": [],
            "cascade": {
                "small_model": small_model,
                "large_model": large_model,
                "vulnerability_pass": "batched_json",
            },
        }

    vulnerability_types = get_vulnerability_types()
    vulns_to_check = vulnerability_types
    if vuln_filter:
        vs = set(vuln_filter)
        vulns_to_check = [v for v in vulnerability_types if v["name"] in vs]

    vuln_results = []
    total = len(vulns_to_check)
    step = 0

    for idx, vuln in enumerate(vulns_to_check):
        messages_bin = build_prompt(
            source_code=source_code,
            vuln_name=vuln["name"],
            vuln_description=vuln["description"],
            mode="binary",
            example_vulnerable=vuln.get("example_vulnerable", ""),
            example_fixed=vuln.get("example_fixed", ""),
            slither_reference=slither_reference,
        )
        small_resp = query_llm(messages_bin, model=small_model, temperature=temperature)
        step += 1
        if progress_callback:
            progress_callback(step, total * 2, f"{vuln['name']} (small)")

        if _cascade_small_clear_no(small_resp):
            combined = (
                f"NO\n\n[Cascade: {small_model} binary — {large_model} skipped]\n\n{small_resp}"
            )
            vuln_results.append({"vuln_name": vuln["name"], "response": combined})
            continue

        messages_deep = build_prompt(
            source_code=source_code,
            vuln_name=vuln["name"],
            vuln_description=vuln["description"],
            mode="non_binary",
            example_vulnerable=vuln.get("example_vulnerable", ""),
            example_fixed=vuln.get("example_fixed", ""),
            slither_reference=slither_reference,
        )
        large_resp = query_llm(messages_deep, model=large_model, temperature=temperature)
        step += 1
        if progress_callback:
            progress_callback(step, total * 2, f"{vuln['name']} (large)")

        combined = (
            f"[Cascade: {small_model} → {large_model}]\n\n"
            f"--- Cheap pass ---\n{small_resp}\n\n--- Deep pass ---\n{large_resp}"
        )
        vuln_results.append({"vuln_name": vuln["name"], "response": combined})

    function_names = extract_function_names(source_code)
    function_results = []
    for fn_name in function_names:
        messages = build_cot_function_prompt(source_code, fn_name)
        response = query_llm(messages, model=large_model, temperature=temperature)
        function_results.append({"function_name": fn_name, "response": response})

    result = {
        "contract_name": contract_name,
        "vuln_results": vuln_results,
        "function_results": function_results,
        "cascade": {"small_model": small_model, "large_model": large_model},
    }

    if verify:
        try:
            from phase2_llm_engine.output_parser import AuditResult, Finding, parse_audit_response
            from phase2_llm_engine.self_checker import self_check_audit

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
                initial,
                source_code,
                query_llm,
                model=large_model,
                temperature=temperature or 0.0,
                use_rag=verify_with_rag,
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


def run_multi_llm_audit(
    source_code: str,
    contract_name: str = "Unknown",
    models: Optional[Sequence[str]] = None,
    mode: Optional[str] = None,
    temperature: Optional[float] = None,
    aggregation: str = "majority",
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    vuln_filter: Optional[Sequence[str]] = None,
    agent_mode: bool = False,
    agent_judge_model: Optional[str] = None,
    parallel_models: bool = False,
    slither_reference: str = "",
) -> dict:
    """
    Run audit with multiple LLMs and aggregate results.

    Parameters
    ----------
    source_code : str
        Pre-processed Solidity source.
    contract_name : str
        Human-readable name for logging.
    models : sequence of str, optional
        List of model names (default: ["gpt-4o", "gpt-4o-mini", "deepseek-v3.2"]).
    mode : str, optional
        Classification mode (default: non_binary).
    temperature : float, optional
        Temperature for all models.
    aggregation : str
        "majority" = majority vote per vuln; "consensus" = all must agree for YES.
    progress_callback : callable, optional
        Called as (current, total, message).
    vuln_filter : sequence of str, optional
        If provided, only check these vulnerability types (reduces API calls).
    agent_mode : bool
        If True, each model runs 2-step (analyze → judge) before aggregation.
    agent_judge_model : str, optional
        Judge model when agent_mode=True (default: same as analyzer).
    parallel_models : bool
        If True, run each model in a thread pool (faster; watch API rate limits).

    Returns
    -------
    dict
        Same structure as analyze_contract, with added "multi_llm_votes" per vuln.
    """
    effective_mode = mode or CLASSIFICATION_MODE
    model_list = list(models or ["gpt-4o", "gpt-4o-mini", "deepseek-v3.2"])
    use_batch = bool(vuln_filter) and not agent_mode
    logger.info(
        "Multi-LLM audit '%s' | models=%s | aggregation=%s | batch_prompt=%s | parallel=%s",
        contract_name,
        model_list,
        aggregation,
        use_batch,
        parallel_models,
    )

    def _run_one_model(model: str) -> dict:
        if use_batch:
            return run_batched_vulnerability_audit(
                source_code=source_code,
                contract_name=contract_name,
                model=model,
                mode=effective_mode,
                temperature=temperature,
                vuln_filter=vuln_filter,
                progress_callback=None,
                slither_reference=slither_reference,
            )
        return analyze_contract(
            source_code=source_code,
            contract_name=contract_name,
            mode=effective_mode,
            model=model,
            temperature=temperature,
            verify=False,
            vuln_filter=vuln_filter,
            agent_mode=agent_mode,
            agent_judge_model=agent_judge_model,
            slither_reference=slither_reference,
        )

    all_results: list[dict] = []

    if parallel_models and len(model_list) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(model_list))) as ex:
            futures = {ex.submit(_run_one_model, m): m for m in model_list}
            tmp: dict[str, dict] = {}
            for fut in as_completed(futures):
                m = futures[fut]
                try:
                    tmp[m] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Model %s failed: %s", m, exc)
                    tmp[m] = {
                        "contract_name": contract_name,
                        "vuln_results": [],
                        "error": str(exc),
                    }
            all_results = [tmp[m] for m in model_list if m in tmp]
    else:
        for mi, model in enumerate(model_list):
            if progress_callback:
                progress_callback(mi, len(model_list), f"Running {model}")
            all_results.append(_run_one_model(model))

    # Aggregate vuln_results (use vuln names from first result)
    vulnerability_types = get_vulnerability_types()
    vulns_to_aggregate = (
        [r["vuln_name"] for r in all_results[0]["vuln_results"]]
        if all_results and all_results[0].get("vuln_results")
        else [v["name"] for v in vulnerability_types]
    )
    aggregated_vuln_results = []
    for vuln_name in vulns_to_aggregate:
        votes: list[dict] = []
        for i, res in enumerate(all_results):
            vr = next(
                (r for r in res.get("vuln_results", []) if r["vuln_name"] == vuln_name),
                None,
            )
            if vr:
                resp = vr.get("response", "")
                is_yes = (
                    resp.strip().upper().startswith("YES")
                    or "YES" in resp[:20].upper()
                )
                votes.append({
                    "model": model_list[i],
                    "response": resp,
                    "vote": "YES" if is_yes else "NO",
                })

        yes_count = sum(1 for v in votes if v["vote"] == "YES")
        if aggregation == "consensus":
            final_yes = yes_count == len(votes) and len(votes) > 0
        else:
            final_yes = yes_count > len(votes) / 2

        combined_response = (
            f"{'YES' if final_yes else 'NO'}\n"
            f"[Multi-LLM: {yes_count}/{len(votes)} voted YES]\n"
            + "\n".join(f"- {v['model']}: {v['vote']}" for v in votes)
        )
        aggregated_vuln_results.append({
            "vuln_name": vuln_name,
            "response": combined_response,
            "multi_llm_votes": votes,
            "yes_count": yes_count,
            "total_votes": len(votes),
        })

    # Use first model's function_results (or empty)
    function_results = all_results[0].get("function_results", []) if all_results else []

    return {
        "contract_name": contract_name,
        "vuln_results": aggregated_vuln_results,
        "function_results": function_results,
        "models_used": model_list,
        "aggregation": aggregation,
    }
