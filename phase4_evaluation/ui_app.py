"""
Phase 4 – Evaluation: Human-in-the-Loop Streamlit UI.

Run with:
    streamlit run phase4_evaluation/ui_app.py

Features:
- Upload or paste a Solidity contract.
- Select vulnerability type(s) and classification mode.
- Call the LLM and display results.
- Highlight the specific lines flagged by the LLM so auditors can verify quickly.
- Show the scoring dashboard (TP/FP/TN/FN, F1/Precision/Recall).
"""

from __future__ import annotations

import re
import json
import sys
import os
import logging
import math

# ---------------------------------------------------------------------------
# Make parent directory importable when running as `streamlit run ...`
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd

from config import (
    DEFAULT_MODEL,
    TEMPERATURE,
    CLASSIFICATION_MODE,
    API_PAUSE_SECONDS,
    BATCH_VULNS_PER_PROMPT,
)
from phase1_data_pipeline.token_counter import count_tokens
from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
from phase2_llm_engine.llm_client import query_llm
from phase2_llm_engine.cot_analyzer import run_multi_llm_audit, analyze_contract
from phase2_llm_engine.prompt_builder import build_batch_audit_prompt
from phase4_evaluation.scorer import compute_metrics, evaluate_batch

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _extract_flagged_lines(response: str, source_code: str) -> list[int]:
    """
    Heuristically extract line numbers from the LLM response.

    Looks for patterns like:
    - "line 42"  /  "line 42-45"
    - "L42"  /  "L42-45"
    - Function names that appear in the response and match lines in the source.
    """
    lines = source_code.splitlines()
    flagged: set[int] = set()

    # Pattern: "line 42" or "lines 42-45" (1-indexed)
    for m in re.finditer(r"\blines?\s+(\d+)(?:\s*[-–]\s*(\d+))?", response, re.IGNORECASE):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        for ln in range(start, end + 1):
            if 1 <= ln <= len(lines):
                flagged.add(ln)

    # Pattern: "L42" or "L42-45"
    for m in re.finditer(r"\bL(\d+)(?:\s*[-–]\s*L?(\d+))?", response):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        for ln in range(start, end + 1):
            if 1 <= ln <= len(lines):
                flagged.add(ln)

    # Match function names mentioned in the response against source lines
    func_names_in_response = re.findall(r"\b(\w+)\(\)", response)
    for fn in func_names_in_response:
        for i, line in enumerate(lines, start=1):
            if re.search(rf"\bfunction\s+{re.escape(fn)}\s*\(", line):
                flagged.add(i)

    return sorted(flagged)


def _build_highlighted_html(source_code: str, flagged_lines: list[int]) -> str:
    """Build an HTML code block with flagged lines highlighted in red."""
    lines = source_code.splitlines()
    flagged_set = set(flagged_lines)
    html_lines = ['<pre style="background:#1e1e1e;color:#d4d4d4;padding:1em;border-radius:6px;overflow-x:auto;">']
    for i, line in enumerate(lines, start=1):
        escaped = (
            line.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        line_num = f"<span style='color:#858585;user-select:none'>{i:4d} | </span>"
        if i in flagged_set:
            html_lines.append(
                f'<span style="background:#5a1a1a;display:block">{line_num}'
                f'<span style="color:#f14c4c">{escaped}</span></span>'
            )
        else:
            html_lines.append(f"<span style='display:block'>{line_num}{escaped}</span>")
    html_lines.append("</pre>")
    return "\n".join(html_lines)


def _is_positive_finding(response: str) -> bool:
    """Return True if response likely indicates a vulnerability finding."""
    return response.strip().upper().startswith("YES") or ("YES" in response[:20].upper())


def _chunk_list(items: list[str], chunk_size: int) -> list[list[str]]:
    """Split items into fixed-size chunks."""
    if chunk_size <= 0:
        return [items]
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def _extract_json_payload(raw_text: str) -> dict | None:
    """Extract and parse a JSON object from model output (supports fenced blocks)."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = cleaned[start:end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            return None
    return None


def _build_batch_messages(source_code: str, selected_batch: list[dict], mode: str) -> list[dict]:
    """Build one prompt that audits a batch of vulnerabilities (uses shared prompt with hints)."""
    return build_batch_audit_prompt(source_code, selected_batch, mode)


def _format_batch_item_as_response(item: dict) -> str:
    """Convert parsed batch JSON item to response text compatible with existing UI logic."""
    verdict = str(item.get("verdict", "UNCERTAIN")).upper()
    explanation = str(item.get("explanation", "")).strip()
    recommendation = str(item.get("recommendation", "")).strip()
    confidence = item.get("confidence", None)
    evidence_lines = item.get("evidence_lines", [])

    if isinstance(evidence_lines, list):
        line_tokens = [f"L{ln}" for ln in evidence_lines if isinstance(ln, int)]
    else:
        line_tokens = []

    lines_text = ", ".join(line_tokens) if line_tokens else "None"
    confidence_text = f"{float(confidence):.2f}" if isinstance(confidence, (int, float)) else "N/A"

    return (
        f"{verdict}\n"
        f"Confidence: {confidence_text}\n"
        f"Explanation: {explanation}\n"
        f"Evidence lines: {lines_text}\n"
        f"Recommendation: {recommendation}"
    )


def _run_batched_checks(
    source_code: str,
    selected_vuln_names: list[str],
    mode: str,
    model_choice: str,
    temperature: float,
    batch_size: int,
    progress_bar,
    status_text,
) -> list[dict]:
    """Run vulnerability checks in batches and split JSON output back per vulnerability."""
    vuln_by_name = {v["name"]: v for v in VULNERABILITY_TYPES}
    selected_vulns = [vuln_by_name[name] for name in selected_vuln_names if name in vuln_by_name]
    chunks = _chunk_list([v["name"] for v in selected_vulns], max(1, batch_size))

    results: list[dict] = []
    completed = 0
    total = len(selected_vuln_names)

    for chunk_idx, chunk_names in enumerate(chunks, start=1):
        status_text.text(
            f"Checking batch {chunk_idx}/{len(chunks)}: {', '.join(chunk_names[:2])}"
            + (" ..." if len(chunk_names) > 2 else "")
        )
        logger.info(
            "Checking vulnerability batch %d/%d (%d items)",
            chunk_idx,
            len(chunks),
            len(chunk_names),
        )

        chunk_vulns = [vuln_by_name[name] for name in chunk_names]
        messages = _build_batch_messages(source_code, chunk_vulns, mode)

        try:
            raw_response = query_llm(messages, model=model_choice, temperature=temperature)
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
                    response = (
                        "ERROR: Batch result missing this vulnerability in JSON output. "
                        "Try smaller batch size."
                    )
                else:
                    response = _format_batch_item_as_response(item)
                results.append({"vuln_name": vuln_name, "response": response})
                completed += 1
                progress_bar.progress(completed / total)

        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed vulnerability batch %d/%d", chunk_idx, len(chunks))
            for vuln_name in chunk_names:
                results.append({"vuln_name": vuln_name, "response": f"ERROR: {exc}"})
                completed += 1
                progress_bar.progress(completed / total)

    return results

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Smart Contract Auditor",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Smart Contract Vulnerability Auditor")
st.caption(
    "Human-in-the-Loop interface for LLM-assisted smart contract security auditing."
)
st.info(
    "流程: 1) 粘贴/上传合约 2) 在侧边栏选择 **Audit Mode** 和模型 3) 选择漏洞类型 4) Run Audit"
)

# ---------------------------------------------------------------------------
# Sidebar – configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Configuration")

    st.subheader("📋 Audit Mode")
    audit_mode = st.radio(
        "选择审计模式",
        options=["standard", "agent", "multi_llm", "multi_llm_agent"],
        format_func=lambda x: {
            "standard": "① Standard — 单模型直接分析",
            "agent": "② Agent — 单模型分析 + 另一模型判断",
            "multi_llm": "③ Multi-LLM — 多模型各自分析，多数投票",
            "multi_llm_agent": "④ Multi-LLM + Agent — 多模型各自 2 步推理，再投票",
        }[x],
        index=0,
        help="Standard=快; Agent=每步有反思; Multi-LLM=多模型投票; ④=最严格",
    )

    model_options = ["gpt-4o", "gpt-4o-mini", "deepseek-v3.2", "claude-3-5-sonnet", "custom"]
    default_model_index = model_options.index(DEFAULT_MODEL) if DEFAULT_MODEL in model_options else 0
    model_choice = st.selectbox("主模型 (Standard/Agent 用)", model_options, index=min(default_model_index, 4))
    if model_choice == "custom":
        model_choice = st.text_input("Custom model", placeholder="e.g. deepseek-chat")

    agent_judge_model = None
    multi_models = ["gpt-4o", "gpt-4o-mini"]
    aggregation_mode = "majority"

    if audit_mode in ("agent", "multi_llm_agent"):
        agent_judge_model = st.selectbox(
            "Judge 模型 (反思/判断用)",
            options=["gpt-4o", "gpt-4o-mini", "deepseek-v3.2", "claude-3-5-sonnet"],
            index=2,
            help="对每个分析结果做二次判断",
        )
    if audit_mode in ("multi_llm", "multi_llm_agent"):
        multi_models = st.multiselect(
            "参与投票的模型",
            options=["gpt-4o", "gpt-4o-mini", "deepseek-v3.2", "claude-3-5-sonnet"],
            default=["gpt-4o", "gpt-4o-mini"],
            key="multi_llm_models",
        )
        aggregation_mode = st.radio("聚合方式", ["majority", "consensus"], format_func=lambda x: "多数投票" if x == "majority" else "全一致")

    temperature = st.slider("Temperature", 0.0, 1.0, float(TEMPERATURE), 0.1)
    mode = st.selectbox(
        "Classification Mode",
        ["binary", "non_binary", "cot", "multi_vuln"],
        index=1,
        help="non_binary=详细解释; binary=仅 YES/NO",
    )
    batch_size = st.slider("Batch Size (Standard 模式)", 1, 12, max(1, min(BATCH_VULNS_PER_PROMPT, 12)), 1)

    # Workflow summary
    workflow_desc = {
        "standard": f"→ {model_choice} 直接分析",
        "agent": f"→ {model_choice} 分析 → {agent_judge_model or 'same'} 判断",
        "multi_llm": f"→ {', '.join(multi_models)} 各自分析 → {aggregation_mode} 投票",
        "multi_llm_agent": f"→ 各模型({', '.join(multi_models)})分析+{agent_judge_model}判断 → {aggregation_mode} 投票",
    }[audit_mode]
    st.info(f"**当前流程:** {workflow_desc}")

    st.markdown("---")
    st.header("📊 Scoring Dashboard")
    if "score_history" not in st.session_state:
        st.session_state.score_history = []

    if st.session_state.score_history:
        tp = sum(r["tp"] for r in st.session_state.score_history)
        fp = sum(r["fp"] for r in st.session_state.score_history)
        tn = sum(r["tn"] for r in st.session_state.score_history)
        fn = sum(r["fn"] for r in st.session_state.score_history)
        metrics = compute_metrics(tp, fp, tn, fn)
        col1, col2 = st.columns(2)
        with col1:
            st.metric("TP", tp)
            st.metric("FP", fp)
        with col2:
            st.metric("TN", tn)
            st.metric("FN", fn)
        st.metric("F1 Score", f"{metrics['f1']:.4f}")
        st.metric("Precision", f"{metrics['precision']:.4f}")
        st.metric("Recall", f"{metrics['recall']:.4f}")
        if st.button("Clear History"):
            st.session_state.score_history = []
            st.rerun()

# ---------------------------------------------------------------------------
# Main area – contract input
# ---------------------------------------------------------------------------

tab_paste, tab_upload, tab_benchmark = st.tabs(["📝 Paste Code", "📂 Upload File", "📊 Benchmark"])

source_code_input = ""

with tab_paste:
    source_code_input = st.text_area(
        "Paste Solidity source code here:",
        height=300,
        placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n...",
    )

with tab_upload:
    uploaded_file = st.file_uploader("Upload a .sol or .json file", type=["sol", "json"])
    if uploaded_file is not None:
        raw = uploaded_file.read().decode("utf-8")
        if uploaded_file.name.endswith(".json"):
            try:
                data = json.loads(raw)
                source_code_input = data.get("source_code", raw)
            except json.JSONDecodeError:
                source_code_input = raw
        else:
            source_code_input = raw

with tab_benchmark:
    st.subheader("📊 Benchmark 数据集")
    from phase1_data_pipeline.benchmark_datasets import load_benchmark

    bench_dataset = st.selectbox("数据集", ["smartbugs", "solidifi"], index=0)
    bench_limit = st.number_input("加载前 N 条合约", min_value=1, max_value=200, value=3, step=1)
    if st.button("📥 Load Benchmark"):
        contracts = load_benchmark(bench_dataset)
        if not contracts:
            st.error(f"数据集 '{bench_dataset}' 未找到，请先运行: git clone ... data/benchmarks/{bench_dataset}")
        else:
            subset = contracts[:bench_limit]
            st.session_state.benchmark_contracts = subset
            st.session_state.benchmark_ground_truth = {
                c["name"]: [lb["vuln_type"] for lb in c.get("labels", [])]
                for c in subset
            }
            st.success(f"已加载 {len(subset)} 条合约")

    if "benchmark_contracts" in st.session_state:
        bc = st.session_state.benchmark_contracts
        st.markdown(f"**已加载 {len(bc)} 条:**")
        for i, c in enumerate(bc):
            labels_str = ", ".join(lb["vuln_type"] for lb in c.get("labels", []))
            st.caption(f"{i + 1}. **{c['name']}** — Ground Truth: [{labels_str}]")
        st.markdown("---")
        st.subheader("JSON 预览")
        display_data = [
            {"name": c["name"], "labels": [lb["vuln_type"] for lb in c.get("labels", [])], "source": c.get("source", "")}
            for c in bc
        ]
        st.json(display_data)

        # Vuln types to check: union of all ground-truth labels in loaded contracts
        gt = st.session_state.benchmark_ground_truth
        bench_vulns = sorted(set(v for vulns in gt.values() for v in vulns))
        st.caption(f"将检测的漏洞类型 (来自 Ground Truth): {', '.join(bench_vulns) if bench_vulns else '无'}")

        if st.button("🚀 Run Benchmark Audit", type="primary", key="run_bench_audit"):
            if not bench_vulns:
                st.error("加载的合约无 Ground Truth 标签，无法评估")
            else:
                st.session_state.benchmark_audit_requested = True
                st.rerun()

    # Run benchmark audit when requested (uses sidebar config: model_choice, mode, etc.)
    if st.session_state.get("benchmark_audit_requested") and "benchmark_contracts" in st.session_state:
        bc = st.session_state.benchmark_contracts
        gt = st.session_state.benchmark_ground_truth
        bench_vulns = sorted(set(v for vulns in gt.values() for v in vulns))
        if bench_vulns:
            st.session_state.benchmark_audit_requested = False
            progress_bar = st.progress(0)
            status = st.empty()
            audit_results = []
            for i, contract in enumerate(bc):
                status.text(f"Auditing {i + 1}/{len(bc)}: {contract['name']}")
                preprocessed = preprocess_contract(contract["source_code"], model=model_choice)
                src = preprocessed["source_code"]
                try:
                    res = analyze_contract(
                        source_code=src,
                        contract_name=contract["name"],
                        mode=mode,
                        model=model_choice,
                        temperature=temperature,
                        vuln_filter=bench_vulns,
                    )
                    audit_results.append(res)
                except Exception as exc:
                    audit_results.append({
                        "contract_name": contract["name"],
                        "vuln_results": [],
                        "error": str(exc),
                    })
                progress_bar.progress((i + 1) / len(bc))
            status.text("✅ Audit complete. Computing metrics...")
            scores = evaluate_batch(audit_results, gt)
            st.session_state.benchmark_audit_results = {"audit_results": audit_results, "scores": scores}
            progress_bar.empty()
            status.empty()
            st.rerun()

    if "benchmark_audit_results" in st.session_state:
        bar = st.session_state.benchmark_audit_results
        st.subheader("📈 Benchmark 评估结果")
        agg = bar["scores"].get("aggregate", {})
        counts = agg.get("counts", {})
        metrics = agg.get("metrics", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("TP", counts.get("TP", 0))
        c2.metric("FP", counts.get("FP", 0))
        c3.metric("TN", counts.get("TN", 0))
        c4.metric("FN", counts.get("FN", 0))
        st.metric("F1", f"{metrics.get('f1', 0):.4f}")
        st.markdown("---")
        st.subheader("结果 JSON")
        export = {
            "per_contract": bar["scores"].get("per_contract", []),
            "aggregate": agg,
            "audit_results": [
                {"contract_name": r["contract_name"], "vuln_results": r.get("vuln_results", [])}
                for r in bar["audit_results"]
            ],
        }
        st.json(export)
        if st.button("Clear Benchmark Results", key="clear_bench_results"):
            del st.session_state.benchmark_audit_results
            st.rerun()

source_code = source_code_input

# ---------------------------------------------------------------------------
# Token count + preprocessing
# ---------------------------------------------------------------------------

if source_code:
    token_count = count_tokens(source_code, model_choice)
    st.info(f"Token count: **{token_count:,}**")
    preprocessed = preprocess_contract(source_code, model=model_choice)
    if preprocessed["truncated"]:
        st.warning(
            f"⚠️ Contract was truncated to fit within the context window "
            f"(original: {token_count:,} → {preprocessed['token_count']:,} tokens)."
        )
    source_code = preprocessed["source_code"]

# ---------------------------------------------------------------------------
# Vulnerability selection
# ---------------------------------------------------------------------------

st.subheader("🔍 Vulnerability Selection")

vuln_names = [v["name"] for v in VULNERABILITY_TYPES]
if "selected_vulns" not in st.session_state:
    st.session_state.selected_vulns = vuln_names[:5]

quick_col1, quick_col2, quick_col3 = st.columns(3)
with quick_col1:
    if st.button("Top 5", use_container_width=True):
        st.session_state.selected_vulns = vuln_names[:5]
        st.rerun()
with quick_col2:
    if st.button("Select All", use_container_width=True):
        st.session_state.selected_vulns = vuln_names
        st.rerun()
with quick_col3:
    if st.button("Clear", use_container_width=True):
        st.session_state.selected_vulns = []
        st.rerun()

selected_vulns = st.multiselect(
    "Select vulnerability types to check:",
    vuln_names,
    key="selected_vulns",
)

effective_selected_vulns = selected_vulns

estimated_batches = (
    max(1, math.ceil(len(effective_selected_vulns) / max(1, batch_size)))
    if effective_selected_vulns
    else 0
)
estimated_seconds = max(1, int(estimated_batches * API_PAUSE_SECONDS)) if effective_selected_vulns else 0
if audit_mode in ("multi_llm", "multi_llm_agent") and multi_models:
    n = len(effective_selected_vulns) * len(multi_models)
    mult = 2 if audit_mode == "multi_llm_agent" else 1
    total_calls = n * mult
    estimated_seconds = max(1, int(total_calls * API_PAUSE_SECONDS)) if effective_selected_vulns else 0
    st.caption(
        f"{len(effective_selected_vulns)} vulns × {len(multi_models)} models × {mult} steps = {total_calls} API calls • ~{estimated_seconds}s"
    )
else:
    st.caption(
        f"Selected: {len(effective_selected_vulns)} • batches: {estimated_batches} • ~{estimated_seconds}s"
    )

# ---------------------------------------------------------------------------
# Audit button
# ---------------------------------------------------------------------------

if not source_code:
    st.warning("Add Solidity code first to enable audit.")

if st.button("🚀 Run Audit", type="primary", disabled=not source_code or not effective_selected_vulns):
    if not effective_selected_vulns:
        st.error("Please select at least one vulnerability type.")
    else:
        if audit_mode in ("multi_llm", "multi_llm_agent"):
            use_agent = audit_mode == "multi_llm_agent"
            logger.info(
                "Multi-LLM audit: models=%s agent=%s aggregation=%s",
                multi_models,
                use_agent,
                aggregation_mode,
            )
            progress_bar = st.progress(0)
            status_text = st.empty()
            multi_kwargs = dict(
                source_code=source_code,
                contract_name="uploaded_contract",
                models=multi_models,
                mode=mode,
                temperature=temperature,
                aggregation=aggregation_mode,
                vuln_filter=effective_selected_vulns,
                progress_callback=lambda c, t, m: (
                    progress_bar.progress(c / max(1, t)),
                    status_text.text(m),
                ),
            )
            if use_agent:
                multi_kwargs["agent_mode"] = True
                multi_kwargs["agent_judge_model"] = agent_judge_model
            multi_result = run_multi_llm_audit(**multi_kwargs)
            status_text.text("✅ Multi-LLM audit complete!")
            results = [
                {"vuln_name": vr["vuln_name"], "response": vr["response"]}
                for vr in multi_result.get("vuln_results", [])
                if vr["vuln_name"] in effective_selected_vulns
            ]
            if not results:
                results = [{"vuln_name": vr["vuln_name"], "response": vr["response"]} for vr in multi_result.get("vuln_results", [])]
            st.session_state.last_results = results
            st.session_state.last_source = source_code
        elif audit_mode == "agent":
            logger.info("Agent audit: model=%s judge=%s", model_choice, agent_judge_model)
            progress_bar = st.progress(0)
            status_text = st.empty()
            agent_result = analyze_contract(
                source_code=source_code,
                contract_name="uploaded_contract",
                mode=mode,
                model=model_choice,
                temperature=temperature,
                agent_mode=True,
                agent_judge_model=agent_judge_model,
                vuln_filter=effective_selected_vulns,
                progress_callback=lambda c, t, m: (
                    progress_bar.progress(c / max(1, t)),
                    status_text.text(m),
                ),
            )
            status_text.text("✅ Agent audit complete!")
            st.session_state.last_results = [{"vuln_name": vr["vuln_name"], "response": vr["response"]} for vr in agent_result.get("vuln_results", [])]
            st.session_state.last_source = source_code
        else:
            logger.info(
                "Audit started: model=%s mode=%s selected_vulnerabilities=%d",
                model_choice,
                mode,
                len(effective_selected_vulns),
            )
            progress_bar = st.progress(0)
            status_text = st.empty()

            results = _run_batched_checks(
                source_code=source_code,
                selected_vuln_names=effective_selected_vulns,
                mode=mode,
                model_choice=model_choice,
                temperature=temperature,
                batch_size=batch_size,
                progress_bar=progress_bar,
                status_text=status_text,
            )

            status_text.text("✅ Audit complete!")
            logger.info("Audit completed: processed_vulnerabilities=%d", len(effective_selected_vulns))
            st.session_state.last_results = results
            st.session_state.last_source = source_code

# ---------------------------------------------------------------------------
# Results display with line highlighting
# ---------------------------------------------------------------------------

if "last_results" in st.session_state:
    st.subheader("📋 Audit Results")
    results = st.session_state.last_results
    source = st.session_state.last_source

    total_checks = len(results)
    error_count = sum(1 for r in results if r["response"].startswith("ERROR:"))
    positive_count = sum(1 for r in results if _is_positive_finding(r["response"]))
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Checks", total_checks)
    c2.metric("Potential Findings", positive_count)
    c3.metric("Errors", error_count)

    for r in results:
        is_error = r["response"].startswith("ERROR:")
        is_vuln = _is_positive_finding(r["response"])
        icon = "🔴" if is_vuln else "🟢"
        if is_error:
            icon = "🟠"
        with st.expander(f"{icon} {r['vuln_name']}", expanded=is_vuln or is_error):
            st.write(r["response"])

            # ── Highlight flagged lines ──────────────────────────────────────
            # Extract line numbers or function names from the response
            flagged_lines = _extract_flagged_lines(r["response"], source)
            if flagged_lines:
                st.markdown("**🔦 Flagged lines:**")
                highlighted_html = _build_highlighted_html(source, flagged_lines)
                st.markdown(highlighted_html, unsafe_allow_html=True)
            elif is_error:
                st.info("No code lines highlighted because this check returned an API/runtime error.")

            # ── Human-in-the-Loop scoring ────────────────────────────────────
            st.markdown("**✅ Human Verification:**")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("True Positive", key=f"tp_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 1, "fp": 0, "tn": 0, "fn": 0}
                    )
                    st.success("Recorded as True Positive")
            with col2:
                if st.button("False Positive", key=f"fp_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 0, "fp": 1, "tn": 0, "fn": 0}
                    )
                    st.info("Recorded as False Positive")
            with col3:
                if st.button("False Negative", key=f"fn_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 0, "fp": 0, "tn": 0, "fn": 1}
                    )
                    st.warning("Recorded as False Negative")


