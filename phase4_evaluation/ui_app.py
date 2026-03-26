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
- Optional Benchmark tab: load SmartBugs/SolidiFI subset, run audit vs ground truth, show aggregate metrics.
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
from phase2_llm_engine.cot_analyzer import analyze_contract, analyze_contract_cascade, run_multi_llm_audit
from phase4_evaluation.scorer import compute_metrics, evaluate_batch

# Models available for cascade / multi-LLM (no "custom" placeholder in multiselects).
_KNOWN_MODEL_IDS = [
    "deepseek-v3.2",
    "gpt-4o",
    "gpt-4o-mini",
]

PIPELINE_LABELS = {
    "standard": "Standard (batch JSON)",
    "cascade": "Cascade (small→large + per-function CoT)",
    "multi_llm": "Multi-LLM (ensemble)",
}

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
    """Build one prompt that audits a batch of vulnerabilities and returns strict JSON."""
    mode_instruction = {
        "binary": "Use YES/NO verdict for each vulnerability, with a concise but specific explanation.",
        "non_binary": "Provide detailed explanation for each vulnerability, including why it applies or does not apply.",
        "cot": "Reason step-by-step internally and provide concise final explanations without revealing hidden chain-of-thought.",
        "multi_vuln": "Audit all listed vulnerabilities together and provide detailed per-vulnerability explanations.",
    }.get(mode, "Provide detailed explanation for each vulnerability.")

    vuln_block = "\n".join(
        f"- {v['name']}: {v['description']}" for v in selected_batch
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
        "Requirements:\n"
        "1) Return one result object for EVERY listed vulnerability (no omissions).\n"
        "2) Keep vuln_name exactly identical to the provided name.\n"
        "3) For each item, verdict MUST be YES or NO (binary judgment); use UNCERTAIN only if truly impossible.\n"
        "4) explanation must be specific and detailed per vulnerability.\n"
        "5) evidence_lines should contain concrete line numbers when available, else [].\n"
        "6) recommendation should be a practical fix for that vulnerability.\n\n"
        f"Output schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Source Code:\n{source_code}"
    )

    return [
        {"role": "system", "content": "You are a senior smart contract security auditor. Output valid JSON only."},
        {"role": "user", "content": user_prompt},
    ]


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
    "Workflow: (1) Paste or upload a contract, (2) choose model, mode, and pipeline in the sidebar, "
    "(3) select vulnerability types, (4) Run Audit, (5) review results — prompts require **YES/NO on line 1** "
    "for per-vulnerability checks."
)

# ---------------------------------------------------------------------------
# Sidebar – configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Configuration")

    model_options = [
        "deepseek-v3.2",
        "gpt-4o",
        "gpt-4o-mini",
        "custom",
    ]
    default_model_index = model_options.index(DEFAULT_MODEL) if DEFAULT_MODEL in model_options else 0

    model_choice = st.selectbox(
        "LLM Model",
        model_options,
        index=default_model_index,
    )

    if model_choice == "custom":
        model_choice = st.text_input(
            "Custom model name",
            value="",
            placeholder="e.g. deepseek-chat",
        )

    st.caption(
        f"The selected model is passed to `query_llm`. CLI `python main.py audit` without `--model` "
        f"uses **DEFAULT_MODEL** from `.env` (currently `{DEFAULT_MODEL}`), not this dropdown."
    )

    temperature = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=float(TEMPERATURE),
        step=0.1,
        help="0 = deterministic, 1 = more creative",
    )

    mode_options = ["binary", "non_binary", "cot", "multi_vuln"]
    default_mode_index = mode_options.index(CLASSIFICATION_MODE) if CLASSIFICATION_MODE in mode_options else 1

    mode = st.selectbox(
        "Classification Mode",
        mode_options,
        index=default_mode_index,
        help=(
            "binary = concise verdict; non_binary = detailed per-vulnerability explanation; "
            "cot = deeper reasoning style; multi_vuln = optimized batch analysis"
        ),
    )

    use_agent = st.checkbox(
        "Agent mode (analyze → judge, same as CLI `--agent`)",
        value=False,
        disabled=(mode == "multi_vuln"),
        help=(
            "Per vulnerability: analyze, then a second model reviews. "
            "Final reply still starts with YES/NO for `infer_verdict_for_scoring` / Benchmark. "
            "This is not multi_vuln."
        ),
    )
    agent_judge_model: str | None = None
    if use_agent:
        _judge_options = ["(same as primary model)"] + _KNOWN_MODEL_IDS
        _j = st.selectbox("Judge model (second pass)", _judge_options, index=0)
        if _j != "(same as primary model)":
            agent_judge_model = _j

    st.markdown("---")
    st.subheader("Audit pipeline")
    audit_pipeline = st.radio(
        "Pipeline",
        options=list(PIPELINE_LABELS.keys()),
        format_func=lambda k: PIPELINE_LABELS[k],
        index=0,
        help="Standard matches CLI batch mode; Cascade mirrors --cascade; Multi-LLM mirrors audit-multi.",
    )

    cascade_small = "gpt-4o-mini"
    cascade_large = "gpt-4o"
    verify_cascade = False
    verify_rag_cascade = False
    multi_models = list(_KNOWN_MODEL_IDS)
    multi_parallel = False
    multi_aggregation = "majority"

    if audit_pipeline == "cascade":
        cascade_small = st.selectbox(
            "Small model (binary pass)",
            _KNOWN_MODEL_IDS,
            index=_KNOWN_MODEL_IDS.index("gpt-4o-mini") if "gpt-4o-mini" in _KNOWN_MODEL_IDS else 0,
        )
        cascade_large = st.selectbox(
            "Large model (deep pass + CoT)",
            _KNOWN_MODEL_IDS,
            index=_KNOWN_MODEL_IDS.index("gpt-4o") if "gpt-4o" in _KNOWN_MODEL_IDS else 0,
        )
        verify_cascade = st.checkbox(
            "Post-verify positive findings (self-check)",
            value=False,
            help="Same as CLI --verify; optional second pass on flagged issues.",
        )
        verify_rag_cascade = st.checkbox(
            "Use RAG in verification",
            value=False,
            disabled=not verify_cascade,
            help="Requires scikit-learn; same as --verify-rag.",
        )
    elif audit_pipeline == "multi_llm":
        multi_models = st.multiselect(
            "Models",
            _KNOWN_MODEL_IDS,
            default=["gpt-4o", "gpt-4o-mini", "deepseek-v3.2"],
            help="Each model runs the same batch audit; then votes are aggregated.",
        )
        multi_parallel = st.checkbox(
            "Run models in parallel",
            value=False,
            help="Faster; same as audit-multi --parallel. Watch rate limits.",
        )
        multi_aggregation = st.radio(
            "Aggregation",
            ["majority", "consensus"],
            horizontal=True,
            help="majority = >50% YES; consensus = all models must agree YES.",
        )

    batch_size = st.slider(
        "Batch Size (vulnerabilities per LLM call)",
        min_value=1,
        max_value=12,
        value=max(1, min(BATCH_VULNS_PER_PROMPT, 12)),
        step=1,
        help="Larger batch = fewer API calls and faster runs, but harder JSON parsing.",
        disabled=audit_pipeline != "standard",
    )

    st.caption(
        "Run locally: `streamlit run phase4_evaluation/ui_app.py` → http://localhost:8501"
    )

    # Current workflow summary (sidebar)
    _flow_parts = [
        f"Pipeline: **{PIPELINE_LABELS[audit_pipeline]}**",
        f"Primary model `{model_choice}`",
        f"Mode `{mode}`",
    ]
    if audit_pipeline == "cascade":
        _flow_parts.append(f"Cascade `{cascade_small}` → `{cascade_large}`")
    elif audit_pipeline == "multi_llm":
        _flow_parts.append(f"Models {', '.join(multi_models)} · {multi_aggregation}")
    if use_agent and mode != "multi_vuln":
        _flow_parts.append(f"Agent judge `{agent_judge_model or model_choice}`")
    st.info(" · ".join(_flow_parts))

    st.markdown("---")
    st.header("📊 Scoring Dashboard")

    if "score_history" not in st.session_state:
        st.session_state.score_history = []

    _hist = st.session_state.score_history
    tp = sum(r["tp"] for r in _hist)
    fp = sum(r["fp"] for r in _hist)
    tn = sum(r["tn"] for r in _hist)
    fn = sum(r["fn"] for r in _hist)
    metrics_hitl = compute_metrics(tp, fp, tn, fn)

    st.subheader("Human-in-the-loop")
    st.caption("In the main results area, click True Positive / False Positive / False Negative to record labels.")
    h1, h2 = st.columns(2)
    with h1:
        st.metric("TP", tp)
        st.metric("FP", fp)
    with h2:
        st.metric("TN", tn)
        st.metric("FN", fn)
    st.metric("F1 Score", f"{metrics_hitl['f1']:.4f}")
    st.metric("Precision", f"{metrics_hitl['precision']:.4f}")
    st.metric("Recall", f"{metrics_hitl['recall']:.4f}")
    if st.button("Clear HITL History", key="clear_hitl_sidebar"):
        st.session_state.score_history = []
        st.rerun()

    _bench = st.session_state.get("benchmark_audit_results")
    if _bench:
        st.subheader("Benchmark (latest run)")
        agg_b = _bench.get("scores", {}).get("aggregate", {})
        cnt_b = agg_b.get("counts", {})
        met_b = agg_b.get("metrics", {})
        b1, b2, b3, b4 = st.columns(4)
        b1.metric("TP", cnt_b.get("TP", 0))
        b2.metric("FP", cnt_b.get("FP", 0))
        b3.metric("TN", cnt_b.get("TN", 0))
        b4.metric("FN", cnt_b.get("FN", 0))
        st.metric("F1", f"{met_b.get('f1', 0):.4f}")
        _sk = agg_b.get("skipped_unparseable", 0)
        if _sk:
            st.caption(f"Unparseable replies (skipped): {_sk}")
        st.caption("Updated after you run an evaluation on the **Benchmark** tab. Clear results there.")

# `analyze_contract` returns early on multi_vuln — agent loop never runs.
agent_mode_effective = bool(use_agent) and mode != "multi_vuln"

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
    st.subheader("📊 Benchmark dataset")
    from phase1_data_pipeline.benchmark_datasets import load_benchmark

    bench_dataset = st.selectbox("Dataset", ["smartbugs", "solidifi"], index=0)
    bench_limit = st.number_input("Load first N contracts", min_value=1, max_value=200, value=3, step=1)
    if st.button("📥 Load Benchmark"):
        contracts = load_benchmark(bench_dataset)
        if not contracts:
            st.error(
                f"Dataset '{bench_dataset}' not found. Clone into "
                f"`data/benchmarks/{bench_dataset}` or run "
                f"`python main.py download-benchmarks --dataset {bench_dataset}`"
            )
        else:
            subset = contracts[: int(bench_limit)]
            st.session_state.benchmark_contracts = subset
            st.session_state.benchmark_ground_truth = {
                c["name"]: [lb["vuln_type"] for lb in c.get("labels", [])]
                for c in subset
            }
            st.success(f"Loaded {len(subset)} contract(s).")

    if "benchmark_contracts" in st.session_state:
        bc = st.session_state.benchmark_contracts
        st.markdown(f"**Loaded {len(bc)} contract(s):**")
        for i, c in enumerate(bc):
            labels_str = ", ".join(lb["vuln_type"] for lb in c.get("labels", []))
            st.caption(f"{i + 1}. **{c['name']}** — Ground truth: [{labels_str}]")
        st.markdown("---")
        st.subheader("JSON preview")
        display_data = [
            {
                "name": c["name"],
                "labels": [lb["vuln_type"] for lb in c.get("labels", [])],
                "source_code": (c.get("source_code") or "")[:2000],
            }
            for c in bc
        ]
        st.json(display_data)

        gt = st.session_state.benchmark_ground_truth
        bench_vulns = sorted({v for vulns in gt.values() for v in vulns})
        st.caption(
            f"Vulnerability types under test (from ground truth): "
            f"{', '.join(bench_vulns) if bench_vulns else '(none)'}"
        )
        st.info(
            "**Evaluation contract:** per-vulnerability checks; each model reply must yield a readable **YES/NO** "
            "on line 1 to compute TP/FP/TN/FN. "
            "**multi_vuln** is a single prompt for all types — not compatible with per-type labels. "
            "**Agent** (sidebar) adds a second pass; the stitched reply still starts with the final **YES/NO** verdict."
        )
        if mode == "multi_vuln":
            st.warning(
                "**multi_vuln** uses one batched prompt and cannot align with per-vulnerability ground truth. "
                "Switch Classification Mode to **binary**, **non_binary**, or **cot**."
            )

        if st.button(
            "🚀 Run Benchmark Audit",
            type="primary",
            key="run_bench_audit",
            disabled=(mode == "multi_vuln"),
        ):
            if not bench_vulns:
                st.error("Loaded contracts have no ground-truth labels; cannot evaluate.")
            else:
                st.session_state.benchmark_audit_requested = True
                st.rerun()

    if st.session_state.get("benchmark_audit_requested") and "benchmark_contracts" in st.session_state:
        bc = st.session_state.benchmark_contracts
        gt = st.session_state.benchmark_ground_truth
        bench_vulns = sorted({v for vulns in gt.values() for v in vulns})
        if bench_vulns:
            st.session_state.benchmark_audit_requested = False
            progress_bar = st.progress(0)
            status = st.empty()
            audit_results: list[dict] = []
            for i, contract in enumerate(bc):
                status.text(f"Auditing {i + 1}/{len(bc)}: {contract['name']}")
                raw_src = contract.get("source_code") or ""
                preprocessed = preprocess_contract(raw_src, model=model_choice)
                src = preprocessed["source_code"]
                try:
                    res = analyze_contract(
                        source_code=src,
                        contract_name=contract["name"],
                        mode=mode,
                        model=model_choice,
                        temperature=temperature,
                        vuln_filter=bench_vulns,
                        agent_mode=agent_mode_effective,
                        agent_judge_model=agent_judge_model,
                    )
                    audit_results.append(res)
                except Exception as exc:  # noqa: BLE001
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
        st.subheader("📈 Benchmark results")
        agg = bar["scores"].get("aggregate", {})
        counts = agg.get("counts", {})
        metrics = agg.get("metrics", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("TP", counts.get("TP", 0))
        c2.metric("FP", counts.get("FP", 0))
        c3.metric("TN", counts.get("TN", 0))
        c4.metric("FN", counts.get("FN", 0))
        st.metric("F1", f"{metrics.get('f1', 0):.4f}")
        _skip = agg.get("skipped_unparseable", 0)
        if _skip:
            st.warning(
                f"**{_skip}** vulnerability reply/replies could not be parsed as YES/NO and were skipped "
                "(not counted in TP/FP/TN/FN). Check the terminal for `Unparseable verdict` logs. "
                "Ensure line 1 is English **YES** or **NO** (prompts enforce this)."
            )
        st.markdown("---")
        st.subheader("Export JSON")
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
if audit_pipeline == "standard":
    st.caption(
        f"Selected checks: {len(effective_selected_vulns)} • batches: {estimated_batches} • "
        f"estimated minimum runtime: ~{estimated_seconds}s"
    )
else:
    st.caption(
        f"Selected checks: {len(effective_selected_vulns)} • pipeline: {PIPELINE_LABELS[audit_pipeline]} "
        "(runtime depends on API latency and contract size)"
    )

# ---------------------------------------------------------------------------
# Audit button
# ---------------------------------------------------------------------------

if not source_code:
    st.warning("Add Solidity code first to enable audit.")

_audit_disabled = (
    not source_code
    or not effective_selected_vulns
    or (audit_pipeline == "multi_llm" and not multi_models)
)
if st.button("🚀 Run Audit", type="primary", disabled=_audit_disabled):
    if not effective_selected_vulns:
        st.error("Please select at least one vulnerability type.")
    elif audit_pipeline == "multi_llm" and not multi_models:
        st.error("Multi-LLM requires at least one model in the sidebar.")
    else:
        logger.info(
            "Audit started: pipeline=%s model=%s mode=%s selected_vulnerabilities=%d",
            audit_pipeline,
            model_choice,
            mode,
            len(effective_selected_vulns),
        )
        progress_bar = st.progress(0)
        status_text = st.empty()

        def _progress_cb(cur: int, total: int, msg: str) -> None:
            if total and total > 0:
                progress_bar.progress(min(1.0, float(cur) / float(total)))
            status_text.text(msg)

        try:
            if audit_pipeline == "standard":
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
                st.session_state.cascade_extra = None
                st.session_state.last_pipeline = "standard"
            elif audit_pipeline == "cascade":
                status_text.text("Cascade audit running…")
                cascade_result = analyze_contract_cascade(
                    source_code=source_code,
                    contract_name="Streamlit",
                    small_model=cascade_small,
                    large_model=cascade_large,
                    temperature=temperature,
                    verify=verify_cascade,
                    verify_with_rag=verify_rag_cascade and verify_cascade,
                    vuln_filter=effective_selected_vulns,
                    progress_callback=_progress_cb,
                )
                results = [
                    {"vuln_name": r["vuln_name"], "response": r["response"]}
                    for r in cascade_result.get("vuln_results", [])
                ]
                st.session_state.cascade_extra = {
                    "function_results": cascade_result.get("function_results", []),
                    "verified_findings": cascade_result.get("verified_findings"),
                    "cascade_meta": cascade_result.get("cascade"),
                }
                st.session_state.last_pipeline = "cascade"
            else:
                status_text.text(
                    "Multi-LLM audit running…"
                    + (" (parallel)" if multi_parallel else "")
                )
                multi_result = run_multi_llm_audit(
                    source_code=source_code,
                    contract_name="Streamlit",
                    models=multi_models,
                    mode=mode,
                    temperature=temperature,
                    aggregation=multi_aggregation,
                    vuln_filter=effective_selected_vulns,
                    parallel_models=multi_parallel,
                    progress_callback=None if multi_parallel else _progress_cb,
                )
                results = [
                    {"vuln_name": r["vuln_name"], "response": r["response"]}
                    for r in multi_result.get("vuln_results", [])
                ]
                st.session_state.cascade_extra = {
                    "function_results": multi_result.get("function_results") or [],
                    "verified_findings": None,
                    "models_used": multi_result.get("models_used"),
                    "aggregation": multi_result.get("aggregation"),
                }
                st.session_state.last_pipeline = "multi_llm"
        except Exception as exc:  # noqa: BLE001
            logger.exception("Audit failed")
            st.error(f"Audit failed: {exc}")
            st.stop()

        progress_bar.progress(1.0)
        status_text.text("✅ Audit complete!")
        logger.info("Audit completed: processed_vulnerabilities=%d", len(results))
        st.session_state.last_results = results
        st.session_state.last_source = source_code

# ---------------------------------------------------------------------------
# Results display with line highlighting
# ---------------------------------------------------------------------------

if "last_results" in st.session_state:
    st.subheader("📋 Audit Results")
    _lp = st.session_state.get("last_pipeline", "standard")
    st.caption(f"Pipeline: {PIPELINE_LABELS.get(_lp, _lp)}")

    extra = st.session_state.get("cascade_extra")
    if extra:
        if extra.get("verified_findings"):
            st.subheader("🔎 Self-check verification")
            st.dataframe(pd.DataFrame(extra["verified_findings"]))
        fr_list = extra.get("function_results") or []
        if fr_list:
            st.subheader("🧩 Per-function CoT")
            for fr_item in fr_list:
                fn = fr_item.get("function_name", "?")
                with st.expander(f"Function: {fn}", expanded=False):
                    st.write(fr_item.get("response", ""))
        if extra.get("models_used"):
            st.caption(
                f"Multi-LLM models: {extra['models_used']} • aggregation: {extra.get('aggregation', '')}"
            )

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


