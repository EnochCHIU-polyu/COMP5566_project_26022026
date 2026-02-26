"""
Phase 4 – Evaluation: Human-in-the-Loop Streamlit UI.

Run with:
    streamlit run phase4_evaluation/ui_app.py

Features:
- Upload or paste a Solidity contract.
- Enter API keys locally (stored only in the browser session – never written to disk).
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

# ---------------------------------------------------------------------------
# Make parent directory importable when running as `streamlit run ...`
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd

from config import DEFAULT_MODEL, TEMPERATURE, CLASSIFICATION_MODE, OPENAI_API_KEY, ANTHROPIC_API_KEY
from phase1_data_pipeline.token_counter import count_tokens
from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
from phase2_llm_engine.prompt_builder import build_prompt, extract_function_names
from phase2_llm_engine.llm_client import query_llm
from phase4_evaluation.scorer import compute_metrics

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Smart Contract Auditor",
    page_icon="🔐",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Custom CSS for a cleaner look
# ---------------------------------------------------------------------------

st.markdown(
    """
    <style>
    /* Tighten the sidebar */
    section[data-testid="stSidebar"] > div { padding-top: 1rem; }
    /* Card-like expanders */
    div[data-testid="stExpander"] { border: 1px solid #2d2d2d; border-radius: 8px; margin-bottom: 0.5rem; }
    /* Subtle metric boxes */
    div[data-testid="stMetric"] { background: #1a1a2e; border-radius: 6px; padding: 0.4rem 0.6rem; }
    /* Primary button */
    button[kind="primary"] { width: 100%; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 Smart Contract Vulnerability Auditor")
st.caption(
    "Human-in-the-Loop interface for LLM-assisted smart contract security auditing."
)

# ---------------------------------------------------------------------------
# Sidebar – configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Configuration")

    # ── API Keys ──────────────────────────────────────────────────────────────
    with st.expander("🔑 API Keys", expanded=not bool(OPENAI_API_KEY or ANTHROPIC_API_KEY)):
        st.caption(
            "Keys are stored **only** in your browser session and are never written to disk. "
            "Leave blank to use the value from your `.env` file."
        )
        ui_openai_key = st.text_input(
            "OpenAI API Key",
            type="password",
            value="",
            placeholder="sk-…  (leave blank to use .env)",
            key="openai_key_input",
        )
        ui_anthropic_key = st.text_input(
            "Anthropic API Key",
            type="password",
            value="",
            placeholder="sk-ant-…  (leave blank to use .env)",
            key="anthropic_key_input",
        )

    # Resolve the effective key: UI input takes priority over env/config value
    effective_openai_key: str = ui_openai_key.strip() or OPENAI_API_KEY
    effective_anthropic_key: str = ui_anthropic_key.strip() or ANTHROPIC_API_KEY

    st.markdown("---")

    # ── Model & inference settings ────────────────────────────────────────────
    st.subheader("🤖 Model Settings")

    model_choice = st.selectbox(
        "LLM Model",
        [
            "gpt-4o",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
        ],
        index=0,
        help="OpenAI models require an OpenAI key; Claude models require an Anthropic key.",
    )

    temperature = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=float(TEMPERATURE),
        step=0.1,
        help="0 = deterministic, 1 = more creative / random",
    )

    mode = st.radio(
        "Classification Mode",
        ["binary", "non_binary"],
        index=0 if CLASSIFICATION_MODE == "binary" else 1,
        format_func=lambda m: "Binary (YES / NO)" if m == "binary" else "Non-Binary (detailed)",
        help="Binary = fast YES/NO; Non-Binary = full explanation",
    )

    # Warn if the selected model has no key
    if model_choice.startswith("claude") and not effective_anthropic_key:
        st.warning("⚠️ No Anthropic API key provided.")
    elif not model_choice.startswith("claude") and not effective_openai_key:
        st.warning("⚠️ No OpenAI API key provided.")
    else:
        st.success("✅ API key configured")

    st.markdown("---")

    # ── Scoring Dashboard ─────────────────────────────────────────────────────
    st.subheader("📊 Scoring Dashboard")
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

        if st.button("🗑️ Clear History"):
            st.session_state.score_history = []
            st.rerun()
    else:
        st.info("No evaluations recorded yet.")

# ---------------------------------------------------------------------------
# Main area – contract input
# ---------------------------------------------------------------------------

tab_paste, tab_upload = st.tabs(["📝 Paste Code", "📂 Upload File"])

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

source_code = source_code_input

# ---------------------------------------------------------------------------
# Token count + preprocessing
# ---------------------------------------------------------------------------

if source_code:
    token_count = count_tokens(source_code, model_choice)
    st.info(f"📏 Token count: **{token_count:,}**")
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

col_sel, col_all = st.columns([4, 1])
vuln_names = [v["name"] for v in VULNERABILITY_TYPES]

with col_all:
    run_all = st.checkbox("Select all", value=False)

with col_sel:
    selected_vulns = st.multiselect(
        "Select vulnerability types to check:",
        vuln_names,
        default=vuln_names[:5],
        disabled=run_all,
    )

if run_all:
    selected_vulns = vuln_names

# ---------------------------------------------------------------------------
# Audit button
# ---------------------------------------------------------------------------

# Determine the effective API key for the chosen model
_active_api_key = effective_anthropic_key if model_choice.startswith("claude") else effective_openai_key

col_run, col_clear = st.columns([3, 1])
with col_run:
    run_disabled = not source_code or not _active_api_key
    run_help = "Provide source code and an API key to run the audit." if run_disabled else None
    run_audit = st.button(
        "🚀 Run Audit",
        type="primary",
        disabled=run_disabled,
        help=run_help,
        use_container_width=True,
    )
with col_clear:
    if st.button("🧹 Clear Results", use_container_width=True):
        st.session_state.pop("last_results", None)
        st.session_state.pop("last_source", None)
        st.rerun()

if run_audit:
    if not selected_vulns:
        st.error("Please select at least one vulnerability type.")
    else:
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()

        for i, vuln_name in enumerate(selected_vulns):
            vuln = next(v for v in VULNERABILITY_TYPES if v["name"] == vuln_name)
            status_text.text(f"Checking: {vuln_name} ({i + 1}/{len(selected_vulns)})")
            messages = build_prompt(
                source_code=source_code,
                vuln_name=vuln["name"],
                vuln_description=vuln["description"],
                mode=mode,
            )
            try:
                response = query_llm(
                    messages,
                    model=model_choice,
                    temperature=temperature,
                    api_key=_active_api_key or None,
                )
            except Exception as exc:  # noqa: BLE001
                response = f"ERROR: {exc}"
            results.append({"vuln_name": vuln_name, "response": response})
            progress_bar.progress((i + 1) / len(selected_vulns))

        status_text.text("✅ Audit complete!")
        st.session_state.last_results = results
        st.session_state.last_source = source_code

# ---------------------------------------------------------------------------
# Results display with line highlighting
# ---------------------------------------------------------------------------

if "last_results" in st.session_state:
    st.subheader("📋 Audit Results")
    results = st.session_state.last_results
    source = st.session_state.last_source

    # Summary bar
    n_flagged = sum(1 for r in results if _is_vulnerability_flagged(r["response"]))
    n_total = len(results)
    if n_flagged:
        st.error(f"🔴 {n_flagged} / {n_total} vulnerability type(s) flagged")
    else:
        st.success(f"🟢 No vulnerabilities detected across {n_total} check(s)")

    for r in results:
        is_vuln = _is_vulnerability_flagged(r["response"])
        icon = "🔴" if is_vuln else "🟢"
        with st.expander(f"{icon} {r['vuln_name']}", expanded=is_vuln):
            st.write(r["response"])

            # ── Highlight flagged lines ──────────────────────────────────────
            flagged_lines = _extract_flagged_lines(r["response"], source)
            if flagged_lines:
                st.markdown("**🔦 Flagged lines:**")
                highlighted_html = _build_highlighted_html(source, flagged_lines)
                st.markdown(highlighted_html, unsafe_allow_html=True)

            # ── Human-in-the-Loop scoring ────────────────────────────────────
            st.markdown("**✅ Human Verification:**")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("✔️ True Positive", key=f"tp_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 1, "fp": 0, "tn": 0, "fn": 0}
                    )
                    st.success("Recorded as True Positive")
            with col2:
                if st.button("✖️ False Positive", key=f"fp_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 0, "fp": 1, "tn": 0, "fn": 0}
                    )
                    st.info("Recorded as False Positive")
            with col3:
                if st.button("⚠️ False Negative", key=f"fn_{r['vuln_name']}"):
                    st.session_state.score_history.append(
                        {"tp": 0, "fp": 0, "tn": 0, "fn": 1}
                    )
                    st.warning("Recorded as False Negative")


def _is_vulnerability_flagged(response: str) -> bool:
    """Return True when the LLM response indicates a vulnerability was detected."""
    return response.strip().upper().startswith("YES") or "YES" in response[:20].upper()


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
