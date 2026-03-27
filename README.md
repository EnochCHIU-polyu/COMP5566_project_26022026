# COMP5566 Smart Contract Vulnerability Detection Framework

An LLM-powered security auditing framework for Ethereum smart contracts.  
It uses GPT-4 / Claude / DeepSeek to systematically check a contract against **38 known DeFi vulnerability types**, produces structured JSON findings with line-level citations, runs a self-consistency verification pass to reduce false positives, and provides a Streamlit web interface for human-in-the-loop review.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Project Structure](#2-project-structure)
   - [Frontend/Backend App Summary](#21-frontendbackend-app-summary)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
   - [Run Frontend + Backend (Full-Stack)](#41-run-frontend--backend-full-stack)
5. [Configuration](#5-configuration)
6. [Usage](#6-usage)
   - [Audit a Contract (CLI)](#61-audit-a-contract-via-cli)
   - [Generate Synthetic Contracts](#62-generate-synthetic-test-contracts)
   - [Download Benchmark Datasets](#63-download-benchmark-datasets)
   - [Generate an Audit Report](#64-generate-an-audit-report)
   - [Launch the Web UI](#65-launch-the-streamlit-web-ui)
7. [Running Tests](#7-running-tests)
8. [How It Works](#8-how-it-works)
   - [Prompt Architecture](#81-prompt-architecture)
   - [Self-Check Verification](#82-self-check-verification)
   - [Keyword Pre-Filtering](#83-keyword-pre-filtering)
   - [Evaluation Metrics](#84-evaluation-metrics)
9. [Phase-Level Documentation](#9-phase-level-documentation)

---

## 1. System Overview

The framework is organised into four phases, each substantially upgraded from the original baseline:

| Phase | Name                  | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | Data Pipeline         | Fetches contracts from Etherscan, loads SmartBugs / SolidiFI benchmark datasets, generates 15 synthetic templates with semantic mutation operators, normalises source code (comment stripping, line-number annotation), and smart-chunks large contracts instead of blindly truncating them.                                                                                                                                                                                                  |
| **2** | LLM Engine            | Builds structured prompts with a 4-section architecture (role, vulnerability context with examples, JSON output schema, line-numbered source). Supports _binary_, _non-binary_, _Chain-of-Thought_, and _multi-vuln batch_ modes. A keyword relevance pre-filter eliminates irrelevant checks (~60–80 % fewer API calls). A self-consistency verification pass re-checks each finding with a sceptical prompt to cut false positives. Exponential-backoff retry handles transient API errors. |
| **3** | Hyperparameter Tuning | `TuningConfig` dataclass with new fields (`verify`, `batch_vulns`, `use_filter`, `few_shot`). Predefined grid now includes GPT-4o, Claude-3-Opus, and DeepSeek-v3.2 at multiple temperatures, plus a multi-vuln batch config.                                                                                                                                                                                                                                                                 |
| **4** | Evaluation & UI       | Full metric suite: Precision / Recall / F1 (micro & macro), AUC-ROC, PR-AUC, per-vulnerability-type breakdown, and confidence calibration. Batch experiment runner executes the entire config grid against a benchmark dataset. Report generator produces markdown / HTML audit reports. Results logger persists all runs for reproducibility.                                                                                                                                                |

---

## 2. Project Structure

```
COMP5566_project_26022026/
├── config.py                              # Central config (API keys, model, temperature …)
├── main.py                                # CLI entry point
├── requirements.txt
│
├── phase1_data_pipeline/                  # → See phase1_data_pipeline/README.md
│   ├── benchmark_datasets.py              # SmartBugs / SolidiFI downloader + normaliser
│   ├── contract_chunker.py                # Function-level & sliding-window chunker
│   ├── contract_normalizer.py             # Comment stripping, whitespace, line numbering
│   ├── contract_preprocessor.py          # Token counting + normalise + chunk pipeline
│   ├── dataset_loader.py                  # Load .sol / .json files from disk
│   ├── etherscan_scraper.py               # Fetch verified contracts from Etherscan API
│   ├── synthetic_contracts.py             # 15 templates + semantic mutation operators
│   └── token_counter.py                   # tiktoken-based counting + fallback
│
├── phase2_llm_engine/                     # → See phase2_llm_engine/README.md
│   ├── cot_analyzer.py                    # Orchestrates full audit (38 vulns + CoT)
│   ├── llm_client.py                      # OpenAI / Anthropic / DeepSeek client + retry
│   ├── output_parser.py                   # Parse structured JSON findings from LLM output
│   ├── prompt_builder.py                  # 4-section prompt builder (structured / legacy)
│   ├── relevance_filter.py                # Keyword pre-filter to skip irrelevant checks
│   ├── self_checker.py                    # Two-pass self-consistency verification
│   └── vulnerability_types.py             # 38 vuln definitions with SWC/CWE/keywords
│
├── phase3_hyperparameter/                 # → See phase3_hyperparameter/README.md
│   └── tuning_config.py                   # TuningConfig dataclass + 9-config grid
│
├── phase4_evaluation/                     # → See phase4_evaluation/README.md
│   ├── experiment_runner.py               # Batch grid runner with resume support
│   ├── report_generator.py                # Markdown / HTML audit report generator
│   ├── results_logger.py                  # Persistent experiment logger + CSV export
│   ├── scorer.py                          # TP/FP/TN/FN + AUC-ROC / PR-AUC / calibration
│   └── ui_app.py                          # Streamlit human-in-the-loop web interface
│
├── data/
│   ├── benchmarks/                        # Cached SmartBugs / SolidiFI datasets
│   ├── vulnerable_contracts/              # Known-vulnerable .sol / .json files
│   └── synthetic_contracts/              # Auto-generated synthetic contracts
│
├── frontend/                              # React + TypeScript + Vite web client
│   ├── src/
│   │   ├── pages/                         # Landing/Audit/Benchmark/New Vulnerability pages
│   │   ├── features/                      # Feature modules (audit/benchmark/vulnerabilities)
│   │   └── components/                    # Shared layout/navigation components
│   └── README.md                          # Frontend setup and architecture notes
│
├── backend/                               # FastAPI service layer and API routes
│   ├── app/
│   │   ├── api/routes/                    # audits/benchmark/vulnerabilities endpoints
│   │   ├── schemas/                       # Pydantic request/response models
│   │   └── services/                      # Domain services and persistence integration
│   └── README.md                          # Backend setup and API notes
│
├── supabase/
│   ├── schema.sql                         # Shared database schema
│   └── migrations/                        # Incremental SQL migrations
│
├── results/                               # Experiment run outputs (auto-created)
└── tests/                                 # Pytest unit tests for all four phases
```

---

## 2.1 Frontend/Backend App Summary

This repository now includes a production-style full-stack web app in addition
to the Streamlit UI.

- Frontend: React + TypeScript + Vite + Tailwind
  - Source: `frontend/src/`
  - Main routes: `/`, `/audit`, `/benchmark`, `/new-vulnerability`
  - API base URL: `VITE_API_URL` (fallback `http://localhost:8000`)
- Backend: FastAPI
  - Source: `backend/app/`
  - Health endpoint: `GET /healthz`
  - Feature APIs:
    - Audits: `POST /api/v1/audits`, `GET /api/v1/audits/{id}`, `GET /api/v1/audits/{id}/stream`
    - Benchmark: `GET /api/v1/benchmark/contracts`, `GET /api/v1/benchmark/llm-check`, `POST /api/v1/benchmark/run`
    - Vulnerability submit: `POST /api/v1/vulnerabilities/submissions`

Detailed docs:

- Frontend detail: [frontend/README.md](frontend/README.md)
- Backend detail: [backend/README.md](backend/README.md)

---

## 3. Requirements

- Python **3.10 or higher** (**3.11/3.12 recommended for Streamlit startup speed**)
- A **GitHub Personal Access Token (PAT)** for GitHub Models (recommended)
- (Optional) An **OpenAI API key** and/or **Anthropic API key** for direct provider access
- (Optional) An **Etherscan API key** to scrape contracts directly from the blockchain

Python dependencies (installed via `requirements.txt`):

| Package         | Purpose                         |
| --------------- | ------------------------------- |
| `openai`        | GPT-4o / GPT-4-turbo API        |
| `anthropic`     | Claude API                      |
| `tiktoken`      | Token counting                  |
| `streamlit`     | Web UI                          |
| `pandas`        | Tabular results                 |
| `scikit-learn`  | AUC-ROC, PR-AUC, calibration    |
| `plotly`        | Interactive charts in Streamlit |
| `matplotlib`    | Report plots                    |
| `python-dotenv` | `.env` file loading             |
| `pytest`        | Test runner                     |

---

## 4. Installation

```bash
# 1. Clone the repository
git clone https://github.com/EnochCHIU-polyu/COMP5566_project_26022026.git
cd COMP5566_project_26022026

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt
```

### 4.1 Run Frontend + Backend (Full-Stack)

Use two terminals from the repository root.

Terminal A (Backend):

```bash
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Terminal B (Frontend):

```bash
cd frontend
npm install
npm run dev
```

Open the frontend URL shown by Vite (usually `http://localhost:5173`).

If your frontend targets a different backend URL, set:

```bash
export VITE_API_URL=http://localhost:8000
```

---

## 5. Configuration

Create a `.env` file in the project root (already in `.gitignore`):

```dotenv
# ── API Keys ──────────────────────────────────────────────────────
# Poe (OpenAI-compatible API)
POE_API_KEY=poe_xxx
OPENAI_API_KEY=${POE_API_KEY}
OPENAI_BASE_URL=https://api.poe.com/v1

# Optional GitHub Models token (only needed if you still use GitHub-hosted models)
GITHUB_TOKEN=

# Optional providers
ANTHROPIC_API_KEY=sk-ant-...
ETHERSCAN_API_KEY=...          # only needed for Etherscan scraping

# ── LLM Settings ──────────────────────────────────────────────────
DEFAULT_MODEL=deepseek-v3.2    # e.g. deepseek-v3.2 | openai/o4-mini | claude-3-opus-20240229
TEMPERATURE=0                  # 0 = deterministic, 1 = more creative
MAX_CONTEXT_TOKENS=32000
API_PAUSE_SECONDS=13           # minimum pause between LLM calls

# ── Classification ─────────────────────────────────────────────────
CLASSIFICATION_MODE=non_binary # binary | non_binary | cot | multi_vuln

# ── Experiment Settings ────────────────────────────────────────────
BENCHMARK_DATASET=smartbugs    # smartbugs | solidifi | synthetic | all
SELF_CHECK_ENABLED=true
SELF_CHECK_CONFIDENCE_THRESHOLD=0.6
KEYWORD_PREFILTER_ENABLED=true
BATCH_VULNS_PER_PROMPT=8
FEW_SHOT_EXAMPLES=true

# ── Shared DB (Supabase) ──────────────────────────────────────────
DATA_BACKEND=local             # local | supabase
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_KEY=<anon-or-service-role-key>
SUPABASE_CONTRACTS_TABLE=contracts
SUPABASE_SUBMISSIONS_TABLE=flagged_contract_submissions
SUPABASE_VULNERABILITIES_TABLE=vulnerability_types
```

### Supabase bootstrap (for shared datasets)

1. Create a Supabase project.
2. Open SQL Editor and run [supabase/schema.sql](supabase/schema.sql).
3. Set `DATA_BACKEND=supabase` in `.env` to make loaders prefer shared DB.
4. Keep `.env` private; do not commit real keys.

For first setup, copy [.env.example](.env.example) to `.env` and fill in values.

### GitHub Models quick check

This project supports the same client pattern as the GitHub sample:

```python
import os
from openai import OpenAI

client = OpenAI(
   base_url="https://models.github.ai/inference",
   api_key=os.environ["GITHUB_TOKEN"],
)
```

If you update `.env`, restart your Python/Streamlit process so environment variables are reloaded.

All settings can also be changed directly in `config.py`.

### Streamlit DB workflow

- In the **Benchmark** tab, enable **Use shared Supabase dataset** to load contracts from DB first.
- In the **Flag & Review** tab, users can submit fully detailed vulnerable-contract reports to a pending queue.
- Reviewer can mark submissions `under_review` / `rejected`, or **Approve + Publish** to append into shared vulnerable contracts.
- Vulnerability catalog is loaded from Supabase table `vulnerability_types` (with local fallback).
- Audit now always runs full-catalog detection for every contract (no manual vulnerability selection UI).
- In the main audit view, run **Slither Pre-Scan** first to generate static-detector findings; those findings are injected into LLM prompts as reference context.

---

## 6. Usage

### 6.1 Audit a Contract via CLI

```bash
# Standard non-binary audit (detailed explanation per vuln)
python main.py audit --contract path/to/MyContract.sol

# Binary mode – YES/NO only (fastest)
python main.py audit --contract path/to/MyContract.sol --mode binary

# Chain-of-Thought per-function review
python main.py audit --contract path/to/MyContract.sol --mode cot

# Structured JSON output with self-check verification pass
python main.py audit --contract path/to/MyContract.sol --verify

# Save results to a JSON file instead of stdout
python main.py audit --contract path/to/MyContract.sol --output results.json

# Override temperature
python main.py audit --contract path/to/MyContract.sol --temperature 0.3
```

**Flags for `audit`:**

| Flag            | Values                                            | Default          | Description                          |
| --------------- | ------------------------------------------------- | ---------------- | ------------------------------------ |
| `--contract`    | file path                                         | _(required)_     | Path to the `.sol` file to audit     |
| `--mode`        | `binary` \| `non_binary` \| `cot` \| `multi_vuln` | `non_binary`     | Classification mode                  |
| `--temperature` | `0.0` – `1.0`                                     | from `config.py` | LLM sampling temperature             |
| `--output`      | file path                                         | _(stdout)_       | Write JSON results to a file         |
| `--verify`      | flag                                              | `false`          | Run two-pass self-check verification |

The JSON result contains:

- `vuln_results` – one entry per vulnerability type checked (up to 38), each with `vuln_name` and LLM `response`.
- `function_results` – one entry per Solidity function (CoT pass).
- `verified_findings` – present only when `--verify` is used; each entry has `verified`, `verification_confidence`, and `verification_reasoning`.

---

### 6.2 Generate Synthetic Test Contracts

```bash
# Inject 2 vulnerabilities per contract (quick smoke-test)
python main.py generate-synthetic --num-vulns 2

# Inject 15 vulnerabilities per contract (comprehensive mutation test)
python main.py generate-synthetic --num-vulns 15
```

**Example output:**

```
Generated 5 synthetic contracts in data/synthetic_contracts/
  SecureVault:   labels = ['Reentrancy']
  SecureToken:   labels = ['Integer Overflow']
  SecureStaking: labels = ['Unchecked Return Value', 'Timestamp Dependence']
  ...
```

---

### 6.3 Download Benchmark Datasets

You need to manually clone the benchmark datasets into the `data/benchmarks` directory before using them:

```bash
# Download SmartBugs Curated
git clone https://github.com/smartbugs/smartbugs-curated.git data/benchmarks/smartbugs

# Download SolidiFI injected-bug dataset
git clone https://github.com/smartbugs/SolidiFI-benchmark data/benchmarks/solidifi

# After cloning, you can verify they load correctly
python main.py download-benchmarks --dataset all
```

Datasets are expected in `data/benchmarks/` to be parsed by the engine.  
See [`phase1_data_pipeline/README.md`](phase1_data_pipeline/README.md) for more setup details.

---

### 6.4 Generate an Audit Report

```bash
# Generate a markdown report from saved JSON results
python main.py report --results results.json --output report.md

# Generate an HTML report
python main.py report --results results.json --output report.html --format html
```

### 6.5 Seed Vulnerability Catalog to Supabase

If your `vulnerability_types` table is empty, seed it from local
`phase2_llm_engine/vulnerability_types.py`:

```bash
python main.py seed-vulnerability-catalog
```

Force upsert all local rows even when DB already has data:

```bash
python main.py seed-vulnerability-catalog --force
```

If RLS blocks insert/update with anon key, set `SUPABASE_SERVICE_ROLE_KEY` in `.env`
for one-time seeding, run the command, then remove it from local environment.

---

### 6.6 Launch the Streamlit Web UI

```bash
streamlit run phase4_evaluation/ui_app.py
```

Open **http://localhost:8501** in your browser.

**UI features:**

- **Paste or upload** a Solidity contract (`.sol` or `.json`).
- Token count displayed automatically; oversized contracts truncated with a warning.
- **Select vulnerability types** from all 38, or tick _"Run all 38"_.
- Choose **LLM model** (GPT-4o, Claude, DeepSeek, or custom) and **temperature** in the sidebar.
- Click **🚀 Run Audit** — progress bar tracks each check.
- Results shown as collapsible panels (🔴 flagged / 🟢 clean).
- Flagged lines **highlighted in the source code viewer**.
- **True Positive / False Positive / False Negative** buttons record your verdict.
- Sidebar shows live **F1 / Precision / Recall** scores.

---

## 7. Running Tests

```bash
# Run the full test suite (52 tests, no API calls required)
python -m pytest tests/ -v

# Run tests for a specific phase only
python -m pytest tests/test_phase1.py -v
python -m pytest tests/test_phase2.py -v
python -m pytest tests/test_phase3.py -v
python -m pytest tests/test_phase4.py -v
```

All tests run **offline** — no API keys are needed.

---

## 8. How It Works

### 8.1 Prompt Architecture

Each audit uses a **4-section structured prompt**:

```
┌─────────────────────────────────────────────────────────────────┐
│ Section 1 – Role Definition                                      │
│   "You are a senior smart contract security auditor with 10+    │
│    years of experience in Solidity and EVM internals…"          │
├─────────────────────────────────────────────────────────────────┤
│ Section 2 – Vulnerability Context                                │
│   Definition + SWC/CWE ID + example vulnerable code +           │
│   example fixed code (from vulnerability_types.py)              │
├─────────────────────────────────────────────────────────────────┤
│ Section 3 – Task Instruction + JSON Output Schema                │
│   "Is the contract vulnerable to [Vuln]? Cite exact line        │
│    numbers. Return JSON: {findings:[…], summary, risk_score}"   │
├─────────────────────────────────────────────────────────────────┤
│ Section 4 – Source Code (line-numbered)                          │
│   /* L1 */ pragma solidity ^0.8.0;                              │
│   /* L2 */ contract Vault {                                      │
│   …                                                              │
└─────────────────────────────────────────────────────────────────┘
```

**Multi-vuln batch mode** (`--mode multi_vuln`) groups up to 8 vulnerability checks into a single LLM call, reducing API calls from 38 to ~5.

### 8.2 Self-Check Verification

When `--verify` is used, each candidate finding goes through a second _sceptical_ pass:

```
Pass 1 (Detect):  Standard audit → N candidate findings
Pass 2 (Verify):  For each finding, ask:
                  "A security auditor claims [VulnType] at [Lines].
                   Is this genuine or a false positive?
                   → {verified: bool, confidence: float, reasoning: str}"
Pass 3 (Merge):   Findings below confidence threshold (default 0.6)
                  are demoted to INFO severity.
```

### 8.3 Keyword Pre-Filtering

Before sending a contract to the LLM, `relevance_filter.py` checks each vulnerability's `detection_keywords` against the contract source:

- If none of a vulnerability's keywords appear → skip that check entirely.
- `Integer Overflow/Underflow` is automatically skipped for Solidity ≥ 0.8.0.
- Reduces API calls by **60–80 %** on average.

### 8.4 Evaluation Metrics

The evaluation suite computes:

| Metric                                 | Function                              |
| -------------------------------------- | ------------------------------------- |
| Precision / Recall / F1 (per contract) | `compute_metrics()`                   |
| Per-vulnerability-type F1 breakdown    | `compute_per_vuln_metrics()`          |
| Macro-F1 / Micro-F1                    | `evaluate_batch()`                    |
| AUC-ROC                                | `compute_auc_roc()`                   |
| PR-AUC (better for imbalanced data)    | `compute_pr_auc()`                    |
| 38-row confusion matrix                | `compute_confusion_matrix_per_type()` |
| Confidence calibration                 | `compute_calibration()`               |

---

## 9. Phase-Level Documentation

Each phase has its own detailed README:

| Phase                           | README                                                               |
| ------------------------------- | -------------------------------------------------------------------- |
| Phase 1 – Data Pipeline         | [`phase1_data_pipeline/README.md`](phase1_data_pipeline/README.md)   |
| Phase 2 – LLM Engine            | [`phase2_llm_engine/README.md`](phase2_llm_engine/README.md)         |
| Phase 3 – Hyperparameter Tuning | [`phase3_hyperparameter/README.md`](phase3_hyperparameter/README.md) |
| Phase 4 – Evaluation & UI       | [`phase4_evaluation/README.md`](phase4_evaluation/README.md)         |
