# COMP5566 Smart Contract Vulnerability Detection Framework

An LLM-powered security auditing framework for Ethereum smart contracts.  
It uses GPT-4 / Claude to systematically check a contract against **38 known DeFi vulnerability types**, produces a human-readable audit report, and provides a Streamlit web interface that lets a human auditor verify findings with highlighted source lines.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Project Structure](#2-project-structure)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Configuration](#5-configuration)
6. [Usage](#6-usage)
   - [Generate Synthetic Contracts](#61-generate-synthetic-test-contracts)
   - [Audit a Contract (CLI)](#62-audit-a-contract-via-cli)
   - [Launch the Web UI](#63-launch-the-streamlit-web-ui)
7. [Running Tests](#7-running-tests)
8. [How It Works](#8-how-it-works)

---

## 1. System Overview

The framework is divided into four phases:

| Phase | Name | What it does |
|-------|------|-------------|
| **1** | Data Pipeline | Fetches contract source code from Etherscan, loads local datasets, generates synthetic contracts with injected vulnerabilities, and preprocesses code to fit inside the LLM context window. |
| **2** | LLM Engine | Builds the Master Prompt Template and queries GPT-4 or Claude for each of the 38 vulnerability types. Supports *binary* (YES/NO), *non-binary* (detailed explanation), and *Chain-of-Thought* (per-function review) modes. A mandatory 13-second pause between API calls prevents rate-limit errors. |
| **3** | Hyperparameter Tuning | Provides a predefined experiment grid covering Temperature 0 and Temperature 1 for both GPT-4o and Claude, enabling reproducible comparison runs. |
| **4** | Evaluation & UI | Calculates TP / FP / TN / FN, Precision, Recall, and F1-score. Includes a Streamlit web application where human auditors can paste a contract, run the audit, see flagged lines highlighted in the source, and record their verification decisions. |

---

## 2. Project Structure

```
COMP5566_project_26022026/
├── config.py                          # Central configuration (API keys, model, temperature …)
├── main.py                            # CLI entry point
├── requirements.txt
│
├── phase1_data_pipeline/
│   ├── etherscan_scraper.py           # Fetch verified contracts from Etherscan API
│   ├── dataset_loader.py              # Load .sol / .json contract files from disk
│   ├── synthetic_contracts.py         # Generate 5 synthetic contracts with injected vulns
│   ├── token_counter.py               # Count tokens (tiktoken) + offline fallback
│   └── contract_preprocessor.py      # Truncate contracts that exceed the context window
│
├── phase2_llm_engine/
│   ├── vulnerability_types.py         # 38 DeFi vulnerability definitions
│   ├── prompt_builder.py              # Build binary / non-binary / CoT prompts
│   ├── llm_client.py                  # OpenAI + Anthropic client with rate-limit pause
│   └── cot_analyzer.py               # Full audit: 38 vuln loop + per-function CoT loop
│
├── phase3_hyperparameter/
│   └── tuning_config.py              # TuningConfig dataclass + experiment grid
│
├── phase4_evaluation/
│   ├── scorer.py                      # TP/FP/TN/FN, Precision, Recall, F1
│   └── ui_app.py                      # Streamlit human-in-the-loop web interface
│
├── data/
│   ├── vulnerable_contracts/          # Place known-vulnerable .sol / .json files here
│   └── synthetic_contracts/          # Auto-generated synthetic contracts saved here
│
└── tests/                             # Pytest unit tests for all four phases
```

---

## 3. Requirements

- Python **3.10 or higher**
- An **OpenAI API key** (for GPT-4 / GPT-4o) and/or an **Anthropic API key** (for Claude)
- (Optional) An **Etherscan API key** to scrape contracts directly from the blockchain

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

---

## 5. Configuration

Create a `.env` file in the project root (it is already listed in `.gitignore` so your keys stay private):

```dotenv
# Required for LLM auditing
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Required only for scraping contracts from Etherscan
ETHERSCAN_API_KEY=...

# Optional overrides (defaults shown)
DEFAULT_MODEL=gpt-4o          # or claude-3-opus-20240229
TEMPERATURE=0                 # 0 = deterministic, 1 = more creative
MAX_CONTEXT_TOKENS=32000
API_PAUSE_SECONDS=13          # pause between LLM calls (avoids rate limits)
CLASSIFICATION_MODE=non_binary  # binary | non_binary | cot
```

All settings can also be changed directly in `config.py`.

---

## 6. Usage

### 6.1 Generate Synthetic Test Contracts

Creates 5 Solidity contracts with vulnerabilities deliberately injected, then saves them to `data/synthetic_contracts/` as JSON files.

```bash
# Inject 2 vulnerabilities per contract (quick smoke-test)
python main.py generate-synthetic --num-vulns 2

# Inject 15 vulnerabilities per contract (comprehensive mutation test)
python main.py generate-synthetic --num-vulns 15
```

**Example output:**
```
Generated 5 synthetic contracts in data/synthetic_contracts/
  SecureVault: labels = ['Reentrancy']
  SecureToken: labels = ['Integer Overflow']
  ...
```

---

### 6.2 Audit a Contract via CLI

Runs the full 38-vulnerability audit on a Solidity file and prints the results as JSON.

```bash
# Non-binary mode (detailed explanations) – default
python main.py audit --contract path/to/MyContract.sol

# Binary mode (YES/NO answers only – faster)
python main.py audit --contract path/to/MyContract.sol --mode binary

# Chain-of-Thought mode (per-function deep review)
python main.py audit --contract path/to/MyContract.sol --mode cot

# Override temperature for this run
python main.py audit --contract path/to/MyContract.sol --temperature 1
```

**Available flags for `audit`:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--contract` | file path | *(required)* | Path to the `.sol` file to audit |
| `--mode` | `binary` \| `non_binary` \| `cot` | `non_binary` | Classification mode |
| `--temperature` | `0.0` – `1.0` | from `config.py` | LLM sampling temperature |

The command prints a JSON object with two arrays:

- `vuln_results` – one entry per vulnerability type (38 total), each with `vuln_name` and the LLM `response`.
- `function_results` – one entry per Solidity function found in the contract (CoT pass).

```bash
# Save the output to a file
python main.py audit --contract MyContract.sol --mode binary > audit_report.json
```

---

### 6.3 Launch the Streamlit Web UI

The web interface is designed for human auditors to interactively review findings.

```bash
streamlit run phase4_evaluation/ui_app.py
```

Then open **http://localhost:8501** in your browser.

**UI features:**

- **Paste or upload** a Solidity contract (`.sol` or `.json`).
- Token count is displayed automatically; oversized contracts are truncated with a warning.
- **Select vulnerability types** from the full list of 38, or tick *"Run all 38"*.
- Choose the **LLM model** and **temperature** in the sidebar.
- Click **🚀 Run Audit** – a progress bar tracks each vulnerability check.
- Results are shown as collapsible panels (🔴 flagged / 🟢 clean).
- Flagged lines are **highlighted in the source code viewer** so you can verify them instantly.
- Use the **True Positive / False Positive / False Negative** buttons to record your verdict; the sidebar shows live **F1 / Precision / Recall** scores.

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

All tests run offline — no API keys are needed.

---

## 8. How It Works

Each audit call follows the **Master Prompt Template** from the research paper:

```
System: You are an AI smart contract auditor … Think step by step.

User:   [Vulnerability Definition]
        Perform a proper security audit …
        Is the following smart contract vulnerable to [Vulnerability Name] attacks?

        Source Code:
        [Contract Source]
```

The framework loops this prompt 38 times (once per vulnerability type) and, in CoT mode, additionally loops over every function in the contract. A minimum **13-second pause** is enforced between API calls to stay within rate limits.

The **Evaluation module** compares LLM predictions against ground-truth labels and reports:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-score** = 2 × Precision × Recall / (Precision + Recall)