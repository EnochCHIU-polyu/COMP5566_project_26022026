# Phase 4 – Evaluation & UI

This package scores audit results, runs batch experiment grids, generates audit reports, persists all experiment data for reproducibility, and provides a Streamlit web interface for human-in-the-loop review.

---

## Table of Contents

1. [Module Overview](#1-module-overview)
2. [Scorer (`scorer.py`)](#2-scorer)
3. [Experiment Runner (`experiment_runner.py`)](#3-experiment-runner)
4. [Report Generator (`report_generator.py`)](#4-report-generator)
5. [Results Logger (`results_logger.py`)](#5-results-logger)
6. [Streamlit UI (`ui_app.py`)](#6-streamlit-ui)
7. [Output Directory Structure](#7-output-directory-structure)

---

## 1. Module Overview

| File                   | Purpose                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `scorer.py`            | TP/FP/TN/FN, Precision, Recall, F1, AUC-ROC, PR-AUC, per-vuln breakdown, calibration |
| `experiment_runner.py` | Batch grid runner — benchmark × config grid → results                                |
| `report_generator.py`  | Generate markdown / HTML audit reports                                               |
| `results_logger.py`    | Persist predictions, metrics, timing, and comparison CSV                             |
| `ui_app.py`            | Streamlit HITL web interface                                                         |

---

## 2. Scorer

**File:** `scorer.py`

Computes a comprehensive evaluation metric suite for comparing LLM audit configurations.

### Core functions

```python
from phase4_evaluation.scorer import (
    compute_metrics,
    evaluate_batch,
    compute_per_vuln_metrics,
    compute_auc_roc,
    compute_pr_auc,
    compute_confusion_matrix_per_type,
    compute_calibration,
)
```

#### `compute_metrics(tp, fp, tn, fn) -> dict`

Returns `{"precision": float, "recall": float, "f1": float, "accuracy": float}`.

#### `evaluate_batch(audit_results, ground_truth) -> dict`

Evaluates a list of audit results against ground-truth labels.

```python
ground_truth = {
    "SecureVault": ["Reentrancy"],
    "SecureToken": [],
}
scores = evaluate_batch(audit_results, ground_truth)
# {
#   "per_contract": [...],
#   "aggregate": {"counts": {"TP": N, "FP": N, "TN": N, "FN": N},
#                 "metrics": {"precision": 0.8, "recall": 0.7, "f1": 0.75, …}}
# }
```

#### `compute_per_vuln_metrics(results, ground_truth) -> dict`

Returns a per-vulnerability-type breakdown:

```python
{
    "Reentrancy":     {"precision": 0.9, "recall": 0.8, "f1": 0.85, "tp": 5, …},
    "Access Control": {"precision": 0.7, "recall": 0.6, "f1": 0.65, …},
    …
}
```

#### `compute_auc_roc(predictions, ground_truth) -> float`

Requires confidence scores from `output_parser.py`. Uses `sklearn.metrics.roc_auc_score`. Returns `0.0` if sklearn is unavailable.

#### `compute_pr_auc(predictions, ground_truth) -> float`

Precision-Recall AUC — preferred over ROC-AUC for the heavily imbalanced case where most vulnerability checks are negative. Uses `sklearn.metrics.average_precision_score`.

#### `compute_confusion_matrix_per_type(results, ground_truth) -> list[dict]`

Returns a 38-row list, one per vulnerability type:

```python
[
    {"vuln_type": "Reentrancy", "tp": 5, "fp": 1, "tn": 30, "fn": 2,
     "precision": 0.833, "recall": 0.714, "f1": 0.769},
    …
]
```

#### `compute_calibration(predictions, ground_truth, n_bins=10) -> dict`

Reliability diagram data for assessing whether predicted confidence scores match actual accuracy:

```python
{
    "bin_centres":   [0.05, 0.15, …, 0.95],
    "actual_acc":    [0.12, 0.30, …, 0.91],
    "bin_counts":    [40, 35, …, 15],
}
```

---

## 3. Experiment Runner

**File:** `experiment_runner.py`

Runs the complete evaluation pipeline: benchmark → config grid → audit → score → save.

### CLI usage

```bash
# Run all configs against SmartBugs
python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs all

# Run a specific config
python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs T0-gpt4o-binary

# Resume an interrupted run (skips completed configs)
python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs all \
    --output results/my_run/ --resume
```

### Python API

```python
from phase4_evaluation.experiment_runner import run_experiment, score_experiment, save_experiment, run_grid

# Single config run
experiment = run_experiment(contracts, config)
scored     = score_experiment(experiment, ground_truth)
output_dir = save_experiment(scored)

# Full grid
results = run_grid(
    contracts=contracts,
    configs=DEFAULT_EXPERIMENT_GRID,
    ground_truth=ground_truth,
    output_dir="results/grid_run/",
    resume=True,
)
```

### Output

Each config run is saved to `results/{config_name}_{timestamp}/` containing:

| File               | Contents                           |
| ------------------ | ---------------------------------- |
| `config.json`      | TuningConfig snapshot              |
| `predictions.json` | Per-contract, per-vuln predictions |
| `metrics.json`     | Aggregated scores                  |
| `timing.json`      | Per-contract latency               |

---

## 4. Report Generator

**File:** `report_generator.py`

Generates professional audit reports from `analyze_contract()` output.

### Report structure

1. **Executive Summary** — total findings, severity breakdown table, risk score
2. **Findings** — sorted by severity; each finding shows severity, affected lines, description, recommendation
3. **Methodology** — model, temperature, mode, number of checks run
4. _(Optional)_ **Appendix** — full raw LLM responses

### Usage

```bash
# Generate markdown report from CLI
python main.py report --results audit_output.json --output report.md

# Generate HTML report
python main.py report --results audit_output.json --output report.html --format html
```

```python
from phase4_evaluation.report_generator import generate_markdown_report, save_report

md = generate_markdown_report(
    audit_result=result,
    contract_name="MyContract.sol",
    model="gpt-4o",
    temperature=0.0,
    mode="non_binary",
    include_appendix=False,
)

save_report(
    audit_result=result,
    contract_name="MyContract.sol",
    output_path="reports/MyContract_report.md",
    format="markdown",         # or "html"
    model="gpt-4o",
    temperature=0.0,
)
```

### Severity icons

| Severity | Icon |
| -------- | ---- |
| CRITICAL | 🔴   |
| HIGH     | 🟠   |
| MEDIUM   | 🟡   |
| LOW      | 🔵   |
| INFO     | ⚪   |

---

## 5. Results Logger

**File:** `results_logger.py`

Persistent logger for storing all experiment data in a structured directory.

```python
from phase4_evaluation.results_logger import ResultsLogger
from phase3_hyperparameter.tuning_config import TuningConfig

logger = ResultsLogger("my_experiment")

# Log the config
logger.log_config(my_config)

# Log individual predictions
logger.log_prediction(
    contract_name="SecureVault",
    vuln_name="Reentrancy",
    predicted=True,
    actual=True,
    confidence=0.9,
    response="YES, the withdraw function…",
)

# Log timing
logger.log_timing("SecureVault", elapsed_seconds=4.2, tokens_used=1500, api_calls=8)

# Persist everything
logger.save_all(metrics=aggregate_metrics)
```

### Comparison CSV

```python
from phase4_evaluation.results_logger import ResultsLogger

ResultsLogger.save_comparison_csv(
    experiments=all_scored_results,
    output_path="results/comparison.csv",
)
```

The CSV contains one row per config:

```
config_name, model, temperature, mode, contracts_tested, macro_f1, precision, recall, total_time_seconds
T0-gpt4o-binary, gpt-4o, 0.0, binary, 143, 0.742, 0.801, 0.692, 4320.5
…
```

---

## 6. Streamlit UI

**File:** `ui_app.py`

Human-in-the-loop web interface for interactive contract auditing.

### Launch

```bash
streamlit run phase4_evaluation/ui_app.py
# → http://localhost:8501
```

### Features

| Feature                    | Description                                                                                                |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Contract input**         | Paste Solidity code or upload `.sol` / `.json` file                                                        |
| **Token counter**          | Automatically displayed; warns if contract is truncated                                                    |
| **Vulnerability coverage** | Full-catalog scan is always on; catalog is loaded dynamically from Supabase (with local fallback)          |
| **Model selector**         | `deepseek-v3.2`, `gpt-4o`, `gpt-4o-mini`, or custom model string                                           |
| **Temperature slider**     | 0.0 – 1.0                                                                                                  |
| **Classification mode**    | Binary (YES/NO) or Non-Binary (detailed)                                                                   |
| **Progress bar**           | Shows progress through selected vulnerability types                                                        |
| **Result panels**          | 🔴 / 🟢 per vulnerability, collapsible                                                                     |
| **Line highlighting**      | Flagged source lines shown in red inside a code viewer                                                     |
| **HITL scoring**           | True Positive / False Positive / False Negative buttons                                                    |
| **Live metrics**           | Sidebar shows cumulative F1, Precision, Recall                                                             |
| **Flag + review queue**    | Reporter submits contract + evidence; suspected vulnerability types are auto-inferred for moderator triage |

### Screenshot workflow

```
1. Paste a Solidity contract in the "📝 Paste Code" tab
   (or upload a .sol / .json file)

2. System automatically runs all vulnerability checks (full catalog)
    → no manual vulnerability selection is required

3. Configure the model, temperature, and mode in the sidebar

4. Click 🚀 Run Audit

5. Review collapsible result panels:
   🔴 = LLM flagged a vulnerability
   🟢 = LLM found no issue

6. Click into flagged results to see the highlighted source lines

7. Use TP / FP / FN buttons to record your verdict
   → The sidebar updates F1 / Precision / Recall in real time
```

---

## 7. Output Directory Structure

```
results/
└── {config_name}_{timestamp}/
    ├── config.json          ← TuningConfig snapshot
    ├── predictions.json     ← per-contract, per-vuln predictions + confidence
    ├── metrics.json         ← aggregated scores (Precision, Recall, F1, AUC, …)
    └── timing.json          ← per-contract latency and token usage

results/
└── grid_{timestamp}/
    ├── T0-gpt4o-binary_{ts}/
    │   ├── config.json
    │   ├── predictions.json
    │   ├── metrics.json
    │   └── timing.json
    ├── T0-gpt4o-nonbinary_{ts}/
    │   └── …
    └── comparison.csv       ← cross-config summary table
```
