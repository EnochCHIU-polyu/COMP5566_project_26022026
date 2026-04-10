# Phase 3 – Hyperparameter Tuning

This package defines the `TuningConfig` dataclass and the predefined experiment grid used for systematic comparison of LLM models, temperatures, and prompt modes.

---

## Table of Contents

1. [Module Overview](#1-module-overview)
2. [`TuningConfig` Dataclass](#2-tuningconfig-dataclass)
3. [Predefined Experiment Grid](#3-predefined-experiment-grid)
4. [Using the Config in an Experiment](#4-using-the-config-in-an-experiment)
5. [Extending the Grid](#5-extending-the-grid)

---

## 1. Module Overview

| File | Purpose |
|------|---------|
| `tuning_config.py` | `TuningConfig` dataclass + 9-configuration experiment grid + `get_config_by_name()` helper |

The actual execution of the experiment grid is handled by `phase4_evaluation/experiment_runner.py`.

---

## 2. `TuningConfig` Dataclass

```python
from phase3_hyperparameter.tuning_config import TuningConfig

@dataclass
class TuningConfig:
    name:        str            # human-readable label, e.g. "T0-gpt4o-binary"
    model:       str   = "gpt-4o"
    temperature: float = 0.0
    mode:        str   = "non_binary"   # binary | non_binary | cot | multi_vuln
    max_tokens:  int   = 2048
    notes:       str   = ""

    # New fields (WP-6)
    verify:      bool  = False   # run self-check verification pass
    batch_vulns: int   = 1       # vulns checked per prompt (1 = one at a time)
    use_filter:  bool  = True    # apply keyword relevance pre-filter
    few_shot:    bool  = False   # include few-shot examples in prompt
```

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | *(required)* | Unique identifier for this configuration |
| `model` | `str` | `"gpt-4o"` | LLM model identifier |
| `temperature` | `float` | `0.0` | Sampling temperature (0 = deterministic, 1 = creative) |
| `mode` | `str` | `"non_binary"` | Prompt mode: `binary`, `non_binary`, `cot`, `multi_vuln` |
| `max_tokens` | `int` | `2048` | Maximum tokens in the LLM response |
| `notes` | `str` | `""` | Free-text description |
| `verify` | `bool` | `False` | Enable two-pass self-consistency verification |
| `batch_vulns` | `int` | `1` | Vulnerability types batched per prompt (see multi-vuln mode) |
| `use_filter` | `bool` | `True` | Apply keyword pre-filter before auditing |
| `few_shot` | `bool` | `False` | Include few-shot code examples in the prompt |

---

## 3. Predefined Experiment Grid

`DEFAULT_EXPERIMENT_GRID` contains 9 ready-to-run configurations:

| Name | Model | Temp | Mode | Notes |
|------|-------|------|------|-------|
| `T0-gpt4o-binary` | gpt-4o | 0.0 | binary | Deterministic binary scan – high precision baseline |
| `T0-gpt4o-nonbinary` | gpt-4o | 0.0 | non_binary | Deterministic deep analysis |
| `T1-gpt4o-nonbinary` | gpt-4o | 1.0 | non_binary | Creative non-binary – may improve recall |
| `T0-gpt4o-cot` | gpt-4o | 0.0 | cot | Chain-of-Thought per-function review |
| `T0-claude-nonbinary` | claude-3-opus-20240229 | 0.0 | non_binary | Claude deterministic deep analysis |
| `T1-claude-nonbinary` | claude-3-opus-20240229 | 1.0 | non_binary | Claude creative non-binary |
| `T0-deepseek-binary` | deepseek-v3.2 | 0.0 | binary | DeepSeek deterministic binary scan |
| `T0-deepseek-nonbinary` | deepseek-v3.2 | 0.0 | non_binary | DeepSeek deterministic non-binary |
| `T0-gpt4o-multivuln` | gpt-4o | 0.0 | multi_vuln | Batch mode (~5 calls instead of 38) |

```python
from phase3_hyperparameter.tuning_config import DEFAULT_EXPERIMENT_GRID, get_config_by_name

# Access all configs
for cfg in DEFAULT_EXPERIMENT_GRID:
    print(cfg.name, cfg.model, cfg.temperature)

# Look up by name
cfg = get_config_by_name("T0-gpt4o-binary")
```

---

## 4. Using the Config in an Experiment

The experiment runner in Phase 4 consumes these configs directly:

```python
from phase3_hyperparameter.tuning_config import DEFAULT_EXPERIMENT_GRID
from phase4_evaluation.experiment_runner import run_grid
from phase1_data_pipeline.benchmark_datasets import load_benchmark

contracts = load_benchmark("smartbugs")
ground_truth = {c["name"]: [lb["vuln_type"] for lb in c["labels"]] for c in contracts}

results = run_grid(
    contracts=contracts,
    configs=DEFAULT_EXPERIMENT_GRID,
    ground_truth=ground_truth,
    output_dir="results/grid_run_1/",
    resume=True,              # skip already-completed configs
)
```

Or run the experiment runner from the CLI:

```bash
# Run all configs against the SmartBugs dataset
python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs all

# Run a specific config
python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs T0-gpt4o-binary
```

---

## 5. Extending the Grid

Add a custom config by appending to `DEFAULT_EXPERIMENT_GRID` or by creating a standalone `TuningConfig`:

```python
from phase3_hyperparameter.tuning_config import TuningConfig, DEFAULT_EXPERIMENT_GRID

# Standalone config
my_cfg = TuningConfig(
    name="my-deepseek-cot-verify",
    model="deepseek-v3.2",
    temperature=0.0,
    mode="cot",
    verify=True,
    use_filter=True,
    notes="DeepSeek CoT with self-check enabled",
)

# Add to the grid for a full comparison run
my_grid = DEFAULT_EXPERIMENT_GRID + [my_cfg]
```
