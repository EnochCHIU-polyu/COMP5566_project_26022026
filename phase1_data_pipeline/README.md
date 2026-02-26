# Phase 1 – Data Pipeline

This package handles everything related to acquiring, normalising, and pre-processing Solidity smart-contract source code before it is sent to the LLM engine.

---

## Table of Contents

1. [Module Overview](#1-module-overview)
2. [Benchmark Datasets (`benchmark_datasets.py`)](#2-benchmark-datasets)
3. [Contract Normaliser (`contract_normalizer.py`)](#3-contract-normaliser)
4. [Contract Chunker (`contract_chunker.py`)](#4-contract-chunker)
5. [Contract Pre-processor (`contract_preprocessor.py`)](#5-contract-pre-processor)
6. [Synthetic Contracts (`synthetic_contracts.py`)](#6-synthetic-contracts)
7. [Dataset Loader (`dataset_loader.py`)](#7-dataset-loader)
8. [Token Counter (`token_counter.py`)](#8-token-counter)
9. [Etherscan Scraper (`etherscan_scraper.py`)](#9-etherscan-scraper)
10. [Unified Contract Record Format](#10-unified-contract-record-format)

---

## 1. Module Overview

| File | Purpose |
|------|---------|
| `benchmark_datasets.py` | Download & cache SmartBugs / SolidiFI; normalise labels to internal taxonomy |
| `contract_normalizer.py` | Strip comments, collapse whitespace, annotate line numbers |
| `contract_chunker.py` | Split large contracts into function-level or sliding-window chunks |
| `contract_preprocessor.py` | Token-count → normalise → truncate/chunk pipeline |
| `synthetic_contracts.py` | 15 Solidity templates + semantic mutation operators |
| `dataset_loader.py` | Load `.sol` / `.json` files from a local directory |
| `token_counter.py` | tiktoken-based token counting with offline character fallback |
| `etherscan_scraper.py` | Fetch verified source code from the Etherscan API |

---

## 2. Benchmark Datasets

**File:** `benchmark_datasets.py`

Downloads and normalises established benchmark datasets into the [unified contract record format](#10-unified-contract-record-format).

### Supported datasets

| Dataset | Contracts | Vulnerability categories |
|---------|-----------|--------------------------|
| SmartBugs Curated | 143 | 10 (reentrancy, access control, arithmetic, …) |
| SolidiFI | 9 369 injected bugs across 50 base contracts | 7 |

### Key functions

```python
from phase1_data_pipeline.benchmark_datasets import (
    download_smartbugs,
    download_solidifi,
    normalize_labels,
    split_dataset,
    load_benchmark,
)
```

#### `download_smartbugs(output_dir=None) -> list[dict]`

Downloads SmartBugs Curated from GitHub and returns a list of contract records.  
Results are cached in `data/benchmarks/smartbugs/contracts.json`.

**Manual setup** (if automatic download fails):

```bash
git clone https://github.com/smartbugs/smartbugs-curated.git \
    data/benchmarks/smartbugs
```

#### `download_solidifi(output_dir=None) -> list[dict]`

Same as above for the SolidiFI dataset.  
Manual setup: <https://github.com/smartbugs/SolidiFI-benchmark>

#### `normalize_labels(external_labels, taxonomy_map) -> list[dict]`

Maps external label taxonomies (SmartBugs categories, SWC IDs) to the 38 internal vulnerability names defined in `phase2_llm_engine/vulnerability_types.py`.

#### `split_dataset(contracts, train=0.7, val=0.15, test=0.15, seed=42) -> list[dict]`

Stratified train/val/test split. Adds a `"split"` field to each record.

#### `load_benchmark(dataset="smartbugs") -> list[dict]`

High-level loader. `dataset` can be `"smartbugs"`, `"solidifi"`, or `"all"`.

---

## 3. Contract Normaliser

**File:** `contract_normalizer.py`

Normalises Solidity source code for consistent, reproducible LLM input.

### Key functions

```python
from phase1_data_pipeline.contract_normalizer import (
    strip_comments,
    normalize_whitespace,
    standardize_pragma,
    add_line_numbers,
    normalize_contract,
)
```

#### `strip_comments(source_code, keep_natspec=True) -> str`

Removes `// single-line` and `/* block */` comments.  
With `keep_natspec=True` (default), NatSpec documentation comments (`///` and `/** … */`) are preserved.

#### `normalize_whitespace(source_code) -> str`

Collapses three or more consecutive blank lines into a single blank line.

#### `standardize_pragma(source_code) -> str`

Ensures the pragma statement uses consistent spacing.

#### `add_line_numbers(source_code) -> str`

Prefixes every line with `/* L{n} */` so the LLM can reference exact line numbers in its findings:

```solidity
/* L1 */ pragma solidity ^0.8.0;
/* L2 */ contract Vault {
/* L3 */     address public owner;
```

#### `normalize_contract(source_code, strip_comments_flag=False, keep_natspec=True, add_line_nums=False) -> str`

Convenience wrapper that runs all normalisation steps in sequence.

---

## 4. Contract Chunker

**File:** `contract_chunker.py`

Splits contracts that exceed the LLM context window into smaller, semantically meaningful chunks instead of blindly truncating them.

### Key functions

```python
from phase1_data_pipeline.contract_chunker import (
    extract_pragma_and_imports,
    extract_state_variables,
    extract_functions,
    chunk_by_function,
    sliding_window_chunks,
)
```

#### `chunk_by_function(source_code, max_tokens=4000, count_tokens_fn=None) -> list[dict]`

Produces one chunk per function (or group of functions that fit within `max_tokens`).  
Each chunk contains:
- The pragma / import block
- All state variable declarations
- The target function(s)

```python
chunks = chunk_by_function(source_code, max_tokens=4000)
# [
#   {"source_code": "pragma … contract A { … function deposit() { … } }",
#    "functions": ["deposit"], "chunk_index": 0},
#   {"source_code": "pragma … contract A { … function withdraw() { … } }",
#    "functions": ["withdraw"], "chunk_index": 1},
# ]
```

#### `sliding_window_chunks(source_code, chunk_size=3000, overlap=500, count_tokens_fn=None) -> list[dict]`

Creates overlapping window chunks. Useful for contracts with complex cross-function interactions where losing context is undesirable.

---

## 5. Contract Pre-processor

**File:** `contract_preprocessor.py`

Pipeline step that combines token counting, optional normalisation, and truncation/chunking.

```python
from phase1_data_pipeline.contract_preprocessor import preprocess_contract

result = preprocess_contract(
    source_code=raw_source,
    max_tokens=32000,
    reserve_tokens=2000,   # leave headroom for prompt + response
    normalize=True,        # run contract_normalizer.normalize_contract()
)
# Returns: {"source_code": str, "token_count": int, "truncated": bool}
```

When `normalize=True`, the source is normalised (whitespace, pragma) before token counting.

---

## 6. Synthetic Contracts

**File:** `synthetic_contracts.py`

Generates labelled Solidity contracts with deliberately injected vulnerabilities, useful for offline testing without real benchmark data.

### Templates (15 total)

| Template | Description |
|----------|-------------|
| `SecureVault` | ETH vault with owner-only withdraw |
| `SecureToken` | Minimal ERC-20-like token |
| `SecureStaking` | Simple staking contract |
| `SecureMultiSig` | 2-of-3 multisig wallet |
| `SecureLending` | Overcollateralised lending |
| `ProxyContract` | Upgradeable proxy pattern |
| `DEXRouter` | Simple DEX router |
| `LendingPool` | Aave-like lending pool |
| `GovernanceContract` | On-chain governance |
| `NFTMarketplace` | NFT buy/sell marketplace |
| `FlashLoanReceiver` | Flash loan callback receiver |
| `StablecoinMinter` | Overcollateralised stablecoin |
| `YieldFarm` | Yield farming contract |
| `TimelockController` | Timelock for governance |
| `MultiTokenVault` | ERC-4626-like multi-token vault |

### Vulnerability patches (15 semantic mutations)

The injection patches cover:

- Reentrancy (state update after external call)
- Integer Overflow (downgrade to `pragma solidity ^0.7.0`)
- Unchecked Return Value
- Missing access control
- Timestamp dependence
- `tx.origin` authentication
- Unprotected `selfdestruct`
- Unbounded loop DoS
- Front-running (no slippage protection)
- `delegatecall` to user-supplied address
- Flash-loan price manipulation
- Signature replay (no nonce)
- Uninitialized storage pointer
- Arithmetic precision loss
- Additional semantic mutations on new templates

### Key functions

```python
from phase1_data_pipeline.synthetic_contracts import (
    generate_synthetic_contracts,
    generate_large_synthetic_dataset,
    save_synthetic_contracts,
)

# 5 contracts, 2 injected vulns each
contracts = generate_synthetic_contracts(num_vulns=2)

# 5 contracts, all 15 patches applied
contracts = generate_synthetic_contracts(num_vulns=15)

# 50+ contracts for statistical evaluation
contracts = generate_large_synthetic_dataset(count=50)

save_synthetic_contracts(contracts, directory="data/synthetic_contracts/")
```

---

## 7. Dataset Loader

**File:** `dataset_loader.py`

Loads `.sol` or `.json` contract files from a local directory.

```python
from phase1_data_pipeline.dataset_loader import load_contracts_from_dir

contracts = load_contracts_from_dir("data/vulnerable_contracts/")
# Each contract: {"name": str, "source_code": str, "labels": list}
```

JSON files may contain a `labels` list and a `source_code` key.  
`.sol` files are read as plain source; `labels` defaults to `[]`.

---

## 8. Token Counter

**File:** `token_counter.py`

Uses **tiktoken** for accurate token counting with an offline character-based fallback (`len(text) // 4`).

```python
from phase1_data_pipeline.token_counter import count_tokens, truncate_to_token_limit

n = count_tokens("pragma solidity ^0.8.0;", model="gpt-4o")

truncated = truncate_to_token_limit(long_source, max_tokens=30000)
# Appended notice: "... [TRUNCATED]"
```

---

## 9. Etherscan Scraper

**File:** `etherscan_scraper.py`

Fetches verified Solidity source code from the Etherscan API given a contract address.

```python
from phase1_data_pipeline.etherscan_scraper import fetch_contract_source

source = fetch_contract_source("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
```

Requires `ETHERSCAN_API_KEY` to be set in `.env` / `config.py`.

---

## 10. Unified Contract Record Format

All benchmark datasets are normalised to this schema:

```json
{
    "id": "sb_a1b2c3d4e5f6",
    "name": "MyContract",
    "source_code": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n...",
    "compiler_version": "0.8.19",
    "labels": [
        {
            "vuln_type": "Reentrancy",
            "swc_id": "SWC-107",
            "severity": "critical",
            "lines": [42, 43, 44],
            "function": "withdraw",
            "description": "State update occurs after external call."
        }
    ],
    "source": "smartbugs",
    "split": "test"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | SHA-256-based unique identifier |
| `name` | `str` | Contract file name (without extension) |
| `source_code` | `str` | Full Solidity source |
| `compiler_version` | `str` | e.g. `"0.8.19"` |
| `labels` | `list[dict]` | Multi-label ground truth (may be empty for benign contracts) |
| `labels[].vuln_type` | `str` | Matches a name in `vulnerability_types.py` |
| `labels[].swc_id` | `str \| null` | SWC identifier (e.g. `"SWC-107"`) |
| `labels[].severity` | `str` | `critical \| high \| medium \| low \| info` |
| `labels[].lines` | `list[int]` | 1-indexed affected line numbers |
| `labels[].function` | `str \| null` | Affected function name |
| `source` | `str` | `smartbugs \| solidifi \| etherscan \| synthetic` |
| `split` | `str` | `train \| val \| test` |
