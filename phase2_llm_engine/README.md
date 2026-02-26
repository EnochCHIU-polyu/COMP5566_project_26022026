# Phase 2 – LLM Engine

This package builds prompts, queries language models, parses structured responses, pre-filters irrelevant vulnerability checks, and runs a self-consistency verification pass.

---

## Table of Contents

1. [Module Overview](#1-module-overview)
2. [Vulnerability Types (`vulnerability_types.py`)](#2-vulnerability-types)
3. [Prompt Builder (`prompt_builder.py`)](#3-prompt-builder)
4. [LLM Client (`llm_client.py`)](#4-llm-client)
5. [Output Parser (`output_parser.py`)](#5-output-parser)
6. [Relevance Filter (`relevance_filter.py`)](#6-relevance-filter)
7. [Self-Checker (`self_checker.py`)](#7-self-checker)
8. [CoT Analyzer (`cot_analyzer.py`)](#8-cot-analyzer)
9. [Prompt Architecture](#9-prompt-architecture)

---

## 1. Module Overview

| File | Purpose |
|------|---------|
| `vulnerability_types.py` | 38 DeFi vulnerability definitions with SWC/CWE IDs, severity, keywords, and code examples |
| `prompt_builder.py` | Build binary / non-binary / CoT / structured / few-shot / multi-vuln prompts |
| `llm_client.py` | OpenAI + Anthropic + DeepSeek client with rate-limit pause and retry backoff |
| `output_parser.py` | Parse JSON findings from LLM responses (handles clean, markdown-wrapped, and malformed JSON) |
| `relevance_filter.py` | Keyword pre-filter — skip vulnerability checks with no matching keywords in the contract |
| `self_checker.py` | Two-pass self-consistency verification to reduce false positives |
| `cot_analyzer.py` | Orchestrates the full audit (38-vuln loop + per-function CoT) |

---

## 2. Vulnerability Types

**File:** `vulnerability_types.py`

Defines all 38 vulnerability types the framework checks. Each entry now carries:

```python
{
    "name": "Reentrancy",
    "description": "A reentrancy attack occurs when…",
    "swc_id": "SWC-107",
    "cwe_id": "CWE-841",
    "severity_default": "critical",
    "detection_keywords": [".call{", "call.value", ".call(", "external"],
    "example_vulnerable": "// Vulnerable:\nfunction withdraw() {\n    msg.sender.call{value: bal}(\"\");\n    balances[msg.sender] = 0;\n}",
    "example_fixed":      "// Fixed:\nfunction withdraw() {\n    uint bal = balances[msg.sender];\n    balances[msg.sender] = 0;\n    msg.sender.call{value: bal}(\"\");\n}",
}
```

| Field | Description |
|-------|-------------|
| `name` | Short identifier used in prompts and results |
| `description` | Technical definition injected into the prompt |
| `swc_id` | Smart Contract Weakness Classification ID (e.g. `SWC-107`) |
| `cwe_id` | Common Weakness Enumeration ID |
| `severity_default` | Default severity (`critical / high / medium / low / info`) |
| `detection_keywords` | Keywords used by `relevance_filter.py` to pre-screen contracts |
| `example_vulnerable` | Short Solidity snippet showing the vulnerable pattern |
| `example_fixed` | Short Solidity snippet showing the corrected pattern |

**Complete list of the 38 vulnerability types:**

| # | Name | SWC | Default Severity |
|---|------|-----|-----------------|
| 1 | Reentrancy | SWC-107 | critical |
| 2 | Integer Overflow/Underflow | SWC-101 | high |
| 3 | Access Control | SWC-105 | high |
| 4 | Unchecked Return Value | SWC-104 | medium |
| 5 | Timestamp Dependence | SWC-116 | low |
| 6 | Tx.Origin Authentication | SWC-115 | high |
| 7 | Unprotected Self-Destruct | SWC-106 | critical |
| 8 | Denial of Service | SWC-113 | high |
| 9 | Front-Running | SWC-114 | medium |
| 10 | Delegate Call | SWC-112 | critical |
| 11 | Flash Loan Attack | — | critical |
| 12 | Oracle Manipulation | — | high |
| 13 | Signature Replay | SWC-121 | high |
| 14 | Uninitialized Storage Pointer | SWC-109 | high |
| 15 | Arithmetic Precision Loss | — | medium |
| 16 | Logic Error | — | high |
| 17 | Improper Input Validation | SWC-103 | medium |
| 18 | Centralization Risk | — | medium |
| 19 | Price Manipulation | — | critical |
| 20 | Sandwich Attack | — | medium |
| 21 | Governance Attack | — | critical |
| 22 | Cross-Function Reentrancy | SWC-107 | critical |
| 23 | Read-Only Reentrancy | SWC-107 | high |
| 24 | ERC-20 Approval Exploit | — | high |
| 25 | Griefing | — | medium |
| 26 | Short Address Attack | SWC-102 | medium |
| 27 | Forced Ether Send | SWC-132 | low |
| 28 | Unsafe Randomness | SWC-120 | high |
| 29 | Upgradability Flaw | — | high |
| 30 | Denial of Service via Revert | SWC-113 | high |
| 31 | Token Inflation | — | high |
| 32 | Liquidity Drain | — | critical |
| 33 | Incorrect Inheritance | — | medium |
| 34 | Phantom Function | — | high |
| 35 | Event Spoofing | — | low |
| 36 | Insufficient Gas Stipend | SWC-134 | medium |
| 37 | Frozen Ether | SWC-132 | high |
| 38 | Misuse of Assembly | SWC-127 | high |

---

## 3. Prompt Builder

**File:** `prompt_builder.py`

Constructs LLM message lists for all supported audit modes.

### Prompt modes

| Mode | Function | Description |
|------|----------|-------------|
| Legacy non-binary | `build_prompt(..., mode="non_binary")` | Open-ended analysis (backward compat) |
| Legacy binary | `build_prompt(..., mode="binary")` | YES/NO answer only |
| Legacy CoT | `build_cot_function_prompt(src, fn)` | Per-function chain-of-thought |
| Structured JSON | `build_prompt(..., structured=True)` | 4-section prompt with JSON output schema |
| Few-shot | `build_few_shot_prompt(...)` | Includes vulnerable/fixed exemplars before the contract |
| Multi-vuln batch | `build_multi_vuln_prompt(src, vulns)` | Check 5-8 vulns in a single LLM call |

### Legacy API (backward compatible)

```python
from phase2_llm_engine.prompt_builder import build_prompt, build_cot_function_prompt

# Non-binary (returns list of {"role", "content"} dicts)
messages = build_prompt(source_code, "Reentrancy", description, mode="non_binary")

# Binary YES/NO
messages = build_prompt(source_code, "Reentrancy", description, mode="binary")

# Structured JSON output mode
messages = build_prompt(source_code, "Reentrancy", description, structured=True)
```

### New functions

```python
from phase2_llm_engine.prompt_builder import (
    add_line_numbers,
    build_few_shot_prompt,
    build_multi_vuln_prompt,
    extract_function_names,
    SYSTEM_PROMPT,
)

# Add /* L{n} */ annotations to every line
annotated = add_line_numbers(source_code)

# Few-shot prompt with example findings
messages = build_few_shot_prompt(source_code, vuln_name, description, examples)

# Check multiple vulns in one call
vulns = VULNERABILITY_TYPES[:8]   # batch of 8
messages = build_multi_vuln_prompt(source_code, vulns)

# Extract function names from source
names = extract_function_names(source_code)  # ["deposit", "withdraw", ...]
```

---

## 4. LLM Client

**File:** `llm_client.py`

Wraps the OpenAI and Anthropic APIs with:

- **Rate-limit pause** — enforces `API_PAUSE_SECONDS` (default 13 s) between calls.
- **Retry with exponential backoff** — 3 retries at 2 / 4 / 8 second intervals on transient errors.
- **Model routing** — `gpt-*` → OpenAI, `claude-*` → Anthropic, everything else → OpenAI-compatible endpoint.
- **Lazy client creation** — clients are only instantiated when first needed.

```python
from phase2_llm_engine.llm_client import query_llm

response = query_llm(
    messages=[{"role": "user", "content": "Hello"}],
    model="gpt-4o",        # optional, defaults to config.DEFAULT_MODEL
    temperature=0.0,       # optional, defaults to config.TEMPERATURE
    max_tokens=2048,
)
```

### Supported models

| Model string | Provider |
|-------------|----------|
| `gpt-4o` | OpenAI |
| `gpt-4-turbo` | OpenAI |
| `gpt-3.5-turbo` | OpenAI |
| `claude-3-opus-20240229` | Anthropic |
| `claude-3-sonnet-20240229` | Anthropic |
| `deepseek-v3.2` | OpenAI-compatible (set base URL in env) |

---

## 5. Output Parser

**File:** `output_parser.py`

Parses raw LLM responses into typed `Finding` / `AuditResult` objects. Handles three response formats:

1. **Clean JSON** — `{"findings": [...], "summary": "...", "risk_score": 7.5}`
2. **Markdown-fenced JSON** — ` ```json { … } ``` `
3. **Malformed / partial JSON** — attempts `json.loads` on extracted `{…}` substrings
4. **Fallback** — regex extraction of vulnerability mentions and line-number patterns

### Data classes

```python
from phase2_llm_engine.output_parser import Finding, AuditResult

@dataclass
class Finding:
    vuln_type: str
    severity: str = "MEDIUM"       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float = 0.5        # 0.0 – 1.0
    lines: list[int] = []          # 1-indexed line numbers
    function: str | None = None
    description: str = ""
    recommendation: str = ""

@dataclass
class AuditResult:
    findings: list[Finding] = []
    summary: str = ""
    risk_score: float = 0.0        # 0.0 – 10.0
    raw_response: str = ""
```

### Usage

```python
from phase2_llm_engine.output_parser import parse_audit_response, extract_confidence

result = parse_audit_response(raw_llm_response)
for finding in result.findings:
    print(f"{finding.severity} | {finding.vuln_type} @ L{finding.lines}")

# Heuristic confidence from language markers
conf = extract_confidence("This contract definitely has a reentrancy vulnerability")
# → 0.95
```

### Certainty markers

| Marker | Score |
|--------|-------|
| `definitely`, `certainly` | 0.95 |
| `clearly` | 0.90 |
| `likely`, `probably` | 0.75 / 0.70 |
| `possibly` | 0.50 |
| `might`, `could` | 0.45 / 0.40 |
| `unlikely` | 0.25 |

---

## 6. Relevance Filter

**File:** `relevance_filter.py`

Fast keyword-based pre-screening that eliminates vulnerability checks before any API call is made.

```python
from phase2_llm_engine.relevance_filter import filter_relevant_vulns
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES

relevant = filter_relevant_vulns(
    source_code=contract_source,
    vuln_types=VULNERABILITY_TYPES,
    no_filter=False,   # True = disable filter (for benchmarking)
)
# INFO: Relevance filter: 12/38 vuln types selected (26 skipped)
```

### Logic

1. For each vulnerability type, look up its `detection_keywords` list.
2. If **none** of the keywords appear in `source_code.lower()` → **skip** that check.
3. Special case: `Integer Overflow/Underflow` is always skipped for contracts with `pragma solidity >=0.8.0`.
4. Vulnerability types with an empty `detection_keywords` list are always included.

**Typical reduction:** 60–80 % fewer API calls on contracts that don't use many low-level primitives.

---

## 7. Self-Checker

**File:** `self_checker.py`

Implements a two-pass verification architecture to reduce false positives.

```
Pass 1 (Detect):  Standard audit → N candidate findings
Pass 2 (Verify):  For each finding, send a sceptical prompt:
                  "Auditor claims [VulnType] at [Lines]. Genuine or false positive?
                   → {verified: bool, confidence: float, reasoning: str}"
Pass 3 (Merge):   Findings with confidence < threshold → demoted to INFO severity
```

### Data classes

```python
@dataclass
class VerifiedFinding:
    finding: Finding                    # original Finding from Pass 1
    verified: bool                      # True = confirmed genuine
    verification_confidence: float      # 0.0 – 1.0
    verification_reasoning: str         # LLM's reasoning text
```

### Usage

```python
from phase2_llm_engine.self_checker import self_check_audit, verify_finding
from phase2_llm_engine.llm_client import query_llm

# Verify a single finding
vf = verify_finding(finding, source_code, query_fn=query_llm)

# Verify all findings in an AuditResult
verified = self_check_audit(
    initial_result=audit_result,
    source_code=source_code,
    query_fn=query_llm,
    confidence_threshold=0.6,   # findings below this → demoted to INFO
)
```

---

## 8. CoT Analyzer

**File:** `cot_analyzer.py`

High-level orchestrator that runs the full audit pipeline.

```python
from phase2_llm_engine.cot_analyzer import analyze_contract

result = analyze_contract(
    source_code=preprocessed_source,
    contract_name="MyContract.sol",
    mode="non_binary",           # binary | non_binary | cot | multi_vuln
    model="gpt-4o",
    temperature=0.0,
    verify=True,                 # enable two-pass self-check
    progress_callback=lambda i, n, name: print(f"{i}/{n}: {name}"),
)
```

### Result structure

```python
{
    "contract_name": "MyContract.sol",
    "vuln_results": [
        {"vuln_name": "Reentrancy",  "response": "YES, the withdraw function…"},
        {"vuln_name": "Access Control", "response": "NO, the contract…"},
        # ... 38 entries total
    ],
    "function_results": [
        {"function_name": "withdraw", "response": "The withdraw function…"},
        # ... one entry per Solidity function
    ],
    # present only when verify=True:
    "verified_findings": [
        {
            "finding": {"vuln_type": "Reentrancy", "severity": "CRITICAL", …},
            "verified": true,
            "verification_confidence": 0.9,
            "verification_reasoning": "The external call on line 42 precedes…"
        }
    ]
}
```

---

## 9. Prompt Architecture

### Structured prompt (4 sections)

```
┌──────────────────────────────────────────────────────────────────────┐
│ SYSTEM – Role Definition                                              │
│   "You are a senior smart contract security auditor with 10+ years   │
│    of experience in Solidity, EVM internals, and DeFi protocol       │
│    design …"                                                         │
├──────────────────────────────────────────────────────────────────────┤
│ USER Section 1 – Vulnerability Context                                │
│   Definition of [VulnType] + SWC/CWE + example vulnerable code +    │
│   example fixed code                                                 │
├──────────────────────────────────────────────────────────────────────┤
│ USER Section 2 – Task Instruction + JSON Output Schema               │
│   "Is the contract vulnerable to [VulnType]? Cite exact line         │
│    numbers using L{n}. Return valid JSON:                            │
│    {findings:[{vuln_type,severity,confidence,lines,function,         │
│                description,recommendation}],                         │
│     summary, risk_score}"                                            │
├──────────────────────────────────────────────────────────────────────┤
│ USER Section 3 – Source Code (line-numbered)                         │
│   /* L1 */ pragma solidity ^0.8.0;                                   │
│   /* L2 */ contract Vault {                                          │
│   …                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

### Multi-vuln batch mode

Groups up to 8 vulnerability checks into one LLM call. Reduces 38 API calls to ~5 calls (a ~7× speedup).

```python
from phase2_llm_engine.prompt_builder import build_multi_vuln_prompt
from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES

# Batch first 8 vulns
messages = build_multi_vuln_prompt(source_code, VULNERABILITY_TYPES[:8])
```

### JSON output schema

```json
{
  "findings": [
    {
      "vuln_type": "Reentrancy",
      "severity": "CRITICAL",
      "confidence": 0.95,
      "lines": [42, 43],
      "function": "withdraw",
      "description": "State update occurs after the external call on L42.",
      "recommendation": "Move balance update before the external call."
    }
  ],
  "summary": "The contract has a critical reentrancy vulnerability in the withdraw function.",
  "risk_score": 9.0
}
```
