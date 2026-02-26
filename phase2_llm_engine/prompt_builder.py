"""
Phase 2 – LLM Engine: Master prompt builder.

Constructs the system instruction, context definitions, and task query.
Supports Binary, Non-Binary, CoT, and structured JSON output modes.
"""

from __future__ import annotations

import json
import re

# Enhanced system prompt for structured JSON output mode
SYSTEM_PROMPT = """You are a senior smart contract security auditor with 10+ years of experience \
in Solidity, EVM internals, and DeFi protocol design. You have audited protocols managing \
billions of dollars in TVL.

Your task: Perform a rigorous security audit of the provided smart contract.

RULES:
1. Analyze ONLY what is in the code. Do not speculate about external contracts unless \
   their interface is visible.
2. For each finding, you MUST cite the exact line number(s) using the format L{n}.
3. Rate severity as: CRITICAL (immediate fund loss), HIGH (fund loss under conditions), \
   MEDIUM (governance/logic risk), LOW (best practice), INFO (observation).
4. Output your response as valid JSON matching the schema below.

OUTPUT SCHEMA:
{
  "findings": [
    {
      "vuln_type": "<vulnerability name>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "confidence": <float 0.0-1.0>,
      "lines": [<int>, ...],
      "function": "<function name or null>",
      "description": "<1-2 sentence explanation>",
      "recommendation": "<1-sentence fix suggestion>"
    }
  ],
  "summary": "<2-3 sentence overall assessment>",
  "risk_score": <float 0.0-10.0>
}
"""

# Legacy system instruction (kept for backward compat)
_SYSTEM_INSTRUCTION = (
    "You are an AI smart contract auditor that excels at finding vulnerabilities "
    "in blockchain smart contracts. Review the following smart contract code in "
    "detail and very thoroughly. Think step by step."
)

_TASK_QUERY_TEMPLATE = (
    "Perform a proper security audit of this contract, identify critical issues "
    "that can lead to loss of funds, pay special attention to logic issues. "
    "It makes sense to audit each function independently and then see how they "
    "link to other functions. First, read each function critically and identify "
    "critical security issues that can lead to loss of funds.\n\n"
    "Is the following smart contract vulnerable to {vuln_name} attacks?"
)

_BINARY_SUFFIX = (
    "\n\nAnswer with YES or NO only, followed by a one-sentence justification."
)

_COT_FUNCTION_QUERY = "Do a proper review of the {function_name}() function."


def build_prompt(
    source_code: str,
    vuln_name: str,
    vuln_description: str,
    mode: str = "non_binary",
    structured: bool = False,
) -> list[dict]:
    """
    Build a list of LLM messages for a single vulnerability check.

    Parameters
    ----------
    source_code : str
        Pre-processed Solidity contract source.
    vuln_name : str
        Name of the vulnerability being checked (e.g. ``"Reentrancy"``).
    vuln_description : str
        Technical definition of the vulnerability.
    mode : str
        ``"binary"`` – force YES/NO answer.
        ``"non_binary"`` – open-ended analysis.
        ``"cot"`` – chain-of-thought (same as non_binary, CoT handled separately).
    structured : bool
        If True, use the enhanced SYSTEM_PROMPT and request JSON output.

    Returns
    -------
    list[dict]
        List of ``{"role": ..., "content": ...}`` message dicts suitable for
        the OpenAI / Anthropic chat API.
    """
    if structured:
        user_content = (
            f"Check specifically for {vuln_name} vulnerability.\n\n"
            f"Definition: {vuln_description}\n\n"
            f"Source Code:\n{source_code}"
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]
    context = (
        f"To help you, find here a definition of a {vuln_name} attack: "
        f"{vuln_description}"
    )
    task = _TASK_QUERY_TEMPLATE.format(vuln_name=vuln_name)
    if mode == "binary":
        task += _BINARY_SUFFIX

    user_content = (
        f"{context}\n\n"
        f"{task}\n\n"
        f"Source Code:\n{source_code}"
    )

    return [
        {"role": "system", "content": _SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_content},
    ]


def extract_function_names(source_code: str) -> list[str]:
    """
    Extract all Solidity function names from *source_code*.

    Parameters
    ----------
    source_code : str
        Solidity contract source.

    Returns
    -------
    list[str]
        Ordered list of unique function names.
    """
    pattern = r"\bfunction\s+(\w+)\s*\("
    return list(dict.fromkeys(re.findall(pattern, source_code)))


def build_cot_function_prompt(
    source_code: str,
    function_name: str,
) -> list[dict]:
    """
    Build a Chain-of-Thought prompt focused on a single contract function.

    Parameters
    ----------
    source_code : str
        Full contract source (the model needs the full context to understand
        how functions interact).
    function_name : str
        Name of the function to review.

    Returns
    -------
    list[dict]
        Chat message list.
    """
    user_content = (
        f"Source Code:\n{source_code}\n\n"
        + _COT_FUNCTION_QUERY.format(function_name=function_name)
    )
    return [
        {"role": "system", "content": _SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_content},
    ]


def add_line_numbers(source_code: str) -> str:
    """
    Add ``/* L{n} */`` annotation at the start of each line.

    Parameters
    ----------
    source_code : str
        Solidity source code.

    Returns
    -------
    str
        Source with line numbers prepended to every line.
    """
    lines = source_code.splitlines()
    annotated = [f"/* L{i + 1} */ {line}" for i, line in enumerate(lines)]
    return "\n".join(annotated)


def build_few_shot_prompt(
    source_code: str,
    vuln_name: str,
    vuln_description: str,
    examples: list[dict],
    mode: str = "non_binary",
) -> list[dict]:
    """
    Build a few-shot prompt that includes 2-3 exemplar contracts.

    Parameters
    ----------
    source_code : str
        Contract to audit.
    vuln_name : str
        Vulnerability type name.
    vuln_description : str
        Technical definition.
    examples : list[dict]
        List of exemplar dicts with keys ``"source_code"``, ``"label"``
        (``"YES"``/``"NO"``), and ``"explanation"``.
    mode : str
        Classification mode.

    Returns
    -------
    list[dict]
        Chat messages with few-shot examples in the user turn.
    """
    example_text = ""
    for i, ex in enumerate(examples, 1):
        label = ex.get("label", "YES")
        explanation = ex.get("explanation", "")
        code = ex.get("source_code", "")
        example_text += (
            f"\n--- Example {i} ---\n"
            f"Contract:\n{code}\n"
            f"Answer: {label}\n"
            f"Explanation: {explanation}\n"
        )

    context = (
        f"To help you, find here a definition of a {vuln_name} attack: "
        f"{vuln_description}"
    )
    task = _TASK_QUERY_TEMPLATE.format(vuln_name=vuln_name)
    if mode == "binary":
        task += _BINARY_SUFFIX

    user_content = (
        f"{context}\n\n"
        f"Here are some examples to guide your analysis:{example_text}\n\n"
        f"--- Now analyze this contract ---\n"
        f"{task}\n\n"
        f"Source Code:\n{source_code}"
    )
    return [
        {"role": "system", "content": _SYSTEM_INSTRUCTION},
        {"role": "user", "content": user_content},
    ]


def build_multi_vuln_prompt(
    source_code: str,
    vulns: list[dict],
) -> list[dict]:
    """
    Build a single prompt that checks multiple vulnerability types at once.

    Returns a JSON-schema response listing all detected vulnerabilities.

    Parameters
    ----------
    source_code : str
        Contract to audit.
    vulns : list[dict]
        List of vulnerability type dicts (from ``VULNERABILITY_TYPES``).

    Returns
    -------
    list[dict]
        Chat messages requesting JSON output.
    """
    vuln_list = "\n".join(
        f"- {v['name']}: {v['description']}" for v in vulns
    )
    user_content = (
        f"Audit the following contract for ALL of these vulnerability types:\n\n"
        f"{vuln_list}\n\n"
        f"Source Code:\n{source_code}\n\n"
        f"For each vulnerability type found, include it in the JSON findings array."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
