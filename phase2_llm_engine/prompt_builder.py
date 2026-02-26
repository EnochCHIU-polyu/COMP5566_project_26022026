"""
Phase 2 – LLM Engine: Master prompt builder.

Constructs the system instruction, context definitions, and task query
described in the research paper's Master LLM Prompt Template.
Supports Binary, Non-Binary, and Chain-of-Thought (CoT) modes.
"""

from __future__ import annotations

import re

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

    Returns
    -------
    list[dict]
        List of ``{"role": ..., "content": ...}`` message dicts suitable for
        the OpenAI / Anthropic chat API.
    """
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
