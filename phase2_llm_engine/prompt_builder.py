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
    "detail and very thoroughly. Think step by step. "
    "For reentrancy: if state is updated AFTER an external call (.call, .transfer, etc.), "
    "the verdict should be YES — that is a classic vulnerability. "
    "Whenever the user instructions require a line-1 verdict, you MUST output YES or NO "
    "on the first line of your reply before any explanation."
)

_TASK_QUERY_TEMPLATE = (
    "Perform a proper security audit of this contract, identify critical issues "
    "that can lead to loss of funds, pay special attention to logic issues. "
    "It makes sense to audit each function independently and then see how they "
    "link to other functions. First, read each function critically and identify "
    "critical security issues that can lead to loss of funds.\n\n"
    "Question: Is the following smart contract vulnerable to {vuln_name} attacks?\n"
    "You must decide and state a clear binary verdict (see VERDICT section below)."
)

# Verdict-first: parsers and benchmarks rely on line 1 being exactly YES or NO.
_BINARY_SUFFIX = (
    "\n\n=== MANDATORY VERDICT (BINARY MODE) ===\n"
    "Output rules (strict):\n"
    "- Line 1: ONLY the English word YES or NO (no punctuation, no label, no markdown heading on line 1).\n"
    "- Meaning: YES = the contract IS vulnerable to this attack type; NO = it is NOT.\n"
    "- Line 2: exactly one short English sentence justifying the verdict.\n"
    "- Do not put analysis before line 1. Automated evaluation reads line 1 only for the verdict."
)

_SCORING_FIRST_LINE_SUFFIX = (
    "\n\n=== MANDATORY VERDICT (DETAILED MODE) ===\n"
    "Output rules (strict):\n"
    "- Line 1: ONLY the English word YES or NO.\n"
    "- YES = the contract IS vulnerable to {vuln_name}; NO = it is NOT vulnerable to that type.\n"
    "- Line 2 onward: full analysis in English (reasoning, code references, steps).\n"
    "- Do not prefix line 1 with labels like 'Verdict:' — the first characters of your reply must be Y-E-S or N-O.\n"
    "- Breaking this format invalidates automated scoring."
)

_COT_FUNCTION_QUERY = (
    "Do a proper security review of the {function_name}() function.\n\n"
    "=== MANDATORY VERDICT ===\n"
    "Line 1: ONLY the English word YES or NO.\n"
    "YES = you find a security concern in this function; NO = no material concern for this function.\n"
    "Line 2+: reasoning and references."
)

# Per-vulnerability-type critical hints for Agent/judge (all 38 types)
VULN_CRITICAL_HINTS = {
    "Reentrancy": "State updated AFTER external call (.call{value}) → YES",
    "Cross-Function Reentrancy": "State shared across functions, external call before update → YES",
    "Read-Only Reentrancy": "View function calls external before state read → YES",
    "Integer Overflow/Underflow": "Solidity <0.8 without SafeMath, or unchecked block → YES",
    "Access Control": "Privileged function without onlyOwner/require(msg.sender) → YES",
    "Unchecked Return Value": "Low-level call/send/transfer return value ignored → YES",
    "Timestamp Dependence": "block.timestamp for randomness or critical logic → YES",
    "Tx.Origin Authentication": "tx.origin used for auth instead of msg.sender → YES",
    "Unprotected Self-Destruct": "selfdestruct without access control → YES",
    "Delegate Call": "delegatecall to user-controlled address → YES",
    "Unsafe Randomness": "block.timestamp/hash for randomness → YES",
    "Oracle Manipulation": "Single oracle or manipulable price source → YES",
    "Signature Replay": "Signature used without nonce/chainId → YES",
    "Uninitialized Storage Pointer": "Storage pointer to uninitialized storage → YES",
    "Logic Error": "Incorrect business logic, wrong condition → YES",
    "Improper Input Validation": "Missing require/validation on inputs → YES",
    "Denial of Service": "Loop over unbounded array, or revert blocks progress → YES",
    "Front-Running": "Mempool-visible tx order dependency → YES",
    "Flash Loan Attack": "Single-tx manipulation via flash loan → YES",
    "ERC-20 Approval Exploit": "Approval before transfer, or infinite approval → YES",
    "Forced Ether Send": "Contract assumes msg.value or balance without check → YES",
    "Griefing": "Attacker can cause revert or block progress → YES",
    "Short Address Attack": "ERC-20 transfer with padded address → YES",
    "Upgradability Flaw": "Proxy/upgrade without proper initialization → YES",
    "Denial of Service via Revert": "External call can revert and block → YES",
    "Token Inflation": "Unchecked mint or supply manipulation → YES",
    "Liquidity Drain": "Manipulable AMM or oracle → YES",
    "Incorrect Inheritance": "Wrong override order or missing super → YES",
    "Phantom Function": "Fallback/receive without proper handling → YES",
    "Event Spoofing": "Missing indexed or verifiable event → YES",
    "Insufficient Gas Stipend": "Low-level call with limited gas → YES",
    "Frozen Ether": "ETH stuck due to missing receive/fallback → YES",
    "Misuse of Assembly": "Unsafe assembly, storage collision → YES",
    "Centralization Risk": "Single admin/owner with excessive power → YES",
    "Price Manipulation": "TWAP or oracle manipulable in one block → YES",
    "Sandwich Attack": "Mempool front-run + back-run → YES",
    "Governance Attack": "Vote manipulation or flash loan governance → YES",
}


def build_prompt(
    source_code: str,
    vuln_name: str,
    vuln_description: str,
    mode: str = "non_binary",
    structured: bool = False,
    example_vulnerable: str = "",
    example_fixed: str = "",
    slither_reference: str = "",
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
        ``"binary"`` – YES/NO plus short justification.
        ``"non_binary"`` / ``"cot"`` – first line MUST still be YES or NO (for scoring), then detailed analysis.
        ``"multi_vuln"`` – not used here; see ``build_multi_vuln_prompt``.
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
    if example_vulnerable:
        context += f"\n\nVulnerable pattern example:\n{example_vulnerable}"
    if example_fixed:
        context += f"\n\nFixed pattern example:\n{example_fixed}"
    hint = VULN_CRITICAL_HINTS.get(vuln_name, "")
    if hint:
        context += f"\n\nCRITICAL: {hint}"
    if slither_reference.strip():
        context += (
            "\n\nStatic analysis reference (Slither, may include false positives):\n"
            f"{slither_reference.strip()}"
        )
    task = _TASK_QUERY_TEMPLATE.format(vuln_name=vuln_name)
    if mode == "binary":
        task += _BINARY_SUFFIX
    elif mode in ("non_binary", "cot"):
        task += _SCORING_FIRST_LINE_SUFFIX.format(vuln_name=vuln_name)

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
    elif mode in ("non_binary", "cot"):
        task += _SCORING_FIRST_LINE_SUFFIX.format(vuln_name=vuln_name)

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


def build_agent_reflection_prompt(
    source_code: str,
    vuln_name: str,
    vuln_description: str,
    initial_analysis: str,
    slither_reference: str = "",
) -> list[dict]:
    """
    Build prompt for agent reflection step: judge whether initial analysis is correct.

    Parameters
    ----------
    source_code : str
        Contract source.
    vuln_name : str
        Vulnerability type being checked.
    vuln_description : str
        Definition of the vulnerability.
    initial_analysis : str
        First LLM's analysis/response.

    Returns
    -------
    list[dict]
        Chat messages for reflection/judgment step.
    """
    system = (
        "You are a senior smart contract security auditor acting as a critical reviewer. "
        "Your task: Review another auditor's analysis and decide if it is correct. "
        "Be rigorous: reject vague or incorrect reasoning. "
        "MANDATORY: Line 1 of your reply must be exactly the English word YES or NO (verdict). "
        "Line 2+: brief justification."
    )
    hint = VULN_CRITICAL_HINTS.get(vuln_name, "")
    hint_block = f"\nCritical pattern to check: {hint}" if hint else ""
    slither_block = (
        "\n\nStatic analysis reference (Slither, may include false positives):\n"
        f"{slither_reference.strip()}"
        if slither_reference.strip()
        else ""
    )
    user_content = (
        f"Vulnerability type: {vuln_name}\n"
        f"Definition: {vuln_description}{hint_block}\n\n"
        f"{slither_block}\n"
        f"Another auditor's analysis:\n{initial_analysis}\n\n"
        f"Source code (excerpt):\n{source_code[:4000]}\n\n"
        "Is this analysis correct? Does the contract actually have this vulnerability? "
        "Your first line must be YES or NO only; then explain in 1-2 sentences."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]


def build_multi_vuln_prompt(
    source_code: str,
    vulns: list[dict],
    slither_reference: str = "",
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
    slither_block = (
        "Slither reference (may include false positives):\n"
        f"{slither_reference.strip()}\n\n"
        if slither_reference.strip()
        else ""
    )
    user_content = (
        f"Audit the following contract for ALL of these vulnerability types:\n\n"
        f"{vuln_list}\n\n"
        f"{slither_block}"
        f"Source Code:\n{source_code}\n\n"
        f"For each vulnerability type found, include it in the JSON findings array."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def build_batch_audit_prompt(
    source_code: str,
    vulns: list[dict],
    mode: str = "non_binary",
    slither_reference: str = "",
) -> list[dict]:
    """
    Build batch prompt with strict JSON schema. Includes per-vuln examples and hints.
    """
    mode_instruction = {
        "binary": "Use YES/NO verdict for each vulnerability, with a concise but specific explanation.",
        "non_binary": "Provide detailed explanation for each vulnerability, including why it applies or does not apply.",
        "cot": "Reason step-by-step internally and provide concise final explanations.",
        "multi_vuln": "Audit all listed vulnerabilities together and provide detailed per-vulnerability explanations.",
    }.get(mode, "Provide detailed explanation for each vulnerability.")

    vuln_blocks = []
    for v in vulns:
        name = v.get("name", "")
        desc = v.get("description", "")
        ex_v = v.get("example_vulnerable", "")
        ex_f = v.get("example_fixed", "")
        hint = VULN_CRITICAL_HINTS.get(name, "")
        block = f"- **{name}**: {desc}"
        if ex_v:
            block += f"\n  Vulnerable pattern: {ex_v[:200]}..."
        if ex_f:
            block += f"\n  Fixed pattern: {ex_f[:150]}..."
        if hint:
            block += f"\n  CRITICAL: {hint}"
        vuln_blocks.append(block)
    vuln_block = "\n\n".join(vuln_blocks)

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
    slither_block = (
        "Static analysis reference (Slither, may include false positives):\n"
        f"{slither_reference.strip()}\n\n"
        if slither_reference.strip()
        else ""
    )
    user_prompt = (
        "Audit the smart contract for each selected vulnerability and return ONLY valid JSON.\n\n"
        f"Mode: {mode}\nInstruction: {mode_instruction}\n\n"
        "Selected vulnerabilities (with patterns and critical hints):\n"
        f"{vuln_block}\n\n"
        f"{slither_block}"
        "Requirements:\n"
        "1) Return one result object for EVERY listed vulnerability (no omissions).\n"
        "2) Keep vuln_name exactly identical to the provided name.\n"
        "3) verdict MUST be YES or NO when possible (binary judgment per vulnerability); use UNCERTAIN only if truly undecidable.\n"
        "4) explanation must cite specific code and match the CRITICAL pattern.\n"
        "5) evidence_lines should contain concrete line numbers when available, else [].\n\n"
        f"Output schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Source Code:\n{source_code}"
    )
    return [
        {"role": "system", "content": "You are a senior smart contract security auditor. Output valid JSON only."},
        {"role": "user", "content": user_prompt},
    ]
