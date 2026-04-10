"""
core.taxonomy_engine
=====================
Evolvable Vulnerability Taxonomy Engine for the Autonomous Smart Contract Auditor.

Overview
--------
The taxonomy is the "brain" of the auditor's classification system.  It stores
structured natural-language definitions of vulnerability types and supports a
**"Defining Loop"** — a self-learning mechanism that extends the taxonomy
whenever Agent 2 (The Reasoner) identifies a high-confidence threat that does
not map to any existing label.

Architecture
------------

::

    vuln_definitions.json          ← persistent store (human-readable JSON)
           │
           ▼
    VulnerabilityTaxonomy          ← in-memory manager loaded at start-up
           │
    ┌──────┴─────────────────┐
    │  definitions: dict     │  name → VulnerabilityDefinition
    │  expand_taxonomy_from_audit() │  ← Learning Loop entry point
    └────────────────────────┘

VulnerabilityDefinition Schema
------------------------------
Each definition captures the fields from Table 7 of the paper
"Do you still need a manual smart contract audit?":

    name            : str   — short canonical identifier
    description     : str   — natural-language technical definition (from paper)
    risk_indicators : list  — code-level patterns that signal this vulnerability
    swc_id          : str   — Smart Contract Weakness Classification ID (or "")
    severity        : str   — "critical" | "high" | "medium" | "low"
    source          : str   — "paper" | "llm_derived" | "manual"
    added_at        : str   — ISO-8601 UTC timestamp

The Defining Loop (expand_taxonomy_from_audit)
----------------------------------------------
When Agent 2 returns a verdict with:
  • ``confidence >= EXPANSION_CONFIDENCE_THRESHOLD`` (default 0.85)
  • ``vuln_type`` not present in the current taxonomy

…the engine triggers a **sub-agent** (an LLM call) to synthesise a new
definition entry from the audit evidence and verdict reasoning.

The sub-agent receives a structured prompt containing:
  1. The contract name and source snippet
  2. The agent verdict (reasoning, evidence_lines, confidence)
  3. All existing taxonomy names (so it avoids duplicates)

The sub-agent returns JSON matching the VulnerabilityDefinition schema.
The engine validates and appends it to ``vuln_definitions.json``.

This design means the taxonomy **grows over time** as the system encounters
novel attack patterns in live contracts, without manual intervention.

Usage
-----
    from core.taxonomy_engine import VulnerabilityTaxonomy

    tax = VulnerabilityTaxonomy()              # loads from default JSON
    defn = tax.get("Reentrancy")               # look up a definition
    prompt = tax.build_audit_prompt(defn, src) # inject into audit query

    # Learning loop (called after each high-confidence Agent2 verdict):
    new_entry = tax.expand_taxonomy_from_audit(
        verdict=agent2_result["verdict"],
        contract_name="MyContract",
        source_snippet=source[:2000],
        llm_client=my_llm_fn,   # (prompt: str) -> str
    )
    if new_entry:
        print(f"New vulnerability type discovered: {new_entry.name}")
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_TAXONOMY_FILE = _PROJECT_ROOT / "data" / "vuln_definitions.json"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum Agent 2 confidence required to trigger a taxonomy expansion.
# Set deliberately high to avoid polluting the taxonomy with low-quality signals.
EXPANSION_CONFIDENCE_THRESHOLD: float = 0.85

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VulnerabilityDefinition:
    """
    A single vulnerability definition entry in the taxonomy.

    Attributes
    ----------
    name : str
        Canonical short name used as the taxonomy key (e.g. "Reentrancy").
    description : str
        Full natural-language technical definition, sourced from the research
        paper's Table 7 for the five core types, or synthesised by the LLM
        sub-agent for derived types.
    risk_indicators : list[str]
        Concrete code-level patterns or behavioural signals that indicate this
        vulnerability may be present.  Used to build targeted audit prompts.
    swc_id : str
        Smart Contract Weakness Classification identifier (e.g. "SWC-107").
        Empty string if no SWC mapping exists.
    severity : str
        Default severity: "critical", "high", "medium", or "low".
    source : str
        How this definition entered the taxonomy:
        - "paper"        — pre-populated from the research paper
        - "llm_derived"  — auto-generated by the Defining Loop
        - "manual"       — added or edited by a human
    added_at : str
        ISO-8601 UTC timestamp of when the entry was added.
    """

    name: str
    description: str
    risk_indicators: list[str]
    swc_id: str = ""
    severity: str = "high"
    source: str = "manual"
    added_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityDefinition":
        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            risk_indicators=list(data.get("risk_indicators", [])),
            swc_id=str(data.get("swc_id", "")),
            severity=str(data.get("severity", "high")),
            source=str(data.get("source", "manual")),
            added_at=str(data.get("added_at", datetime.now(timezone.utc).isoformat())),
        )


# ---------------------------------------------------------------------------
# Core pre-populated definitions (Table 7 of the paper)
# ---------------------------------------------------------------------------

# These five definitions are directly sourced from the natural-language
# descriptions in "Do you still need a manual smart contract audit?"
# They represent the canonical logical vulnerability taxonomy used for
# all audit queries by default.

_CORE_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "Reentrancy",
        "description": (
            "A reentrancy vulnerability occurs when a smart contract makes an external "
            "call to another contract before it finishes updating its own state. The "
            "called contract can then call back into the original contract in a recursive "
            "manner, repeatedly executing the same logic (typically a withdrawal) before "
            "the initial invocation completes. This allows an attacker to drain funds far "
            "in excess of their legitimate balance. The canonical defence is the "
            "checks-effects-interactions pattern: update all state variables before any "
            "external call, or use a reentrancy guard (mutex). The vulnerability maps to "
            "SWC-107 and is responsible for high-profile exploits including The DAO hack."
        ),
        "risk_indicators": [
            "external call (call, send, transfer) before state update",
            "balances[msg.sender] read after .call{value:}",
            "msg.sender.call{value: bal}() before balances[msg.sender] = 0",
            "missing reentrancy guard / nonReentrant modifier",
            "cross-function reentrancy via shared state variable",
            "delegatecall to external address with mutable state",
        ],
        "swc_id": "SWC-107",
        "severity": "critical",
        "source": "paper",
    },
    {
        "name": "Oracle Manipulation",
        "description": (
            "Oracle manipulation exploits the fact that a smart contract reads an on-chain "
            "price feed (e.g. a Uniswap spot price or Curve pool ratio) that can be "
            "transiently moved by a large trade within the same transaction block. An "
            "attacker — typically using a flash loan to acquire temporary capital — "
            "manipulates the oracle price, executes a contract interaction at the "
            "artificial price (e.g. borrowing against over-valued collateral or "
            "liquidating a position at an under-valued price), and then reverses the "
            "price manipulation, all within a single atomic transaction. Defences include "
            "using time-weighted average prices (TWAPs), multi-source price aggregation "
            "(e.g. Chainlink), and sanity-check bounds on price deviation."
        ),
        "risk_indicators": [
            "single-block or spot price read from AMM (getReserves, slot0)",
            "collateral value calculated from on-chain DEX price",
            "liquidation threshold or collateral ratio based on AMM spot price",
            "price oracle call in same block as large trade in the same pool",
            "no TWAP or price deviation guard",
            "Uniswap V2/V3 getReserves() used directly for pricing",
        ],
        "swc_id": "",
        "severity": "critical",
        "source": "paper",
    },
    {
        "name": "Flash Loan Attack",
        "description": (
            "A flash loan attack leverages uncollateralised loans (available from protocols "
            "such as Aave, dYdX, or Uniswap V3) that must be borrowed and repaid within a "
            "single transaction. The temporary capital — potentially millions of dollars — "
            "allows an attacker to overwhelm governance mechanisms (buying a supermajority "
            "of voting tokens), manipulate market prices, or exploit arithmetic invariants "
            "that hold only within normal liquidity bounds. The key risk indicator is the "
            "availability of large single-transaction capital combined with a logic "
            "assumption about the scale of user funds. Defences include using commit-reveal "
            "voting, TWAP prices, and per-block liquidity limits."
        ),
        "risk_indicators": [
            "governance vote weight derived from token balance at call time",
            "snapshot of balances without time-lock or commit-reveal",
            "price or collateral calculation in same tx as a large flashLoan() callback",
            "executeOperation / onFlashLoan callback invoked before state update",
            "protocol invariant (e.g. k=xy) checked only at end of transaction",
            "balanceOf(address(this)) used as an oracle or invariant check",
        ],
        "swc_id": "",
        "severity": "critical",
        "source": "paper",
    },
    {
        "name": "Access Control Flaws",
        "description": (
            "Access control flaws occur when privileged functions — such as those that "
            "transfer ownership, drain funds, upgrade logic, pause the contract, or "
            "destroy it — are callable by any externally-owned account without proper "
            "authorisation checks. Common root causes include missing onlyOwner or "
            "role-based modifiers, reliance on tx.origin instead of msg.sender for "
            "authentication (which can be spoofed via a phishing contract), incorrect "
            "visibility specifiers (public instead of internal/private), and broken "
            "initialisation patterns in upgradeable proxies (where an attacker calls "
            "initialize() on an un-initialised implementation contract). This maps to "
            "SWC-105 and SWC-115 and is one of the most frequent causes of protocol losses."
        ),
        "risk_indicators": [
            "public/external function modifying owner, admin, or treasury without access check",
            "selfdestruct or delegatecall callable without require(msg.sender == owner)",
            "tx.origin used instead of msg.sender for authorisation",
            "initialize() function callable more than once (missing initialised flag)",
            "role assignment (grantRole, transferOwnership) without existing-role check",
            "unprotected upgrade function in proxy pattern (UUPS / Transparent Proxy)",
            "missing access modifier on fund withdrawal or emergency functions",
        ],
        "swc_id": "SWC-105",
        "severity": "high",
        "source": "paper",
    },
    {
        "name": "Unsafe Delegatecall",
        "description": (
            "delegatecall executes the code of a target contract in the context of the "
            "calling contract's storage, message sender, and value.  An unsafe delegatecall "
            "vulnerability arises when the target address is user-supplied, stored in a "
            "storage slot that can be overwritten, or can be updated by an unprivileged "
            "actor.  An attacker can supply a malicious contract address and execute "
            "arbitrary code with full write access to the caller's storage — including "
            "overwriting the owner variable, draining funds, or bricking the contract. "
            "Proxy upgrade patterns are especially susceptible if the implementation "
            "address can be set without access control. Defences include validating the "
            "target address against a whitelist, restricting who can change it, and "
            "auditing storage layout compatibility between proxy and implementation."
        ),
        "risk_indicators": [
            "delegatecall(target) where target is msg.data-derived or user-supplied",
            "implementation address stored in a publicly-writable storage slot",
            "fallback function with delegatecall to a variable address",
            "unprotected setImplementation() or upgradeTo() function",
            "storage layout mismatch between proxy and implementation contracts",
            "libraries with non-pure/non-view functions called via delegatecall",
        ],
        "swc_id": "SWC-112",
        "severity": "critical",
        "source": "paper",
    },
]


# ---------------------------------------------------------------------------
# LLM sub-agent prompt for taxonomy expansion
# ---------------------------------------------------------------------------

_EXPANSION_PROMPT_TEMPLATE = """
You are a smart contract security research assistant specialised in vulnerability taxonomy.

A smart contract auditor has identified a high-confidence security threat in the contract
"{contract_name}" that does NOT map to any existing vulnerability category.

=== EXISTING TAXONOMY (do NOT duplicate any of these) ===
{existing_names}

=== AGENT VERDICT ===
{verdict_json}

=== CONTRACT SOURCE SNIPPET (first 3000 chars) ===
{source_snippet}

Your task: Define a NEW vulnerability category for this threat.
Return ONLY a valid JSON object with these exact fields (no extra text):

{{
  "name": "<short canonical name, max 5 words>",
  "description": "<precise technical definition, 3-6 sentences, citing the attack vector, root cause, and impact>",
  "risk_indicators": [
    "<code-level indicator 1>",
    "<code-level indicator 2>",
    "<code-level indicator 3>",
    "<code-level indicator 4>"
  ],
  "swc_id": "<SWC-XXX or empty string>",
  "severity": "<critical|high|medium|low>"
}}

Rules:
- The name must be unique and not overlap with existing taxonomy names.
- The description must be technically precise and cite the specific root cause observed.
- Risk indicators must be actionable code-search patterns.
- Do NOT wrap in markdown fences.  Return raw JSON only.
""".strip()


# ---------------------------------------------------------------------------
# VulnerabilityTaxonomy class
# ---------------------------------------------------------------------------


class VulnerabilityTaxonomy:
    """
    Manages the vulnerability definition knowledge base.

    The taxonomy is loaded from (and persisted to) a JSON file.  On first use
    it is auto-seeded with the five core definitions sourced from the research
    paper.  As the system audits contracts, the ``expand_taxonomy_from_audit``
    method can add new entries autonomously.

    Parameters
    ----------
    taxonomy_file : str | Path | None
        Path to ``vuln_definitions.json``.  Defaults to
        ``data/vuln_definitions.json`` relative to the project root.
    auto_seed : bool
        If True (default), populate the five core entries if the file does not
        yet exist or is empty.

    The Defining Loop
    -----------------
    Call ``expand_taxonomy_from_audit`` after each Agent 2 verdict.  If the
    verdict's ``vuln_type`` is "other" or unknown, and the confidence is at
    least ``EXPANSION_CONFIDENCE_THRESHOLD``, the method:

    1. Builds a structured prompt containing the verdict, source snippet, and
       existing taxonomy names.
    2. Calls the provided ``llm_client`` to synthesise a new definition.
    3. Validates the LLM response (JSON schema, uniqueness).
    4. Appends the new entry to the in-memory taxonomy and persists it to disk.
    5. Returns the new ``VulnerabilityDefinition`` (or ``None`` if not triggered).

    This loop allows the taxonomy to grow organically as the auditor encounters
    novel attack patterns on live contracts, without any manual curation step.
    """

    def __init__(
        self,
        taxonomy_file: str | Path | None = None,
        auto_seed: bool = True,
    ) -> None:
        self._path = Path(taxonomy_file) if taxonomy_file else _DEFAULT_TAXONOMY_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.definitions: dict[str, VulnerabilityDefinition] = {}
        self._load()
        if auto_seed and not self.definitions:
            self._seed_core_definitions()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load definitions from disk; silently skip if the file is absent."""
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load taxonomy from %s: %s", self._path, exc)
            return

        entries = raw if isinstance(raw, list) else raw.get("definitions", [])
        for item in entries:
            try:
                defn = VulnerabilityDefinition.from_dict(item)
                self.definitions[defn.name] = defn
            except (KeyError, TypeError) as exc:
                logger.warning("Skipping malformed taxonomy entry: %s", exc)

        logger.info(
            "Taxonomy loaded from %s (%d entries)",
            self._path, len(self.definitions),
        )

    def _persist(self) -> None:
        """Atomically write the taxonomy to disk."""
        tmp = self._path.with_suffix(".tmp")
        payload = {
            "schema_version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self.definitions),
            "definitions": [d.to_dict() for d in self.definitions.values()],
        }
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        tmp.replace(self._path)
        logger.debug("Taxonomy persisted to %s (%d entries)", self._path, len(self.definitions))

    def _seed_core_definitions(self) -> None:
        """Populate the five paper-sourced core definitions and save to disk."""
        for entry in _CORE_DEFINITIONS:
            defn = VulnerabilityDefinition.from_dict(entry)
            self.definitions[defn.name] = defn
        self._persist()
        logger.info("Taxonomy seeded with %d core definitions.", len(self.definitions))

    # ── Read API ─────────────────────────────────────────────────────────────

    def get(self, name: str) -> VulnerabilityDefinition | None:
        """Return the definition for *name*, or None if not found."""
        return self.definitions.get(name)

    def all_definitions(self) -> list[VulnerabilityDefinition]:
        """Return all definitions in insertion order."""
        return list(self.definitions.values())

    def names(self) -> list[str]:
        """Return all definition names."""
        return list(self.definitions.keys())

    def __len__(self) -> int:
        return len(self.definitions)

    def __contains__(self, name: str) -> bool:
        return name in self.definitions

    # ── Audit prompt builder ─────────────────────────────────────────────────

    def build_audit_prompt(
        self,
        definition: VulnerabilityDefinition,
        source_code: str,
        max_source_chars: int = 12000,
    ) -> str:
        """
        Build a targeted audit prompt that injects the vulnerability definition
        into the query for the LLM.

        This is the bridge between the taxonomy and the LLM engine.  Each
        definition's ``description`` and ``risk_indicators`` are included
        verbatim so the model has precise natural-language guidance.

        Parameters
        ----------
        definition : VulnerabilityDefinition
            The vulnerability to check for.
        source_code : str
            The Solidity source to audit.
        max_source_chars : int
            Character limit for the source excerpt in the prompt.

        Returns
        -------
        str
            A ready-to-send LLM prompt string.
        """
        indicators_block = "\n".join(
            f"  - {ind}" for ind in definition.risk_indicators
        )
        source_excerpt = source_code[:max_source_chars]
        if len(source_code) > max_source_chars:
            source_excerpt += "\n\n// [SOURCE TRUNCATED FOR PROMPT LENGTH]"

        return (
            f"You are a smart contract security auditor.\n\n"
            f"## Vulnerability under examination\n"
            f"**Name**: {definition.name}\n"
            f"**SWC ID**: {definition.swc_id or 'N/A'}\n"
            f"**Severity**: {definition.severity}\n\n"
            f"**Definition** (from research literature):\n{definition.description}\n\n"
            f"**Risk Indicators** — code patterns that suggest this vulnerability:\n"
            f"{indicators_block}\n\n"
            f"## Smart Contract Source Code\n"
            f"```solidity\n{source_excerpt}\n```\n\n"
            f"## Audit Task\n"
            f"Determine whether this contract contains a **{definition.name}** vulnerability.\n"
            f"Reason step by step, then produce a JSON verdict:\n"
            f"{{\n"
            f'  "vulnerable": <true|false>,\n'
            f'  "vuln_type": "{definition.name}",\n'
            f'  "reasoning": "<one paragraph>",\n'
            f'  "evidence_lines": [<line numbers if applicable>],\n'
            f'  "confidence": <0.0-1.0>,\n'
            f'  "definition_cited": "{definition.name}"\n'
            f"}}"
        )

    # ── Learning Loop: Defining Loop ──────────────────────────────────────────

    def expand_taxonomy_from_audit(
        self,
        verdict: dict[str, Any],
        contract_name: str,
        source_snippet: str = "",
        llm_client: Callable[[str], str] | None = None,
        confidence_threshold: float = EXPANSION_CONFIDENCE_THRESHOLD,
    ) -> VulnerabilityDefinition | None:
        """
        The Defining Loop — expand the taxonomy when a novel threat is detected.

        This method is the heart of the "Learning Loop" described in the problem
        statement.  It is designed to be called after every Agent 2 verdict.
        Most of the time it returns ``None`` immediately (wrong vuln_type or
        low confidence).  When it fires, it invokes an LLM sub-agent to draft
        a new taxonomy entry, validates the response, adds it to the taxonomy,
        persists to disk, and returns the new ``VulnerabilityDefinition``.

        Over many auditing runs the taxonomy accumulates new entries,
        progressively covering more attack patterns without manual curation.

        Parameters
        ----------
        verdict : dict
            Agent 2 verdict dict with keys:
              - ``vuln_type``    : str   — e.g. "other", or an unrecognised name
              - ``confidence``  : float — 0.0-1.0
              - ``reasoning``   : str
              - ``evidence_lines`` : list[int]
              - ``vulnerable``  : bool
        contract_name : str
            Used in the sub-agent prompt for context.
        source_snippet : str
            First ~3000 characters of the contract source (for context).
        llm_client : callable | None
            ``(prompt: str) -> str``.  If None, falls back to the repo's
            ``phase2_llm_engine.llm_client.query_llm``.
        confidence_threshold : float
            Minimum confidence to trigger expansion (default 0.85).

        Returns
        -------
        VulnerabilityDefinition | None
            The newly added definition, or None if expansion was not triggered.
        """
        # ── Gate: only expand for high-confidence, novel, positive verdicts ──
        if not verdict.get("vulnerable", False):
            return None

        confidence = float(verdict.get("confidence", 0.0))
        if confidence < confidence_threshold:
            logger.debug(
                "Skipping taxonomy expansion: confidence %.2f < threshold %.2f",
                confidence, confidence_threshold,
            )
            return None

        vuln_type = str(verdict.get("vuln_type", "none") or "none").strip()

        # If the vuln_type already matches an existing definition, no expansion needed
        if vuln_type in self.definitions:
            logger.debug(
                "Taxonomy already contains '%s'; expansion not needed.", vuln_type,
            )
            return None

        # Also check case-insensitively to avoid near-duplicates
        lower_names = {n.lower() for n in self.definitions}
        if vuln_type.lower() in lower_names:
            logger.debug(
                "Taxonomy already contains a case variant of '%s'.", vuln_type,
            )
            return None

        logger.info(
            "Defining Loop triggered: novel vuln_type='%s' at confidence=%.2f "
            "in contract '%s'.",
            vuln_type, confidence, contract_name,
        )

        # ── Build sub-agent prompt ────────────────────────────────────────────
        verdict_json = json.dumps(
            {k: verdict.get(k) for k in
             ("vulnerable", "vuln_type", "reasoning", "evidence_lines", "confidence")},
            indent=2,
        )
        existing_names_block = "\n".join(f"  - {n}" for n in self.names())
        prompt = _EXPANSION_PROMPT_TEMPLATE.format(
            contract_name=contract_name,
            existing_names=existing_names_block or "  (none yet)",
            verdict_json=verdict_json,
            source_snippet=source_snippet[:3000] if source_snippet else "(not provided)",
        )

        # ── Call the LLM sub-agent ────────────────────────────────────────────
        if llm_client is None:
            llm_client = self._default_llm_client

        try:
            raw_response = llm_client(prompt)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Taxonomy expansion LLM call failed: %s", exc)
            return None

        # ── Parse and validate the response ──────────────────────────────────
        new_defn = self._parse_expansion_response(raw_response, confidence)
        if new_defn is None:
            return None

        # Final uniqueness guard after parsing (name might have been normalised)
        if new_defn.name in self.definitions:
            logger.warning(
                "LLM-derived definition name '%s' already exists; skipping.",
                new_defn.name,
            )
            return None

        # ── Add to taxonomy and persist ───────────────────────────────────────
        self.definitions[new_defn.name] = new_defn
        self._persist()

        logger.info(
            "Taxonomy expanded: added new definition '%s' (source=llm_derived).",
            new_defn.name,
        )
        return new_defn

    def _default_llm_client(self, prompt: str) -> str:
        """Use the repo's existing LLM client as the default sub-agent caller."""
        from phase2_llm_engine.llm_client import query_llm  # noqa: PLC0415

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a smart contract security taxonomy expert. "
                    "Return strict JSON only — no markdown, no prose."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        return query_llm(messages=messages)

    def _parse_expansion_response(
        self,
        raw: str,
        trigger_confidence: float,
    ) -> VulnerabilityDefinition | None:
        """
        Extract and validate a VulnerabilityDefinition from the LLM's response.

        Returns None if the response is malformed or fails validation.
        """
        raw = (raw or "").strip()
        if not raw:
            logger.warning("Taxonomy sub-agent returned an empty response.")
            return None

        # Strip optional markdown code fences
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)

        # Extract first JSON object
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end <= start:
            logger.warning("No JSON object found in taxonomy sub-agent response.")
            return None

        snippet = raw[start: end + 1]
        try:
            parsed = json.loads(snippet)
        except json.JSONDecodeError as exc:
            logger.warning("Could not parse taxonomy sub-agent JSON: %s", exc)
            return None

        # Validate required fields
        required = {"name", "description", "risk_indicators"}
        missing = required - set(parsed.keys())
        if missing:
            logger.warning(
                "Taxonomy sub-agent response missing required fields: %s", missing
            )
            return None

        name = str(parsed.get("name", "")).strip()
        if not name:
            logger.warning("Taxonomy sub-agent returned an empty name field.")
            return None

        risk_indicators = parsed.get("risk_indicators", [])
        if not isinstance(risk_indicators, list):
            risk_indicators = [str(risk_indicators)]

        severity = str(parsed.get("severity", "high")).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "high"

        return VulnerabilityDefinition(
            name=name,
            description=str(parsed.get("description", "")),
            risk_indicators=[str(r) for r in risk_indicators if r],
            swc_id=str(parsed.get("swc_id", "")),
            severity=severity,
            source="llm_derived",
            added_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── Manual management helpers ─────────────────────────────────────────────

    def add(self, definition: VulnerabilityDefinition, persist: bool = True) -> None:
        """Manually add or replace a definition, then optionally persist."""
        self.definitions[definition.name] = definition
        if persist:
            self._persist()

    def remove(self, name: str, persist: bool = True) -> bool:
        """Remove a definition by name.  Returns True if it was present."""
        if name in self.definitions:
            del self.definitions[name]
            if persist:
                self._persist()
            return True
        return False

    def reload(self) -> None:
        """Re-read the taxonomy file from disk (e.g. after external edits)."""
        self.definitions.clear()
        self._load()

    def summary(self) -> dict[str, Any]:
        """Return a compact summary dict for logging or reporting."""
        return {
            "total": len(self.definitions),
            "file": str(self._path),
            "names": self.names(),
            "by_source": {
                "paper": sum(1 for d in self.definitions.values() if d.source == "paper"),
                "llm_derived": sum(
                    1 for d in self.definitions.values() if d.source == "llm_derived"
                ),
                "manual": sum(
                    1 for d in self.definitions.values() if d.source == "manual"
                ),
            },
        }
