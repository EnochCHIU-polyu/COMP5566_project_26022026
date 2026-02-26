"""
Phase 3 – Hyperparameter Tuning Module.

Provides a TuningConfig dataclass and a helper that runs the same contract
through multiple hyperparameter configurations so results can be compared.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TuningConfig:
    """
    Encapsulates a single hyperparameter configuration for one experiment run.

    Attributes
    ----------
    name : str
        Human-readable label (e.g. ``"T0-gpt4o"``).
    model : str
        LLM model identifier (e.g. ``"gpt-4o"`` or ``"claude-3-opus-20240229"``).
    temperature : float
        Sampling temperature.  Use 0 for deterministic output; 1 for more
        creative / diverse responses.
    mode : str
        ``"binary"``, ``"non_binary"``, ``"cot"``, or ``"multi_vuln"``.
    max_tokens : int
        Maximum response tokens.
    notes : str
        Optional free-text notes about this configuration.
    verify : bool
        If True, run self-check verification pass on findings.
    batch_vulns : int
        Number of vulnerability types to batch into a single prompt (1 = one at a time).
    use_filter : bool
        If True, apply keyword relevance filter before auditing.
    few_shot : bool
        If True, use few-shot prompting with examples.
    """

    name: str
    model: str = "gpt-4o"
    temperature: float = 0.0
    mode: str = "non_binary"
    max_tokens: int = 2048
    notes: str = ""
    verify: bool = False
    batch_vulns: int = 1
    use_filter: bool = True
    few_shot: bool = False


# ---------------------------------------------------------------------------
# Predefined experiment grid
# ---------------------------------------------------------------------------

DEFAULT_EXPERIMENT_GRID: list[TuningConfig] = [
    TuningConfig(
        name="T0-gpt4o-binary",
        model="gpt-4o",
        temperature=0.0,
        mode="binary",
        notes="Deterministic binary scan – high precision baseline",
    ),
    TuningConfig(
        name="T0-gpt4o-nonbinary",
        model="gpt-4o",
        temperature=0.0,
        mode="non_binary",
        notes="Deterministic non-binary deep analysis",
    ),
    TuningConfig(
        name="T1-gpt4o-nonbinary",
        model="gpt-4o",
        temperature=1.0,
        mode="non_binary",
        notes="Creative non-binary – may improve F1 score",
    ),
    TuningConfig(
        name="T0-gpt4o-cot",
        model="gpt-4o",
        temperature=0.0,
        mode="cot",
        notes="Chain-of-Thought per-function review",
    ),
    TuningConfig(
        name="T0-claude-nonbinary",
        model="claude-3-opus-20240229",
        temperature=0.0,
        mode="non_binary",
        notes="Claude deterministic deep analysis",
    ),
    TuningConfig(
        name="T1-claude-nonbinary",
        model="claude-3-opus-20240229",
        temperature=1.0,
        mode="non_binary",
        notes="Claude creative non-binary",
    ),
    TuningConfig(
        name="T0-deepseek-binary",
        model="deepseek-v3.2",
        temperature=0.0,
        mode="binary",
        notes="DeepSeek deterministic binary scan",
    ),
    TuningConfig(
        name="T0-deepseek-nonbinary",
        model="deepseek-v3.2",
        temperature=0.0,
        mode="non_binary",
        notes="DeepSeek deterministic non-binary analysis",
    ),
    TuningConfig(
        name="T0-gpt4o-multivuln",
        model="gpt-4o",
        temperature=0.0,
        mode="multi_vuln",
        notes="GPT-4o multi-vulnerability batch mode",
    ),
]


def get_config_by_name(name: str) -> Optional[TuningConfig]:
    """Return the :class:`TuningConfig` with the given *name*, or ``None``."""
    for cfg in DEFAULT_EXPERIMENT_GRID:
        if cfg.name == name:
            return cfg
    return None
