"""
Phase 4 – Evaluation: Scoring dashboard.

Computes TP, FP, TN, FN and derived metrics (Precision, Recall, F1-score)
for a batch of audit results against ground-truth labels.
"""

from __future__ import annotations

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _parse_binary_response(response: str) -> Optional[bool]:
    """
    Parse a binary YES/NO response from the LLM.

    Returns ``True`` if the model flagged a vulnerability, ``False`` if not,
    or ``None`` if the response could not be parsed.
    """
    text = response.strip().upper()
    if text.startswith("YES"):
        return True
    if text.startswith("NO"):
        return False
    # Fallback: search for YES/NO as whole words in the first 20 characters
    snippet = text[:20]
    if re.search(r"\bYES\b", snippet):
        return True
    if re.search(r"\bNO\b", snippet):
        return False
    return None


def score_binary_result(
    predicted_vulnerable: bool,
    actually_vulnerable: bool,
) -> str:
    """
    Classify a single prediction as TP, FP, TN, or FN.

    Parameters
    ----------
    predicted_vulnerable : bool
        Whether the LLM predicted a vulnerability.
    actually_vulnerable : bool
        Ground truth.

    Returns
    -------
    str
        One of ``"TP"``, ``"FP"``, ``"TN"``, ``"FN"``.
    """
    if predicted_vulnerable and actually_vulnerable:
        return "TP"
    if predicted_vulnerable and not actually_vulnerable:
        return "FP"
    if not predicted_vulnerable and not actually_vulnerable:
        return "TN"
    return "FN"


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    """
    Compute Precision, Recall, F1-score and Accuracy.

    Parameters
    ----------
    tp, fp, tn, fn : int
        Confusion-matrix counts.

    Returns
    -------
    dict
        ``{"precision": float, "recall": float, "f1": float, "accuracy": float}``
    """
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def evaluate_batch(
    audit_results: list[dict],
    ground_truth: dict[str, list[str]],
) -> dict:
    """
    Evaluate a batch of audit results against ground-truth vulnerability labels.

    Parameters
    ----------
    audit_results : list[dict]
        Output from :func:`phase2_llm_engine.cot_analyzer.analyze_contract`,
        one item per contract.
    ground_truth : dict[str, list[str]]
        Mapping of contract name → list of known vulnerability names.
        e.g. ``{"SecureVault": ["Reentrancy"], "SecureToken": []}``

    Returns
    -------
    dict
        Per-contract and aggregate confusion-matrix counts and metrics.
    """
    aggregate = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    per_contract = []

    for result in audit_results:
        name = result["contract_name"]
        known_vulns = set(ground_truth.get(name, []))
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

        for vr in result.get("vuln_results", []):
            vuln_name = vr["vuln_name"]
            predicted = _parse_binary_response(vr["response"])
            if predicted is None:
                # Cannot parse → skip this entry
                continue
            actual = vuln_name in known_vulns
            outcome = score_binary_result(predicted, actual)
            counts[outcome] += 1
            aggregate[outcome] += 1

        metrics = compute_metrics(**{k.lower(): v for k, v in counts.items()})
        per_contract.append(
            {"contract_name": name, "counts": counts, "metrics": metrics}
        )
        logger.info(
            "Contract '%s': TP=%d FP=%d TN=%d FN=%d | F1=%.4f",
            name,
            counts["TP"],
            counts["FP"],
            counts["TN"],
            counts["FN"],
            metrics["f1"],
        )

    aggregate_metrics = compute_metrics(
        tp=aggregate["TP"],
        fp=aggregate["FP"],
        tn=aggregate["TN"],
        fn=aggregate["FN"],
    )

    return {
        "per_contract": per_contract,
        "aggregate": {"counts": aggregate, "metrics": aggregate_metrics},
    }
