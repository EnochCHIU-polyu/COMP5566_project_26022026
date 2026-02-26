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


def compute_per_vuln_metrics(audit_results: list[dict], ground_truth: dict) -> dict:
    """
    Compute Precision/Recall/F1 for each vulnerability type separately.

    Parameters
    ----------
    audit_results : list[dict]
        List of audit result dicts from analyze_contract().
    ground_truth : dict
        Contract name → list of known vulnerability names.

    Returns
    -------
    dict
        Mapping of vuln_type → {"precision", "recall", "f1", "tp", "fp", "tn", "fn"}.
    """
    counts: dict[str, dict] = {}

    for result in audit_results:
        name = result["contract_name"]
        known_vulns = set(ground_truth.get(name, []))
        for vr in result.get("vuln_results", []):
            vuln_name = vr["vuln_name"]
            predicted = _parse_binary_response(vr["response"])
            if predicted is None:
                continue
            actual = vuln_name in known_vulns
            outcome = score_binary_result(predicted, actual)
            if vuln_name not in counts:
                counts[vuln_name] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
            counts[vuln_name][outcome] += 1

    result_dict = {}
    for vuln_name, c in counts.items():
        metrics = compute_metrics(tp=c["TP"], fp=c["FP"], tn=c["TN"], fn=c["FN"])
        result_dict[vuln_name] = {**metrics, **{k.lower(): v for k, v in c.items()}}
    return result_dict


def compute_auc_roc(predictions: list[dict], ground_truth: dict) -> float:
    """
    Compute AUC-ROC using sklearn.

    Parameters
    ----------
    predictions : list[dict]
        Each dict has "contract_name" and "vuln_results" with "confidence" scores.
    ground_truth : dict
        Contract name → list of known vulnerability names.

    Returns
    -------
    float
        AUC-ROC score, or 0.0 if sklearn is unavailable.
    """
    try:
        from sklearn.metrics import roc_auc_score
    except ImportError:
        logger.warning("sklearn not available; returning 0.0 for AUC-ROC")
        return 0.0

    y_true, y_score = [], []
    for result in predictions:
        name = result.get("contract_name", "")
        known_vulns = set(ground_truth.get(name, []))
        for vr in result.get("vuln_results", []):
            vuln_name = vr.get("vuln_name", "")
            confidence = float(vr.get("confidence", 0.5))
            actual = 1 if vuln_name in known_vulns else 0
            y_true.append(actual)
            y_score.append(confidence)

    if len(set(y_true)) < 2:
        logger.warning("AUC-ROC requires both classes present; returning 0.0")
        return 0.0

    try:
        return float(roc_auc_score(y_true, y_score))
    except Exception as exc:  # noqa: BLE001
        logger.warning("roc_auc_score failed: %s", exc)
        return 0.0


def compute_pr_auc(predictions: list[dict], ground_truth: dict) -> float:
    """
    Compute PR-AUC (average precision) using sklearn.

    Parameters
    ----------
    predictions : list[dict]
        Each dict has "contract_name" and "vuln_results" with "confidence" scores.
    ground_truth : dict
        Contract name → list of known vulnerability names.

    Returns
    -------
    float
        PR-AUC score, or 0.0 if sklearn is unavailable.
    """
    try:
        from sklearn.metrics import average_precision_score
    except ImportError:
        logger.warning("sklearn not available; returning 0.0 for PR-AUC")
        return 0.0

    y_true, y_score = [], []
    for result in predictions:
        name = result.get("contract_name", "")
        known_vulns = set(ground_truth.get(name, []))
        for vr in result.get("vuln_results", []):
            vuln_name = vr.get("vuln_name", "")
            confidence = float(vr.get("confidence", 0.5))
            actual = 1 if vuln_name in known_vulns else 0
            y_true.append(actual)
            y_score.append(confidence)

    if len(set(y_true)) < 2:
        logger.warning("PR-AUC requires both classes present; returning 0.0")
        return 0.0

    try:
        return float(average_precision_score(y_true, y_score))
    except Exception as exc:  # noqa: BLE001
        logger.warning("average_precision_score failed: %s", exc)
        return 0.0


def compute_confusion_matrix_per_type(
    results: list[dict],
    ground_truth: dict,
) -> list[dict]:
    """
    Return one row per vulnerability type with TP/FP/TN/FN/Precision/Recall/F1.

    Parameters
    ----------
    results : list[dict]
        Audit result dicts.
    ground_truth : dict
        Contract name → list of known vulnerability names.

    Returns
    -------
    list[dict]
        Each dict: vuln_type | TP | FP | TN | FN | precision | recall | f1.
    """
    per_vuln = compute_per_vuln_metrics(results, ground_truth)
    rows = []
    for vuln_type, m in per_vuln.items():
        rows.append({
            "vuln_type": vuln_type,
            "TP": m.get("tp", 0),
            "FP": m.get("fp", 0),
            "TN": m.get("tn", 0),
            "FN": m.get("fn", 0),
            "Precision": m.get("precision", 0.0),
            "Recall": m.get("recall", 0.0),
            "F1": m.get("f1", 0.0),
        })
    return rows


def compute_calibration(
    predictions: list[dict],
    ground_truth: dict,
    n_bins: int = 10,
) -> dict:
    """
    Compute reliability diagram data (predicted confidence vs actual accuracy per bin).

    Parameters
    ----------
    predictions : list[dict]
        Audit result dicts with confidence scores.
    ground_truth : dict
        Contract name → list of known vulnerability names.
    n_bins : int
        Number of bins for the reliability diagram.

    Returns
    -------
    dict
        {"bins": [...], "mean_predicted": [...], "fraction_positive": [...]}
    """
    confidences, actuals = [], []
    for result in predictions:
        name = result.get("contract_name", "")
        known_vulns = set(ground_truth.get(name, []))
        for vr in result.get("vuln_results", []):
            vuln_name = vr.get("vuln_name", "")
            confidence = float(vr.get("confidence", 0.5))
            actual = 1 if vuln_name in known_vulns else 0
            confidences.append(confidence)
            actuals.append(actual)

    if not confidences:
        return {"bins": [], "mean_predicted": [], "fraction_positive": []}

    bin_edges = [i / n_bins for i in range(n_bins + 1)]
    bin_mean_pred, bin_frac_pos, bin_labels = [], [], []

    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        indices = [j for j, c in enumerate(confidences) if lo <= c < hi]
        if not indices:
            continue
        mean_pred = sum(confidences[j] for j in indices) / len(indices)
        frac_pos = sum(actuals[j] for j in indices) / len(indices)
        bin_mean_pred.append(round(mean_pred, 4))
        bin_frac_pos.append(round(frac_pos, 4))
        bin_labels.append(f"{lo:.1f}-{hi:.1f}")

    return {
        "bins": bin_labels,
        "mean_predicted": bin_mean_pred,
        "fraction_positive": bin_frac_pos,
    }
