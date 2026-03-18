"""
Phase 4 – Evaluation: Batch experiment runner.

Runs audit on benchmark datasets with multiple TuningConfig settings,
scores results, and saves to JSON/CSV for analysis.

Usage:
    python -m phase4_evaluation.experiment_runner --dataset smartbugs --configs all
"""

from __future__ import annotations
import os
import json
import time
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional, Callable

logger = logging.getLogger(__name__)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
HISTORY_FILE = os.path.join(RESULTS_DIR, 'experiment_history.jsonl')


def run_experiment(
    contracts: list[dict],
    config,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    run_id: Optional[str] = None,
    analyzer_fn=None,
    **analyzer_kwargs,
) -> dict:
    """
    Run audit on a list of contracts with a given TuningConfig.

    Parameters
    ----------
    contracts : list[dict]
        Benchmark contracts with "source_code", "name", "labels".
    config : TuningConfig
        Experiment configuration.
    progress_callback : callable, optional
        Called as (current_index, total, contract_name).
    run_id : str, optional
        Unique run identifier for history logging.
    analyzer_fn : callable, optional
        Custom analyzer function (default: analyze_contract).
        Signature: (source_code, contract_name, **kwargs) -> dict.
    **analyzer_kwargs
        Extra kwargs passed to analyzer_fn (e.g. agent_mode, verify).

    Returns
    -------
    dict
        Experiment results with predictions and timing.
    """
    from phase2_llm_engine.cot_analyzer import analyze_contract

    analyzer = analyzer_fn or analyze_contract
    results = []
    total_time = 0.0
    _run_id = run_id or f"{config.name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    for i, contract in enumerate(contracts):
        if progress_callback:
            progress_callback(i, len(contracts), contract.get("name", ""))

        start = time.time()
        try:
            base_kw = {
                "mode": config.mode if config.mode != "multi_vuln" else "non_binary",
                "model": config.model,
                "temperature": config.temperature,
                "verify": getattr(config, "verify", False),
                "agent_mode": getattr(config, "agent_mode", False),
                "agent_judge_model": getattr(config, "agent_judge_model", None),
            }
            base_kw.update(analyzer_kwargs)
            audit_result = analyzer(
                source_code=contract["source_code"],
                contract_name=contract.get("name", f"contract_{i}"),
                **base_kw,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Audit failed for %s: %s", contract.get("name"), exc)
            audit_result = {
                "contract_name": contract.get("name", ""),
                "vuln_results": [],
                "function_results": [],
                "error": str(exc),
            }
        elapsed = time.time() - start
        total_time += elapsed

        results.append({
            "contract": contract,
            "audit_result": audit_result,
            "elapsed_seconds": elapsed,
        })

    return {
        "config_name": config.name,
        "model": config.model,
        "temperature": config.temperature,
        "mode": config.mode,
        "run_id": _run_id,
        "results": results,
        "total_time_seconds": total_time,
        "contracts_tested": len(contracts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def score_experiment(
    experiment: dict,
    ground_truth: dict,
    include_auc: bool = True,
    log_history: bool = True,
    history_path: Optional[str] = None,
) -> dict:
    """
    Score experiment results against ground truth.

    Uses dataset + rule-based evaluation: parse YES/NO from response, compare to ground truth.

    Parameters
    ----------
    experiment : dict
        Output from run_experiment.
    ground_truth : dict
        Contract name → list of known vulnerability names.
    include_auc : bool
        If True, compute AUC-ROC and PR-AUC.
    log_history : bool
        If True, append this run to experiment history.
    history_path : str, optional
        Path to history JSONL file (default: results/experiment_history.jsonl).

    Returns
    -------
    dict
        Experiment dict with added "scores" (incl. auc_roc, pr_auc) and "per_vuln_metrics".
    """
    from phase4_evaluation.scorer import (
        evaluate_batch,
        compute_per_vuln_metrics,
        compute_auc_roc,
        compute_pr_auc,
    )

    audit_results = [r["audit_result"] for r in experiment["results"]]
    batch_scores = evaluate_batch(audit_results, ground_truth)
    per_vuln = compute_per_vuln_metrics(audit_results, ground_truth)

    scores = {**batch_scores}
    if include_auc:
        scores["auc_roc"] = round(
            compute_auc_roc(audit_results, ground_truth), 4
        )
        scores["pr_auc"] = round(
            compute_pr_auc(audit_results, ground_truth), 4
        )

    result = {
        **experiment,
        "scores": scores,
        "per_vuln_metrics": per_vuln,
    }

    if log_history:
        _append_to_history(result, history_path or HISTORY_FILE)

    return result


def _append_to_history(experiment: dict, path: str) -> None:
    """Append a single experiment summary to the history JSONL file."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    agg = experiment.get("scores", {}).get("aggregate", {}).get("metrics", {})
    entry = {
        "run_id": experiment.get("run_id", ""),
        "config_name": experiment.get("config_name", ""),
        "model": experiment.get("model", ""),
        "mode": experiment.get("mode", ""),
        "timestamp": experiment.get("timestamp", ""),
        "contracts_tested": experiment.get("contracts_tested", 0),
        "f1": agg.get("f1", 0),
        "precision": agg.get("precision", 0),
        "recall": agg.get("recall", 0),
        "auc_roc": experiment.get("scores", {}).get("auc_roc"),
        "pr_auc": experiment.get("scores", {}).get("pr_auc"),
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info("Logged to history: %s", path)


def save_experiment(experiment: dict, output_dir: Optional[str] = None) -> str:
    """Save experiment results to disk."""
    if output_dir is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(RESULTS_DIR, f"{experiment['config_name']}_{timestamp}")

    os.makedirs(output_dir, exist_ok=True)

    config_path = os.path.join(output_dir, 'config.json')
    with open(config_path, 'w') as f:
        json.dump({
            "config_name": experiment["config_name"],
            "model": experiment["model"],
            "temperature": experiment["temperature"],
            "mode": experiment["mode"],
            "timestamp": experiment.get("timestamp", ""),
        }, f, indent=2)

    predictions = []
    for r in experiment.get("results", []):
        predictions.append({
            "contract_name": r["contract"].get("name", ""),
            "audit_result": {
                "contract_name": r["audit_result"].get("contract_name", ""),
                "vuln_results": r["audit_result"].get("vuln_results", []),
            },
            "elapsed_seconds": r.get("elapsed_seconds", 0),
        })
    predictions_path = os.path.join(output_dir, 'predictions.json')
    with open(predictions_path, 'w') as f:
        json.dump(predictions, f, indent=2)

    if "scores" in experiment:
        metrics_path = os.path.join(output_dir, 'metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(experiment["scores"], f, indent=2)

    timing = {
        "total_time_seconds": experiment.get("total_time_seconds", 0),
        "contracts_tested": experiment.get("contracts_tested", 0),
        "avg_time_per_contract": (
            experiment.get("total_time_seconds", 0)
            / max(1, experiment.get("contracts_tested", 1))
        ),
    }
    timing_path = os.path.join(output_dir, 'timing.json')
    with open(timing_path, 'w') as f:
        json.dump(timing, f, indent=2)

    logger.info("Saved experiment to %s", output_dir)
    return output_dir


def run_grid(
    contracts: list[dict],
    configs: list,
    ground_truth: dict,
    output_dir: Optional[str] = None,
    resume: bool = False,
    include_auc: bool = True,
    log_history: bool = True,
    vuln_filter: Optional[list] = None,
) -> list[dict]:
    """
    Run all configs against all contracts.

    Parameters
    ----------
    contracts : list[dict]
        Benchmark contracts.
    configs : list[TuningConfig]
        Experiment configurations to run.
    ground_truth : dict
        Contract name → list of known vulnerabilities.
    output_dir : str, optional
        Base directory for results.
    resume : bool
        If True, skip already-completed config runs.

    Returns
    -------
    list[dict]
        List of scored experiment results.
    """
    if output_dir is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(RESULTS_DIR, f"grid_{timestamp}")

    all_results = []
    for cfg in configs:
        cfg_dir = os.path.join(output_dir, cfg.name)
        if resume and os.path.exists(os.path.join(cfg_dir, 'metrics.json')):
            logger.info("Skipping %s (already completed)", cfg.name)
            continue

        logger.info("Running config: %s", cfg.name)

        def _progress(i: int, total: int, name: str) -> None:
            print(f"  [{i + 1}/{total}] Auditing: {name}", flush=True)

        experiment = run_experiment(
            contracts,
            cfg,
            progress_callback=_progress,
            vuln_filter=vuln_filter,
        )
        scored = score_experiment(
            experiment,
            ground_truth,
            include_auc=include_auc,
            log_history=log_history,
        )
        save_experiment(scored, cfg_dir)
        all_results.append(scored)

    return all_results


def main():
    parser = argparse.ArgumentParser(description="Run batch experiment grid")
    parser.add_argument("--dataset", default="smartbugs", help="Dataset to use (smartbugs/solidifi/all)")
    parser.add_argument("--limit", type=int, default=None, help="Limit to first N contracts for quick testing")
    parser.add_argument("--vulns", default=None, help="Comma-separated vuln types to check (e.g. Reentrancy,Access Control). Default: all 38")
    parser.add_argument("--list-vulns", action="store_true", help="Print available vulnerability types and exit")
    parser.add_argument("--configs", default="all", help="Config name(s) or 'all'")
    parser.add_argument("--output", default=None, help="Output directory")
    parser.add_argument("--resume", action="store_true", help="Resume incomplete runs")
    parser.add_argument("--no-auc", action="store_true", help="Skip AUC/PR-AUC computation")
    parser.add_argument("--no-history", action="store_true", help="Do not append to experiment_history.jsonl")
    args = parser.parse_args()

    from phase1_data_pipeline.benchmark_datasets import load_benchmark
    from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
    from phase3_hyperparameter.tuning_config import DEFAULT_EXPERIMENT_GRID, get_config_by_name

    if args.list_vulns:
        print("Available vulnerability types (use with --vulns):")
        for v in VULNERABILITY_TYPES:
            print(f"  {v['name']}")
        return

    contracts = load_benchmark(args.dataset)
    if not contracts:
        print(f"No contracts found for dataset '{args.dataset}'")
        return
    if args.limit:
        contracts = contracts[: args.limit]
        print(f"Using first {args.limit} contracts for quick test")

    vuln_filter = None
    if args.vulns:
        vuln_filter = [n.strip() for n in args.vulns.split(",") if n.strip()]
        valid = {v["name"] for v in VULNERABILITY_TYPES}
        invalid = [n for n in vuln_filter if n not in valid]
        if invalid:
            print(f"Unknown vuln types: {invalid}. Run with --list-vulns to see available names.")
            return
        print(f"Checking only: {', '.join(vuln_filter)}")

    n_vulns = len(vuln_filter) if vuln_filter else 38
    print(f"Note: Each contract checks {n_vulns} vuln type(s). Please wait...", flush=True)

    if args.configs == "all":
        configs = DEFAULT_EXPERIMENT_GRID
    else:
        configs = [
            get_config_by_name(n)
            for n in args.configs.split(",")
            if get_config_by_name(n)
        ]

    ground_truth = {
        c["name"]: [lb["vuln_type"] for lb in c.get("labels", [])]
        for c in contracts
    }

    results = run_grid(
        contracts,
        configs,
        ground_truth,
        args.output,
        args.resume,
        include_auc=not args.no_auc,
        log_history=not args.no_history,
        vuln_filter=vuln_filter,
    )
    print(f"Completed {len(results)} experiment runs")
    for r in results:
        agg = r.get("scores", {}).get("aggregate", {}).get("metrics", {})
        f1 = agg.get("f1", 0)
        prec = agg.get("precision", 0)
        auc = r.get("scores", {}).get("auc_roc")
        pr_auc = r.get("scores", {}).get("pr_auc")
        extra = ""
        if auc is not None:
            extra += f" AUC={auc:.4f}"
        if pr_auc is not None:
            extra += f" PR-AUC={pr_auc:.4f}"
        print(f"  {r['config_name']}: F1={f1:.4f} Precision={prec:.4f}{extra}")


if __name__ == "__main__":
    main()
