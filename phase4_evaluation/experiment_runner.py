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
from typing import Optional

logger = logging.getLogger(__name__)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')


def run_experiment(
    contracts: list[dict],
    config,
    progress_callback=None,
) -> dict:
    """
    Run audit on a list of contracts with a given TuningConfig.

    Returns experiment results dict with predictions and timing.
    """
    from phase2_llm_engine.cot_analyzer import analyze_contract

    results = []
    total_tokens = 0
    total_time = 0.0

    for i, contract in enumerate(contracts):
        if progress_callback:
            progress_callback(i, len(contracts), contract.get("name", ""))

        start = time.time()
        try:
            audit_result = analyze_contract(
                source_code=contract["source_code"],
                contract_name=contract.get("name", f"contract_{i}"),
                mode=config.mode if config.mode != "multi_vuln" else "non_binary",
                model=config.model,
                temperature=config.temperature,
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
        "results": results,
        "total_time_seconds": total_time,
        "contracts_tested": len(contracts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def score_experiment(experiment: dict, ground_truth: dict) -> dict:
    """Score experiment results against ground truth."""
    from phase4_evaluation.scorer import evaluate_batch, compute_per_vuln_metrics

    audit_results = [r["audit_result"] for r in experiment["results"]]
    batch_scores = evaluate_batch(audit_results, ground_truth)
    per_vuln = compute_per_vuln_metrics(audit_results, ground_truth)

    return {
        **experiment,
        "scores": batch_scores,
        "per_vuln_metrics": per_vuln,
    }


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
        experiment = run_experiment(contracts, cfg)
        scored = score_experiment(experiment, ground_truth)
        save_experiment(scored, cfg_dir)
        all_results.append(scored)

    return all_results


def main():
    parser = argparse.ArgumentParser(description="Run batch experiment grid")
    parser.add_argument("--dataset", default="smartbugs", help="Dataset to use")
    parser.add_argument("--configs", default="all", help="Config name(s) or 'all'")
    parser.add_argument("--output", default=None, help="Output directory")
    parser.add_argument("--resume", action="store_true", help="Resume incomplete runs")
    args = parser.parse_args()

    from phase1_data_pipeline.benchmark_datasets import load_benchmark
    from phase3_hyperparameter.tuning_config import DEFAULT_EXPERIMENT_GRID, get_config_by_name

    contracts = load_benchmark(args.dataset)
    if not contracts:
        print(f"No contracts found for dataset '{args.dataset}'")
        return

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

    results = run_grid(contracts, configs, ground_truth, args.output, args.resume)
    print(f"Completed {len(results)} experiment runs")
    for r in results:
        agg = r.get("scores", {}).get("aggregate", {}).get("metrics", {})
        f1 = agg.get("f1", 0)
        prec = agg.get("precision", 0)
        print(f"  {r['config_name']}: F1={f1:.4f} Precision={prec:.4f}")


if __name__ == "__main__":
    main()
