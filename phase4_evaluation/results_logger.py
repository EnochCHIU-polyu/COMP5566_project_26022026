"""
Phase 4 – Evaluation: Persistent experiment results logger.

Saves and loads experiment results for reproducibility and comparison.
"""

from __future__ import annotations
import os
import json
import csv
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')


class ResultsLogger:
    """Logs and retrieves experiment results."""

    def __init__(self, experiment_name: str, base_dir: Optional[str] = None):
        self.experiment_name = experiment_name
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if base_dir is None:
            base_dir = RESULTS_DIR
        self.output_dir = os.path.join(base_dir, f"{experiment_name}_{timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        self._predictions: list[dict] = []
        self._timing: list[dict] = []

    def log_config(self, config) -> None:
        """Save TuningConfig snapshot."""
        config_dict = {
            "name": config.name,
            "model": config.model,
            "temperature": config.temperature,
            "mode": config.mode,
            "max_tokens": config.max_tokens,
            "notes": config.notes,
        }
        with open(os.path.join(self.output_dir, 'config.json'), 'w') as f:
            json.dump(config_dict, f, indent=2)

    def log_prediction(
        self,
        contract_name: str,
        vuln_name: str,
        predicted: bool,
        actual: Optional[bool],
        confidence: float = 0.5,
        response: str = "",
    ) -> None:
        """Log a single prediction."""
        self._predictions.append({
            "contract_name": contract_name,
            "vuln_name": vuln_name,
            "predicted": predicted,
            "actual": actual,
            "confidence": confidence,
            "response_snippet": response[:200],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_timing(
        self,
        contract_name: str,
        elapsed_seconds: float,
        tokens_used: int = 0,
        api_calls: int = 0,
    ) -> None:
        """Log timing information for a contract audit."""
        self._timing.append({
            "contract_name": contract_name,
            "elapsed_seconds": elapsed_seconds,
            "tokens_used": tokens_used,
            "api_calls": api_calls,
        })

    def save_predictions(self) -> None:
        """Persist all logged predictions to disk."""
        path = os.path.join(self.output_dir, 'predictions.json')
        with open(path, 'w') as f:
            json.dump(self._predictions, f, indent=2)

    def save_metrics(self, metrics: dict) -> None:
        """Save aggregated metrics."""
        path = os.path.join(self.output_dir, 'metrics.json')
        with open(path, 'w') as f:
            json.dump(metrics, f, indent=2)

    def save_timing(self) -> None:
        """Save timing data."""
        path = os.path.join(self.output_dir, 'timing.json')
        total_time = sum(t["elapsed_seconds"] for t in self._timing)
        total_tokens = sum(t["tokens_used"] for t in self._timing)
        with open(path, 'w') as f:
            json.dump({
                "per_contract": self._timing,
                "total_seconds": total_time,
                "total_tokens": total_tokens,
                "avg_seconds_per_contract": total_time / max(1, len(self._timing)),
            }, f, indent=2)

    def save_all(self, metrics: Optional[dict] = None) -> None:
        """Save all logged data."""
        self.save_predictions()
        self.save_timing()
        if metrics:
            self.save_metrics(metrics)
        logger.info("Results saved to %s", self.output_dir)

    @staticmethod
    def save_comparison_csv(experiments: list[dict], output_path: str) -> None:
        """Save cross-config comparison table as CSV."""
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fieldnames = [
            "config_name", "model", "temperature", "mode",
            "contracts_tested", "macro_f1", "precision", "recall",
            "total_time_seconds",
        ]
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for exp in experiments:
                agg_metrics = exp.get("scores", {}).get("aggregate", {}).get("metrics", {})
                writer.writerow({
                    "config_name": exp.get("config_name", ""),
                    "model": exp.get("model", ""),
                    "temperature": exp.get("temperature", ""),
                    "mode": exp.get("mode", ""),
                    "contracts_tested": exp.get("contracts_tested", 0),
                    "macro_f1": agg_metrics.get("f1", 0.0),
                    "precision": agg_metrics.get("precision", 0.0),
                    "recall": agg_metrics.get("recall", 0.0),
                    "total_time_seconds": exp.get("total_time_seconds", 0.0),
                })
