#!/usr/bin/env python3
"""
Benchmark a single SmartBugs category folder and report per-vulnerability-type F1.

Loads every .sol file in a given folder, derives ground-truth labels from the folder
name (via SMARTBUGS_CATEGORY_MAP, optionally enriched by vulnerabilities.json), runs
the audit pipeline (standard or multi_llm), then prints a per-vuln-type F1 table and
writes the full result to JSON.

Usage (from repo root):
  PYTHONPATH=".:backend" python3 scripts/run_folder_benchmark.py \\
      --folder data/benchmarks/smartbugs/dataset/front_running \\
      -o results/front_running.json

  # Use multi_llm pipeline with two models:
  PYTHONPATH=".:backend" python3 scripts/run_folder_benchmark.py \\
      --folder data/benchmarks/smartbugs/dataset/reentrancy \\
      --pipeline multi_llm --multi-models deepseek-v3.2,gpt-4o-mini \\
      -o results/reentrancy.json

  # Verbose (shows per-LLM-call logs):
  PYTHONPATH=".:backend" python3 scripts/run_folder_benchmark.py \\
      --folder data/benchmarks/smartbugs/dataset/front_running -v
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# ── path bootstrap ──────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from phase1_data_pipeline.benchmark_datasets import SMARTBUGS_CATEGORY_MAP  # noqa: E402
from phase1_data_pipeline.contract_preprocessor import preprocess_contract   # noqa: E402
from phase2_llm_engine.cot_analyzer import (                                  # noqa: E402
    analyze_contract,
    run_multi_llm_audit,
)
from phase4_evaluation.scorer import (                                        # noqa: E402
    compute_per_vuln_metrics,
    evaluate_batch,
)
from app.utils.async_compat import to_thread                                  # noqa: E402

VULNS_JSON = ROOT / "data" / "benchmarks" / "smartbugs" / "vulnerabilities.json"


# ── helpers ──────────────────────────────────────────────────────────────────

def _info(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _load_vulns_json() -> dict[str, list[str]]:
    """
    Parse vulnerabilities.json into {filename (no .sol): [category_label, ...]}.
    Uses SMARTBUGS_CATEGORY_MAP so labels match the catalog DB names.
    """
    if not VULNS_JSON.exists():
        return {}
    with VULNS_JSON.open(encoding="utf-8") as fh:
        entries = json.load(fh)
    mapping: dict[str, list[str]] = {}
    for entry in entries:
        raw_name = str(entry.get("name", "")).replace(".sol", "")
        labels: list[str] = []
        for vuln in entry.get("vulnerabilities", []):
            cat = str(vuln.get("category", "")).lower()
            label = SMARTBUGS_CATEGORY_MAP.get(cat, cat)
            if label and label not in labels:
                labels.append(label)
        if raw_name:
            mapping[raw_name] = labels
    return mapping


def _collect_contracts(folder: Path, vuln_label: str, vuln_json_map: dict[str, list[str]]) -> list[dict]:
    """
    Load every .sol file in folder.

    Ground truth per contract:
      1. Look up the file name (without .sol) in vulnerabilities.json mapping.
      2. If not found, fall back to the folder-derived vuln_label for every file.
    """
    contracts: list[dict] = []
    for sol in sorted(folder.glob("*.sol")):
        name = sol.stem
        source_code = sol.read_text(encoding="utf-8", errors="ignore")
        # Prefer exact match in vulnerabilities.json; fall back to folder label
        labels_raw = vuln_json_map.get(name) or [vuln_label]
        labels = [{"vuln_type": lbl} for lbl in labels_raw]
        contracts.append(
            {
                "name": name,
                "source_code": source_code,
                "labels": labels,
                "path": str(sol),
            }
        )
    return contracts


def _print_table(per_vuln: dict[str, dict]) -> None:
    """Print a formatted per-vulnerability-type results table to stderr."""
    header = f"{'Vulnerability Type':<40} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  {'P':>6} {'R':>6} {'F1':>6}"
    sep = "-" * len(header)
    _info("")
    _info("=== Per-Vulnerability-Type Results ===")
    _info(sep)
    _info(header)
    _info(sep)
    for vtype, m in sorted(per_vuln.items(), key=lambda kv: kv[1].get("f1", 0), reverse=True):
        _info(
            f"{vtype:<40} {m.get('tp',0):>4} {m.get('fp',0):>4} {m.get('tn',0):>4} {m.get('fn',0):>4}"
            f"  {m.get('precision',0):>6.3f} {m.get('recall',0):>6.3f} {m.get('f1',0):>6.3f}"
        )
    _info(sep)


# ── core async runner ─────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace) -> None:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.is_dir():
        _info(f"[ERROR] Not a directory: {folder}")
        raise SystemExit(1)

    folder_name = folder.name.lower()
    vuln_label = SMARTBUGS_CATEGORY_MAP.get(folder_name, folder_name.replace("_", " ").title())
    _info(f"[folder]  {folder}")
    _info(f"[label]   folder '{folder_name}' → ground-truth label: '{vuln_label}'")

    vuln_json_map = _load_vulns_json()
    contracts = _collect_contracts(folder, vuln_label, vuln_json_map)
    if not contracts:
        _info("[ERROR] No .sol files found in folder.")
        raise SystemExit(1)
    _info(f"[contracts] {len(contracts)} .sol file(s) found")

    # Collect all distinct vuln labels used in ground truth for this folder
    all_labels: set[str] = set()
    for c in contracts:
        for lbl in c["labels"]:
            all_labels.add(lbl["vuln_type"])
    bench_vulns = sorted(all_labels)
    _info(f"[ground-truth vuln types] {bench_vulns}")

    ground_truth: dict[str, list[str]] = {
        c["name"]: [lb["vuln_type"] for lb in c["labels"]]
        for c in contracts
    }

    multi_models = [m.strip() for m in args.multi_models.split(",") if m.strip()]
    _info(
        f"[pipeline] pipeline={args.pipeline} model={args.model}"
        + (f" multi_models={multi_models}" if args.pipeline == "multi_llm" else "")
    )

    audit_results: list[dict] = []
    for idx, contract in enumerate(contracts, start=1):
        name = contract["name"]
        _info(f"[audit {idx}/{len(contracts)}] {name} ...")
        raw_source = contract["source_code"]

        try:
            preprocessed = await to_thread(preprocess_contract, raw_source, model=args.model)
            source_code = str(preprocessed.get("source_code", ""))

            t0 = time.perf_counter()
            if args.pipeline == "multi_llm":
                result = await to_thread(
                    run_multi_llm_audit,
                    source_code,
                    name,
                    multi_models,
                    args.mode,
                    args.temperature,
                    args.multi_aggregation,
                    None,           # progress_callback
                    bench_vulns,    # vuln_filter
                    False,          # verify
                    None,           # verify_with_rag
                    args.multi_parallel,
                    "",             # slither_reference
                )
            else:
                result = await to_thread(
                    analyze_contract,
                    source_code,
                    name,
                    args.mode,
                    args.model,
                    args.temperature,
                    False,          # verify
                    False,          # verify_with_rag
                    None,           # progress_callback
                    False,          # agent_mode
                    None,           # agent_judge_model
                    bench_vulns,    # vuln_filter
                    "",             # slither_reference
                )
            elapsed = time.perf_counter() - t0
            _info(f"  done in {elapsed:.1f}s — {len(result.get('vuln_results', []))} vuln checks")
            audit_results.append(
                {
                    "contract_name": name,
                    "vuln_results": result.get("vuln_results", []),
                }
            )
        except Exception as exc:  # noqa: BLE001
            _info(f"  [ERROR] {name}: {exc}")
            audit_results.append({"contract_name": name, "vuln_results": [], "error": str(exc)})

    # ── scoring ───────────────────────────────────────────────────────────────
    scores = await to_thread(evaluate_batch, audit_results, ground_truth)
    per_vuln = await to_thread(compute_per_vuln_metrics, audit_results, ground_truth)

    agg = scores.get("aggregate", {})
    counts = agg.get("counts", {})
    metrics = agg.get("metrics", {})
    _info(
        f"\n[aggregate] TP={counts.get('TP',0)} FP={counts.get('FP',0)} "
        f"TN={counts.get('TN',0)} FN={counts.get('FN',0)} | "
        f"P={metrics.get('precision',0):.3f} R={metrics.get('recall',0):.3f} "
        f"F1={metrics.get('f1',0):.3f}"
    )

    _print_table(per_vuln)

    # ── save full JSON ────────────────────────────────────────────────────────
    payload = {
        "folder": str(folder),
        "ground_truth_label": vuln_label,
        "bench_vulns": bench_vulns,
        "contracts_evaluated": len(contracts),
        "pipeline": args.pipeline,
        "model": args.model,
        "mode": args.mode,
        "scores": scores,
        "per_vuln_metrics": per_vuln,
        "audit_results": audit_results,
    }
    out_path = Path(args.output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    _info(f"\n[saved] {out_path.resolve()} ({out_path.stat().st_size} bytes)")

    # stdout: per-vuln summary JSON (useful for scripting / piping)
    print(json.dumps({"aggregate": agg, "per_vuln_metrics": per_vuln}, ensure_ascii=False, indent=2), flush=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Benchmark a SmartBugs category folder and report per-vuln-type F1."
    )
    p.add_argument(
        "--folder",
        required=True,
        help="Path to a folder of .sol files (e.g. data/benchmarks/smartbugs/dataset/front_running)",
    )
    p.add_argument("--output", "-o", default="benchmark_folder_result.json",
                   help="Output JSON file path (default: benchmark_folder_result.json)")

    # Pipeline / model
    p.add_argument("--pipeline", default="standard", choices=["standard", "multi_llm"],
                   help="Audit pipeline (default: standard)")
    p.add_argument("--model", default="deepseek-v3.2", help="Primary LLM model")
    p.add_argument("--mode", default="non_binary", choices=["binary", "non_binary", "cot"],
                   help="Audit classification mode (default: non_binary)")
    p.add_argument("--temperature", type=float, default=0.0)

    # multi_llm options
    p.add_argument("--multi-models", default="deepseek-v3.2,gpt-4o-mini",
                   help="Comma-separated model list for multi_llm pipeline")
    p.add_argument("--multi-parallel", action="store_true", help="Run models concurrently")
    p.add_argument("--multi-aggregation", default="majority", choices=["majority", "consensus"])

    # Logging
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show INFO logs from phase2/app (LLM request detail)")

    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )

    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        _info("[benchmark] Interrupted (KeyboardInterrupt)")
        raise SystemExit(130) from None
    except Exception as exc:  # noqa: BLE001
        _info(f"[benchmark] Failed: {exc}")
        raise


if __name__ == "__main__":
    main()
