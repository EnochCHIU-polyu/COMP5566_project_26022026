#!/usr/bin/env python3
"""
Benchmark all (or selected) SmartBugs category folders and print one summary row per category.

For each category folder the script:
  1. Loads all .sol files
  2. Resolves ground truth from vulnerabilities.json (fallback: folder name)
  3. Runs analyze_contract (or run_multi_llm_audit) with vuln_filter = that folder's label
  4. Scores with evaluate_batch + compute_per_vuln_metrics

Final output on stderr: a table with one row per category.
Stdout: full JSON (aggregate + per-category) — useful for piping / saving.

Usage (from repo root):
  # All categories, standard pipeline:
  PYTHONPATH=".:backend" ./.venv/bin/python scripts/run_all_benchmark.py \\
      -o results/all_categories.json

  # Specific categories only:
  PYTHONPATH=".:backend" ./.venv/bin/python scripts/run_all_benchmark.py \\
      --categories front_running reentrancy arithmetic \\
      -o results/selected.json

  # multi_llm pipeline, parallel models:
  PYTHONPATH=".:backend" ./.venv/bin/python scripts/run_all_benchmark.py \\
      --pipeline multi_llm --multi-models deepseek-v3.2,gpt-4o-mini --multi-parallel \\
      -o results/all_multi.json

  # Verbose LLM logs:
  PYTHONPATH=".:backend" ./.venv/bin/python scripts/run_all_benchmark.py -v \\
      --categories front_running -o results/debug.json
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
from phase4_evaluation.swe_mapping import (                                   # noqa: E402
    build_swe_mapping_rows,
    resolve_swe_label,
)
from phase4_evaluation.scorer import (                                        # noqa: E402
    compute_per_vuln_metrics,
    evaluate_batch,
)
from app.utils.async_compat import to_thread                                  # noqa: E402

DATASET_DIR = ROOT / "data" / "benchmarks" / "smartbugs" / "dataset"
VULNS_JSON  = ROOT / "data" / "benchmarks" / "smartbugs" / "vulnerabilities.json"


# ── helpers ──────────────────────────────────────────────────────────────────

def _info(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _load_vulns_json() -> dict[str, list[str]]:
    """Return {filename_without_ext: [label, ...]} from vulnerabilities.json."""
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
    contracts: list[dict] = []
    for sol in sorted(folder.glob("*.sol")):
        name = sol.stem
        source_code = sol.read_text(encoding="utf-8", errors="ignore")
        labels_raw = vuln_json_map.get(name) or [vuln_label]
        labels = [{"vuln_type": lbl} for lbl in labels_raw]
        contracts.append({"name": name, "source_code": source_code, "labels": labels})
    return contracts


async def _audit_contract(
    name: str,
    source_code: str,
    bench_vulns: list[str],
    args: argparse.Namespace,
    multi_models: list[str],
) -> dict:
    """Preprocess + audit one contract; return audit_result dict."""
    try:
        preprocessed = await to_thread(preprocess_contract, source_code, model=args.model)
        src = str(preprocessed.get("source_code", ""))
        if args.pipeline == "multi_llm":
            result = await to_thread(
                run_multi_llm_audit,
                src, name, multi_models, args.mode, args.temperature,
                args.multi_aggregation, None, bench_vulns,
                False, None, args.multi_parallel, "",
            )
        else:
            result = await to_thread(
                analyze_contract,
                src, name, args.mode, args.model, args.temperature,
                False, False, None, False, None, bench_vulns, "",
            )
        return {"contract_name": name, "vuln_results": result.get("vuln_results", [])}
    except Exception as exc:  # noqa: BLE001
        _info(f"    [ERROR] {name}: {exc}")
        return {"contract_name": name, "vuln_results": [], "error": str(exc)}


async def _run_category(
    folder: Path,
    vuln_json_map: dict[str, list[str]],
    args: argparse.Namespace,
    multi_models: list[str],
) -> dict:
    """Run the full audit+score pipeline for one category folder. Returns summary dict."""
    folder_name = folder.name.lower()
    vuln_label = SMARTBUGS_CATEGORY_MAP.get(folder_name, folder_name.replace("_", " ").title())
    swe_summary = resolve_swe_label(vuln_label)

    contracts = _collect_contracts(folder, vuln_label, vuln_json_map)
    if not contracts:
        return {
            "category": folder_name,
            "label": vuln_label,
            "swe_field_id": swe_summary.get("swe_field_id"),
            "swe_field": swe_summary.get("swe_field", "Unmapped"),
            "swe_weakness": swe_summary.get("swe_weakness", "Unmapped"),
            "contracts": 0,
            "skipped": 0,
            "tp": 0, "fp": 0, "tn": 0, "fn": 0,
            "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "per_vuln_metrics": {},
            "swe_mapping": [],
            "audit_results": [],
            "error": "no .sol files",
        }

    all_labels: set[str] = set()
    for c in contracts:
        for lb in c["labels"]:
            all_labels.add(lb["vuln_type"])
    bench_vulns = sorted(all_labels)

    ground_truth = {
        c["name"]: [lb["vuln_type"] for lb in c["labels"]]
        for c in contracts
    }

    _info(f"  [{folder_name}] {len(contracts)} contracts, vulns={bench_vulns}")
    audit_results: list[dict] = []
    for c in contracts:
        ar = await _audit_contract(c["name"], c["source_code"], bench_vulns, args, multi_models)
        audit_results.append(ar)

    scores     = await to_thread(evaluate_batch, audit_results, ground_truth)
    per_vuln   = await to_thread(compute_per_vuln_metrics, audit_results, ground_truth)

    agg     = scores.get("aggregate", {})
    counts  = agg.get("counts", {})
    metrics = agg.get("metrics", {})

    return {
        "category": folder_name,
        "label": vuln_label,
        "swe_field_id": swe_summary.get("swe_field_id"),
        "swe_field": swe_summary.get("swe_field", "Unmapped"),
        "swe_weakness": swe_summary.get("swe_weakness", "Unmapped"),
        "contracts": len(contracts),
        "skipped": agg.get("skipped_unparseable", 0),
        "tp": counts.get("TP", 0),
        "fp": counts.get("FP", 0),
        "tn": counts.get("TN", 0),
        "fn": counts.get("FN", 0),
        "precision": metrics.get("precision", 0.0),
        "recall":    metrics.get("recall",    0.0),
        "f1":        metrics.get("f1",        0.0),
        "per_vuln_metrics": per_vuln,
        "swe_mapping": build_swe_mapping_rows(bench_vulns),
        "audit_results": audit_results,
    }


def _print_summary_table(rows: list[dict]) -> None:
    """Print a formatted multi-category summary table."""
    col_cat  = max(len("Category"), max(len(r["label"]) for r in rows)) + 2
    col_field = max(len("SWE Field"), max(len(str(r.get("swe_field", "Unmapped"))) for r in rows)) + 2
    col_weak = max(len("Weakness"), max(len(str(r.get("swe_weakness", "Unmapped"))) for r in rows)) + 2
    header = (
        f"{'Category':<{col_cat}} {'SWE Field':<{col_field}} {'Weakness':<{col_weak}} {'#':>4}  "
        f"{'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  "
        f"{'Precision':>9} {'Recall':>7} {'F1':>7}"
    )
    sep = "─" * len(header)
    _info("")
    _info("╔" + "═" * (len(header) + 2) + "╗")
    _info("║  " + "BENCHMARK SUMMARY — ALL CATEGORIES".center(len(header)) + "  ║")
    _info("╠" + "═" * (len(header) + 2) + "╣")
    _info("  " + header)
    _info("  " + sep)
    for r in rows:
        err = "  [error]" if r.get("error") else ""
        swe_field = str(r.get("swe_field", "Unmapped"))
        if r.get("swe_field_id"):
            swe_field = f"{r['swe_field_id']}. {swe_field}"
        _info(
            f"  {r['label']:<{col_cat}} {swe_field:<{col_field}} {str(r.get('swe_weakness','Unmapped')):<{col_weak}} {r['contracts']:>4}  "
            f"{r['tp']:>4} {r['fp']:>4} {r['tn']:>4} {r['fn']:>4}  "
            f"{r['precision']:>9.3f} {r['recall']:>7.3f} {r['f1']:>7.3f}"
            + err
        )
    _info("  " + sep)

    # totals row
    tp  = sum(r["tp"]  for r in rows)
    fp  = sum(r["fp"]  for r in rows)
    tn  = sum(r["tn"]  for r in rows)
    fn  = sum(r["fn"]  for r in rows)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    total_c = sum(r["contracts"] for r in rows)
    _info(
        f"  {'TOTAL':<{col_cat}} {'-':<{col_field}} {'-':<{col_weak}} {total_c:>4}  "
        f"{tp:>4} {fp:>4} {tn:>4} {fn:>4}  "
        f"{prec:>9.3f} {rec:>7.3f} {f1:>7.3f}"
    )
    _info("╚" + "═" * (len(header) + 2) + "╝")
    _info("")


# ── main async runner ─────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace) -> None:
    multi_models = [m.strip() for m in args.multi_models.split(",") if m.strip()]
    vuln_json_map = _load_vulns_json()

    # Resolve category folders
    if args.categories:
        folders = [DATASET_DIR / cat for cat in args.categories]
        missing = [f for f in folders if not f.is_dir()]
        if missing:
            _info(f"[ERROR] Folders not found: {[str(m) for m in missing]}")
            raise SystemExit(1)
    else:
        folders = sorted(
            f for f in DATASET_DIR.iterdir()
            if f.is_dir() and not f.name.startswith(".")
        )

    _info(f"[categories] {len(folders)} folder(s): {[f.name for f in folders]}")
    _info(f"[pipeline]   pipeline={args.pipeline} model={args.model} mode={args.mode}")

    rows: list[dict] = []
    t_total = time.perf_counter()

    for folder in folders:
        _info(f"\n── {folder.name} ──────────────────────────────────")
        t0 = time.perf_counter()
        row = await _run_category(folder, vuln_json_map, args, multi_models)
        elapsed = time.perf_counter() - t0
        _info(
            f"  [{folder.name}] done in {elapsed:.1f}s  "
            f"F1={row['f1']:.3f}  TP={row['tp']} FP={row['fp']} TN={row['tn']} FN={row['fn']}"
        )
        rows.append(row)

    elapsed_total = time.perf_counter() - t_total
    _info(f"\n[total time] {elapsed_total:.1f}s")

    _print_summary_table(rows)

    # ── save JSON ─────────────────────────────────────────────────────────────
    payload = {
        "pipeline": args.pipeline,
        "model":    args.model,
        "mode":     args.mode,
        "categories": rows,
        "summary": {
            "total_contracts":  sum(r["contracts"] for r in rows),
            "total_tp": sum(r["tp"] for r in rows),
            "total_fp": sum(r["fp"] for r in rows),
            "total_tn": sum(r["tn"] for r in rows),
            "total_fn": sum(r["fn"] for r in rows),
        },
    }
    out_path = Path(args.output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    _info(f"[saved] {out_path.resolve()} ({out_path.stat().st_size} bytes)")

    # stdout: clean per-category summary (pipe-friendly)
    summary_rows = [
        {
            "category": r["label"],
            "swe_field_id": r.get("swe_field_id"),
            "swe_field": r.get("swe_field", "Unmapped"),
            "swe_weakness": r.get("swe_weakness", "Unmapped"),
            "contracts": r["contracts"],
            "tp": r["tp"], "fp": r["fp"], "tn": r["tn"], "fn": r["fn"],
            "precision": round(r["precision"], 4),
            "recall":    round(r["recall"],    4),
            "f1":        round(r["f1"],        4),
        }
        for r in rows
    ]
    print(json.dumps(summary_rows, ensure_ascii=False, indent=2), flush=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Benchmark all SmartBugs category folders and print a summary table."
    )
    p.add_argument(
        "--categories", nargs="+", metavar="FOLDER",
        help=(
            "Space-separated folder names to run (e.g. front_running reentrancy). "
            "Omit to run ALL folders under data/benchmarks/smartbugs/dataset/."
        ),
    )
    p.add_argument("--output", "-o", default="results/all_categories.json",
                   help="Output JSON file (default: results/all_categories.json)")

    # pipeline / model
    p.add_argument("--pipeline", default="standard", choices=["standard", "multi_llm"])
    p.add_argument("--model", default="deepseek-v3.2")
    p.add_argument("--mode", default="non_binary", choices=["binary", "non_binary", "cot"])
    p.add_argument("--temperature", type=float, default=0.0)

    # multi_llm options
    p.add_argument("--multi-models", default="deepseek-v3.2,gpt-4o-mini")
    p.add_argument("--multi-parallel", action="store_true")
    p.add_argument("--multi-aggregation", default="majority", choices=["majority", "consensus"])

    # logging
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show INFO logs from phase2/app (LLM detail) on stderr")

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
        _info("\n[benchmark] Interrupted — partial results may be in output file.")
        raise SystemExit(130) from None
    except Exception as exc:  # noqa: BLE001
        _info(f"[benchmark] Failed: {exc}")
        raise


if __name__ == "__main__":
    main()
