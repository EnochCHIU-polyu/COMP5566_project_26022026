"""
Main entry point for the Smart Contract Vulnerability Detection Framework.

Usage examples
--------------
# Audit a single contract file (non-binary mode):
    python main.py audit --contract path/to/contract.sol

# Use a specific model (otherwise DEFAULT_MODEL from .env / config, e.g. deepseek-v3.2):
    python main.py audit --contract path/to/contract.sol --model gpt-4o

# Run with binary mode and temperature 0:
    python main.py audit --contract path/to/contract.sol --mode binary --temperature 0

# Audit and write results to file:
    python main.py audit --contract path/to/contract.sol --output results.json

# Audit with self-check verification:
    python main.py audit --contract path/to/contract.sol --verify

# Generate and save 5 synthetic contracts with 2 injected vulnerabilities:
    python main.py generate-synthetic --num-vulns 2

# Download benchmark datasets:
    python main.py download-benchmarks --dataset smartbugs

# Generate a markdown report from saved results:
    python main.py report --results results.json --output report.md

# Launch the Streamlit UI:
    streamlit run phase4_evaluation/ui_app.py

# Multi-LLM audit (aggregate results from multiple models):
    python main.py audit-multi --contract path/to/contract.sol --models gpt-4o,gpt-4o-mini
# Multi-LLM parallel + cascade + verification RAG:
    python main.py audit-multi --contract c.sol --models gpt-4o,gpt-4o-mini --parallel
    python main.py audit --contract c.sol --cascade --cascade-small gpt-4o-mini --cascade-large gpt-4o
    python main.py audit --contract c.sol --verify --verify-rag
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from config import DEFAULT_MODEL

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _run_audit(args: argparse.Namespace) -> None:
    from phase1_data_pipeline.contract_preprocessor import preprocess_contract
    from phase2_llm_engine.cot_analyzer import analyze_contract

    with open(args.contract, "r", encoding="utf-8") as fh:
        raw_source = fh.read()

    preprocessed = preprocess_contract(raw_source)
    if preprocessed["truncated"]:
        from phase1_data_pipeline.token_counter import count_tokens
        original_count = count_tokens(raw_source)
        logger.warning(
            "Contract was truncated (%d → %d tokens).",
            original_count,
            preprocessed["token_count"],
        )

    if getattr(args, "cascade", False):
        from phase2_llm_engine.cot_analyzer import analyze_contract_cascade

        logger.info(
            "Cascade audit: small=%s large=%s (set via --cascade-small / --cascade-large)",
            getattr(args, "cascade_small", "gpt-4o-mini"),
            getattr(args, "cascade_large", "gpt-4o"),
        )
        result = analyze_contract_cascade(
            source_code=preprocessed["source_code"],
            contract_name=os.path.basename(args.contract),
            small_model=getattr(args, "cascade_small", "gpt-4o-mini"),
            large_model=getattr(args, "cascade_large", "gpt-4o"),
            temperature=args.temperature,
            verify=getattr(args, "verify", False),
            verify_with_rag=getattr(args, "verify_rag", False),
        )
    else:
        _cli_model = getattr(args, "model", None)
        logger.info(
            "Single-model audit: model=%s (CLI --model, or DEFAULT_MODEL from .env: %s)",
            _cli_model or DEFAULT_MODEL,
            DEFAULT_MODEL,
        )
        result = analyze_contract(
            source_code=preprocessed["source_code"],
            contract_name=os.path.basename(args.contract),
            mode=args.mode,
            model=_cli_model,
            temperature=args.temperature,
            verify=getattr(args, "verify", False),
            verify_with_rag=getattr(args, "verify_rag", False),
            agent_mode=getattr(args, "agent", False),
            agent_judge_model=getattr(args, "agent_judge", None),
        )

    output_json = json.dumps(result, indent=2)
    print(output_json)

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_json)
        logger.info("Results written to %s", args.output)


def _run_multi_llm_audit(args: argparse.Namespace) -> None:
    from phase1_data_pipeline.contract_preprocessor import preprocess_contract
    from phase2_llm_engine.cot_analyzer import run_multi_llm_audit

    with open(args.contract, "r", encoding="utf-8") as fh:
        raw_source = fh.read()

    preprocessed = preprocess_contract(raw_source)
    if preprocessed["truncated"]:
        from phase1_data_pipeline.token_counter import count_tokens
        original_count = count_tokens(raw_source)
        logger.warning(
            "Contract was truncated (%d → %d tokens).",
            original_count,
            preprocessed["token_count"],
        )

    models = [m.strip() for m in (args.models or "gpt-4o,gpt-4o-mini").split(",") if m.strip()]
    result = run_multi_llm_audit(
        source_code=preprocessed["source_code"],
        contract_name=os.path.basename(args.contract),
        models=models,
        mode=getattr(args, "mode", None),
        temperature=getattr(args, "temperature", None),
        aggregation=getattr(args, "aggregation", "majority"),
        parallel_models=getattr(args, "parallel", False),
    )

    output_json = json.dumps(result, indent=2)
    print(output_json)

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_json)
        logger.info("Results written to %s", args.output)


def _generate_synthetic(args: argparse.Namespace) -> None:
    from phase1_data_pipeline.synthetic_contracts import (
        generate_synthetic_contracts,
        save_synthetic_contracts,
    )

    contracts = generate_synthetic_contracts(num_vulns=args.num_vulns)
    save_synthetic_contracts(contracts)
    print(f"Generated {len(contracts)} synthetic contracts in data/synthetic_contracts/")
    for c in contracts:
        print(f"  {c['name']}: labels = {c['labels']}")


def _download_benchmarks(args: argparse.Namespace) -> None:
    from phase1_data_pipeline.benchmark_datasets import load_benchmark

    dataset = getattr(args, "dataset", "smartbugs")
    contracts = load_benchmark(dataset)
    print(f"Loaded {len(contracts)} contracts from '{dataset}' dataset")


def _generate_report(args: argparse.Namespace) -> None:
    from phase4_evaluation.report_generator import generate_markdown_report, save_report

    with open(args.results, "r", encoding="utf-8") as fh:
        audit_result = json.load(fh)

    contract_name = audit_result.get("contract_name", os.path.basename(args.results))
    report_format = getattr(args, "format", "markdown")
    output_path = getattr(args, "output", None) or f"{contract_name}_report.md"

    save_report(audit_result, contract_name, output_path, format=report_format)
    print(f"Report written to {output_path}")


def _seed_vulnerability_catalog(args: argparse.Namespace) -> None:
    from phase2_llm_engine.vulnerability_store import seed_vulnerability_catalog

    summary = seed_vulnerability_catalog(force=bool(getattr(args, "force", False)))
    status = "OK" if summary.get("ok") else "FAILED"
    print(f"[{status}] {summary.get('message', '')}")
    if "existing" in summary and summary.get("existing") is not None:
        print(f"Existing rows: {summary.get('existing')}")
    print(f"Seeded rows: {summary.get('seeded', 0)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Smart Contract Vulnerability Detection Framework"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── audit sub-command ──────────────────────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Audit a smart contract file")
    audit_parser.add_argument("--contract", required=True, help="Path to .sol file")
    audit_parser.add_argument(
        "--model",
        default=None,
        metavar="NAME",
        help=(
            f"LLM model id for this run (default: DEFAULT_MODEL from env/config, "
            f"currently {DEFAULT_MODEL!r})"
        ),
    )
    audit_parser.add_argument(
        "--mode",
        choices=["binary", "non_binary", "cot", "multi_vuln"],
        default="non_binary",
    )
    audit_parser.add_argument("--temperature", type=float, default=None)
    audit_parser.add_argument("--output", default=None, help="Write JSON results to file")
    audit_parser.add_argument(
        "--verify",
        action="store_true",
        help="Run self-check verification pass on findings",
    )
    audit_parser.add_argument(
        "--agent",
        action="store_true",
        help="Use agent mode: 2-step reasoning (analyze → reflect/judge) per vulnerability",
    )
    audit_parser.add_argument(
        "--agent-judge",
        default=None,
        help="Model for agent reflection step (default: same as main model)",
    )
    audit_parser.add_argument(
        "--verify-rag",
        action="store_true",
        help="With --verify: inject TF-IDF retrieved context into verification (1 LLM call)",
    )
    audit_parser.add_argument(
        "--cascade",
        action="store_true",
        help="Cheap model binary first; expensive model only when not clearly safe (faster)",
    )
    audit_parser.add_argument(
        "--cascade-small",
        default="gpt-4o-mini",
        help="Small/cheap model for cascade first pass (default: gpt-4o-mini)",
    )
    audit_parser.add_argument(
        "--cascade-large",
        default="gpt-4o",
        help="Large model for cascade second pass (default: gpt-4o)",
    )

    # ── audit-multi sub-command (multi-LLM) ──────────────────────────────────
    audit_multi_parser = subparsers.add_parser(
        "audit-multi",
        help="Audit contract with multiple LLMs and aggregate results",
    )
    audit_multi_parser.add_argument("--contract", required=True, help="Path to .sol file")
    audit_multi_parser.add_argument(
        "--models",
        default="gpt-4o,gpt-4o-mini",
        help="Comma-separated model names (default: gpt-4o,gpt-4o-mini)",
    )
    audit_multi_parser.add_argument(
        "--aggregation",
        choices=["majority", "consensus"],
        default="majority",
        help="majority=half+ vote YES; consensus=all must agree",
    )
    audit_multi_parser.add_argument("--mode", choices=["binary", "non_binary", "cot", "multi_vuln"], default="non_binary")
    audit_multi_parser.add_argument("--temperature", type=float, default=None)
    audit_multi_parser.add_argument("--output", default=None, help="Write JSON results to file")
    audit_multi_parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run models concurrently (faster; respect API rate limits)",
    )

    # ── generate sub-command ───────────────────────────────────────────────
    gen_parser = subparsers.add_parser(
        "generate-synthetic",
        help="Generate synthetic contracts with injected vulnerabilities",
    )
    gen_parser.add_argument(
        "--num-vulns",
        type=int,
        choices=[2, 15],
        default=2,
        help="Number of vulnerabilities to inject (2 or 15)",
    )

    # ── download-benchmarks sub-command ───────────────────────────────────
    dl_parser = subparsers.add_parser(
        "download-benchmarks",
        help="Download and cache benchmark datasets",
    )
    dl_parser.add_argument(
        "--dataset",
        choices=["smartbugs", "solidifi", "all"],
        default="smartbugs",
        help="Dataset to download",
    )

    # ── report sub-command ─────────────────────────────────────────────────
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a markdown/HTML audit report from saved results",
    )
    report_parser.add_argument("--results", required=True, help="Path to JSON results file")
    report_parser.add_argument("--output", default=None, help="Output report file path")
    report_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format",
    )

    # ── seed-vulnerability-catalog sub-command ─────────────────────────────
    seed_vuln_parser = subparsers.add_parser(
        "seed-vulnerability-catalog",
        help="Seed vulnerability_types catalog from local file into Supabase",
    )
    seed_vuln_parser.add_argument(
        "--force",
        action="store_true",
        help="Upsert all local rows even when DB table already has data",
    )

    args = parser.parse_args()

    if args.command == "audit":
        _run_audit(args)
    elif args.command == "audit-multi":
        _run_multi_llm_audit(args)
    elif args.command == "generate-synthetic":
        _generate_synthetic(args)
    elif args.command == "download-benchmarks":
        _download_benchmarks(args)
    elif args.command == "report":
        _generate_report(args)
    elif args.command == "seed-vulnerability-catalog":
        _seed_vulnerability_catalog(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
