"""
Main entry point for the Smart Contract Vulnerability Detection Framework.

Usage examples
--------------
# Audit a single contract file (non-binary mode):
    python main.py audit --contract path/to/contract.sol

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
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

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

    result = analyze_contract(
        source_code=preprocessed["source_code"],
        contract_name=os.path.basename(args.contract),
        mode=args.mode,
        temperature=args.temperature,
        verify=getattr(args, "verify", False),
        use_filter=not getattr(args, "no_filter", False),
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Smart Contract Vulnerability Detection Framework"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── audit sub-command ──────────────────────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Audit a smart contract file")
    audit_parser.add_argument("--contract", required=True, help="Path to .sol file")
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
        "--no-filter",
        action="store_true",
        help="Disable keyword relevance pre-filter (check all 38 vuln types)",
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

    args = parser.parse_args()

    if args.command == "audit":
        _run_audit(args)
    elif args.command == "generate-synthetic":
        _generate_synthetic(args)
    elif args.command == "download-benchmarks":
        _download_benchmarks(args)
    elif args.command == "report":
        _generate_report(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
