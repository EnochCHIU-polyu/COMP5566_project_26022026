"""
Main entry point for the Smart Contract Vulnerability Detection Framework.

Usage examples
--------------
# Audit a single contract file (non-binary mode):
    python main.py --contract path/to/contract.sol

# Run with binary mode and temperature 0:
    python main.py --contract path/to/contract.sol --mode binary --temperature 0

# Generate and save 5 synthetic contracts with 2 injected vulnerabilities:
    python main.py --generate-synthetic --num-vulns 2

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
        logger.warning(
            "Contract was truncated (%d → %d tokens).",
            preprocessed["token_count"],  # after truncation
            preprocessed["token_count"],
        )

    result = analyze_contract(
        source_code=preprocessed["source_code"],
        contract_name=os.path.basename(args.contract),
        mode=args.mode,
        temperature=args.temperature,
    )

    print(json.dumps(result, indent=2))


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
        choices=["binary", "non_binary", "cot"],
        default="non_binary",
    )
    audit_parser.add_argument("--temperature", type=float, default=None)

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

    args = parser.parse_args()

    if args.command == "audit":
        _run_audit(args)
    elif args.command == "generate-synthetic":
        _generate_synthetic(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
