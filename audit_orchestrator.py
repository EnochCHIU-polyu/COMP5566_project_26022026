"""
audit_orchestrator.py
======================
Research-Centric Autonomous Audit Orchestrator

This is the new system entry point described in the paper
"Do you still need a manual smart contract audit?".  It coordinates the full
pipeline:

  1. **Ingest**   — call :mod:`data_pipeline.batch_fetcher` to download target
                    contracts from Etherscan or load already-fetched contracts
                    from disk.
  2. **Iterate**  — for every contract × every definition in the Taxonomy Engine,
                    build a targeted audit prompt and send it to the LLM.
  3. **Cross-Reference** — compare findings against the Taxonomy's definitions;
                    detect novel attack patterns and trigger the Defining Loop
                    to expand the taxonomy when confidence is high.
  4. **Report**   — write a structured audit report (JSON + Markdown) that cites
                    the specific natural-language definition used for each finding.

Usage
-----
    # Full pipeline: fetch from Etherscan, audit with all taxonomy definitions:
    python audit_orchestrator.py \\
        --input data/input_addresses.csv \\
        --output-dir reports/

    # Audit pre-fetched .sol files without re-downloading:
    python audit_orchestrator.py \\
        --sol-dir data/raw/batch_audit/20260410T120000Z/ \\
        --output-dir reports/

    # Limit to specific vulnerability categories:
    python audit_orchestrator.py \\
        --input data/input_addresses.csv \\
        --categories Reentrancy "Access Control Flaws" \\
        --output-dir reports/

    # Skip LLM calls (validation / dry-run of the pipeline):
    python audit_orchestrator.py \\
        --sol-dir data/raw/ \\
        --no-llm \\
        --output-dir reports/

Requirements
------------
    pip install requests>=2.28.0 pandas>=2.0.0 python-dotenv>=1.0.0
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("audit_orchestrator")

# ---------------------------------------------------------------------------
# Project-relative defaults
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent
_DEFAULT_INPUT_CSV = _PROJECT_ROOT / "data" / "input_addresses.csv"
_DEFAULT_OUTPUT_DIR = _PROJECT_ROOT / "reports"
_DEFAULT_TAXONOMY_FILE = _PROJECT_ROOT / "data" / "vuln_definitions.json"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truncate(text: str, max_chars: int = 12000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n// [TRUNCATED]"


def _load_sol_files(sol_dir: Path) -> list[dict[str, Any]]:
    """Load all .sol files from *sol_dir* into a list of contract dicts."""
    contracts = []
    for sol_path in sorted(sol_dir.glob("*.sol")):
        try:
            src = sol_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Could not read %s: %s", sol_path, exc)
            continue
        contracts.append(
            {
                "filename": sol_path.name,
                "contract_name": sol_path.stem,
                "source_code": src,
                "address": "",
            }
        )
    return contracts


def _enrich_with_manifest(
    contracts: list[dict[str, Any]],
    manifest_path: Path,
) -> list[dict[str, Any]]:
    """Attach address and label metadata from a batch_fetcher manifest.json."""
    if not manifest_path.exists():
        return contracts

    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return contracts

    entries: dict[str, dict] = manifest.get("entries", {})
    # Build filename → entry lookup
    by_filename: dict[str, dict] = {
        e.get("filename", ""): e for e in entries.values() if e.get("filename")
    }

    for c in contracts:
        entry = by_filename.get(c["filename"], {})
        if entry:
            c["address"] = entry.get("address", c.get("address", ""))
            c["contract_name"] = entry.get("contract_name") or c["contract_name"]
            for extra_key in ("label", "note"):
                if extra_key in entry:
                    c[extra_key] = entry[extra_key]
    return contracts


# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------


def _run_llm_audit(
    prompt: str,
    llm_client=None,
) -> dict[str, Any]:
    """
    Send a single audit prompt to the LLM and parse the JSON verdict.

    Returns a normalised verdict dict or a fallback heuristic verdict on error.
    """
    if llm_client is None:
        from phase2_llm_engine.llm_client import query_llm  # noqa: PLC0415

        def llm_client(p: str) -> str:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a precise smart contract security auditor. "
                        "Return strict JSON only."
                    ),
                },
                {"role": "user", "content": p},
            ]
            return query_llm(messages=messages)

    try:
        raw = llm_client(prompt)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM call failed: %s", exc)
        return {
            "vulnerable": False,
            "vuln_type": "none",
            "reasoning": f"LLM error: {exc}",
            "evidence_lines": [],
            "confidence": 0.0,
            "definition_cited": "",
            "_llm_error": str(exc),
        }

    # Extract JSON object from response
    raw = (raw or "").strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(raw[start: end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    logger.warning("Could not parse LLM audit response as JSON; returning raw text.")
    return {
        "vulnerable": False,
        "vuln_type": "none",
        "reasoning": raw,
        "evidence_lines": [],
        "confidence": 0.0,
        "definition_cited": "",
        "_parse_error": "non-json response",
    }


def _disabled_llm_client(_: str) -> str:
    raise RuntimeError("LLM disabled via --no-llm")


# ---------------------------------------------------------------------------
# Cross-reference / finding deduplication
# ---------------------------------------------------------------------------


def _is_new_pattern(
    finding: dict[str, Any],
    taxonomy_names: list[str],
) -> bool:
    """
    Return True if the finding's vuln_type is NOT in the existing taxonomy.
    Used to trigger the Defining Loop.
    """
    vuln_type = str(finding.get("vuln_type", "none") or "none").strip()
    if vuln_type in ("none", "other", ""):
        return False
    lower_names = {n.lower() for n in taxonomy_names}
    return vuln_type.lower() not in lower_names


# ---------------------------------------------------------------------------
# Markdown report generator
# ---------------------------------------------------------------------------


def _build_markdown_report(
    audit_results: list[dict[str, Any]],
    taxonomy_summary: dict[str, Any],
    pipeline_meta: dict[str, Any],
) -> str:
    """Build a Markdown audit report from the pipeline results."""
    lines: list[str] = []
    ts = pipeline_meta.get("started_at", _now_iso())

    lines.append("# Autonomous Smart Contract Audit Report")
    lines.append(f"\n**Generated**: {ts}  ")
    lines.append(f"**Total contracts audited**: {pipeline_meta.get('contracts_audited', 0)}  ")
    lines.append(f"**Taxonomy definitions used**: {taxonomy_summary.get('total', 0)}  ")
    new_patterns = pipeline_meta.get("new_patterns_discovered", 0)
    lines.append(f"**New patterns discovered**: {new_patterns}  ")
    lines.append("")

    # Table of contents
    lines.append("## Table of Contents\n")
    for i, result in enumerate(audit_results, 1):
        name = result.get("contract_name", f"Contract {i}")
        anchor = name.lower().replace(" ", "-").replace("/", "")
        lines.append(f"{i}. [{name}](#{anchor})")
    lines.append("")

    # Per-contract sections
    for result in audit_results:
        name = result.get("contract_name", "Unknown")
        address = result.get("address", "")
        lines.append(f"---\n\n## {name}")
        if address:
            lines.append(f"\n**Address**: `{address}`  ")
        lines.append(f"**File**: `{result.get('filename', '')}`  \n")

        findings = result.get("findings", [])
        positive = [f for f in findings if f.get("vulnerable")]
        if not positive:
            lines.append("✅ **No vulnerabilities detected.**\n")
        else:
            lines.append(f"⚠️ **{len(positive)} vulnerability finding(s):**\n")

        for finding in positive:
            vuln = finding.get("vuln_type", "Unknown")
            conf = finding.get("confidence", 0.0)
            defn_cited = finding.get("definition_cited", vuln)
            reasoning = finding.get("reasoning", "")
            evidence = finding.get("evidence_lines", [])
            severity = finding.get("severity", "")

            lines.append(f"### 🔴 {vuln}")
            if severity:
                lines.append(f"- **Severity**: {severity.upper()}")
            lines.append(f"- **Confidence**: {conf:.0%}")
            if defn_cited:
                lines.append(
                    f"- **Definition cited**: _{defn_cited}_ "
                    f"(from taxonomy)"
                )
            if evidence:
                lines.append(f"- **Evidence lines**: {evidence}")
            if reasoning:
                lines.append(f"\n**Reasoning**:\n> {reasoning}\n")

        # Show negative results as a compact list
        negative = [f for f in findings if not f.get("vulnerable")]
        if negative:
            negatives_str = ", ".join(
                f.get("vuln_type") or f.get("definition_checked", "?")
                for f in negative
            )
            lines.append(f"\n_Checked (no issue found)_: {negatives_str}\n")

    # Taxonomy section
    lines.append("---\n\n## Taxonomy Used\n")
    lines.append(
        f"The following {taxonomy_summary.get('total', 0)} vulnerability definitions "
        f"were used as the reference for all audit queries:\n"
    )
    for defn_name in taxonomy_summary.get("names", []):
        source_tag = ""
        if defn_name in taxonomy_summary.get("llm_derived_names", []):
            source_tag = " _(auto-discovered)_"
        lines.append(f"- **{defn_name}**{source_tag}")

    if new_patterns > 0:
        lines.append(
            f"\n> 🧠 **{new_patterns} new pattern(s) were auto-discovered** during this "
            f"run and appended to `vuln_definitions.json` via the Defining Loop."
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


def run_audit_pipeline(
    input_csv: str | Path | None = None,
    sol_dir: str | Path | None = None,
    output_dir: str | Path = _DEFAULT_OUTPUT_DIR,
    taxonomy_file: str | Path = _DEFAULT_TAXONOMY_FILE,
    categories: list[str] | None = None,
    api_key: str = "",
    fetch_rate: float = 5.0,
    no_llm: bool = False,
    dry_run: bool = False,
    batch_tag: str = "",
) -> dict[str, Any]:
    """
    Run the full autonomous audit pipeline.

    Parameters
    ----------
    input_csv : str | Path | None
        CSV of addresses to fetch via Etherscan.  Mutually exclusive with
        ``sol_dir``.
    sol_dir : str | Path | None
        Directory of pre-fetched ``.sol`` files.  Used instead of fetching.
    output_dir : str | Path
        Where to write the JSON + Markdown reports.
    taxonomy_file : str | Path
        Path to ``vuln_definitions.json``.
    categories : list[str] | None
        Subset of taxonomy definition names to audit against.  None = all.
    api_key : str
        Etherscan API key (falls back to ETHERSCAN_API_KEY env var).
    fetch_rate : float
        Etherscan API rate (calls/sec).
    no_llm : bool
        Skip actual LLM calls (useful for pipeline validation).
    dry_run : bool
        Validate inputs and skip both API calls and LLM calls.
    batch_tag : str
        Optional label for the batch_fetcher output directory.

    Returns
    -------
    dict
        Pipeline summary with keys: started_at, completed_at,
        contracts_audited, total_findings, new_patterns_discovered,
        report_json, report_md, taxonomy_file.
    """
    from core.taxonomy_engine import VulnerabilityTaxonomy  # noqa: PLC0415

    started_at = _now_iso()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Ingest ────────────────────────────────────────────────────────
    contracts: list[dict[str, Any]] = []
    manifest_path: Path | None = None

    if sol_dir:
        sol_dir = Path(sol_dir)
        logger.info("Loading pre-fetched contracts from %s", sol_dir)
        contracts = _load_sol_files(sol_dir)
        # Look for a manifest.json in the same directory
        candidate_manifest = sol_dir / "manifest.json"
        if candidate_manifest.exists():
            manifest_path = candidate_manifest
    elif input_csv:
        if not dry_run:
            from data_pipeline.batch_fetcher import run_batch  # noqa: PLC0415

            logger.info("Fetching contracts via Etherscan batch fetcher…")
            fetch_summary = run_batch(
                input_csv=input_csv,
                api_key=api_key,
                rate=fetch_rate,
                dry_run=dry_run,
                batch_tag=batch_tag,
            )
            fetched_dir = Path(fetch_summary["output_dir"])
            contracts = _load_sol_files(fetched_dir)
            manifest_path = fetched_dir / "manifest.json"
            logger.info("Fetched %d contracts.", len(contracts))
        else:
            logger.info("Dry-run: skipping Etherscan fetch.")
    else:
        raise ValueError("Provide either --input (CSV) or --sol-dir (pre-fetched .sol files).")

    if manifest_path:
        contracts = _enrich_with_manifest(contracts, manifest_path)

    if not contracts:
        logger.warning("No contracts available to audit.")
        return {"started_at": started_at, "contracts_audited": 0}

    logger.info("Auditing %d contract(s).", len(contracts))

    # ── Step 2: Load taxonomy ─────────────────────────────────────────────────
    taxonomy = VulnerabilityTaxonomy(taxonomy_file=taxonomy_file)
    logger.info("Taxonomy loaded: %s", taxonomy.summary())

    definitions = taxonomy.all_definitions()
    if categories:
        definitions = [d for d in definitions if d.name in set(categories)]
        if not definitions:
            raise ValueError(
                f"None of the requested categories were found in the taxonomy.\n"
                f"Requested: {categories}\n"
                f"Available: {taxonomy.names()}"
            )
    logger.info(
        "Auditing against %d definition(s): %s",
        len(definitions), [d.name for d in definitions],
    )

    # ── Step 3: Iterate contracts × definitions ──────────────────────────────
    llm_client = _disabled_llm_client if (no_llm or dry_run) else None
    audit_results: list[dict[str, Any]] = []
    new_patterns_discovered = 0
    total_findings = 0

    for contract in contracts:
        contract_name = contract.get("contract_name", contract.get("filename", "unknown"))
        source_code = contract.get("source_code", "")
        logger.info("  Auditing contract: %s", contract_name)

        findings: list[dict[str, Any]] = []

        for defn in definitions:
            prompt = taxonomy.build_audit_prompt(
                definition=defn,
                source_code=source_code,
            )

            if no_llm or dry_run:
                verdict = {
                    "vulnerable": False,
                    "vuln_type": defn.name,
                    "reasoning": "Skipped (--no-llm / --dry-run).",
                    "evidence_lines": [],
                    "confidence": 0.0,
                    "definition_cited": defn.name,
                }
            else:
                verdict = _run_llm_audit(prompt, llm_client=llm_client)
                # Ensure definition_cited is set
                if not verdict.get("definition_cited"):
                    verdict["definition_cited"] = defn.name
                # Attach taxonomy severity for reporting
                verdict["severity"] = defn.severity

            findings.append(
                {
                    "definition_checked": defn.name,
                    **verdict,
                }
            )

            if verdict.get("vulnerable"):
                total_findings += 1

            # ── Step 3b: Cross-reference — Defining Loop ──────────────────────
            if not (no_llm or dry_run) and verdict.get("vulnerable"):
                if _is_new_pattern(verdict, taxonomy.names()):
                    logger.info(
                        "  → Potential novel pattern detected in '%s': %s",
                        contract_name, verdict.get("vuln_type"),
                    )
                    new_defn = taxonomy.expand_taxonomy_from_audit(
                        verdict=verdict,
                        contract_name=contract_name,
                        source_snippet=source_code[:3000],
                        llm_client=llm_client,
                    )
                    if new_defn is not None:
                        new_patterns_discovered += 1
                        verdict["taxonomy_expanded"] = new_defn.name

        audit_results.append(
            {
                "contract_name": contract_name,
                "filename": contract.get("filename", ""),
                "address": contract.get("address", ""),
                "label": contract.get("label", ""),
                "findings": findings,
                "audited_at": _now_iso(),
            }
        )

    # ── Step 4: Report ────────────────────────────────────────────────────────
    completed_at = _now_iso()
    tax_summary = taxonomy.summary()
    # Track LLM-derived names for the report
    tax_summary["llm_derived_names"] = [
        d.name
        for d in taxonomy.all_definitions()
        if d.source == "llm_derived"
    ]

    pipeline_meta = {
        "started_at": started_at,
        "completed_at": completed_at,
        "contracts_audited": len(contracts),
        "definitions_used": [d.name for d in definitions],
        "total_findings": total_findings,
        "new_patterns_discovered": new_patterns_discovered,
        "taxonomy_file": str(taxonomy._path),
    }

    full_report = {
        **pipeline_meta,
        "taxonomy_summary": tax_summary,
        "audit_results": audit_results,
    }

    # Write JSON report
    ts_safe = started_at.replace(":", "").replace("+", "").replace(".", "")[:17]
    report_json_path = output_dir / f"audit_report_{ts_safe}.json"
    report_md_path = output_dir / f"audit_report_{ts_safe}.md"

    report_json_path.write_text(
        json.dumps(full_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info("JSON report written to %s", report_json_path)

    # Write Markdown report
    md_content = _build_markdown_report(audit_results, tax_summary, pipeline_meta)
    report_md_path.write_text(md_content, encoding="utf-8")
    logger.info("Markdown report written to %s", report_md_path)

    return {
        **pipeline_meta,
        "report_json": str(report_json_path.resolve()),
        "report_md": str(report_md_path.resolve()),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_orchestrator",
        description=(
            "Research-Centric Autonomous Smart Contract Audit Orchestrator.\n\n"
            "Fetches contracts from Etherscan, audits each against the Taxonomy "
            "Engine's vulnerability definitions, triggers the Defining Loop when "
            "novel threats are found, and produces a structured report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--input",
        default=None,
        metavar="CSV",
        help="CSV file with an 'address' column (triggers Etherscan batch fetch).",
    )
    source_group.add_argument(
        "--sol-dir",
        default=None,
        metavar="DIR",
        help=(
            "Directory containing pre-fetched .sol files.  "
            "Skips the Etherscan fetch step."
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=str(_DEFAULT_OUTPUT_DIR),
        metavar="DIR",
        help="Directory to write JSON + Markdown audit reports.",
    )
    parser.add_argument(
        "--taxonomy-file",
        default=str(_DEFAULT_TAXONOMY_FILE),
        metavar="FILE",
        help="Path to vuln_definitions.json.",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        metavar="NAME",
        help=(
            "Subset of taxonomy definitions to audit against.  "
            "Default: all definitions.  "
            "Example: --categories Reentrancy 'Access Control Flaws'"
        ),
    )
    parser.add_argument(
        "--api-key",
        default="",
        metavar="KEY",
        help="Etherscan API key (overrides ETHERSCAN_API_KEY env var).",
    )
    parser.add_argument(
        "--fetch-rate",
        type=float,
        default=5.0,
        metavar="N",
        help="Etherscan API calls per second (free tier: 5).",
    )
    parser.add_argument(
        "--batch-tag",
        default="",
        metavar="TAG",
        help="Optional label for the batch_fetcher output directory.",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM calls (useful for pipeline validation / dry-run).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs, skip Etherscan fetch and LLM calls.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.input and not args.sol_dir:
        # Default to the example CSV if neither is supplied
        if _DEFAULT_INPUT_CSV.exists():
            args.input = str(_DEFAULT_INPUT_CSV)
            logger.info("No --input or --sol-dir provided; using %s", args.input)
        else:
            parser.error(
                "Please provide --input <csv> or --sol-dir <directory>.  "
                f"Default CSV not found at {_DEFAULT_INPUT_CSV}"
            )

    summary = run_audit_pipeline(
        input_csv=args.input,
        sol_dir=args.sol_dir,
        output_dir=args.output_dir,
        taxonomy_file=args.taxonomy_file,
        categories=args.categories,
        api_key=args.api_key,
        fetch_rate=args.fetch_rate,
        no_llm=args.no_llm,
        dry_run=args.dry_run,
        batch_tag=args.batch_tag,
    )

    print("\n=== Audit Orchestrator Summary ===")
    print(f"  Started               : {summary.get('started_at', '')}")
    print(f"  Completed             : {summary.get('completed_at', '')}")
    print(f"  Contracts audited     : {summary.get('contracts_audited', 0)}")
    print(f"  Total findings        : {summary.get('total_findings', 0)}")
    print(f"  New patterns found    : {summary.get('new_patterns_discovered', 0)}")
    if summary.get("report_json"):
        print(f"  JSON report           : {summary['report_json']}")
    if summary.get("report_md"):
        print(f"  Markdown report       : {summary['report_md']}")
    if summary.get("taxonomy_file"):
        print(f"  Taxonomy file         : {summary['taxonomy_file']}")


if __name__ == "__main__":
    main()
