"""
data_pipeline.dataset_builder
==============================
Downloads smart-contract vulnerability datasets from Hugging Face, filters
for logical vulnerability categories (Reentrancy, Access Control, and related
types), saves each contract as a ``.sol`` file under ``data/raw/``, and writes
a ``metadata.json`` index mapping every saved file to its known vulnerability.

Dataset used
------------
    mwritescode/slither-audited-smart-contracts  (default, config="all")
    https://huggingface.co/datasets/mwritescode/slither-audited-smart-contracts

    The dataset contains ~600 k on-chain contracts that have been audited by
    Slither. Each row holds:
      • ``address``     – checksummed Ethereum contract address
      • ``source_code`` – Solidity source (empty string for unverified contracts)
      • ``bytecode``    – deployed bytecode
      • ``slither``     – list of Slither detector IDs that fired on this contract
                         (stored as ClassLabel integers; converted to strings here)

Usage
-----
    # Download up to 500 reentrancy + access-control contracts (streaming):
    python -m data_pipeline.dataset_builder

    # Limit to 200 contracts, use a specific HF config, verbose output:
    python -m data_pipeline.dataset_builder --max-contracts 200 --config big-balanced

    # Include ALL logical-vuln categories (adds overflow, timestamp, tx-origin …):
    python -m data_pipeline.dataset_builder --all-logical

    # Custom output directory and metadata filename:
    python -m data_pipeline.dataset_builder --output-dir /tmp/my_contracts --metadata-file /tmp/meta.json

Requirements
------------
    pip install datasets>=2.14.0 pandas>=2.0.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger("dataset_builder")

# ---------------------------------------------------------------------------
# Default paths — relative to the project root (one level above this package)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_OUTPUT_DIR = _PROJECT_ROOT / "data" / "raw"
_DEFAULT_METADATA_FILE = _DEFAULT_OUTPUT_DIR / "metadata.json"

# ---------------------------------------------------------------------------
# Vulnerability category definitions
# ---------------------------------------------------------------------------

# Maps a human-readable vulnerability category name to the set of Slither
# detector IDs (strings) that indicate that category.  Detectors prefixed
# with "pess-" come from the Pessimistic Security plugin, which is included
# in the dataset alongside the standard Slither detectors.

VULN_CATEGORIES: dict[str, dict[str, Any]] = {
    "Reentrancy": {
        "description": (
            "External call before state update, allowing callee to re-enter "
            "and drain funds (SWC-107)."
        ),
        "swc_id": "SWC-107",
        "severity": "critical",
        "detectors": {
            "reentrancy-eth",           # Re-entrancy with ETH
            "reentrancy-no-eth",        # Re-entrancy without ETH transfer
            "reentrancy-events",        # Re-entrancy that emits an event
            "reentrancy-benign",        # Re-entrancy with no obvious harm (still a smell)
            "pess-reentrancy-events",   # Pessimistic plugin reentrancy variant
            "pess-inconsistent-nonreentrant",  # Missing nonReentrant guard
        },
    },
    "Access Control": {
        "description": (
            "Unrestricted access to privileged functions; any caller can invoke "
            "admin operations such as fund withdrawal or contract destruction "
            "(SWC-105)."
        ),
        "swc_id": "SWC-105",
        "severity": "high",
        "detectors": {
            "arbitrary-send",           # ETH can be sent to an arbitrary address
            "arbitrary-send-erc20",     # ERC-20 tokens can be moved arbitrarily
            "suicidal",                 # selfdestruct callable by anyone
            "unprotected-upgrade",      # UUPS upgrade without access check
            "pess-unprotected-upgrade", # Pessimistic plugin variant
            "controlled-delegatecall",  # delegatecall with user-controlled target
            "pess-arbitrary-send-erc20-permit",  # Permit-based arbitrary ERC-20 transfer
            "events-access",            # Missing event for access-control changes
        },
    },
    # ── Extended logical vulnerabilities (enabled via --all-logical) ──────
    "Integer Overflow/Underflow": {
        "description": "Arithmetic wrap-around in Solidity <0.8.0 (SWC-101).",
        "swc_id": "SWC-101",
        "severity": "high",
        "detectors": {
            "divide-before-multiply",   # Precision loss from division first
            "incorrect-shift",          # Bit-shift direction error
        },
    },
    "Unchecked Return Value": {
        "description": "Return value of low-level call is ignored (SWC-104).",
        "swc_id": "SWC-104",
        "severity": "medium",
        "detectors": {
            "unchecked-lowlevel",
            "unchecked-send",
            "unchecked-transfer",
            "unused-return",
        },
    },
    "Timestamp Dependence": {
        "description": "block.timestamp used for critical logic (SWC-116).",
        "swc_id": "SWC-116",
        "severity": "low",
        "detectors": {"timestamp"},
    },
    "Tx.Origin Authentication": {
        "description": "tx.origin used for access control (SWC-115).",
        "swc_id": "SWC-115",
        "severity": "high",
        "detectors": {"tx-origin"},
    },
    "Unsafe Randomness": {
        "description": "Weak on-chain randomness source (SWC-120).",
        "swc_id": "SWC-120",
        "severity": "high",
        "detectors": {"weak-prng"},
    },
    "Uninitialized Storage": {
        "description": "Uninitialized storage pointer (SWC-109).",
        "swc_id": "SWC-109",
        "severity": "high",
        "detectors": {"uninitialized-storage", "uninitialized-local"},
    },
}

# The two primary categories always included unless overridden
_DEFAULT_CATEGORIES = {"Reentrancy", "Access Control"}

# Build a fast reverse lookup: detector_id → category name
_DETECTOR_TO_CATEGORY: dict[str, str] = {
    det: cat
    for cat, info in VULN_CATEGORIES.items()
    for det in info["detectors"]
}

# ---------------------------------------------------------------------------
# Dataset schema helpers
# ---------------------------------------------------------------------------


def _resolve_slither_labels(
    raw_slither: list,
    feature,  # datasets.Sequence or datasets.ClassLabel feature object
) -> list[str]:
    """
    Convert the ``slither`` column value to a list of detector-name strings.

    The HuggingFace ClassLabel feature stores values as integers (indices
    into the names list).  This function handles both the integer-encoded
    form and the case where labels are already strings (some dataset
    configurations decode automatically).

    Parameters
    ----------
    raw_slither : list
        The raw value from dataset row["slither"].
    feature :
        The feature descriptor from dataset.features["slither"].

    Returns
    -------
    list[str]
        Detector name strings, e.g. ["reentrancy-eth", "arbitrary-send"].
    """
    if not raw_slither:
        return []

    # Detect whether the first element is already a string
    if raw_slither and isinstance(raw_slither[0], str):
        return [str(s) for s in raw_slither if s]

    # Integer-encoded ClassLabel — look up names from feature descriptor
    try:
        # datasets.Sequence wraps a ClassLabel; drill down to it
        inner = feature.feature if hasattr(feature, "feature") else feature
        names: list[str] = inner.names
        resolved = []
        for idx in raw_slither:
            if isinstance(idx, int) and 0 <= idx < len(names):
                resolved.append(names[idx])
        return resolved
    except (AttributeError, IndexError) as exc:
        logger.debug("Could not resolve ClassLabel indices: %s", exc)
        return [str(s) for s in raw_slither]


def _extract_detectors_from_results(results_raw: Any) -> list[str]:
    """Extract detector IDs from the fallback parquet ``results`` payload."""
    if not results_raw:
        return []

    payload = results_raw
    if isinstance(results_raw, str):
        try:
            payload = json.loads(results_raw)
        except json.JSONDecodeError:
            return []

    if not isinstance(payload, dict):
        return []

    detectors = ((payload.get("results") or {}).get("detectors")) or []
    names: list[str] = []
    for det in detectors:
        if isinstance(det, dict):
            name = det.get("check")
            if name:
                names.append(str(name))
        elif det:
            names.append(str(det))
    return names


def _load_streaming_dataset(dataset_name: str, config: str, split: str):
    """
    Load streaming dataset and transparently fall back to Parquet when dataset
    scripts are unsupported by the installed ``datasets`` version.
    """
    from datasets import load_dataset  # noqa: PLC0415

    try:
        dataset = load_dataset(
            dataset_name,
            config,
            split=split,
            streaming=True,
        )
        return dataset, dataset.features.get("slither")
    except RuntimeError as exc:
        msg = str(exc)
        if "Dataset scripts are no longer supported" not in msg:
            raise

        # This dataset exposes script-free parquet shards under data/raw.
        if dataset_name == "mwritescode/slither-audited-smart-contracts":
            if config != "all" or split != "train":
                raise RuntimeError(
                    "Current 'datasets' no longer supports the upstream loading "
                    "script for this dataset. Parquet fallback currently supports "
                    "only config='all' and split='train'."
                ) from exc

            parquet_glob = f"hf://datasets/{dataset_name}/data/raw/*.parquet"
            logger.warning(
                "Dataset script unsupported by local 'datasets'; falling back "
                "to Parquet shards: %s",
                parquet_glob,
            )
            dataset = load_dataset(
                "parquet",
                data_files=parquet_glob,
                split="train",
                streaming=True,
            )
            return dataset, None

        raise


def _safe_filename(address: str, index: int) -> str:
    """
    Produce a safe, unique filename stem for a contract.

    Uses the Ethereum address (stripping the ``0x`` prefix) as the primary
    identifier so the filename is stable and human-readable.  Falls back to
    a sequential index if the address is empty or malformed.
    """
    addr = re.sub(r"[^0-9a-fA-F]", "", address.removeprefix("0x"))
    if addr:
        return f"contract_{addr[:20]}"
    return f"contract_{index:06d}"


def _contract_id(address: str, source_code: str) -> str:
    """Return a 12-char hex fingerprint for deduplication."""
    raw = (address + source_code[:256]).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Core download + filter pipeline
# ---------------------------------------------------------------------------


def iter_filtered_contracts(
    dataset_name: str = "mwritescode/slither-audited-smart-contracts",
    config: str = "all",
    split: str = "train",
    target_categories: set[str] | None = None,
    max_contracts: int = 500,
) -> Iterator[dict[str, Any]]:
    """
    Stream and filter contracts from Hugging Face matching the target categories.

    Uses ``streaming=True`` so the full dataset (600 k+ rows) is never
    downloaded to disk.  Only rows that pass the filter are yielded.

    Parameters
    ----------
    dataset_name : str
        Hugging Face dataset identifier.
    config : str
        Dataset configuration/subset name (e.g. ``"all"``, ``"big-balanced"``).
    split : str
        Dataset split to stream (e.g. ``"train"``).  The ``"all"`` config
        only has a ``"train"`` split; balanced configs add ``"validation"``
        and ``"test"``.
    target_categories : set[str] | None
        Vulnerability category names to keep.  ``None`` defaults to
        ``{"Reentrancy", "Access Control"}``.
    max_contracts : int
        Stop after yielding this many matching contracts (avoids very long
        runs on large configs).

    Yields
    ------
    dict
        {
            "address"          : str,
            "source_code"      : str,
            "slither_detectors": list[str],   resolved detector names
            "vuln_categories"  : list[str],   matched category names
            "split"            : str,
        }
    """
    try:
        from datasets import load_dataset  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "The 'datasets' library is required.\n"
            "Install with:  pip install 'datasets>=2.14.0'"
        ) from exc

    if target_categories is None:
        target_categories = _DEFAULT_CATEGORIES

    # Build the set of all detector IDs we care about for fast lookup
    wanted_detectors: set[str] = set()
    for cat in target_categories:
        info = VULN_CATEGORIES.get(cat)
        if info:
            wanted_detectors.update(info["detectors"])

    if not wanted_detectors:
        raise ValueError(
            f"No detector IDs found for categories: {target_categories}. "
            f"Available categories: {list(VULN_CATEGORIES)}"
        )

    logger.info(
        "Loading dataset '%s' (config=%s, split=%s) in streaming mode…",
        dataset_name, config, split,
    )
    logger.info(
        "Filtering for %d target categories: %s",
        len(target_categories), sorted(target_categories),
    )
    logger.info("Watching for %d Slither detectors.", len(wanted_detectors))

    dataset, slither_feature = _load_streaming_dataset(
        dataset_name=dataset_name,
        config=config,
        split=split,
    )

    yielded = 0
    examined = 0

    for row in dataset:
        examined += 1

        # Skip unverified contracts (no Solidity source available)
        src = (row.get("source_code") or "").strip()
        if not src:
            continue

        # Resolve detector integers → strings for the original schema, or parse
        # detector results from parquet fallback rows.
        if "slither" in row:
            detectors = _resolve_slither_labels(
                row.get("slither") or [],
                slither_feature,
            )
        else:
            detectors = _extract_detectors_from_results(row.get("results"))

        # Check if any fired detector belongs to a wanted category
        matched_categories: list[str] = []
        matched_detectors: list[str] = []
        for det in detectors:
            cat = _DETECTOR_TO_CATEGORY.get(det)
            if cat and cat in target_categories:
                if cat not in matched_categories:
                    matched_categories.append(cat)
                matched_detectors.append(det)

        if not matched_categories:
            continue

        yield {
            "address": str(row.get("address") or row.get("contracts") or ""),
            "source_code": src,
            "slither_detectors": detectors,          # ALL detectors that fired
            "matched_detectors": matched_detectors,  # Only the ones in target cats
            "vuln_categories": matched_categories,
            "split": split,
        }

        yielded += 1
        if yielded >= max_contracts:
            logger.info(
                "Reached --max-contracts limit (%d). Examined %d rows total.",
                max_contracts, examined,
            )
            return

    logger.info(
        "Stream exhausted after examining %d rows; yielded %d matching contracts.",
        examined, yielded,
    )


# ---------------------------------------------------------------------------
# Save contracts to disk
# ---------------------------------------------------------------------------


def save_contracts(
    contracts_iter: Iterator[dict[str, Any]],
    output_dir: str | Path,
    metadata_file: str | Path,
) -> dict[str, Any]:
    """
    Save filtered contracts to ``output_dir`` as ``.sol`` files and write
    a ``metadata.json`` index.

    Parameters
    ----------
    contracts_iter : Iterator[dict]
        Output of :func:`iter_filtered_contracts`.
    output_dir : str | Path
        Directory to write ``.sol`` files into.
    metadata_file : str | Path
        Path to write the JSON metadata index.

    Returns
    -------
    dict
        Summary statistics:
        {
            "total_saved"      : int,
            "skipped_duplicate": int,
            "by_category"      : {category: count},
            "output_dir"       : str,
            "metadata_file"    : str,
        }
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_file = Path(metadata_file)
    metadata_file.parent.mkdir(parents=True, exist_ok=True)

    # Load existing metadata to support resuming interrupted runs
    existing_records: list[dict] = []
    seen_ids: set[str] = set()
    if metadata_file.exists():
        try:
            with metadata_file.open("r", encoding="utf-8") as fh:
                existing_meta = json.load(fh)
            existing_records = existing_meta.get("contracts", [])
            seen_ids = {r["id"] for r in existing_records if "id" in r}
            logger.info(
                "Resuming: found %d existing records in %s",
                len(existing_records), metadata_file,
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Could not load existing metadata (%s); starting fresh.", exc)

    records: list[dict] = list(existing_records)
    skipped_dup = 0
    by_category: dict[str, int] = {}
    new_saved = 0

    for idx, contract in enumerate(contracts_iter):
        contract_id = _contract_id(contract["address"], contract["source_code"])

        # Skip duplicates (same address + source already on disk)
        if contract_id in seen_ids:
            skipped_dup += 1
            continue
        seen_ids.add(contract_id)

        # Choose a stable filename
        filename_stem = _safe_filename(contract["address"], idx)
        sol_path = output_dir / f"{filename_stem}.sol"

        # Avoid collisions when two different addresses produce the same stem
        collision_idx = 0
        while sol_path.exists():
            collision_idx += 1
            sol_path = output_dir / f"{filename_stem}_{collision_idx}.sol"

        # Write the .sol file
        sol_path.write_text(contract["source_code"], encoding="utf-8")

        # Build the metadata record
        record = {
            "id": contract_id,
            "filename": sol_path.name,
            "address": contract["address"],
            "vuln_types": contract["vuln_categories"],
            "slither_detectors_matched": contract["matched_detectors"],
            "slither_detectors_all": contract["slither_detectors"],
            "source_dataset": "mwritescode/slither-audited-smart-contracts",
            "split": contract["split"],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        records.append(record)

        # Update category counters
        for cat in contract["vuln_categories"]:
            by_category[cat] = by_category.get(cat, 0) + 1

        new_saved += 1

        if new_saved % 50 == 0:
            _flush_metadata(records, metadata_file, by_category)
            logger.info("  … saved %d contracts so far", new_saved)

    # Final metadata write
    _flush_metadata(records, metadata_file, by_category)

    total_saved = new_saved + len(existing_records)
    return {
        "total_saved": total_saved,
        "new_this_run": new_saved,
        "skipped_duplicate": skipped_dup,
        "by_category": by_category,
        "output_dir": str(output_dir.resolve()),
        "metadata_file": str(metadata_file.resolve()),
    }


def _flush_metadata(
    records: list[dict],
    metadata_file: Path,
    by_category: dict[str, int],
) -> None:
    """Atomically write metadata.json using a temp file."""
    tmp_path = metadata_file.with_suffix(".tmp")
    payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_contracts": len(records),
        "by_category": by_category,
        "contracts": records,
    }
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    tmp_path.replace(metadata_file)


# ---------------------------------------------------------------------------
# Pandas summary helpers
# ---------------------------------------------------------------------------


def build_summary_dataframe(metadata_file: str | Path) -> pd.DataFrame:
    """
    Load ``metadata.json`` and return a pandas DataFrame for analysis.

    Each row in the DataFrame represents one saved contract, with columns:
        id, filename, address, vuln_types (joined), slither_detectors_matched,
        source_dataset, split, saved_at.

    Parameters
    ----------
    metadata_file : str | Path
        Path to ``metadata.json`` produced by :func:`save_contracts`.

    Returns
    -------
    pd.DataFrame
    """
    with Path(metadata_file).open("r", encoding="utf-8") as fh:
        meta = json.load(fh)

    rows = []
    for record in meta.get("contracts", []):
        rows.append(
            {
                "id": record.get("id", ""),
                "filename": record.get("filename", ""),
                "address": record.get("address", ""),
                "vuln_types": ", ".join(record.get("vuln_types", [])),
                "slither_detectors_matched": ", ".join(
                    record.get("slither_detectors_matched", [])
                ),
                "source_dataset": record.get("source_dataset", ""),
                "split": record.get("split", ""),
                "saved_at": record.get("saved_at", ""),
            }
        )

    df = pd.DataFrame(rows)
    return df


def print_summary(stats: dict[str, Any]) -> None:
    """Print a human-readable download summary to stdout."""
    print("\n" + "=" * 60)
    print("  Dataset Builder — Download Summary")
    print("=" * 60)
    print(f"  Total contracts saved : {stats['total_saved']}")
    print(f"  New this run          : {stats.get('new_this_run', '?')}")
    print(f"  Skipped (duplicate)   : {stats['skipped_duplicate']}")
    print(f"\n  Breakdown by vulnerability category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"    {cat:<30} {count:>5}")
    print(f"\n  Output directory  : {stats['output_dir']}")
    print(f"  Metadata file     : {stats['metadata_file']}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------


def build_dataset(
    dataset_name: str = "mwritescode/slither-audited-smart-contracts",
    config: str = "all",
    split: str = "train",
    target_categories: set[str] | None = None,
    max_contracts: int = 500,
    output_dir: str | Path = _DEFAULT_OUTPUT_DIR,
    metadata_file: str | Path = _DEFAULT_METADATA_FILE,
    all_logical: bool = False,
) -> dict[str, Any]:
    """
    Run the full download → filter → save pipeline.

    Parameters
    ----------
    dataset_name : str
        Hugging Face dataset identifier.
    config : str
        Dataset configuration/subset.
    split : str
        Dataset split to stream.
    target_categories : set[str] | None
        Vulnerability categories to collect.  ``None`` → Reentrancy +
        Access Control.  Pass a set of names from :data:`VULN_CATEGORIES`.
    max_contracts : int
        Maximum number of contracts to download in a single run.
    output_dir : str | Path
        Destination for ``.sol`` files.
    metadata_file : str | Path
        Destination for ``metadata.json``.
    all_logical : bool
        If True, extend target_categories with ALL categories defined in
        :data:`VULN_CATEGORIES` (not just the default two).

    Returns
    -------
    dict
        Summary statistics from :func:`save_contracts`.
    """
    if target_categories is None:
        if all_logical:
            target_categories = set(VULN_CATEGORIES.keys())
            logger.info(
                "--all-logical enabled: collecting all %d categories.",
                len(target_categories),
            )
        else:
            target_categories = set(_DEFAULT_CATEGORIES)

    contracts_iter = iter_filtered_contracts(
        dataset_name=dataset_name,
        config=config,
        split=split,
        target_categories=target_categories,
        max_contracts=max_contracts,
    )

    stats = save_contracts(
        contracts_iter=contracts_iter,
        output_dir=output_dir,
        metadata_file=metadata_file,
    )

    return stats


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dataset_builder",
        description=(
            "Download smart-contract vulnerability data from Hugging Face and "
            "save .sol files + metadata.json to data/raw/."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        default="mwritescode/slither-audited-smart-contracts",
        metavar="HF_DATASET_ID",
        help="Hugging Face dataset identifier.",
    )
    parser.add_argument(
        "--config",
        default="all",
        choices=["all", "big-balanced", "small-balanced", "all-balanced"],
        help=(
            "Dataset configuration. 'all' streams every contract (~600 k rows); "
            "balanced configs are smaller and pre-split into train/val/test."
        ),
    )
    parser.add_argument(
        "--split",
        default="train",
        help="Dataset split to stream (e.g. 'train', 'validation', 'test').",
    )
    parser.add_argument(
        "--max-contracts",
        type=int,
        default=500,
        metavar="N",
        help=(
            "Stop after collecting N matching contracts. "
            "Set to 0 to collect all matches (may take a very long time for "
            "the 'all' config)."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=str(_DEFAULT_OUTPUT_DIR),
        metavar="DIR",
        help="Directory to write .sol files into.",
    )
    parser.add_argument(
        "--metadata-file",
        default=str(_DEFAULT_METADATA_FILE),
        metavar="FILE",
        help="Path to write (or resume) the metadata.json index.",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        metavar="CATEGORY",
        help=(
            "Vulnerability categories to collect. Defaults to 'Reentrancy' and "
            "'Access Control'. "
            "Available: " + ", ".join(f"'{k}'" for k in VULN_CATEGORIES)
        ),
    )
    parser.add_argument(
        "--all-logical",
        action="store_true",
        help=(
            "Collect ALL logical vulnerability categories defined in "
            "VULN_CATEGORIES (overrides --categories)."
        ),
    )
    parser.add_argument(
        "--summary-csv",
        default=None,
        metavar="FILE",
        help="If provided, also export a CSV summary of the saved contracts.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate categories
    target_categories: set[str] | None = None
    if args.categories:
        invalid = [c for c in args.categories if c not in VULN_CATEGORIES]
        if invalid:
            parser.error(
                f"Unknown category name(s): {invalid}. "
                f"Available: {list(VULN_CATEGORIES)}"
            )
        target_categories = set(args.categories)

    max_contracts = args.max_contracts if args.max_contracts > 0 else 10_000_000

    logger.info("=== Smart Contract Dataset Builder ===")
    logger.info("Dataset   : %s (%s / %s)", args.dataset, args.config, args.split)
    logger.info("Output dir: %s", args.output_dir)
    logger.info("Max contracts: %d", max_contracts)

    stats = build_dataset(
        dataset_name=args.dataset,
        config=args.config,
        split=args.split,
        target_categories=target_categories,
        max_contracts=max_contracts,
        output_dir=args.output_dir,
        metadata_file=args.metadata_file,
        all_logical=args.all_logical,
    )

    print_summary(stats)

    if args.summary_csv:
        try:
            df = build_summary_dataframe(args.metadata_file)
            df.to_csv(args.summary_csv, index=False, encoding="utf-8")
            logger.info("CSV summary written to %s (%d rows)", args.summary_csv, len(df))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not write CSV summary: %s", exc)


if __name__ == "__main__":
    main()
