"""
Phase 1 – Data Pipeline: Benchmark dataset downloader and normalizer.

Supports SmartBugs Curated, SolidiFI, and other benchmark datasets.
Downloads and normalizes into a unified contract record format.
"""

from __future__ import annotations
import os
import json
import logging
import hashlib
from typing import Optional

from config import DATA_BACKEND
from phase1_data_pipeline.supabase_store import fetch_contracts, is_supabase_enabled

logger = logging.getLogger(__name__)

BENCHMARKS_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'benchmarks')

# SWC category mappings for SmartBugs
SMARTBUGS_CATEGORY_MAP = {
    "reentrancy": "Reentrancy",
    "access_control": "Access Control",
    "arithmetic": "Integer Overflow/Underflow",
    "unchecked_low_level_calls": "Unchecked Return Value",
    "denial_of_service": "Denial of Service",
    "bad_randomness": "Unsafe Randomness",
    "front_running": "Front-Running",
    "time_manipulation": "Timestamp Dependence",
    "short_addresses": "Short Address Attack",
    "other": "Logic Error",
}


def _make_contract_record(
    contract_id: str,
    name: str,
    source_code: str,
    compiler_version: str,
    labels: list[dict],
    source: str,
    split: str = "test",
) -> dict:
    """Create a standardized contract record."""
    return {
        "id": contract_id,
        "name": name,
        "source_code": source_code,
        "compiler_version": compiler_version,
        "labels": labels,
        "source": source,
        "split": split,
    }


def normalize_labels(
    external_labels: list[dict],
    taxonomy_map: dict,
) -> list[dict]:
    """Map external label taxonomies to internal vulnerability type names."""
    normalized = []
    for label in external_labels:
        vuln_type = label.get("vuln_type", "")
        mapped_type = taxonomy_map.get(vuln_type.lower(), vuln_type)
        normalized.append({
            **label,
            "vuln_type": mapped_type,
        })
    return normalized


def split_dataset(
    contracts: list[dict],
    train: float = 0.7,
    val: float = 0.15,
    test: float = 0.15,
    seed: int = 42,
) -> list[dict]:
    """
    Stratified split of contracts into train/val/test sets.

    Preserves label distribution across splits.
    """
    import random
    random.seed(seed)

    labeled = [c for c in contracts if c.get("labels")]
    unlabeled = [c for c in contracts if not c.get("labels")]

    def _split_group(group):
        random.shuffle(group)
        n = len(group)
        n_train = int(n * train)
        n_val = int(n * val)
        for i, c in enumerate(group):
            if i < n_train:
                c["split"] = "train"
            elif i < n_train + n_val:
                c["split"] = "val"
            else:
                c["split"] = "test"
        return group

    _split_group(labeled)
    _split_group(unlabeled)

    return labeled + unlabeled


def download_smartbugs(output_dir: Optional[str] = None) -> list[dict]:
    """
    Download and parse the SmartBugs Curated dataset.

    Clones from GitHub if not already cached locally.

    Parameters
    ----------
    output_dir : str, optional
        Directory to cache downloaded data.

    Returns
    -------
    list[dict]
        List of standardized contract records.
    """
    if output_dir is None:
        output_dir = os.path.join(BENCHMARKS_DIR, 'smartbugs')

    os.makedirs(output_dir, exist_ok=True)

    cache_file = os.path.join(output_dir, 'contracts.json')
    if os.path.exists(cache_file):
        logger.info("Loading SmartBugs from cache: %s", cache_file)
        with open(cache_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    logger.info("SmartBugs dataset not found locally at %s", output_dir)
    logger.info(
        "To download: git clone https://github.com/smartbugs/smartbugs-curated.git %s",
        output_dir,
    )

    contracts = []
    dataset_dir = os.path.join(output_dir, 'dataset')
    if os.path.isdir(dataset_dir):
        for category in os.listdir(dataset_dir):
            category_dir = os.path.join(dataset_dir, category)
            if not os.path.isdir(category_dir):
                continue
            for filename in os.listdir(category_dir):
                if not filename.endswith('.sol'):
                    continue
                filepath = os.path.join(category_dir, filename)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code = f.read()

                vuln_type = SMARTBUGS_CATEGORY_MAP.get(category, category)
                contract_id = hashlib.sha256(source_code.encode()).hexdigest()[:12]
                contracts.append(_make_contract_record(
                    contract_id=f"sb_{contract_id}",
                    name=filename.replace('.sol', ''),
                    source_code=source_code,
                    compiler_version="unknown",
                    labels=[{
                        "vuln_type": vuln_type,
                        "swc_id": None,
                        "severity": "high",
                        "lines": [],
                        "function": None,
                        "description": f"SmartBugs {category} vulnerability",
                    }],
                    source="smartbugs",
                ))

        if contracts:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(contracts, f, indent=2)
            logger.info("Parsed %d SmartBugs contracts", len(contracts))

    return contracts


def download_solidifi(output_dir: Optional[str] = None) -> list[dict]:
    """
    Download and parse the SolidiFI injected-bug dataset.

    Parameters
    ----------
    output_dir : str, optional
        Directory to cache downloaded data.

    Returns
    -------
    list[dict]
        List of standardized contract records.
    """
    if output_dir is None:
        output_dir = os.path.join(BENCHMARKS_DIR, 'solidifi')

    os.makedirs(output_dir, exist_ok=True)

    cache_file = os.path.join(output_dir, 'contracts.json')
    if os.path.exists(cache_file):
        logger.info("Loading SolidiFI from cache: %s", cache_file)
        with open(cache_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    logger.info("SolidiFI dataset not found locally at %s", output_dir)
    logger.info("To download: https://github.com/smartbugs/SolidiFI-benchmark")

    return []


def load_benchmark(dataset: str = "smartbugs", prefer_supabase: bool = False) -> list[dict]:
    """
    Load a benchmark dataset by name.

    Parameters
    ----------
    dataset : str
        Dataset name: "smartbugs", "solidifi", "synthetic", or "all".

    Returns
    -------
    list[dict]
        List of contract records.
    """
    if (prefer_supabase or DATA_BACKEND == "supabase") and is_supabase_enabled():
        if dataset in {"smartbugs", "solidifi"}:
            shared = fetch_contracts(source=dataset)
            if shared:
                return shared
        if dataset == "all":
            shared_all = fetch_contracts()
            if shared_all:
                return shared_all

    if dataset == "smartbugs":
        return download_smartbugs()
    if dataset == "solidifi":
        return download_solidifi()
    if dataset == "all":
        return download_smartbugs() + download_solidifi()
    logger.warning("Unknown dataset: %s", dataset)
    return []
