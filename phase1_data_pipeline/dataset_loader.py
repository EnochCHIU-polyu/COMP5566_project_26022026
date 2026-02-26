"""
Phase 1 – Data Pipeline: Dataset loader.

Manages the curated dataset of known-vulnerable DeFi smart contracts
and the mutation-testing dataset of synthetic contracts.
"""

import os
import json
from typing import Optional
from config import VULNERABLE_CONTRACTS_DIR, SYNTHETIC_CONTRACTS_DIR


def load_contracts_from_dir(directory: str) -> list[dict]:
    """
    Load all .sol or .json contract files from *directory*.

    Each returned dict has keys:
        - ``name``        : file stem
        - ``source_code`` : raw source string (Solidity)
        - ``labels``      : list of known vulnerability labels (may be empty)

    Parameters
    ----------
    directory : str
        Path to the directory containing contract files.

    Returns
    -------
    list[dict]
    """
    contracts = []
    if not os.path.isdir(directory):
        return contracts

    for filename in sorted(os.listdir(directory)):
        filepath = os.path.join(directory, filename)
        if not os.path.isfile(filepath):
            continue

        if filename.endswith(".sol"):
            with open(filepath, "r", encoding="utf-8") as fh:
                source = fh.read()
            contracts.append(
                {
                    "name": os.path.splitext(filename)[0],
                    "source_code": source,
                    "labels": [],
                }
            )

        elif filename.endswith(".json"):
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            contracts.append(
                {
                    "name": data.get("name", os.path.splitext(filename)[0]),
                    "source_code": data.get("source_code", ""),
                    "labels": data.get("labels", []),
                }
            )

    return contracts


def load_vulnerable_contracts() -> list[dict]:
    """Load the curated dataset of 52 known-vulnerable DeFi contracts."""
    return load_contracts_from_dir(VULNERABLE_CONTRACTS_DIR)


def load_synthetic_contracts() -> list[dict]:
    """Load the mutation-testing dataset of synthetic contracts."""
    return load_contracts_from_dir(SYNTHETIC_CONTRACTS_DIR)
