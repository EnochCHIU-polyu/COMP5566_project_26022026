"""
Phase 2 – LLM Engine: Keyword-based relevance pre-filter.

Fast static analysis to select which vulnerability types are relevant
for a given contract, reducing API calls by 60-80%.
"""

from __future__ import annotations
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _extract_pragma_version(source_code: str) -> Optional[str]:
    """Extract the Solidity compiler version from pragma statement."""
    m = re.search(r'pragma\s+solidity\s+[\^>=<~]*(\d+\.\d+)', source_code)
    return m.group(1) if m else None


def _is_old_solidity(source_code: str) -> bool:
    """Return True if the contract uses Solidity < 0.8.0."""
    version = _extract_pragma_version(source_code)
    if not version:
        return False
    try:
        major, minor = version.split(".")[:2]
        return int(major) == 0 and int(minor) < 8
    except (ValueError, IndexError):
        return False


def filter_relevant_vulns(
    source_code: str,
    vuln_types: list[dict],
    no_filter: bool = False,
) -> list[dict]:
    """
    Return only vulnerability types with keyword matches in the contract.

    Parameters
    ----------
    source_code : str
        Solidity contract source code.
    vuln_types : list[dict]
        List of vulnerability type dicts (from vulnerability_types.py).
    no_filter : bool
        If True, return all vulnerability types without filtering.

    Returns
    -------
    list[dict]
        Filtered list of relevant vulnerability types.
    """
    if no_filter:
        return vuln_types

    relevant = []
    skipped = 0
    source_lower = source_code.lower()
    is_old = _is_old_solidity(source_code)

    for vuln in vuln_types:
        keywords = vuln.get("detection_keywords", [])
        if not keywords:
            # No keywords defined → include by default
            relevant.append(vuln)
            continue

        # Special case: Integer Overflow/Underflow only relevant for old Solidity
        if vuln["name"] == "Integer Overflow/Underflow" and not is_old:
            skipped += 1
            continue

        matched = any(kw.lower() in source_lower for kw in keywords)
        if matched:
            relevant.append(vuln)
        else:
            skipped += 1

    logger.info(
        "Relevance filter: %d/%d vuln types selected (%d skipped)",
        len(relevant), len(vuln_types), skipped,
    )
    return relevant
