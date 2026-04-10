from __future__ import annotations

from typing import Any

SWE_FIELD_LABELS: dict[int, str] = {
    1: "Reentrancy",
    2: "Arithmetic error",
    3: "Time dependency",
    4: "Transaction dependency",
    5: "Unchecked external call",
    6: "Input validation",
    7: "Missing return value",
    8: "Access control",
    9: "Ether/Token locking",
    10: "Token standard violation",
    11: "Denial of Service (DoS)",
    12: "Strict conditions",
    13: "Signature weakness",
    14: "Missing reminders",
    15: "Extra gas consumption",
    16: "Hardcoded gas limit",
    17: "Outdated compiler version",
    18: "Floating pragma",
    19: "Uninitialized data structures",
    20: "Incorrect inheritance order",
    21: "Typographical error",
    22: "Right-to-left-override",
    23: "Code with no effects",
    24: "Shadowed elements",
}

# Keyed by normalized vulnerability label.
SWE_WEAKNESS_MAP: dict[str, tuple[int, str]] = {
    "reentrancy": (1, "Reentrancy"),
    "cross-function reentrancy": (1, "Reentrancy"),
    "read-only reentrancy": (1, "Reentrancy"),
    "integer overflow/underflow": (2, "Integer Overflow"),
    "unsafe type conversion": (2, "Unsafe Type Conversion"),
    "timestamp dependence": (3, "Timestamp Dependency"),
    "block number dependence": (3, "Block Number Dependency"),
    "unsafe randomness": (3, "Random Value Dependency"),
    "front-running": (4, "Transaction Dependency"),
    "tx.origin authentication": (4, "Transaction Dependency"),
    "unchecked return value": (5, "Unchecked External Call"),
    "improper input validation": (6, "Input Validation"),
    "missing return value": (7, "Missing Return Value"),
    "access control": (8, "Access Control"),
    "unprotected self-destruct": (8, "Unsafe Self-destruct"),
    "frozen ether": (9, "Ether/Token Locking"),
    "token standard violation": (10, "Token Standard Violation"),
    "erc-20 approval exploit": (10, "Token Standard Violation"),
    "denial of service": (11, "DoS with Failed Call"),
    "denial of service via revert": (11, "DoS with Failed Call"),
    "insufficient gas stipend": (11, "DoS with Gas Limit"),
    "strict conditions": (12, "Strict require()"),
    "signature malleability": (13, "Signature Malleability"),
    "lack of signature verification": (13, "Lack of Signature Verification"),
    "signature replay": (13, "Lack of Signature Verification"),
    "unencrypted private data": (13, "Unencrypted Private Data"),
    "missing reminders": (14, "Missing Reminders"),
    "extra gas consumption": (15, "High Gas Consumption Functions"),
    "hardcoded gas limit": (16, "Hardcoded Gas Limit"),
    "outdated compiler version": (17, "Outdated Compiler Version"),
    "floating pragma": (18, "Floating Pragma"),
    "uninitialized storage pointer": (19, "Uninitialized Storage Pointer"),
    "uninitialized variables": (19, "Uninitialized Variables"),
    "incorrect inheritance": (20, "Incorrect Inheritance Order"),
    "typographical error": (21, "Typographical Error"),
    "right-to-left-override": (22, "Right-To-Left-Override"),
    "code with no effects": (23, "Code with No Effects"),
    "shadowed elements": (24, "Shadowed Elements"),
}


def resolve_swe_label(label: str) -> dict[str, Any]:
    normalized = str(label).strip().lower()
    match = SWE_WEAKNESS_MAP.get(normalized)
    if not match:
        return {
            "label": label,
            "covered": False,
            "swe_field_id": None,
            "swe_field": "Unmapped",
            "swe_weakness": "Unmapped",
        }

    field_id, weakness = match
    return {
        "label": label,
        "covered": True,
        "swe_field_id": field_id,
        "swe_field": SWE_FIELD_LABELS.get(field_id, "Unknown"),
        "swe_weakness": weakness,
    }


def build_swe_mapping_rows(labels: list[str]) -> list[dict[str, Any]]:
    return [resolve_swe_label(label) for label in sorted(set(labels))]
