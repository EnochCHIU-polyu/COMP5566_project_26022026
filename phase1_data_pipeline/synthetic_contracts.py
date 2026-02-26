"""
Phase 1 – Data Pipeline: Synthetic contract generator.

Creates 5 ostensibly secure Solidity contracts and injects a configurable
number of vulnerabilities (2 or 15) to test the framework against unknown flaws.
"""

import os
import json
from config import SYNTHETIC_CONTRACTS_DIR

# ---------------------------------------------------------------------------
# Base secure contract templates
# ---------------------------------------------------------------------------

_SECURE_TEMPLATES: list[dict] = [
    {
        "name": "SecureVault",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureVault – holds ETH for an owner.
contract SecureVault {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= balance, "Insufficient balance");
        balance -= amount;
        (bool ok, ) = owner.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
""",
        "labels": [],
    },
    {
        "name": "SecureToken",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureToken – minimal ERC-20-like token.
contract SecureToken {
    string public name = "SecureToken";
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
""",
        "labels": [],
    },
    {
        "name": "SecureStaking",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureStaking – simple staking contract.
contract SecureStaking {
    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public stakeTimestamp;

    function stake() external payable {
        require(msg.value > 0, "Must stake positive amount");
        stakedAmount[msg.sender] += msg.value;
        stakeTimestamp[msg.sender] = block.timestamp;
    }

    function unstake() external {
        uint256 amount = stakedAmount[msg.sender];
        require(amount > 0, "Nothing staked");
        stakedAmount[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
""",
        "labels": [],
    },
    {
        "name": "SecureMultiSig",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureMultiSig – 2-of-3 multisig wallet.
contract SecureMultiSig {
    address[3] public owners;
    mapping(bytes32 => uint8) public approvals;

    constructor(address[3] memory _owners) {
        owners = _owners;
    }

    function isOwner(address addr) public view returns (bool) {
        for (uint256 i = 0; i < 3; i++) {
            if (owners[i] == addr) return true;
        }
        return false;
    }

    function approve(bytes32 txHash) external {
        require(isOwner(msg.sender), "Not owner");
        approvals[txHash] += 1;
    }

    function execute(bytes32 txHash, address payable to, uint256 value) external {
        require(approvals[txHash] >= 2, "Not enough approvals");
        approvals[txHash] = 0;
        (bool ok, ) = to.call{value: value}("");
        require(ok, "Transfer failed");
    }
}
""",
        "labels": [],
    },
    {
        "name": "SecureLending",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureLending – basic collateralised lending.
contract SecureLending {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 2, "Insufficient collateral");
        debt[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function repay() external payable {
        require(debt[msg.sender] >= msg.value, "Overpayment");
        debt[msg.sender] -= msg.value;
    }
}
""",
        "labels": [],
    },
]

# ---------------------------------------------------------------------------
# Vulnerability injection patches
# ---------------------------------------------------------------------------

# Each patch is a dict with:
#   "vuln_name"  : label describing the vulnerability
#   "target"     : which contract template name this patch applies to
#   "find"       : exact substring to replace
#   "replace"    : replacement substring that introduces the vulnerability

_VULN_PATCHES: list[dict] = [
    # ── 2-vuln set ──────────────────────────────────────────────────────────
    {
        "id": 1,
        "vuln_name": "Reentrancy",
        "target": "SecureVault",
        "find": (
            "        require(amount <= balance, \"Insufficient balance\");\n"
            "        balance -= amount;\n"
            "        (bool ok, ) = owner.call{value: amount}(\"\");\n"
            "        require(ok, \"Transfer failed\");"
        ),
        "replace": (
            "        require(amount <= balance, \"Insufficient balance\");\n"
            "        // BUG: state update after external call → reentrancy\n"
            "        (bool ok, ) = owner.call{value: amount}(\"\");\n"
            "        require(ok, \"Transfer failed\");\n"
            "        balance -= amount;"
        ),
    },
    {
        "id": 2,
        "vuln_name": "Integer Overflow",
        "target": "SecureToken",
        "find": "pragma solidity ^0.8.0;",
        "replace": "pragma solidity ^0.7.0;  // BUG: <0.8 has no built-in overflow checks",
    },
    # ── Additional vulns to reach 15 ────────────────────────────────────────
    {
        "id": 3,
        "vuln_name": "Unchecked Return Value",
        "target": "SecureStaking",
        "find": (
            "        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "        require(ok, \"Transfer failed\");"
        ),
        "replace": (
            "        // BUG: return value of .call not checked\n"
            "        msg.sender.call{value: amount}(\"\");"
        ),
    },
    {
        "id": 4,
        "vuln_name": "Access Control Missing",
        "target": "SecureMultiSig",
        "find": (
            "    function execute(bytes32 txHash, address payable to, uint256 value) external {\n"
            "        require(approvals[txHash] >= 2, \"Not enough approvals\");"
        ),
        "replace": (
            "    // BUG: no owner check – anyone can call execute\n"
            "    function execute(bytes32 txHash, address payable to, uint256 value) external {\n"
            "        require(approvals[txHash] >= 1, \"Not enough approvals\");"
        ),
    },
    {
        "id": 5,
        "vuln_name": "Reentrancy in Lending",
        "target": "SecureLending",
        "find": (
            "        debt[msg.sender] += amount;\n"
            "        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "        require(ok, \"Transfer failed\");"
        ),
        "replace": (
            "        // BUG: external call before state update → reentrancy\n"
            "        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "        require(ok, \"Transfer failed\");\n"
            "        debt[msg.sender] += amount;"
        ),
    },
    {
        "id": 6,
        "vuln_name": "Timestamp Dependence",
        "target": "SecureStaking",
        "find": "        stakeTimestamp[msg.sender] = block.timestamp;",
        "replace": (
            "        // BUG: block.timestamp can be manipulated by miners\n"
            "        stakeTimestamp[msg.sender] = block.timestamp;\n"
            "        require(block.timestamp % 2 == 0, \"Only even blocks\");"
        ),
    },
    {
        "id": 7,
        "vuln_name": "Tx.Origin Authentication",
        "target": "SecureVault",
        "find": '        require(msg.sender == owner, "Not owner");',
        "replace": '        require(tx.origin == owner, "Not owner");  // BUG: use tx.origin',
    },
    {
        "id": 8,
        "vuln_name": "Unprotected Self-Destruct",
        "target": "SecureVault",
        "find": "    function deposit() external payable {",
        "replace": (
            "    // BUG: anyone can destroy this contract\n"
            "    function kill() external {\n"
            "        selfdestruct(payable(msg.sender));\n"
            "    }\n\n"
            "    function deposit() external payable {"
        ),
    },
    {
        "id": 9,
        "vuln_name": "Denial of Service via Gas Limit",
        "target": "SecureMultiSig",
        "find": (
            "    function isOwner(address addr) public view returns (bool) {\n"
            "        for (uint256 i = 0; i < 3; i++) {"
        ),
        "replace": (
            "    // BUG: unbounded loop can cause out-of-gas DoS\n"
            "    address[] public dynamicOwners;\n\n"
            "    function isOwner(address addr) public view returns (bool) {\n"
            "        for (uint256 i = 0; i < dynamicOwners.length; i++) {"
        ),
    },
    {
        "id": 10,
        "vuln_name": "Front-Running",
        "target": "SecureToken",
        "find": "    function transfer(address to, uint256 amount) external returns (bool) {",
        "replace": (
            "    // BUG: no slippage protection → susceptible to front-running\n"
            "    function transfer(address to, uint256 amount) external returns (bool) {"
        ),
    },
    {
        "id": 11,
        "vuln_name": "Delegate Call to Untrusted Contract",
        "target": "SecureMultiSig",
        "find": (
            "        (bool ok, ) = to.call{value: value}(\"\");\n"
            "        require(ok, \"Transfer failed\");"
        ),
        "replace": (
            "        // BUG: delegatecall forwards execution context\n"
            "        (bool ok, ) = to.delegatecall(abi.encodeWithSignature(\"execute()\"));\n"
            "        require(ok, \"Transfer failed\");"
        ),
    },
    {
        "id": 12,
        "vuln_name": "Flash Loan Price Manipulation",
        "target": "SecureLending",
        "find": "        require(collateral[msg.sender] >= amount * 2, \"Insufficient collateral\");",
        "replace": (
            "        // BUG: price oracle can be manipulated via flash loan\n"
            "        uint256 price = getSpotPrice();\n"
            "        require(collateral[msg.sender] * price >= amount * 2, \"Insufficient collateral\");"
        ),
    },
    {
        "id": 13,
        "vuln_name": "Signature Replay Attack",
        "target": "SecureMultiSig",
        "find": "    function approve(bytes32 txHash) external {",
        "replace": (
            "    // BUG: no nonce → same signature can be replayed\n"
            "    function approve(bytes32 txHash) external {"
        ),
    },
    {
        "id": 14,
        "vuln_name": "Uninitialized Storage Pointer",
        "target": "SecureVault",
        "find": "    function deposit() external payable {\n        balance += msg.value;\n    }",
        "replace": (
            "    struct Config { uint256 fee; address recipient; }\n\n"
            "    function deposit() external payable {\n"
            "        Config storage cfg;  // BUG: uninitialized storage pointer\n"
            "        balance += msg.value - cfg.fee;\n"
            "    }"
        ),
    },
    {
        "id": 15,
        "vuln_name": "Arithmetic Precision Loss",
        "target": "SecureLending",
        "find": (
            "    function repay() external payable {\n"
            "        require(debt[msg.sender] >= msg.value, \"Overpayment\");\n"
            "        debt[msg.sender] -= msg.value;\n"
            "    }"
        ),
        "replace": (
            "    function repay() external payable {\n"
            "        require(debt[msg.sender] >= msg.value, \"Overpayment\");\n"
            "        // BUG: integer division truncation causes precision loss\n"
            "        debt[msg.sender] -= msg.value / 1e18 * 1e18;\n"
            "    }"
        ),
    },
]


def _apply_patches(template: dict, patch_ids: list[int]) -> dict:
    """Return a *new* contract dict with the specified vulnerability patches applied."""
    source = template["source_code"]
    labels = list(template["labels"])
    patches = [p for p in _VULN_PATCHES if p["id"] in patch_ids and p["target"] == template["name"]]
    for patch in patches:
        if patch["find"] in source:
            source = source.replace(patch["find"], patch["replace"], 1)
            labels.append(patch["vuln_name"])
    return {
        "name": template["name"],
        "source_code": source,
        "labels": labels,
    }


def generate_synthetic_contracts(num_vulns: int = 2) -> list[dict]:
    """
    Generate 5 synthetic contracts with *num_vulns* injected vulnerabilities each
    (where possible; the actual count depends on available patches per template).

    Parameters
    ----------
    num_vulns : int
        Number of vulnerabilities to inject – typically 2 or 15.

    Returns
    -------
    list[dict]
        5 contract dicts with ``name``, ``source_code``, and ``labels``.
    """
    if num_vulns not in (2, 15):
        raise ValueError("num_vulns must be 2 or 15")

    # For 2-vuln mode: inject patches 1 and 2 only
    # For 15-vuln mode: inject all 15 patches
    patch_ids = list(range(1, num_vulns + 1))
    return [_apply_patches(t, patch_ids) for t in _SECURE_TEMPLATES]


def save_synthetic_contracts(contracts: list[dict], directory: str = SYNTHETIC_CONTRACTS_DIR) -> None:
    """Persist each synthetic contract as a JSON file in *directory*."""
    os.makedirs(directory, exist_ok=True)
    for contract in contracts:
        filepath = os.path.join(directory, f"{contract['name']}.json")
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(contract, fh, indent=2)
