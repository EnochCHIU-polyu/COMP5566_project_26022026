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


# ---------------------------------------------------------------------------
# Additional secure contract templates (10 more)
# ---------------------------------------------------------------------------

_EXTRA_SECURE_TEMPLATES: list[dict] = [
    {
        "name": "ProxyContract",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ProxyContract – EIP-1967 upgradeable proxy.
contract ProxyContract {
    bytes32 internal constant IMPL_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address impl) {
        assembly { sstore(IMPL_SLOT, impl) }
    }

    function _implementation() internal view returns (address impl) {
        assembly { impl := sload(IMPL_SLOT) }
    }

    fallback() external payable {
        address impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
""",
        "labels": [],
    },
    {
        "name": "DEXRouter",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title DEXRouter – minimal token swap router.
contract DEXRouter {
    mapping(address => mapping(address => uint256)) public reserves;

    function addLiquidity(address tokenA, address tokenB, uint256 amtA, uint256 amtB) external {
        IERC20(tokenA).transferFrom(msg.sender, address(this), amtA);
        IERC20(tokenB).transferFrom(msg.sender, address(this), amtB);
        reserves[tokenA][tokenB] += amtA;
        reserves[tokenB][tokenA] += amtB;
    }

    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        uint256 reserveIn = reserves[tokenIn][tokenOut];
        uint256 reserveOut = reserves[tokenOut][tokenIn];
        amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);
        require(amountOut >= minAmountOut, "Slippage exceeded");
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        reserves[tokenIn][tokenOut] += amountIn;
        reserves[tokenOut][tokenIn] -= amountOut;
    }
}
""",
        "labels": [],
    },
    {
        "name": "LendingPool",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// @title LendingPool – Aave-like lending pool.
contract LendingPool {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    address public token;
    uint256 public constant COLLATERAL_FACTOR = 75; // 75%

    constructor(address _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 maxBorrow = deposits[msg.sender] * COLLATERAL_FACTOR / 100;
        require(borrows[msg.sender] + amount <= maxBorrow, "Undercollateralized");
        borrows[msg.sender] += amount;
        IERC20(token).transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        require(borrows[msg.sender] >= amount, "Overpayment");
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        borrows[msg.sender] -= amount;
    }
}
""",
        "labels": [],
    },
    {
        "name": "GovernanceContract",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title GovernanceContract – on-chain governance.
contract GovernanceContract {
    struct Proposal {
        bytes callData;
        address target;
        uint256 voteEnd;
        uint256 votesFor;
        uint256 votesAgainst;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;

    function propose(address target, bytes calldata data, uint256 duration)
        external returns (uint256 id)
    {
        id = ++proposalCount;
        proposals[id] = Proposal(data, target, block.timestamp + duration, 0, 0, false);
    }

    function vote(uint256 id, bool support) external {
        Proposal storage p = proposals[id];
        require(block.timestamp <= p.voteEnd, "Voting closed");
        require(!hasVoted[id][msg.sender], "Already voted");
        hasVoted[id][msg.sender] = true;
        uint256 power = votingPower[msg.sender];
        if (support) p.votesFor += power;
        else p.votesAgainst += power;
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(block.timestamp > p.voteEnd, "Voting ongoing");
        require(!p.executed, "Already executed");
        require(p.votesFor > p.votesAgainst, "Proposal rejected");
        p.executed = true;
        (bool ok,) = p.target.call(p.callData);
        require(ok, "Execution failed");
    }
}
""",
        "labels": [],
    },
    {
        "name": "NFTMarketplace",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC721 {
    function transferFrom(address, address, uint256) external;
    function ownerOf(uint256) external view returns (address);
}

/// @title NFTMarketplace – simple NFT buy/sell.
contract NFTMarketplace {
    struct Listing {
        address seller;
        uint256 price;
        bool active;
    }

    mapping(address => mapping(uint256 => Listing)) public listings;

    function list(address nft, uint256 tokenId, uint256 price) external {
        require(IERC721(nft).ownerOf(tokenId) == msg.sender, "Not owner");
        listings[nft][tokenId] = Listing(msg.sender, price, true);
    }

    function buy(address nft, uint256 tokenId) external payable {
        Listing storage l = listings[nft][tokenId];
        require(l.active, "Not listed");
        require(msg.value >= l.price, "Insufficient payment");
        l.active = false;
        IERC721(nft).transferFrom(l.seller, msg.sender, tokenId);
        (bool ok,) = l.seller.call{value: l.price}("");
        require(ok, "Payment failed");
        if (msg.value > l.price) {
            (bool refund,) = msg.sender.call{value: msg.value - l.price}("");
            require(refund, "Refund failed");
        }
    }
}
""",
        "labels": [],
    },
    {
        "name": "FlashLoanReceiver",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC3156FlashLender {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data)
        external returns (bool);
}

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title FlashLoanReceiver – ERC-3156 flash loan receiver.
contract FlashLoanReceiver {
    address public owner;

    constructor() { owner = msg.sender; }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        require(initiator == address(this), "Untrusted initiator");
        // Custom logic here (arbitrage, liquidation, etc.)
        uint256 repayAmount = amount + fee;
        IERC20(token).approve(msg.sender, repayAmount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function executeFlashLoan(
        address lender,
        address token,
        uint256 amount
    ) external {
        require(msg.sender == owner, "Not owner");
        IERC3156FlashLender(lender).flashLoan(address(this), token, amount, "");
    }
}
""",
        "labels": [],
    },
    {
        "name": "StablecoinMinter",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title StablecoinMinter – overcollateralised stablecoin.
contract StablecoinMinter {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public minted;
    uint256 public constant MIN_RATIO = 150; // 150% collateral
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function mint(uint256 amount) external {
        uint256 required = amount * MIN_RATIO / 100;
        require(collateral[msg.sender] >= required + minted[msg.sender] * MIN_RATIO / 100,
            "Undercollateralised");
        minted[msg.sender] += amount;
        totalSupply += amount;
        balances[msg.sender] += amount;
    }

    function burn(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        minted[msg.sender] -= amount;
    }

    function withdrawCollateral(uint256 amount) external {
        uint256 minCollateral = minted[msg.sender] * MIN_RATIO / 100;
        require(collateral[msg.sender] - amount >= minCollateral, "Would undercollateralise");
        collateral[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
""",
        "labels": [],
    },
    {
        "name": "YieldFarm",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// @title YieldFarm – simple yield farming contract.
contract YieldFarm {
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    uint256 public rewardRate;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public lastUpdate;
    mapping(address => uint256) public rewards;

    constructor(address _staking, address _reward, uint256 _rate) {
        stakingToken = IERC20(_staking);
        rewardToken = IERC20(_reward);
        rewardRate = _rate;
    }

    function _earned(address user) internal view returns (uint256) {
        return staked[user] * rewardRate * (block.timestamp - lastUpdate[user]) / 1e18;
    }

    function stake(uint256 amount) external {
        rewards[msg.sender] += _earned(msg.sender);
        lastUpdate[msg.sender] = block.timestamp;
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "Insufficient stake");
        rewards[msg.sender] += _earned(msg.sender);
        lastUpdate[msg.sender] = block.timestamp;
        staked[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function claimRewards() external {
        uint256 reward = rewards[msg.sender] + _earned(msg.sender);
        rewards[msg.sender] = 0;
        lastUpdate[msg.sender] = block.timestamp;
        rewardToken.transfer(msg.sender, reward);
    }
}
""",
        "labels": [],
    },
    {
        "name": "TimelockController",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TimelockController – timelock for governance actions.
contract TimelockController {
    uint256 public delay;
    address public admin;
    mapping(bytes32 => uint256) public queue;

    event Queued(bytes32 indexed txId, address target, bytes data, uint256 eta);
    event Executed(bytes32 indexed txId);
    event Cancelled(bytes32 indexed txId);

    constructor(uint256 _delay) {
        delay = _delay;
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function queueTransaction(address target, bytes calldata data)
        external onlyAdmin returns (bytes32 txId)
    {
        uint256 eta = block.timestamp + delay;
        txId = keccak256(abi.encode(target, data, eta));
        require(queue[txId] == 0, "Already queued");
        queue[txId] = eta;
        emit Queued(txId, target, data, eta);
    }

    function executeTransaction(address target, bytes calldata data, uint256 eta)
        external onlyAdmin
    {
        bytes32 txId = keccak256(abi.encode(target, data, eta));
        require(queue[txId] != 0, "Not queued");
        require(block.timestamp >= eta, "Too early");
        delete queue[txId];
        (bool ok,) = target.call(data);
        require(ok, "Execution failed");
        emit Executed(txId);
    }

    function cancel(bytes32 txId) external onlyAdmin {
        require(queue[txId] != 0, "Not queued");
        delete queue[txId];
        emit Cancelled(txId);
    }
}
""",
        "labels": [],
    },
    {
        "name": "MultiTokenVault",
        "source_code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title MultiTokenVault – ERC-4626-like multi-token vault.
contract MultiTokenVault {
    mapping(address => mapping(address => uint256)) public shares; // token => user => shares
    mapping(address => uint256) public totalShares; // token => total shares
    mapping(address => address[]) public depositors; // token => list of depositors

    function deposit(address token, uint256 amount) external returns (uint256 sharesOut) {
        uint256 totalAssets = IERC20(token).balanceOf(address(this));
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (totalShares[token] == 0) {
            sharesOut = amount;
        } else {
            sharesOut = amount * totalShares[token] / totalAssets;
        }
        shares[token][msg.sender] += sharesOut;
        totalShares[token] += sharesOut;
    }

    function withdraw(address token, uint256 sharesIn) external returns (uint256 amountOut) {
        require(shares[token][msg.sender] >= sharesIn, "Insufficient shares");
        uint256 totalAssets = IERC20(token).balanceOf(address(this));
        amountOut = sharesIn * totalAssets / totalShares[token];
        shares[token][msg.sender] -= sharesIn;
        totalShares[token] -= sharesIn;
        IERC20(token).transfer(msg.sender, amountOut);
    }
}
""",
        "labels": [],
    },
]

# Semantic mutation patches for extra templates
_EXTRA_VULN_PATCHES: list[dict] = [
    {
        "id": 101,
        "vuln_name": "Reentrancy in NFTMarketplace",
        "target": "NFTMarketplace",
        "find": (
            "        l.active = false;\n"
            "        IERC721(nft).transferFrom(l.seller, msg.sender, tokenId);\n"
            "        (bool ok,) = l.seller.call{value: l.price}(\"\");"
        ),
        "replace": (
            "        // BUG: state cleared after external call → reentrancy\n"
            "        IERC721(nft).transferFrom(l.seller, msg.sender, tokenId);\n"
            "        (bool ok,) = l.seller.call{value: l.price}(\"\");\n"
            "        l.active = false;"
        ),
    },
    {
        "id": 102,
        "vuln_name": "Access Control Missing in GovernanceContract",
        "target": "GovernanceContract",
        "find": (
            "    function propose(address target, bytes calldata data, uint256 duration)\n"
            "        external returns (uint256 id)"
        ),
        "replace": (
            "    // BUG: anyone can create proposals – no voting power check\n"
            "    function propose(address target, bytes calldata data, uint256 duration)\n"
            "        external returns (uint256 id)"
        ),
    },
    {
        "id": 103,
        "vuln_name": "Unchecked Return Value in DEXRouter",
        "target": "DEXRouter",
        "find": (
            "        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);\n"
            "        IERC20(tokenOut).transfer(msg.sender, amountOut);"
        ),
        "replace": (
            "        // BUG: return values of transferFrom/transfer not checked\n"
            "        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);\n"
            "        IERC20(tokenOut).transfer(msg.sender, amountOut);"
        ),
    },
    {
        "id": 104,
        "vuln_name": "Tx.Origin in TimelockController",
        "target": "TimelockController",
        "find": '        require(msg.sender == admin, "Not admin");',
        "replace": '        require(tx.origin == admin, "Not admin");  // BUG: tx.origin',
    },
    {
        "id": 105,
        "vuln_name": "Delegate Call in ProxyContract",
        "target": "ProxyContract",
        "find": "    fallback() external payable {\n        address impl = _implementation();",
        "replace": (
            "    // BUG: unvalidated implementation address\n"
            "    fallback() external payable {\n        address impl = _implementation();"
        ),
    },
]


def generate_large_synthetic_dataset(count: int = 50) -> list[dict]:
    """
    Generate *count* contracts using all templates and various mutations.

    Parameters
    ----------
    count : int
        Number of contracts to generate.

    Returns
    -------
    list[dict]
        List of contract dicts with ``name``, ``source_code``, and ``labels``.
    """
    all_templates = _SECURE_TEMPLATES + _EXTRA_SECURE_TEMPLATES
    all_patches = _VULN_PATCHES + _EXTRA_VULN_PATCHES
    contracts = []
    idx = 0
    while len(contracts) < count:
        template = all_templates[idx % len(all_templates)]
        # Cycle through patches for variety
        patch_idx = idx % max(1, len(all_patches))
        patch = all_patches[patch_idx]
        if patch["target"] == template["name"] and patch["find"] in template["source_code"]:
            contract = _apply_patches(template, [patch["id"]])
        else:
            contract = {
                "name": f"{template['name']}_{idx}",
                "source_code": template["source_code"],
                "labels": list(template["labels"]),
            }
        # Ensure unique names
        contract["name"] = f"{contract['name']}_{idx}"
        contracts.append(contract)
        idx += 1
    return contracts[:count]
