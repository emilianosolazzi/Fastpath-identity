// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/Bitcoingateway.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address sender) external;
    function addr(uint256 privateKey) external returns (address);
    function warp(uint256 timestamp) external;
}

/**
 * @title Economic Fuzzing Test for BitcoinGateway
 * @notice Defines value functions for adversarial profit optimization
 * @dev Used by economic_fuzzer.py to detect exploits via ΔV maximization
 */
contract BitcoinGatewayEconomicFuzz {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    BitcoinGateway public gateway;
    address public attacker = address(0x1337);
    address public victim = address(0xDEAD);
    address public registeredUser = address(0xBEEF);
    address public feeRecipient = address(0xFEED);

    function setUp() public {
        gateway = new BitcoinGateway(feeRecipient);
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }

    // ==========================================
    // VALUE FUNCTIONS (Economic Fuzzer reads these)
    // ==========================================

    /// @notice Primary value function: attacker's ETH balance
    /// @dev This is what the economic optimizer maximizes: ΔV(attacker)
    function valueETH() public view returns (int256) {
        return int256(attacker.balance);
    }

    /// @notice Alternative: protocol fee theft
    /// @dev Value = accumulated protocol fees that could be stolen
    function valueProtocolFees() public view returns (int256) {
        return int256(gateway.totalProtocolFeesEth());
    }

    /// @notice Alternative: locked ETH in requests (could be drained via exploit)
    function valueLockedETH() public view returns (int256) {
        return int256(address(gateway).balance);
    }

    // ==========================================
    // ATTACK PARAMETERS (Symbolic variables)
    // ==========================================

    /// @notice Params for sendBitcoin (create request)
    function attackParamsSendBitcoin() public pure returns (string[] memory) {
        string[] memory params = new string[](4);
        params[0] = "fromBtcAddress:string";
        params[1] = "toBtcAddress:string";
        params[2] = "amountSats:uint256";
        params[3] = "ethValue:uint256";
        return params;
    }

    /// @notice Params for fulfillPayment (user path)
    function attackParamsFulfill() public pure returns (string[] memory) {
        string[] memory params = new string[](3);
        params[0] = "requestId:uint256";
        params[1] = "btcTxid:bytes32";
        params[2] = "proof:bytes";
        return params;
    }

    /// @notice Params for cancelStuckRequest (refund exploit)
    function attackParamsCancel() public pure returns (string[] memory) {
        string[] memory params = new string[](1);
        params[0] = "requestId:uint256";
        return params;
    }

    /// @notice Params for withdrawProtocolFees (fee theft)
    function attackParamsWithdraw() public pure returns (string[] memory) {
        string[] memory params = new string[](1);
        params[0] = "amount:uint256";
        return params;
    }

    // ==========================================
    // ATTACK SCENARIOS (What to fuzz)
    // ==========================================

    /// @notice Scenario 1: Reentrancy in submitBitcoinProof (user pays fee in)
    /// @dev ETH flows IN during proof submission, not out — reentrancy surface is minimal
    function scenarioReentrancyFulfill() public pure returns (string memory) {
        return "submitBitcoinProof";
    }

    /// @notice Scenario 2: Protocol fee theft via reentrancy on withdrawProtocolFees
    /// @dev Only ETH-out path in v1.3.0; protected by nonReentrant
    function scenarioFeeTheft() public pure returns (string memory) {
        return "withdrawProtocolFees";
    }

    /// @notice Scenario 3: Double-fulfillment exploit
    /// @dev Try to mark same request fulfilled twice
    function scenarioDoubleFulfill() public pure returns (string memory) {
        return "submitBitcoinProof,submitBitcoinProof";
    }

    // ==========================================
    // CONFIGURATION
    // ==========================================

    /// @notice Max transaction trace depth
    function maxTraceDepth() public pure returns (uint256) {
        return 5;
    }

    /// @notice Minimum profitable ΔV to report (0.1 ETH)
    function minProfitThreshold() public pure returns (uint256) {
        return 0.1 ether;
    }

    /// @notice SMT solver timeout (seconds)
    function solverTimeout() public pure returns (uint256) {
        return 60;
    }
}

/**
 * @title Malicious User for Reentrancy Testing
 * @notice Contract that attempts to drain via reentrancy on fee receive
 */
contract MaliciousUser {
    BitcoinGateway public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;

    constructor(BitcoinGateway _target) {
        target = _target;
    }

    receive() external payable {
        // Reentrancy attack when receiving user fee
        if (attackCount < maxAttacks && address(target).balance > 0) {
            attackCount++;
            // Try to fulfill another request or withdraw fees
            // (In real attack, would need valid request IDs)
        }
    }

    function startAttack(uint256 requestId, bytes32 btcTxid, bytes calldata publicKey, bytes calldata proof) external {
        attackCount = 0;
        // User pays a fee in at proof submission time (v1.3.0 model)
        target.submitBitcoinProof{value: 0.001 ether}(requestId, btcTxid, publicKey, proof);
    }
}

/**
 * @title Malicious Requester for Refund Reentrancy
 * @notice Contract that attempts to drain via reentrancy on refund
 */
contract MaliciousRequester {
    BitcoinGateway public target;
    uint256 public requestId;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;

    constructor(BitcoinGateway _target) payable {
        target = _target;
    }

    function createRequest() external returns (uint256) {
        // sendBitcoin is free in v1.3.0 — no ETH locked
        requestId = target.sendBitcoin("bc1qmalicious", "bc1qvictim", 1000, "exploit");
        return requestId;
    }

    receive() external payable {
        // No refund reentrancy vector in v1.3.0 (no cancel/refund functions)
        if (attackCount < maxAttacks && address(target).balance > 0) {
            attackCount++;
        }
    }
}
