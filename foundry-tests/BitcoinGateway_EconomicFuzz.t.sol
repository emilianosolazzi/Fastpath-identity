// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/BitcoinGateway.sol";

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
    address public relayer = address(0xBEEF);
    address public feeRecipient = address(0xFEED);
    
    function setUp() public {
        gateway = new BitcoinGateway(relayer, feeRecipient);
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
    
    /// @notice Params for fulfillPayment (relayer path)
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
    
    /// @notice Scenario 1: Reentrancy in fulfillPayment (relayer fee distribution)
    /// @dev Try to drain ETH via recursive calls when relayer fee is sent
    function scenarioReentrancyFulfill() public pure returns (string memory) {
        return "fulfillPaymentAsRelayer";
    }
    
    /// @notice Scenario 2: Reentrancy in cancelStuckRequest (refund path)
    /// @dev Try to drain ETH via recursive calls when refund is sent
    function scenarioCancelReentrancy() public pure returns (string memory) {
        return "cancelStuckRequest";
    }
    
    /// @notice Scenario 3: Reentrancy in cancelExpiredRequest (refund path)
    /// @dev Try to drain ETH via recursive calls when expired refund is sent
    function scenarioExpiredReentrancy() public pure returns (string memory) {
        return "cancelExpiredRequest";
    }
    
    /// @notice Scenario 4: Protocol fee theft via reentrancy
    /// @dev Try to drain protocol fees via recursive withdrawProtocolFees
    function scenarioFeeTheft() public pure returns (string memory) {
        return "withdrawProtocolFees";
    }
    
    /// @notice Scenario 5: Double-cancel exploit
    /// @dev Try to cancel same request twice for double refund
    function scenarioDoubleCancel() public pure returns (string memory) {
        return "cancelStuckRequest,cancelStuckRequest";
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
 * @title Malicious Relayer for Reentrancy Testing
 * @notice Contract that attempts to drain via reentrancy on fee receive
 */
contract MaliciousRelayer {
    BitcoinGateway public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;
    
    constructor(BitcoinGateway _target) {
        target = _target;
    }
    
    receive() external payable {
        // Reentrancy attack when receiving relayer fee
        if (attackCount < maxAttacks && address(target).balance > 0) {
            attackCount++;
            // Try to fulfill another request or withdraw fees
            // (In real attack, would need valid request IDs)
        }
    }
    
    function startAttack(uint256 requestId, bytes32 btcTxid, bytes calldata publicKey, bytes calldata proof) external {
        attackCount = 0;
        target.fulfillPaymentAsRelayer(requestId, btcTxid, publicKey, proof);
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
    
    function createRequest() external payable returns (uint256) {
        requestId = target.sendBitcoin{value: msg.value}(
            "bc1qmalicious",
            "bc1qvictim",
            1000,
            "exploit"
        );
        return requestId;
    }
    
    receive() external payable {
        // Reentrancy attack when receiving refund
        if (attackCount < maxAttacks && address(target).balance > 0) {
            attackCount++;
            // Try to cancel again (should fail due to fulfilled flag, but let's test)
            try target.cancelStuckRequest(requestId) {} catch {}
        }
    }
    
    function startCancelAttack() external {
        attackCount = 0;
        target.cancelStuckRequest(requestId);
    }
}

