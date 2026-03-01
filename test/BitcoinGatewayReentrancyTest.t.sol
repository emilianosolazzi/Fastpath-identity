// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "contracts/Bitcoingateway.sol";

/**
 * @title Reentrancy Security Tests for BitcoinGateway
 * @notice Tests all reentrancy attack vectors after economic fuzzer detection
 * @dev In v1.3.0 sendBitcoin is free — no ETH is locked. The registered user pays a small
 *      ETH fee in at submitBitcoinProof call time. Only withdrawProtocolFees sends
 *      ETH out, so that is the main reentrancy surface.
 *      Validates that ReentrancyGuard prevents exploits on:
 *      - withdrawProtocolFees (only ETH-out path in v1.3.0)
 */
contract BitcoinGatewayReentrancyTest is Test {
    BitcoinGateway public gateway;
    
    address public owner = address(this);
    address public registeredUser = address(0xBEEF);
    address public feeRecipient = address(0xFEED);
    address public victim = address(0xDEAD);
    
    function setUp() public {
        gateway = new BitcoinGateway(feeRecipient);
        vm.deal(victim, 100 ether);
        vm.deal(registeredUser, 10 ether);
        // Register the default user
        vm.prank(registeredUser);
        gateway.registerUser(bytes32(uint256(0xCC)));
    }
    
    // ==========================================
    // TEST: Plain ETH rejected (no receive function)
    // ==========================================

    function testNoReceiveFunction() public {
        vm.prank(victim);
        (bool success,) = address(gateway).call{value: 1 ether}("");
        assertFalse(success, "contract must not accept plain ETH");
        assertEq(address(gateway).balance, 0, "balance must stay zero");
    }

    // ==========================================
    // ATTACK: Protocol Fee Withdrawal Reentrancy
    // ==========================================

    function testReentrancyProtocolFeeWithdrawal() public {
        uint256 RELAY_FEE = 0.01 ether;
        bytes memory proof = new bytes(64);
        bytes memory pubkey = hex"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

        // Two requests fulfilled -> 2 x RELAY_FEE accumulated in protocol treasury
        vm.startPrank(victim);
        gateway.sendBitcoin("bc1qvictim1", "bc1qrecipient1", 10000, "t1");
        gateway.sendBitcoin("bc1qvictim2", "bc1qrecipient2", 20000, "t2");
        vm.stopPrank();

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, bytes32(uint256(1)), pubkey, proof);
        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(1, bytes32(uint256(2)), pubkey, proof);

        assertEq(gateway.totalProtocolFeesEth(), 2 * RELAY_FEE, "should have 2x RELAY_FEE");

        // Transfer ownership to malicious contract
        MaliciousOwner attacker = new MaliciousOwner(gateway);
        gateway.transferOwnership(address(attacker));

        // Attacker withdraws one RELAY_FEE; in receive() it tries to reenter for the second
        attacker.drainFees(RELAY_FEE);

        // Verify: nonReentrant blocked the re-entry — only one withdrawal succeeded
        assertEq(attacker.attackCount(), 1, "receive() fires once; reentrancy blocked on retry");
        assertEq(gateway.totalProtocolFeesEth(), RELAY_FEE, "second RELAY_FEE must remain (reentry blocked)");
        assertEq(address(attacker).balance, RELAY_FEE, "attacker received exactly one payment");
    }
}

// ==========================================
// MALICIOUS CONTRACTS
// ==========================================

/// @notice Malicious contract that attempts to re-enter withdrawProtocolFees via receive()
/// @dev drainFees() sets feeRecipient to self so receive() fires, then tries to withdraw again.
///      nonReentrant must block the re-entry attempt.
contract MaliciousOwner {
    BitcoinGateway public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;

    constructor(BitcoinGateway _target) {
        target = _target;
    }

    receive() external payable {
        attackCount++;
        uint256 remaining = target.totalProtocolFeesEth();
        if (attackCount < maxAttacks && remaining > 0) {
            // Re-entry attempt: should be blocked by nonReentrant
            try target.withdrawProtocolFees(remaining) {} catch {}
        }
    }

    function drainFees(uint256 amount) external {
        attackCount = 0;
        // Point feeRecipient to self so receive() fires when ETH is sent out
        target.updateFeeRecipient(address(this));
        // Attempt withdrawal — reentrancy will be attempted in receive()
        target.withdrawProtocolFees(amount);
    }
}
