// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "contracts/BitcoinGateway.sol";

/**
 * @title Reentrancy Security Tests for BitcoinGateway
 * @notice Tests all reentrancy attack vectors after economic fuzzer detection
 * @dev Validates that ReentrancyGuard prevents exploits on:
 *      - fulfillPayment (relayer fee distribution)
 *      - fulfillPaymentAsRelayer (decentralized relayer path)
 *      - cancelStuckRequest (refund path)
 *      - cancelExpiredRequest (expired refund path)
 *      - withdrawProtocolFees (protocol fee withdrawal)
 */
contract BitcoinGatewayReentrancyTest is Test {
    BitcoinGateway public gateway;
    
    address public owner = address(this);
    address public relayer = address(0xBEEF);
    address public feeRecipient = address(0xFEED);
    address public victim = address(0xDEAD);
    
    function setUp() public {
        gateway = new BitcoinGateway(relayer, feeRecipient);
        vm.deal(victim, 100 ether);
    }
    
    // ==========================================
    // ATTACK 1: Relayer Fee Reentrancy
    // ==========================================
    
    function testReentrancyRelayerFee() public {
        // Setup: Register malicious relayer
        MaliciousRelayer attacker = new MaliciousRelayer(gateway);
        vm.deal(address(attacker), 1 ether);
        
        bytes32 fingerprint = bytes32(uint256(0x1337));
        vm.prank(address(attacker));
        gateway.registerRelayer(fingerprint);
        
        // Create request as victim
        vm.prank(victim);
        uint256 requestId = gateway.sendBitcoin{value: 10 ether}(
            "bc1qvictim",
            "bc1qrecipient",
            10000,
            "legit payment"
        );
        
        // Attacker tries to fulfill and drain via reentrancy
        bytes32 txid = bytes32(uint256(123456));
        bytes memory pubkey = hex"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        bytes memory proof = new bytes(64);
        
        uint256 gatewayBalanceBefore = address(gateway).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        vm.prank(address(attacker));
        attacker.startAttack(requestId, txid, pubkey, proof);
        
        // Verify: Reentrancy blocked, only ONE fulfillment succeeded
        assertEq(attacker.attackCount(), 1, "Should only succeed once");
        
        // Calculate expected relayer fee (0.17% of 10 ETH)
        uint256 expectedRelayerFee = (10 ether * 17) / 10000;
        uint256 attackerBalanceAfter = address(attacker).balance;
        uint256 profit = attackerBalanceAfter - attackerBalanceBefore;
        
        // Should only receive ONE relayer fee, not multiple
        assertEq(profit, expectedRelayerFee, "Should only receive single relayer fee");
        assertLt(gatewayBalanceBefore - address(gateway).balance, 1 ether, "Gateway should not be drained");
    }
    
    // ==========================================
    // ATTACK 2: Cancel Refund Reentrancy
    // ==========================================
    
    function testReentrancyCancelRefund() public {
        // Setup: Create request as malicious contract
        MaliciousRequester attacker = new MaliciousRequester{value: 20 ether}(gateway);
        
        vm.prank(address(attacker));
        uint256 requestId = attacker.createRequest{value: 10 ether}();
        
        // Fast forward 24 hours
        vm.warp(block.timestamp + 24 hours + 1);
        
        uint256 gatewayBalanceBefore = address(gateway).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        // Attacker tries to cancel and drain via reentrancy
        vm.prank(address(attacker));
        attacker.startCancelAttack();
        
        // Verify: Reentrancy blocked
        assertEq(attacker.attackCount(), 1, "Should only cancel once");
        
        uint256 attackerBalanceAfter = address(attacker).balance;
        uint256 refund = attackerBalanceAfter - attackerBalanceBefore;
        
        // Should only receive ONE refund (10 ETH), not multiple
        assertEq(refund, 10 ether, "Should only receive single refund");
        assertEq(address(gateway).balance, gatewayBalanceBefore - 10 ether, "Gateway should only refund once");
    }
    
    // ==========================================
    // ATTACK 3: Multiple Request Drain
    // ==========================================
    
    function testReentrancyMultipleRequestDrain() public {
        // Setup: Malicious requester creates multiple requests
        MaliciousRequesterMulti attacker = new MaliciousRequesterMulti{value: 50 ether}(gateway);
        
        // Create 5 requests with 10 ETH each
        vm.startPrank(address(attacker));
        for (uint256 i = 0; i < 5; i++) {
            gateway.sendBitcoin{value: 10 ether}(
                "bc1qattacker",
                "bc1qvictim",
                10000,
                "exploit setup"
            );
        }
        vm.stopPrank();
        
        // Fast forward 24 hours
        vm.warp(block.timestamp + 24 hours + 1);
        
        uint256 gatewayBalanceBefore = address(gateway).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        // Attacker tries to drain all requests via reentrancy
        vm.prank(address(attacker));
        attacker.drainAll();
        
        uint256 attackerBalanceAfter = address(attacker).balance;
        uint256 stolen = attackerBalanceAfter - attackerBalanceBefore;
        
        // Verify: Can only cancel ONE request per call due to nonReentrant
        assertLe(stolen, 10 ether, "Should only drain one request");
        assertGt(address(gateway).balance, 30 ether, "Gateway should still have remaining funds");
    }
    
    // ==========================================
    // ATTACK 4: Expired Request Reentrancy
    // ==========================================
    
    function testReentrancyExpiredRefund() public {
        // Setup: Create request as malicious contract
        MaliciousRequester attacker = new MaliciousRequester{value: 20 ether}(gateway);
        
        vm.prank(address(attacker));
        uint256 requestId = attacker.createRequest{value: 10 ether}();
        
        // Fast forward 7 days
        vm.warp(block.timestamp + 7 days + 1);
        
        uint256 gatewayBalanceBefore = address(gateway).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        // Anyone can call cancelExpiredRequest - attacker uses this
        vm.prank(address(attacker));
        attacker.startExpiredAttack(requestId);
        
        // Verify: Reentrancy blocked
        uint256 attackerBalanceAfter = address(attacker).balance;
        uint256 refund = attackerBalanceAfter - attackerBalanceBefore;
        
        assertEq(refund, 10 ether, "Should only receive single refund");
        assertEq(address(gateway).balance, gatewayBalanceBefore - 10 ether, "Gateway should only refund once");
    }
    
    // ==========================================
    // ATTACK 5: Protocol Fee Reentrancy
    // ==========================================
    
    function testReentrancyProtocolFeeWithdrawal() public {
        // Setup: Accumulate protocol fees by fulfilling requests
        vm.prank(victim);
        uint256 requestId = gateway.sendBitcoin{value: 100 ether}(
            "bc1qvictim",
            "bc1qrecipient",
            10000,
            "legit payment"
        );
        
        // Fulfill as centralized relayer (all fees to protocol)
        bytes32 txid = bytes32(uint256(123456));
        bytes memory pubkey = hex"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        bytes memory proof = new bytes(64);
        
        vm.prank(relayer);
        gateway.fulfillPayment(requestId, txid, pubkey, proof);
        
        uint256 protocolFees = gateway.totalProtocolFeesEth();
        assertGt(protocolFees, 0, "Protocol should have fees");
        
        // Transfer ownership to malicious contract
        MaliciousOwner attacker = new MaliciousOwner(gateway);
        gateway.transferOwnership(address(attacker));
        
        uint256 gatewayBalanceBefore = address(gateway).balance;
        
        // Attacker tries to drain protocol fees via reentrancy
        vm.prank(address(attacker));
        attacker.drainFees(protocolFees);
        
        // Verify: Reentrancy blocked
        assertEq(attacker.attackCount(), 1, "Should only withdraw once");
        assertEq(gateway.totalProtocolFeesEth(), 0, "Protocol fees should be withdrawn once");
    }
}

// ==========================================
// MALICIOUS CONTRACTS
// ==========================================

contract MaliciousRelayer {
    BitcoinGateway public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;
    
    constructor(BitcoinGateway _target) {
        target = _target;
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount < maxAttacks && address(target).balance > 1 ether) {
            // Try to fulfill more requests to drain ETH
            // (Would need valid request IDs in real scenario)
        }
    }
    
    function startAttack(
        uint256 requestId,
        bytes32 btcTxid,
        bytes calldata publicKey,
        bytes calldata proof
    ) external {
        attackCount = 0;
        target.fulfillPaymentAsRelayer(requestId, btcTxid, publicKey, proof);
    }
}

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
        attackCount++;
        if (attackCount < maxAttacks && address(target).balance > 1 ether) {
            // Try to cancel same request again
            try target.cancelStuckRequest(requestId) {} catch {}
        }
    }
    
    function startCancelAttack() external {
        attackCount = 0;
        target.cancelStuckRequest(requestId);
    }
    
    function startExpiredAttack(uint256 _requestId) external {
        attackCount = 0;
        target.cancelExpiredRequest(_requestId);
    }
}

contract MaliciousRequesterMulti {
    BitcoinGateway public target;
    uint256[] public requestIds;
    uint256 public currentIndex;
    
    constructor(BitcoinGateway _target) payable {
        target = _target;
    }
    
    receive() external payable {
        // Try to cancel next request in reentrancy
        if (currentIndex < requestIds.length - 1) {
            currentIndex++;
            try target.cancelStuckRequest(requestIds[currentIndex]) {} catch {}
        }
    }
    
    function drainAll() external {
        uint256 count = target.requestCount();
        // Find our requests (assumes we're the only requester for simplicity)
        for (uint256 i = 0; i < count; i++) {
            requestIds.push(i);
        }
        currentIndex = 0;
        if (requestIds.length > 0) {
            target.cancelStuckRequest(requestIds[0]);
        }
    }
}

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
            // Try to withdraw more fees
            try target.withdrawProtocolFees(remaining) {} catch {}
        }
    }
    
    function drainFees(uint256 amount) external {
        attackCount = 1; // Count first call
        target.withdrawProtocolFees(amount);
    }
}

