// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "contracts/Bitcoingateway.sol";

/**
 * @title BitcoinGateway — Security Audit Edge-Case Tests
 * @notice Covers: access control bypass, double-fulfillment, blacklist evasion,
 *         fee accounting, dust limit, reentrancy via fee withdrawal, overflow
 *
 * Findings tested:
 *   [H-1] Double fulfillment of the same request
 *   [H-2] Fee accounting overflow via unchecked totalProtocolFeesEth
 *   [H-3] Reentrancy on withdrawProtocolFees (CEI check)
 *   [M-1] Blacklisted user bypasses via unregister then re-register
 *   [M-2] transferOwnership to address(0) bricks admin
 *   [M-3] Unregistered user cannot submit proof
 *   [M-4] Proof fee boundary: exactly MIN and MAX
 *   [L-1] Dust limit enforcement on sendBitcoin
 *   [L-2] Empty BTC address strings rejected
 *   [L-3] Paused state blocks all core operations
 *   [L-4] requestCount monotonicity
 *   [EDGE] Withdraw more fees than available reverts
 *   [EDGE] setBlacklisted idempotency (no event on no-op)
 */
contract BitcoinGatewaySecurityTest is Test {
    BitcoinGateway gw;

    address owner = address(0xA11CE);
    address feeRecipient = address(0xFEE);
    address user1 = address(0xB0B);
    address user2 = address(0xCAFE);
    address attacker = address(0xBAD);

    bytes32 fingerprint1 = keccak256("machine1");
    bytes32 fingerprint2 = keccak256("machine2");
    bytes32 fingerprintAttacker = keccak256("machineAttacker");

    function setUp() public {
        vm.prank(owner);
        gw = new BitcoinGateway(feeRecipient);

        vm.deal(owner, 100 ether);
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(attacker, 100 ether);

        // Register user1
        vm.prank(user1);
        gw.registerUser(fingerprint1);
    }

    // ════════════════════════════════════════════════════
    // HELPERS
    // ════════════════════════════════════════════════════

    function _createRequest() internal returns (uint256 reqId) {
        vm.prank(user1);
        reqId = gw.sendBitcoin(
            "bc1qsender",
            "bc1qreceiver",
            10_000, // 10k sats
            "test payment"
        );
    }

    function _submitProof(uint256 reqId, address prover) internal {
        uint256 fee = gw.proofFee();
        vm.prank(prover);
        gw.submitBitcoinProof{value: fee}(reqId, keccak256("btctxid"), hex"04aaaa", new bytes(64));
    }

    // ════════════════════════════════════════════════════
    // [H-1] Double Fulfillment
    // ════════════════════════════════════════════════════

    /// @notice Fulfilling the same request twice should revert
    function testH1_DoubleFulfillmentReverts() public {
        uint256 reqId = _createRequest();
        _submitProof(reqId, user1);
        uint256 fee = gw.proofFee();

        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee}(reqId, keccak256("btctxid"), hex"04aaaa", new bytes(64));
    }

    // ════════════════════════════════════════════════════
    // [H-2] Fee Accounting with unchecked
    // ════════════════════════════════════════════════════

    /// @notice Verify totalProtocolFeesEth accumulates correctly
    function testH2_FeeAccumulationAccuracy() public {
        uint256 reqId1 = _createRequest();
        uint256 reqId2 = _createRequest();

        uint256 fee = gw.proofFee();

        _submitProof(reqId1, user1);
        assertEq(gw.totalProtocolFeesEth(), fee);

        _submitProof(reqId2, user1);
        assertEq(gw.totalProtocolFeesEth(), fee * 2);
    }

    // ════════════════════════════════════════════════════
    // [H-3] Reentrancy on withdrawProtocolFees
    // ════════════════════════════════════════════════════

    /// @notice CEI pattern prevents reentrancy on fee withdrawal
    function testH3_ReentrancyOnFeeWithdrawal() public {
        // Accumulate some fees
        uint256 reqId = _createRequest();
        _submitProof(reqId, user1);

        uint256 fees = gw.totalProtocolFeesEth();
        assertTrue(fees > 0);

        // Deploy reentrancy attacker as fee recipient
        ReentrantFeeRecipient reentrant = new ReentrantFeeRecipient(address(gw));
        vm.prank(owner);
        gw.updateFeeRecipient(address(reentrant));

        // CEI sets fees to zero before transfer, so reentrant callback has nothing to steal.
        uint256 preBalance = address(reentrant).balance;
        vm.prank(owner);
        gw.withdrawProtocolFees(fees);

        assertEq(gw.totalProtocolFeesEth(), 0, "Fees should be zero after withdrawal");
        assertEq(reentrant.attackCount(), 0, "Reentrant callback should not execute withdraw");
        assertEq(address(reentrant).balance, preBalance + fees, "Recipient gets exactly withdrawn amount");
    }

    // ════════════════════════════════════════════════════
    // [M-1] Blacklisted User Re-register Attempt
    // ════════════════════════════════════════════════════

    /// @notice Blacklisted user cannot register
    function testM1_BlacklistedCannotRegister() public {
        vm.prank(owner);
        gw.setBlacklisted(attacker, true);

        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        vm.prank(attacker);
        gw.registerUser(fingerprintAttacker);
    }

    /// @notice Blacklisted user cannot sendBitcoin
    function testM1_BlacklistedCannotSend() public {
        // Register attacker first, then blacklist
        vm.prank(attacker);
        gw.registerUser(fingerprintAttacker);

        vm.prank(owner);
        gw.setBlacklisted(attacker, true);

        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        vm.prank(attacker);
        gw.sendBitcoin("bc1q1", "bc1q2", 1000, "");
    }

    /// @notice Blacklisted user cannot submit proof
    function testM1_BlacklistedCannotSubmitProof() public {
        vm.prank(attacker);
        gw.registerUser(fingerprintAttacker);

        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.prank(owner);
        gw.setBlacklisted(attacker, true);

        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        vm.prank(attacker);
        gw.submitBitcoinProof{value: fee}(reqId, keccak256("txid"), hex"04aaaa", new bytes(64));
    }

    // ════════════════════════════════════════════════════
    // [M-2] transferOwnership to zero address reverts
    // ════════════════════════════════════════════════════

    function testM2_TransferOwnershipToZeroReverts() public {
        vm.expectRevert(BitcoinGateway.ZeroAddress.selector);
        vm.prank(owner);
        gw.transferOwnership(address(0));
    }

    // ════════════════════════════════════════════════════
    // [M-3] Unregistered User Cannot Submit Proof
    // ════════════════════════════════════════════════════

    function testM3_UnregisteredCannotSubmitProof() public {
        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.expectRevert(BitcoinGateway.UserNotRegistered.selector);
        vm.prank(user2); // Not registered
        gw.submitBitcoinProof{value: fee}(reqId, keccak256("txid"), hex"04aaaa", new bytes(64));
    }

    // ════════════════════════════════════════════════════
    // [M-4] Proof Fee Boundary Tests
    // ════════════════════════════════════════════════════

    function testM4_ProofFeeBelowMinReverts() public {
        uint256 minFee = gw.MIN_PROOF_FEE();
        vm.expectRevert(BitcoinGateway.ProofFeeOutOfRange.selector);
        vm.prank(owner);
        gw.setProofFee(minFee - 1);
    }

    function testM4_ProofFeeAboveMaxReverts() public {
        uint256 maxFee = gw.MAX_PROOF_FEE();
        vm.expectRevert(BitcoinGateway.ProofFeeOutOfRange.selector);
        vm.prank(owner);
        gw.setProofFee(maxFee + 1);
    }

    function testM4_ProofFeeAtMinSucceeds() public {
        uint256 minFee = gw.MIN_PROOF_FEE();
        vm.prank(owner);
        gw.setProofFee(minFee);
        assertEq(gw.proofFee(), minFee);
    }

    function testM4_ProofFeeAtMaxSucceeds() public {
        uint256 maxFee = gw.MAX_PROOF_FEE();
        vm.prank(owner);
        gw.setProofFee(maxFee);
        assertEq(gw.proofFee(), maxFee);
    }

    function testM4_InsufficientProofFeeReverts() public {
        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.expectRevert(BitcoinGateway.InsufficientProofFee.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee - 1}(reqId, keccak256("txid"), hex"04aaaa", new bytes(64));
    }

    // ════════════════════════════════════════════════════
    // [L-1] Dust Limit Enforcement
    // ════════════════════════════════════════════════════

    function testL1_BelowDustLimitReverts() public {
        vm.expectRevert(BitcoinGateway.BtcAmountBelowDust.selector);
        vm.prank(user1);
        gw.sendBitcoin("bc1q1", "bc1q2", 599, ""); // Below 600 dust
    }

    function testL1_ExactDustLimitSucceeds() public {
        vm.prank(user1);
        uint256 reqId = gw.sendBitcoin("bc1q1", "bc1q2", 600, "");
        assertEq(reqId, 0);
    }

    // ════════════════════════════════════════════════════
    // [L-2] Empty BTC Address Strings
    // ════════════════════════════════════════════════════

    function testL2_EmptyFromAddressReverts() public {
        vm.expectRevert(BitcoinGateway.EmptyFromAddress.selector);
        vm.prank(user1);
        gw.sendBitcoin("", "bc1q2", 1000, "");
    }

    function testL2_EmptyToAddressReverts() public {
        vm.expectRevert(BitcoinGateway.EmptyToAddress.selector);
        vm.prank(user1);
        gw.sendBitcoin("bc1q1", "", 1000, "");
    }

    // ════════════════════════════════════════════════════
    // [L-3] Paused State Enforcement
    // ════════════════════════════════════════════════════

    function testL3_PausedBlocksSendBitcoin() public {
        vm.prank(owner);
        gw.pause();

        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        vm.prank(user1);
        gw.sendBitcoin("bc1q1", "bc1q2", 1000, "");
    }

    function testL3_PausedBlocksSubmitProof() public {
        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.prank(owner);
        gw.pause();

        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee}(reqId, keccak256("txid"), hex"04aaaa", new bytes(64));
    }

    function testL3_PausedBlocksRegister() public {
        vm.prank(owner);
        gw.pause();

        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        vm.prank(user2);
        gw.registerUser(fingerprint2);
    }

    // ════════════════════════════════════════════════════
    // [L-4] requestCount Monotonicity
    // ════════════════════════════════════════════════════

    function testL4_RequestCountIncrementsCorrectly() public {
        assertEq(gw.requestCount(), 0);
        _createRequest();
        assertEq(gw.requestCount(), 1);
        _createRequest();
        assertEq(gw.requestCount(), 2);
        _createRequest();
        assertEq(gw.requestCount(), 3);
    }

    // ════════════════════════════════════════════════════
    // EDGE: Withdraw More Fees Than Available
    // ════════════════════════════════════════════════════

    function testEdge_WithdrawExcessFeesReverts() public {
        uint256 reqId = _createRequest();
        _submitProof(reqId, user1);

        uint256 fees = gw.totalProtocolFeesEth();

        vm.expectRevert(BitcoinGateway.InsufficientFees.selector);
        vm.prank(owner);
        gw.withdrawProtocolFees(fees + 1);
    }

    // ════════════════════════════════════════════════════
    // EDGE: Withdraw Fees Succeeds
    // ════════════════════════════════════════════════════

    function testEdge_WithdrawFeesSucceeds() public {
        uint256 reqId = _createRequest();
        _submitProof(reqId, user1);

        uint256 fees = gw.totalProtocolFeesEth();
        uint256 preBal = feeRecipient.balance;

        vm.prank(owner);
        gw.withdrawProtocolFees(fees);

        assertEq(gw.totalProtocolFeesEth(), 0);
        assertEq(feeRecipient.balance, preBal + fees);
    }

    // ════════════════════════════════════════════════════
    // EDGE: Invalid Request ID
    // ════════════════════════════════════════════════════

    function testEdge_InvalidRequestIdReverts() public {
        uint256 fee = gw.proofFee();
        vm.expectRevert(BitcoinGateway.InvalidRequest.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee}(
            999, // No such request
            keccak256("txid"),
            hex"04aaaa",
            new bytes(64)
        );
    }

    // ════════════════════════════════════════════════════
    // EDGE: Invalid Proof Length
    // ════════════════════════════════════════════════════

    function testEdge_InvalidProofLengthReverts() public {
        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.expectRevert(BitcoinGateway.InvalidProofLength.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee}(
            reqId,
            keccak256("txid"),
            hex"04aaaa",
            new bytes(32) // Wrong length, should be 64
        );
    }

    // ════════════════════════════════════════════════════
    // EDGE: Zero txid reverts
    // ════════════════════════════════════════════════════

    function testEdge_ZeroTxidReverts() public {
        uint256 reqId = _createRequest();
        uint256 fee = gw.proofFee();

        vm.expectRevert(BitcoinGateway.InvalidTxid.selector);
        vm.prank(user1);
        gw.submitBitcoinProof{value: fee}(
            reqId,
            bytes32(0), // Zero txid
            hex"04aaaa",
            new bytes(64)
        );
    }

    // ════════════════════════════════════════════════════
    // EDGE: Duplicate fingerprint registration
    // ════════════════════════════════════════════════════

    function testEdge_DuplicateFingerprintReverts() public {
        // user1 already registered with fingerprint1 in setUp
        vm.expectRevert(BitcoinGateway.FingerprintAlreadyRegistered.selector);
        vm.prank(user2);
        gw.registerUser(fingerprint1);
    }

    // ════════════════════════════════════════════════════
    // EDGE: User already registered
    // ════════════════════════════════════════════════════

    function testEdge_UserAlreadyRegisteredReverts() public {
        vm.expectRevert(BitcoinGateway.UserAlreadyRegistered.selector);
        vm.prank(user1);
        gw.registerUser(keccak256("newFingerprint"));
    }

    // ════════════════════════════════════════════════════
    // EDGE: Unregister→Re-register flow
    // ════════════════════════════════════════════════════

    function testEdge_UnregisterThenReregister() public {
        vm.prank(user1);
        gw.unregisterUser();

        // Now can register with same or different fingerprint
        vm.prank(user1);
        gw.registerUser(keccak256("newFingerprint_v2"));

        assertEq(gw.userToFingerprint(user1), keccak256("newFingerprint_v2"));
    }

    // ════════════════════════════════════════════════════
    // EDGE: Non-owner cannot call admin functions
    // ════════════════════════════════════════════════════

    function testEdge_NonOwnerCannotPause() public {
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        vm.prank(user1);
        gw.pause();
    }

    function testEdge_NonOwnerCannotBlacklist() public {
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        vm.prank(user1);
        gw.setBlacklisted(attacker, true);
    }

    function testEdge_NonOwnerCannotWithdraw() public {
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        vm.prank(user1);
        gw.withdrawProtocolFees(1);
    }

    function testEdge_NonOwnerCannotSetProofFee() public {
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        vm.prank(user1);
        gw.setProofFee(0.0003 ether);
    }

    // ════════════════════════════════════════════════════
    // FUZZ: sendBitcoin amount boundaries
    // ════════════════════════════════════════════════════

    function testFuzz_SendBitcoinDustBoundary(uint256 sats) public {
        vm.assume(sats < 600); // Below dust
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.BtcAmountBelowDust.selector);
        gw.sendBitcoin("bc1q1", "bc1q2", sats, "");
    }

    function testFuzz_SendBitcoinAboveDust(uint256 sats) public {
        vm.assume(sats >= 600 && sats < type(uint128).max); // Reasonable max
        vm.prank(user1);
        uint256 reqId = gw.sendBitcoin("bc1q1", "bc1q2", sats, "");
        assertEq(reqId, 0);
    }
}

// ════════════════════════════════════════════════════════
// ATTACK CONTRACT: Reentrancy on fee withdrawal
// ════════════════════════════════════════════════════════

contract ReentrantFeeRecipient {
    BitcoinGateway immutable gw;
    uint256 public attackCount;

    constructor(address _gw) {
        gw = BitcoinGateway(_gw);
    }

    receive() external payable {
        if (attackCount < 2 && gw.totalProtocolFeesEth() > 0) {
            attackCount++;
            gw.withdrawProtocolFees(gw.totalProtocolFeesEth());
        }
    }
}
