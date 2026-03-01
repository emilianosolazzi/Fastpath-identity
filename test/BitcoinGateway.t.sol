// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/Bitcoingateway.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function expectRevert(bytes4) external;
    function expectEmit(bool, bool, bool, bool) external;
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function warp(uint256 timestamp) external;
}

contract Test {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }

    function assertTrue(bool condition) internal pure {
        require(condition, "assertion failed");
    }

    function assertFalse(bool condition, string memory message) internal pure {
        require(!condition, message);
    }

    function assertFalse(bool condition) internal pure {
        require(!condition, "expected false");
    }

    function assertEq(uint256 a, uint256 b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "values not equal");
    }

    function assertEq(address a, address b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "addresses not equal");
    }

    function assertEq(bool a, bool b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(bytes32 a, bytes32 b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertGt(uint256 a, uint256 b, string memory message) internal pure {
        require(a > b, message);
    }

    function assertLt(uint256 a, uint256 b, string memory message) internal pure {
        require(a < b, message);
    }

    function assertGe(uint256 a, uint256 b, string memory message) internal pure {
        require(a >= b, message);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// TEST CONTRACT
// ══════════════════════════════════════════════════════════════════════════════

contract BitcoinGatewayTest is Test {
    BitcoinGateway public gateway;

    address public owner = address(this);
    address public registeredUser = address(0xBEEF);
    address public feeRecipient = address(0xFEE);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public user3 = address(0x3333);

    bytes32 constant DUMMY_TXID = bytes32(uint256(0xdeadbeef));
    bytes32 constant FINGERPRINT_1 = bytes32(uint256(0xAA));
    bytes32 constant FINGERPRINT_2 = bytes32(uint256(0xBB));
    bytes constant DUMMY_PUBKEY =
        hex"0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
    bytes constant DUMMY_PROOF =
        hex"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";

    uint256 constant RELAY_FEE = 0.001 ether; // ETH paid by user at proof submission
    uint256 constant SATS = 100_000;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        gateway = new BitcoinGateway(feeRecipient);
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(user3, 100 ether);
        vm.deal(registeredUser, 10 ether);
        // Register the default user so they can call submitBitcoinProof
        vm.prank(registeredUser);
        gateway.registerUser(bytes32(uint256(0xCC)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_constructor_setsOwner() public view {
        assertEq(gateway.owner(), owner, "owner mismatch");
    }

    function test_constructor_setsFeeRecipient() public view {
        assertEq(gateway.feeRecipient(), feeRecipient, "feeRecipient mismatch");
    }

    function test_constructor_initialState() public view {
        assertEq(gateway.requestCount(), 0, "requestCount should be 0");
        assertFalse(gateway.paused(), "should not be paused");
        assertEq(gateway.totalProtocolFeesEth(), 0, "fees should be 0");
    }

    function test_constructor_revertsZeroFeeRecipient() public {
        vm.expectRevert(BitcoinGateway.ZeroFeeRecipient.selector);
        new BitcoinGateway(address(0));
    }
    // ══════════════════════════════════════════════════════════════════════════
    // SEND BITCOIN TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_sendBitcoin_createsRequest() public {
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin("bc1qsender", "bc1qreceiver", SATS, "test memo");
        assertEq(id, 0, "first request should be 0");
        assertEq(gateway.requestCount(), 1, "requestCount should be 1");
    }

    function test_sendBitcoin_storesCorrectData() public {
        vm.prank(user1);
        gateway.sendBitcoin("bc1qsender", "bc1qreceiver", SATS, "my memo");

        BitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(0);
        assertEq(req.requester, user1, "requester mismatch");
        assertEq(req.amountSats, SATS, "sats mismatch");
        assertFalse(req.fulfilled, "should not be fulfilled");
        assertEq(req.btcTxid, bytes32(0), "txid should be empty");
    }

    function test_sendBitcoin_multipleRequests() public {
        vm.startPrank(user1);
        uint256 id0 = gateway.sendBitcoin("a", "b", SATS, "");
        uint256 id1 = gateway.sendBitcoin("c", "d", SATS, "");
        uint256 id2 = gateway.sendBitcoin("e", "f", SATS, "");
        vm.stopPrank();

        assertEq(id0, 0);
        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(gateway.requestCount(), 3);
    }

    function test_sendBitcoin_revertsEmptyFrom() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.EmptyFromAddress.selector);
        gateway.sendBitcoin("", "b", SATS, "");
    }

    function test_sendBitcoin_revertsEmptyTo() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.EmptyToAddress.selector);
        gateway.sendBitcoin("a", "", SATS, "");
    }

    function test_sendBitcoin_revertsBelowDust() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.BtcAmountBelowDust.selector);
        gateway.sendBitcoin("a", "b", 599, "");
    }

    function test_sendBitcoin_exactDustLimit() public {
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin("a", "b", 600, "");
        assertEq(id, 0, "exact dust limit should work");
    }

    function test_sendBitcoin_revertsWhenPaused() public {
        gateway.pause();
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.sendBitcoin("a", "b", SATS, "");
    }

    function test_sendBitcoin_revertsWhenBlacklisted() public {
        gateway.setBlacklisted(user1, true);
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        gateway.sendBitcoin("a", "b", SATS, "");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // FULFILL PAYMENT TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_fulfillPayment_revertsInsufficientFee() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.InsufficientProofFee.selector);
        gateway.submitBitcoinProof{value: 0}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsInvalidRequest() public {
        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.InvalidRequest.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(99, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsAlreadyFulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsZeroTxid() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.InvalidTxid.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, bytes32(0), DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsInvalidProofLength() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.InvalidProofLength.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, hex"0011");
    }

    function test_fulfillPayment_revertsWhenPaused() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        gateway.pause();

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // FULFILL AS REGISTERED USER TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_submitProof_success() public {
        // Register user2 as approved user
        vm.prank(user2);
        gateway.registerUser(FINGERPRINT_1);

        // Create request
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        // Submit proof as registered user (paying RELAY_FEE)
        vm.prank(user2);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should be fulfilled");
        assertEq(gateway.requestToProver(0), user2, "prover mismatch");
    }

    function test_submitProof_collectsFee() public {
        // Register user2 as approved user
        vm.prank(user2);
        gateway.registerUser(FINGERPRINT_1);

        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(user2);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // Full RELAY_FEE goes to protocol; user earns in BTC off-chain
        assertEq(gateway.totalProtocolFeesEth(), RELAY_FEE, "protocol should receive full fee");
    }

    function test_submitProof_revertsNotRegistered() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.UserNotRegistered.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // USER MANAGEMENT TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_registerUser_success() public {
        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        assertEq(gateway.fingerprintToUser(FINGERPRINT_1), user1, "fingerprint mapping wrong");
        assertEq(gateway.userToFingerprint(user1), FINGERPRINT_1, "user mapping wrong");
    }

    function test_registerUser_revertsDuplicateFingerprint() public {
        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.FingerprintAlreadyRegistered.selector);
        gateway.registerUser(FINGERPRINT_1);
    }

    function test_registerUser_revertsAlreadyRegistered() public {
        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.UserAlreadyRegistered.selector);
        gateway.registerUser(FINGERPRINT_2);
    }

    function test_unregisterUser_success() public {
        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        vm.prank(user1);
        gateway.unregisterUser();

        assertEq(gateway.fingerprintToUser(FINGERPRINT_1), address(0), "fingerprint should be cleared");
        assertEq(gateway.userToFingerprint(user1), bytes32(0), "user mapping should be cleared");
    }

    function test_unregisterUser_revertsNotRegistered() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.UserNotRegistered.selector);
        gateway.unregisterUser();
    }

    function test_isFingerprintAvailable() public {
        assertTrue(gateway.isFingerprintAvailable(FINGERPRINT_1), "should be available");

        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        assertFalse(gateway.isFingerprintAvailable(FINGERPRINT_1), "should not be available");
    }

    function test_getUserByFingerprint() public {
        assertEq(gateway.getUserByFingerprint(FINGERPRINT_1), address(0), "should be zero");

        vm.prank(user1);
        gateway.registerUser(FINGERPRINT_1);

        assertEq(gateway.getUserByFingerprint(FINGERPRINT_1), user1, "should be user1");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_pause_unpause() public {
        assertFalse(gateway.paused());
        gateway.pause();
        assertTrue(gateway.paused());
        gateway.unpause();
        assertFalse(gateway.paused());
    }

    function test_pause_revertsNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.pause();
    }

    function test_unpause_revertsNotOwner() public {
        gateway.pause();
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.unpause();
    }

    function test_transferOwnership() public {
        gateway.transferOwnership(user1);
        assertEq(gateway.owner(), user1, "owner not transferred");

        // Old owner should fail
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.transferOwnership(user2);
    }

    function test_transferOwnership_revertsZero() public {
        vm.expectRevert(BitcoinGateway.ZeroAddress.selector);
        gateway.transferOwnership(address(0));
    }

    function test_updateFeeRecipient() public {
        gateway.updateFeeRecipient(user1);
        assertEq(gateway.feeRecipient(), user1, "feeRecipient not updated");
    }

    function test_updateFeeRecipient_revertsZero() public {
        vm.expectRevert(BitcoinGateway.ZeroFeeRecipient.selector);
        gateway.updateFeeRecipient(address(0));
    }

    function test_updateFeeRecipient_revertsNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.updateFeeRecipient(user2);
    }

    function test_setBlacklisted() public {
        assertFalse(gateway.blacklisted(user1));
        gateway.setBlacklisted(user1, true);
        assertTrue(gateway.blacklisted(user1));
        gateway.setBlacklisted(user1, false);
        assertFalse(gateway.blacklisted(user1));
    }

    function test_setBlacklisted_revertsZeroAddress() public {
        vm.expectRevert(BitcoinGateway.ZeroAddress.selector);
        gateway.setBlacklisted(address(0), true);
    }

    function test_setBlacklisted_revertsNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.setBlacklisted(user2, true);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // WITHDRAW FEES TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_withdrawProtocolFees_success() public {
        // Create and fulfill a request to generate fees (sendBitcoin is free)
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        uint256 fees = gateway.totalProtocolFeesEth();
        assertGt(fees, 0, "should have fees");

        uint256 recipientBalBefore = feeRecipient.balance;
        gateway.withdrawProtocolFees(fees);

        assertEq(gateway.totalProtocolFeesEth(), 0, "fees should be zero after withdraw");
        assertEq(feeRecipient.balance, recipientBalBefore + fees, "recipient should receive fees");
    }

    function test_withdrawProtocolFees_partial() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        uint256 fees = gateway.totalProtocolFeesEth();
        uint256 halfFees = fees / 2;

        gateway.withdrawProtocolFees(halfFees);
        assertEq(gateway.totalProtocolFeesEth(), fees - halfFees, "partial withdraw mismatch");
    }

    function test_withdrawProtocolFees_revertsInsufficientFees() public {
        vm.expectRevert(BitcoinGateway.InsufficientFees.selector);
        gateway.withdrawProtocolFees(1);
    }

    function test_withdrawProtocolFees_revertsNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.withdrawProtocolFees(0);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW FUNCTION TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_getPaymentRequest_revertsInvalid() public {
        vm.expectRevert(BitcoinGateway.InvalidRequest.selector);
        gateway.getPaymentRequest(0);
    }

    function test_getPaymentStatus_unfulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        (bool fulfilled, bytes32 txid) = gateway.getPaymentStatus(0);
        assertFalse(fulfilled, "should not be fulfilled");
        assertEq(txid, bytes32(0), "txid should be zero");
    }

    function test_getPaymentStatus_fulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        (bool fulfilled, bytes32 txid) = gateway.getPaymentStatus(0);
        assertTrue(fulfilled, "should be fulfilled");
        assertEq(txid, DUMMY_TXID, "txid mismatch");
    }

    function test_getPaymentStatus_invalidRequestReturnsFalse() public view {
        (bool fulfilled, bytes32 txid) = gateway.getPaymentStatus(999);
        assertFalse(fulfilled, "invalid request should return false");
        assertEq(txid, bytes32(0), "invalid request txid should be zero");
    }

    function test_canUserSend() public view {
        assertTrue(gateway.canUserSend(user1), "user1 should be able to send");
    }

    function test_canUserSend_paused() public {
        gateway.pause();
        assertFalse(gateway.canUserSend(user1), "should be false when paused");
    }

    function test_canUserSend_blacklisted() public {
        gateway.setBlacklisted(user1, true);
        assertFalse(gateway.canUserSend(user1), "should be false when blacklisted");
    }

    function test_getMinBtcDust() public view {
        assertEq(gateway.getMinBtcDust(), 600, "dust limit should be 600");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PLAIN ETH REJECTION TEST (no receive() — only submitBitcoinProof accepts ETH)
    // ══════════════════════════════════════════════════════════════════════════

    function test_plainEth_isRejected() public {
        vm.prank(user1);
        (bool success,) = address(gateway).call{value: 1 ether}("");
        assertFalse(success, "contract must not accept plain ETH transfers");
        assertEq(address(gateway).balance, 0, "balance should remain zero");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // INTEGRATION / E2E TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_e2e_fullLifecycle() public {
        // 1. User registers a Bitcoin payment intent — completely free, no ETH locked
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin("bc1qsender", "bc1qreceiver", 50000, "e2e test");

        // 2. Verify request state
        (bool fulfilled,) = gateway.getPaymentStatus(id);
        assertFalse(fulfilled, "should be pending");
        assertEq(address(gateway).balance, 0, "no ETH should be locked");

        // 3. Registered user fulfills on-chain after doing the BTC send;
        //    user pays RELAY_FEE which goes entirely to the protocol treasury
        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 4. Verify fulfilled
        (fulfilled,) = gateway.getPaymentStatus(id);
        assertTrue(fulfilled, "should be fulfilled");

        // 5. Protocol has collected the full RELAY_FEE; withdraw to fee recipient
        uint256 fees = gateway.totalProtocolFeesEth();
        assertEq(fees, RELAY_FEE, "protocol should have exactly RELAY_FEE");

        uint256 recipientBal = feeRecipient.balance;
        gateway.withdrawProtocolFees(fees);
        assertEq(feeRecipient.balance, recipientBal + RELAY_FEE, "fee recipient should get RELAY_FEE");
    }

    function test_e2e_registeredUserFlow() public {
        // 1. Register new user (machine registration)
        vm.prank(user2);
        gateway.registerUser(FINGERPRINT_1);

        // 2. User registers payment intent — free, no ETH locked
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin("bc1qfrom", "bc1qto", 200000, "decentralized");
        assertEq(address(gateway).balance, 0, "no ETH locked after sendBitcoin");

        // 3. User submits proof after doing the BTC send; pays RELAY_FEE to protocol
        uint256 userBalBefore = user2.balance;
        vm.prank(user2);
        gateway.submitBitcoinProof{value: RELAY_FEE}(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 4. Verify: full RELAY_FEE goes to protocol; user earns in BTC off-chain
        assertEq(gateway.totalProtocolFeesEth(), RELAY_FEE, "protocol should receive full RELAY_FEE");
        // User spent RELAY_FEE + gas (balance decreased, not increased)
        assertLt(user2.balance, userBalBefore, "user balance should decrease by fee");

        // 5. User unregisters their machine
        vm.prank(user2);
        gateway.unregisterUser();
        assertTrue(gateway.isFingerprintAvailable(FINGERPRINT_1), "fingerprint should be free");
    }

    function test_e2e_pauseBlocksEverything() public {
        // Create a request first (free — no ETH needed)
        vm.prank(user1);
        gateway.sendBitcoin("a", "b", SATS, "");

        // Pause
        gateway.pause();

        // All operations should fail while paused
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.sendBitcoin("a", "b", SATS, "");

        vm.prank(registeredUser);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.registerUser(FINGERPRINT_1);

        // Unpause and verify recovery
        gateway.unpause();

        vm.prank(registeredUser);
        gateway.submitBitcoinProof{value: RELAY_FEE}(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should work after unpause");
    }

    function test_e2e_blacklistBlocksUser() public {
        // Blacklist user1
        gateway.setBlacklisted(user1, true);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        gateway.sendBitcoin("a", "b", SATS, "");

        // Un-blacklist
        gateway.setBlacklisted(user1, false);

        vm.prank(user1);
        uint256 id = gateway.sendBitcoin("a", "b", SATS, "");
        assertEq(id, 0, "should work after un-blacklist");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // NO-OP IDEMPOTENCY TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_pause_idempotent() public {
        gateway.pause();
        gateway.pause(); // Should not revert
        assertTrue(gateway.paused());
    }

    function test_unpause_idempotent() public {
        gateway.unpause(); // Already unpaused, should not revert
        assertFalse(gateway.paused());
    }

    function test_setBlacklisted_sameValue() public {
        gateway.setBlacklisted(user1, false); // Already false, should not revert
    }

    // Allow this contract to receive ETH (for fee withdrawal)
    receive() external payable {}
}
