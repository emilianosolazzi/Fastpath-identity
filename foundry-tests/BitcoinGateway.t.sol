// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/BitcoinGateway.sol";

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
    address public relayerAddr = address(0xBEEF);
    address public feeRecipient = address(0xFEE);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public user3 = address(0x3333);

    bytes32 constant DUMMY_TXID = bytes32(uint256(0xdeadbeef));
    bytes32 constant FINGERPRINT_1 = bytes32(uint256(0xAA));
    bytes32 constant FINGERPRINT_2 = bytes32(uint256(0xBB));
    bytes constant DUMMY_PUBKEY = hex"0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
    bytes constant DUMMY_PROOF = hex"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";

    uint256 constant SEND_VALUE = 1 ether;
    uint256 constant SATS = 100_000;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        gateway = new BitcoinGateway(relayerAddr, feeRecipient);
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(user3, 100 ether);
        vm.deal(relayerAddr, 10 ether);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_constructor_setsOwner() public view {
        assertEq(gateway.owner(), owner, "owner mismatch");
    }

    function test_constructor_setsRelayer() public view {
        assertEq(gateway.relayer(), relayerAddr, "relayer mismatch");
    }

    function test_constructor_setsFeeRecipient() public view {
        assertEq(gateway.feeRecipient(), feeRecipient, "feeRecipient mismatch");
    }

    function test_constructor_initialState() public view {
        assertEq(gateway.requestCount(), 0, "requestCount should be 0");
        assertFalse(gateway.paused(), "should not be paused");
        assertEq(gateway.totalProtocolFeesEth(), 0, "fees should be 0");
    }

    function test_constructor_revertsZeroRelayer() public {
        vm.expectRevert(BitcoinGateway.ZeroRelayer.selector);
        new BitcoinGateway(address(0), feeRecipient);
    }

    function test_constructor_revertsZeroFeeRecipient() public {
        vm.expectRevert(BitcoinGateway.ZeroFeeRecipient.selector);
        new BitcoinGateway(relayerAddr, address(0));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SEND BITCOIN TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_sendBitcoin_createsRequest() public {
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: SEND_VALUE}(
            "bc1qsender", "bc1qreceiver", SATS, "test memo"
        );
        assertEq(id, 0, "first request should be 0");
        assertEq(gateway.requestCount(), 1, "requestCount should be 1");
    }

    function test_sendBitcoin_storesCorrectData() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}(
            "bc1qsender", "bc1qreceiver", SATS, "my memo"
        );

        BitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(0);
        assertEq(req.requester, user1, "requester mismatch");
        assertEq(req.amountSats, SATS, "sats mismatch");
        assertEq(req.amountEth, SEND_VALUE, "eth mismatch");
        assertFalse(req.fulfilled, "should not be fulfilled");
        assertEq(req.btcTxid, bytes32(0), "txid should be empty");
    }

    function test_sendBitcoin_multipleRequests() public {
        vm.startPrank(user1);
        uint256 id0 = gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");
        uint256 id1 = gateway.sendBitcoin{value: 2 ether}("c", "d", SATS, "");
        uint256 id2 = gateway.sendBitcoin{value: 3 ether}("e", "f", SATS, "");
        vm.stopPrank();

        assertEq(id0, 0);
        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(gateway.requestCount(), 3);
    }

    function test_sendBitcoin_revertsZeroValue() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.ZeroAmount.selector);
        gateway.sendBitcoin{value: 0}("a", "b", SATS, "");
    }

    function test_sendBitcoin_revertsEmptyFrom() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.EmptyFromAddress.selector);
        gateway.sendBitcoin{value: 1 ether}("", "b", SATS, "");
    }

    function test_sendBitcoin_revertsEmptyTo() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.EmptyToAddress.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "", SATS, "");
    }

    function test_sendBitcoin_revertsBelowDust() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.BtcAmountBelowDust.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "b", 599, "");
    }

    function test_sendBitcoin_exactDustLimit() public {
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 1 ether}("a", "b", 600, "");
        assertEq(id, 0, "exact dust limit should work");
    }

    function test_sendBitcoin_revertsWhenPaused() public {
        gateway.pause();
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");
    }

    function test_sendBitcoin_revertsWhenBlacklisted() public {
        gateway.setBlacklisted(user1, true);
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // FULFILL PAYMENT TESTS (CENTRALIZED RELAYER)
    // ══════════════════════════════════════════════════════════════════════════

    function test_fulfillPayment_success() public {
        // Create request
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Fulfill as centralized relayer
        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        BitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(0);
        assertTrue(req.fulfilled, "should be fulfilled");
        assertEq(req.btcTxid, DUMMY_TXID, "txid mismatch");
    }

    function test_fulfillPayment_recordsFulfillingRelayer() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        assertEq(gateway.requestToFulfillingRelayer(0), relayerAddr, "fulfilling relayer mismatch");
    }

    function test_fulfillPayment_collectsFees() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 0.25% of 1 ether = 0.0025 ether
        uint256 expectedFee = (SEND_VALUE * 25) / 10_000;
        assertEq(gateway.totalProtocolFeesEth(), expectedFee, "fee mismatch");
    }

    function test_fulfillPayment_revertsNotRelayer() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.NotAssignedRelayer.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsInvalidRequest() public {
        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.InvalidRequest.selector);
        gateway.fulfillPayment(99, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsAlreadyFulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsZeroTxid() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.InvalidTxid.selector);
        gateway.fulfillPayment(0, bytes32(0), DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_revertsInvalidProofLength() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.InvalidProofLength.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, hex"0011");
    }

    function test_fulfillPayment_revertsWhenPaused() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        gateway.pause();

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // FULFILL AS DECENTRALIZED RELAYER TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_fulfillAsRelayer_success() public {
        // Register user2 as relayer
        vm.prank(user2);
        gateway.registerRelayer(FINGERPRINT_1);

        // Create request
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Fulfill as registered relayer
        vm.prank(user2);
        gateway.fulfillPaymentAsRelayer(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should be fulfilled");
        assertEq(gateway.requestToFulfillingRelayer(0), user2, "relayer mismatch");
    }

    function test_fulfillAsRelayer_splitsFees() public {
        // Register user2 as relayer
        vm.prank(user2);
        gateway.registerRelayer(FINGERPRINT_1);

        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        uint256 relayerBalBefore = user2.balance;

        vm.prank(user2);
        gateway.fulfillPaymentAsRelayer(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // Total fee = 0.25% of 1 ether = 0.0025 ether
        uint256 totalFee = (SEND_VALUE * 25) / 10_000;
        // Relayer gets 0.17% of the 0.25% = (totalFee * 17) / 25
        uint256 relayerFee = (totalFee * 17) / 25;
        uint256 protocolFee = totalFee - relayerFee;

        assertEq(gateway.totalProtocolFeesEth(), protocolFee, "protocol fee mismatch");
        assertEq(user2.balance, relayerBalBefore + relayerFee, "relayer should receive fee");
    }

    function test_fulfillAsRelayer_revertsNotRegistered() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.RelayerNotRegistered.selector);
        gateway.fulfillPaymentAsRelayer(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CANCEL STUCK REQUEST TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_cancelStuckRequest_success() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        uint256 userBalBefore = user1.balance;

        // Warp 25 hours ahead
        vm.warp(block.timestamp + 25 hours);

        // Expect RefundIssued event
        vm.expectEmit(true, true, false, true);
        emit BitcoinGateway.RefundIssued(0, user1, SEND_VALUE);

        vm.prank(user1);
        gateway.cancelStuckRequest(0);

        // Request should be marked fulfilled (prevents double-cancel)
        assertTrue(gateway.getPaymentRequest(0).fulfilled, "cancel should set fulfilled");
        // ETH should be refunded
        assertEq(user1.balance, userBalBefore + SEND_VALUE, "user should get ETH refund");
        // amountEth should be zeroed
        assertEq(gateway.getPaymentRequest(0).amountEth, 0, "amountEth should be zeroed");
    }

    function test_cancelStuckRequest_preventsDoubleCancel() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.warp(block.timestamp + 25 hours);

        vm.prank(user1);
        gateway.cancelStuckRequest(0);

        // Second cancel should revert (marked as fulfilled)
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.cancelStuckRequest(0);
    }

    function test_cancelStuckRequest_revertsTooSoon() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Only 23 hours
        vm.warp(block.timestamp + 23 hours);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.RequestNotStuck.selector);
        gateway.cancelStuckRequest(0);
    }

    function test_cancelStuckRequest_revertsNotRequester() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.warp(block.timestamp + 25 hours);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.NotRequester.selector);
        gateway.cancelStuckRequest(0);
    }

    function test_cancelStuckRequest_revertsAlreadyFulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.warp(block.timestamp + 25 hours);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.cancelStuckRequest(0);
    }

    function test_cancelStuckRequest_revertsInvalidRequest() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.InvalidRequest.selector);
        gateway.cancelStuckRequest(99);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REQUEST EXPIRATION TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_fulfillPayment_revertsExpired() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Warp past 7 days
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.RequestExpired.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_fulfillPayment_worksBeforeExpiry() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Warp to just under 7 days (6 days 23 hours)
        vm.warp(block.timestamp + 6 days + 23 hours);

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should fulfill before expiry");
    }

    function test_cancelExpiredRequest_success() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        uint256 userBalBefore = user1.balance;

        // Warp past 7 days
        vm.warp(block.timestamp + 7 days + 1);

        // Anyone can cancel expired requests
        vm.prank(user2);
        gateway.cancelExpiredRequest(0);

        // Refund goes to requester (user1), not caller (user2)
        assertEq(user1.balance, userBalBefore + SEND_VALUE, "requester should get refund");
        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should be marked fulfilled");
        assertEq(gateway.getPaymentRequest(0).amountEth, 0, "amountEth should be zeroed");
    }

    function test_cancelExpiredRequest_revertsTooSoon() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        // Only 6 days - not expired yet
        vm.warp(block.timestamp + 6 days);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.RequestNotStuck.selector);
        gateway.cancelExpiredRequest(0);
    }

    function test_cancelExpiredRequest_revertsAlreadyFulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.warp(block.timestamp + 8 days);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.cancelExpiredRequest(0);
    }

    function test_isRequestExpired() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        assertFalse(gateway.isRequestExpired(0), "should not be expired yet");

        vm.warp(block.timestamp + 7 days + 1);
        assertTrue(gateway.isRequestExpired(0), "should be expired after 7 days");
    }

    function test_isRequestExpired_falseAfterFulfill() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.warp(block.timestamp + 8 days);
        assertFalse(gateway.isRequestExpired(0), "fulfilled request should return false");
    }

    function test_getMaxRequestAge() public view {
        assertEq(gateway.getMaxRequestAge(), 7 days, "max age should be 7 days");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RELAYER MANAGEMENT TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_registerRelayer_success() public {
        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        assertEq(gateway.fingerprintToRelayer(FINGERPRINT_1), user1, "fingerprint mapping wrong");
        assertEq(gateway.relayerToFingerprint(user1), FINGERPRINT_1, "relayer mapping wrong");
    }

    function test_registerRelayer_revertsDuplicateFingerprint() public {
        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.FingerprintAlreadyRegistered.selector);
        gateway.registerRelayer(FINGERPRINT_1);
    }

    function test_registerRelayer_revertsAlreadyRegistered() public {
        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.RelayerAlreadyRegistered.selector);
        gateway.registerRelayer(FINGERPRINT_2);
    }

    function test_unregisterRelayer_success() public {
        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        vm.prank(user1);
        gateway.unregisterRelayer();

        assertEq(gateway.fingerprintToRelayer(FINGERPRINT_1), address(0), "fingerprint should be cleared");
        assertEq(gateway.relayerToFingerprint(user1), bytes32(0), "relayer mapping should be cleared");
    }

    function test_unregisterRelayer_revertsNotRegistered() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.RelayerNotRegistered.selector);
        gateway.unregisterRelayer();
    }

    function test_isFingerprintAvailable() public {
        assertTrue(gateway.isFingerprintAvailable(FINGERPRINT_1), "should be available");

        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        assertFalse(gateway.isFingerprintAvailable(FINGERPRINT_1), "should not be available");
    }

    function test_getRelayerByFingerprint() public {
        assertEq(gateway.getRelayerByFingerprint(FINGERPRINT_1), address(0), "should be zero");

        vm.prank(user1);
        gateway.registerRelayer(FINGERPRINT_1);

        assertEq(gateway.getRelayerByFingerprint(FINGERPRINT_1), user1, "should be user1");
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

    function test_updateRelayer() public {
        gateway.updateRelayer(user1);
        assertEq(gateway.relayer(), user1, "relayer not updated");
    }

    function test_updateRelayer_revertsZero() public {
        vm.expectRevert(BitcoinGateway.ZeroRelayer.selector);
        gateway.updateRelayer(address(0));
    }

    function test_updateRelayer_revertsNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.NotOwner.selector);
        gateway.updateRelayer(user2);
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
        // Create and fulfill a request to generate fees
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        uint256 fees = gateway.totalProtocolFeesEth();
        assertGt(fees, 0, "should have fees");

        uint256 recipientBalBefore = feeRecipient.balance;
        gateway.withdrawProtocolFees(fees);

        assertEq(gateway.totalProtocolFeesEth(), 0, "fees should be zero after withdraw");
        assertEq(feeRecipient.balance, recipientBalBefore + fees, "recipient should receive fees");
    }

    function test_withdrawProtocolFees_partial() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

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
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        (bool fulfilled, bytes32 txid) = gateway.getPaymentStatus(0);
        assertFalse(fulfilled, "should not be fulfilled");
        assertEq(txid, bytes32(0), "txid should be zero");
    }

    function test_getPaymentStatus_fulfilled() public {
        vm.prank(user1);
        gateway.sendBitcoin{value: SEND_VALUE}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

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
    // RECEIVE ETH TEST
    // ══════════════════════════════════════════════════════════════════════════

    function test_receiveEth() public {
        vm.prank(user1);
        (bool success, ) = address(gateway).call{value: 1 ether}("");
        assertTrue(success, "should accept ETH");
        assertEq(address(gateway).balance, 1 ether, "balance mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // INTEGRATION / E2E TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_e2e_fullLifecycle() public {
        // 1. User sends a request
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 2 ether}(
            "bc1qsender", "bc1qreceiver", 50000, "e2e test"
        );

        // 2. Verify request state
        (bool fulfilled, ) = gateway.getPaymentStatus(id);
        assertFalse(fulfilled, "should be pending");

        // 3. Centralized relayer fulfills
        vm.prank(relayerAddr);
        gateway.fulfillPayment(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 4. Verify fulfilled
        (fulfilled, ) = gateway.getPaymentStatus(id);
        assertTrue(fulfilled, "should be fulfilled");

        // 5. Withdraw fees
        uint256 fees = gateway.totalProtocolFeesEth();
        uint256 expectedFee = (2 ether * 25) / 10_000; // 0.005 ether
        assertEq(fees, expectedFee, "fee calc wrong");

        uint256 recipientBal = feeRecipient.balance;
        gateway.withdrawProtocolFees(fees);
        assertEq(feeRecipient.balance, recipientBal + expectedFee, "recipient should get fees");
    }

    function test_e2e_decentralizedRelayerFlow() public {
        // 1. Register relayer
        vm.prank(user2);
        gateway.registerRelayer(FINGERPRINT_1);

        // 2. User sends request
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 10 ether}(
            "bc1qfrom", "bc1qto", 200000, "decentralized"
        );

        // 3. Registered relayer fulfills
        uint256 relayerBal = user2.balance;
        vm.prank(user2);
        gateway.fulfillPaymentAsRelayer(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 4. Verify fee split
        uint256 totalFee = (10 ether * 25) / 10_000; // 0.025 ether
        uint256 relayerFee = (totalFee * 17) / 25;     // ~0.017 ether
        uint256 protocolFee = totalFee - relayerFee;

        assertEq(user2.balance, relayerBal + relayerFee, "relayer fee wrong");
        assertEq(gateway.totalProtocolFeesEth(), protocolFee, "protocol fee wrong");

        // 5. Relayer unregisters
        vm.prank(user2);
        gateway.unregisterRelayer();
        assertTrue(gateway.isFingerprintAvailable(FINGERPRINT_1), "fingerprint should be free");
    }

    function test_e2e_pauseBlocksEverything() public {
        // Create a request first
        vm.prank(user1);
        gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");

        // Pause
        gateway.pause();

        // All operations should fail
        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        vm.prank(user2);
        vm.expectRevert(BitcoinGateway.ContractPaused.selector);
        gateway.registerRelayer(FINGERPRINT_1);

        // Unpause and verify recovery
        gateway.unpause();

        vm.prank(relayerAddr);
        gateway.fulfillPayment(0, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
        assertTrue(gateway.getPaymentRequest(0).fulfilled, "should work after unpause");
    }

    function test_e2e_blacklistBlocksUser() public {
        // Blacklist user1
        gateway.setBlacklisted(user1, true);

        vm.prank(user1);
        vm.expectRevert(BitcoinGateway.AddressBlacklisted.selector);
        gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");

        // Un-blacklist
        gateway.setBlacklisted(user1, false);

        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 1 ether}("a", "b", SATS, "");
        assertEq(id, 0, "should work after un-blacklist");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // NO-OP IDEMPOTENCY TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_e2e_cancelRefundFlow() public {
        // 1. User deposits 5 ETH
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 5 ether}("a", "b", SATS, "cancel test");

        uint256 contractBal = address(gateway).balance;
        assertEq(contractBal, 5 ether, "contract should hold deposit");

        // 2. Wait 25 hours
        vm.warp(block.timestamp + 25 hours);

        // 3. Cancel and get refund
        uint256 userBalBefore = user1.balance;
        vm.prank(user1);
        gateway.cancelStuckRequest(id);

        // 4. Verify refund
        assertEq(user1.balance, userBalBefore + 5 ether, "user should get 5 ETH back");
        assertEq(address(gateway).balance, 0, "contract should be empty");
        assertTrue(gateway.getPaymentRequest(id).fulfilled, "should be marked fulfilled");

        // 5. Cannot fulfill after cancel
        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.AlreadyFulfilled.selector);
        gateway.fulfillPayment(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);
    }

    function test_e2e_expirationFlow() public {
        // 1. User deposits
        vm.prank(user1);
        uint256 id = gateway.sendBitcoin{value: 3 ether}("a", "b", SATS, "expire test");

        // 2. Relayer can't fulfill after 7 days
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(relayerAddr);
        vm.expectRevert(BitcoinGateway.RequestExpired.selector);
        gateway.fulfillPayment(id, DUMMY_TXID, DUMMY_PUBKEY, DUMMY_PROOF);

        // 3. Anyone can trigger refund
        uint256 userBalBefore = user1.balance;
        vm.prank(user3);
        gateway.cancelExpiredRequest(id);

        // 4. Requester (user1) gets refund, not caller (user3)
        assertEq(user1.balance, userBalBefore + 3 ether, "requester should get refund");
        assertTrue(gateway.getPaymentRequest(id).fulfilled, "should be marked fulfilled");
    }

    function test_pause_idempotent() public {
        gateway.pause();
        gateway.pause(); // Should not revert
        assertTrue(gateway.paused());
    }

    function test_unpause_idempotent() public {
        gateway.unpause(); // Already unpaused, should not revert
        assertFalse(gateway.paused());
    }

    function test_updateRelayer_sameValue() public {
        gateway.updateRelayer(relayerAddr); // Same value, should not revert
        assertEq(gateway.relayer(), relayerAddr);
    }

    function test_setBlacklisted_sameValue() public {
        gateway.setBlacklisted(user1, false); // Already false, should not revert
    }

    // Allow this contract to receive ETH (for fee withdrawal)
    receive() external payable {}
}

