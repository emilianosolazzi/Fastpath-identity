// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "contracts/Fastpathidentity.sol";

/**
 * @title FastPathIdentity — Security Audit Edge-Case Tests
 * @author Security audit by automated analysis
 * @notice Targets: reentrancy, fee manipulation, relink race conditions,
 *         fund isolation, ownership takeover, and accounting invariants.
 *
 * Findings tested:
 *   [H-1] Fee/withdrawal accounting isolation (accumulatedFees vs pendingWithdrawals)
 *   [H-2] Relink race: finalizeRelink after newEvm registered elsewhere
 *   [H-3] Emergency stop bypass via direct storage manipulation
 *   [H-4] Pull-payment reentrancy on withdrawPendingFunds
 *   [M-1] Owner can drain user pending funds via withdrawFees
 *   [M-2] Old EVM retains hasControl after relink (stale cache)
 *   [M-3] receive() ETH goes to accumulatedFees — can inflate withdrawable
 *   [M-4] cancelRelink uses activeEvm but checks btcToEvm for registration
 *   [L-1] setRegistrationFee can be set to MAX then lowered (fee griefing)
 *   [L-2] Duplicate setReceivePreference reverts (no-op prevention)
 */
contract FastPathIdentitySecurityTest is Test {
    FastPathIdentity identity;

    address owner = address(0xA11CE);
    address user1 = address(0xB0B);
    address user2 = address(0xCAFE);
    address user3 = address(0xDEAD);
    address attacker = address(0x666);

    // Known test keypair (secp256k1) — we use storage manipulation to bypass sig checks
    bytes20 hash160_1 = bytes20(keccak256("btc_addr_1"));
    bytes20 hash160_2 = bytes20(keccak256("btc_addr_2"));
    bytes20 hash160_3 = bytes20(keccak256("btc_addr_3"));

    function setUp() public {
        vm.prank(owner);
        identity = new FastPathIdentity(0); // zero fee for testing
    }

    // ════════════════════════════════════════════════════════
    // HELPERS — write directly to storage to bypass sig verification
    // ════════════════════════════════════════════════════════

    function _registerDirect(bytes20 btcHash, address evm) internal {
        // btcToEvm mapping: slot = keccak256(abi.encode(btcHash, 6))
        bytes32 btcToEvmSlot = keccak256(abi.encode(btcHash, uint256(6)));
        vm.store(address(identity), btcToEvmSlot, bytes32(uint256(uint160(evm))));

        // evmToBtc mapping: slot = keccak256(abi.encode(evm, 7))
        bytes32 evmToBtcSlot = keccak256(abi.encode(evm, uint256(7)));
        vm.store(address(identity), evmToBtcSlot, bytes32(btcHash));

        // lastLinkTime mapping: slot = keccak256(abi.encode(btcHash, 8))
        bytes32 lastLinkSlot = keccak256(abi.encode(btcHash, uint256(8)));
        vm.store(address(identity), lastLinkSlot, bytes32(block.timestamp));

        // activeEvm: private mapping at slot 11
        bytes32 activeEvmSlot = keccak256(abi.encode(btcHash, uint256(11)));
        vm.store(address(identity), activeEvmSlot, bytes32(uint256(uint160(evm))));
    }

    function _setPendingRelink(bytes20 btcHash, address newEvm, uint256 unlockTime) internal {
        // pendingRelinks: slot 10, struct { address newEvm, uint256 unlockTime, bool exists }
        bytes32 baseSlot = keccak256(abi.encode(btcHash, uint256(10)));
        // Slot+0: newEvm (address)
        vm.store(address(identity), baseSlot, bytes32(uint256(uint160(newEvm))));
        // Slot+1: unlockTime (uint256)
        vm.store(address(identity), bytes32(uint256(baseSlot) + 1), bytes32(unlockTime));
        // Slot+2: exists (bool)
        vm.store(address(identity), bytes32(uint256(baseSlot) + 2), bytes32(uint256(1)));
    }

    function _setLastLinkTime(bytes20 btcHash, uint256 time) internal {
        bytes32 slot = keccak256(abi.encode(btcHash, uint256(8)));
        vm.store(address(identity), slot, bytes32(time));
    }

    // ════════════════════════════════════════════════════════
    // [H-1] Fee/Withdrawal Accounting Isolation
    // ════════════════════════════════════════════════════════

    /// @notice accumulatedFees and pendingWithdrawals use the SAME ETH balance.
    ///         If withdrawFees drains contract ETH, user withdrawPendingFunds may fail.
    function testH1_FeeWithdrawalIsolation() public {
        _registerDirect(hash160_1, user1);

        // User1 opts into ViaHash160
        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // Someone sends 1 ETH via receiveFunds (credited to pendingWithdrawals)
        vm.deal(user2, 2 ether);
        vm.prank(user2);
        identity.receiveFunds{value: 1 ether}(hash160_1);
        assertEq(identity.pendingWithdrawals(user1), 1 ether);

        // Someone sends ETH directly to contract (goes to accumulatedFees via receive())
        vm.deal(attacker, 5 ether);
        vm.prank(attacker);
        (bool sent,) = address(identity).call{value: 2 ether}("");
        assertTrue(sent);
        assertEq(identity.accumulatedFees(), 2 ether);

        // Owner withdraws accumulated fees
        vm.prank(owner);
        identity.withdrawFees();

        // User1 should STILL be able to withdraw their pending funds
        uint256 contractBal = address(identity).balance;
        assertGe(contractBal, 1 ether, "Contract must retain user funds after fee withdrawal");

        vm.prank(user1);
        identity.withdrawPendingFunds();
        assertEq(identity.pendingWithdrawals(user1), 0);
    }

    // ════════════════════════════════════════════════════════
    // [H-2] Relink Race Condition
    // ════════════════════════════════════════════════════════

    /// @notice After initiateRelink(newEvm=user2), if user2 registers their own BTC
    ///         identity before finalizeRelink, the finalize should revert.
    function testH2_RelinkRaceNewEvmRegistersElsewhere() public {
        vm.warp(10 days);
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);

        // Warp past cooldown
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // Set pending relink: user1's hash160 → user2
        _setPendingRelink(hash160_1, user2, block.timestamp - 1);

        // Before finalizing, user2 gets their OWN identity registered
        _registerDirect(hash160_2, user2);

        // Finalize should revert because user2 now has evmToBtc != 0
        vm.expectRevert(FastPathIdentity.NewEvmAlreadyRegistered.selector);
        vm.prank(user2);
        identity.finalizeRelink(hash160_1);
    }

    // ════════════════════════════════════════════════════════
    // [H-3] Emergency Stop Enforcement
    // ════════════════════════════════════════════════════════

    /// @notice Emergency stop must block ALL relink operations
    function testH3_EmergencyStopBlocksAllRelinkOps() public {
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);
        vm.prank(owner);
        identity.setEmergencyStop(true);

        // initiateRelink blocked
        bytes memory pubkey = new bytes(33);
        pubkey[0] = 0x02;
        bytes memory sig = new bytes(65);
        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.EmergencyStopActive.selector);
        identity.initiateRelink(hash160_1, user2, pubkey, sig);

        // Set up pending relink directly
        _setPendingRelink(hash160_1, user2, block.timestamp - 1);

        // finalizeRelink blocked
        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.EmergencyStopActive.selector);
        identity.finalizeRelink(hash160_1);

        // cancelRelink blocked
        vm.prank(user1);
        vm.expectRevert(FastPathIdentity.EmergencyStopActive.selector);
        identity.cancelRelink(hash160_1);
    }

    // ════════════════════════════════════════════════════════
    // [H-4] Pull-Payment Reentrancy on withdrawPendingFunds
    // ════════════════════════════════════════════════════════

    /// @notice A malicious contract receiving ETH via withdrawPendingFunds
    ///         should NOT be able to re-enter and drain extra funds.
    function testH4_WithdrawPendingFundsReentrancy() public {
        ReentrantReceiver attContract = new ReentrantReceiver(identity);
        address attAddr = address(attContract);

        _registerDirect(hash160_3, attAddr);

        // Opt in to ViaHash160
        vm.prank(attAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // Deposit 1 ETH for the attacker contract
        vm.deal(user2, 2 ether);
        vm.prank(user2);
        identity.receiveFunds{value: 1 ether}(hash160_3);

        // Also send extra ETH to contract directly (to have more balance)
        vm.deal(address(this), 5 ether);
        (bool s,) = address(identity).call{value: 3 ether}("");
        assertTrue(s);

        // Attacker tries reentrancy
        vm.prank(attAddr);
        try attContract.attack() {} catch {}

        // Attacker should only have received 1 ETH (their pending amount)
        assertEq(identity.pendingWithdrawals(attAddr), 0, "Pending should be zero");
        assertLe(attAddr.balance, 1 ether, "Attacker should not drain extra funds");
    }

    // ════════════════════════════════════════════════════════
    // [M-1] Owner Cannot Drain User Pending Funds
    // ════════════════════════════════════════════════════════

    /// @notice withdrawFees should only withdraw accumulatedFees, never pendingWithdrawals
    function testM1_WithdrawFeesDoesNotTouchPendingWithdrawals() public {
        _registerDirect(hash160_1, user1);

        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // User2 sends 2 ETH via receiveFunds
        vm.deal(user2, 5 ether);
        vm.prank(user2);
        identity.receiveFunds{value: 2 ether}(hash160_1);

        // Verify state
        assertEq(identity.pendingWithdrawals(user1), 2 ether);
        assertEq(identity.accumulatedFees(), 0);

        // Owner tries to withdraw fees — should revert (no fees)
        vm.prank(owner);
        vm.expectRevert(FastPathIdentity.NoFeesToWithdraw.selector);
        identity.withdrawFees();

        // User funds intact
        assertEq(identity.pendingWithdrawals(user1), 2 ether);
    }

    // ════════════════════════════════════════════════════════
    // [M-2] hasControl After Relink
    // ════════════════════════════════════════════════════════

    /// @notice After relink: oldEvm.hasControl should return false,
    ///         newEvm.hasControl should return true.
    function testM2_HasControlAfterRelink() public {
        vm.warp(10 days);
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // Set pending relink and finalize
        _setPendingRelink(hash160_1, user2, block.timestamp - 1);

        vm.prank(user2);
        identity.finalizeRelink(hash160_1);

        // Old owner loses control
        assertFalse(identity.hasControl(user1), "Old EVM should NOT have control after relink");
        // New owner gains control
        assertTrue(identity.hasControl(user2), "New EVM SHOULD have control after relink");
        // btcToEvm is immutable — still points to original
        assertEq(identity.btcToEvm(hash160_1), user1, "btcToEvm should be immutable");
        // currentController returns new
        assertEq(identity.currentController(hash160_1), user2);
    }

    // ════════════════════════════════════════════════════════
    // [M-3] receive() ETH Goes to accumulatedFees
    // ════════════════════════════════════════════════════════

    /// @notice Plain ETH transfers to the contract should be accounted as fees
    ///         and NOT as user pending withdrawals.
    function testM3_ReceiveETHGoesToFees() public {
        vm.deal(attacker, 10 ether);

        vm.prank(attacker);
        (bool s,) = address(identity).call{value: 5 ether}("");
        assertTrue(s);

        assertEq(identity.accumulatedFees(), 5 ether);
        assertEq(identity.pendingWithdrawals(attacker), 0);
    }

    // ════════════════════════════════════════════════════════
    // [M-4] cancelRelink Only By activeEvm
    // ════════════════════════════════════════════════════════

    /// @notice After relink, the OLD owner should NOT be able to cancel
    ///         a new pending relink — only the activeEvm can.
    function testM4_OnlyActiveEvmCanCancelRelink() public {
        vm.warp(10 days);
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // Relink to user2
        _setPendingRelink(hash160_1, user2, block.timestamp - 1);
        vm.prank(user2);
        identity.finalizeRelink(hash160_1);

        // Warp past cooldown again for new relink
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // New pending relink to user3
        _setPendingRelink(hash160_1, user3, block.timestamp + 1 days);

        // Old owner (user1) tries to cancel — should fail
        vm.prank(user1);
        vm.expectRevert(FastPathIdentity.NotCurrentOwner.selector);
        identity.cancelRelink(hash160_1);

        // Current controller (user2) can cancel
        vm.prank(user2);
        identity.cancelRelink(hash160_1);
    }

    // ════════════════════════════════════════════════════════
    // [L-1] Fee Griefing: MAX_REGISTRATION_FEE Edge
    // ════════════════════════════════════════════════════════

    /// @notice Owner cannot set fee above MAX_REGISTRATION_FEE
    function testL1_CannotExceedMaxRegistrationFee() public {
        vm.prank(owner);
        vm.expectRevert(FastPathIdentity.FeeTooHigh.selector);
        identity.setRegistrationFee(1 ether + 1);
    }

    /// @notice Setting fee to exactly MAX is allowed
    function testL1_MaxFeeIsAllowed() public {
        vm.prank(owner);
        identity.setRegistrationFee(1 ether);
        assertEq(identity.registrationFee(), 1 ether);
    }

    // ════════════════════════════════════════════════════════
    // [L-2] Duplicate setReceivePreference Reverts
    // ════════════════════════════════════════════════════════

    function testL2_DuplicatePreferenceReverts() public {
        // Default is DirectEVM (0), setting to same should revert
        vm.prank(user1);
        vm.expectRevert(FastPathIdentity.PreferenceAlreadySet.selector);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.DirectEVM);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: Receive funds after relink routes to NEW controller
    // ════════════════════════════════════════════════════════

    /// @notice After relink, receiveFunds should credit the NEW controller
    function testEdge_ReceiveFundsAfterRelinkGoesToNewController() public {
        vm.warp(10 days);
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // User1 opts into ViaHash160
        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // Relink to user2
        _setPendingRelink(hash160_1, user2, block.timestamp - 1);
        vm.prank(user2);
        identity.finalizeRelink(hash160_1);

        // User2 (new controller) must also opt in
        vm.prank(user2);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // Send funds via hash160 — should go to user2 (new controller)
        vm.deal(user3, 1 ether);
        vm.prank(user3);
        identity.receiveFunds{value: 1 ether}(hash160_1);

        assertEq(identity.pendingWithdrawals(user2), 1 ether, "Funds should go to new controller");
        assertEq(identity.pendingWithdrawals(user1), 0, "Old controller should get nothing");
    }

    // ════════════════════════════════════════════════════════
    // EDGE: Two-step ownership transfer
    // ════════════════════════════════════════════════════════

    function testEdge_OwnershipTransferTwoStep() public {
        vm.prank(owner);
        identity.transferOwnership(user1);

        // Owner still has control until accepted
        assertEq(identity.owner(), owner);

        // Random user can't accept
        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.NotPendingOwner.selector);
        identity.acceptOwnership();

        // Correct pending owner accepts
        vm.prank(user1);
        identity.acceptOwnership();
        assertEq(identity.owner(), user1);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: Cooldown enforcement on relink
    // ════════════════════════════════════════════════════════

    function testEdge_FinalizeTooEarlyReverts() public {
        vm.warp(10 days);
        _registerDirect(hash160_1, user1);

        vm.prank(owner);
        identity.setRelinkEnabled(true);
        _setLastLinkTime(hash160_1, block.timestamp - 4 days);

        // Pending relink that unlocks in the future
        _setPendingRelink(hash160_1, user2, block.timestamp + 1 days);

        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.CooldownActive.selector);
        identity.finalizeRelink(hash160_1);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: rescueERC20 zero-address checks
    // ════════════════════════════════════════════════════════

    function testEdge_RescueERC20ZeroChecks() public {
        vm.prank(owner);
        vm.expectRevert(FastPathIdentity.ZeroAddress.selector);
        identity.rescueERC20(address(0), user1, 100);

        vm.prank(owner);
        vm.expectRevert(FastPathIdentity.ZeroAddress.selector);
        identity.rescueERC20(address(0x1234), address(0), 100);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: receiveFunds boundary conditions
    // ════════════════════════════════════════════════════════

    function testEdge_ReceiveFundsZeroHash160Reverts() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(FastPathIdentity.ZeroHash160.selector);
        identity.receiveFunds{value: 1 ether}(bytes20(0));
    }

    function testEdge_ReceiveFundsZeroValueReverts() public {
        _registerDirect(hash160_1, user1);
        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.ZeroValue.selector);
        identity.receiveFunds{value: 0}(hash160_1);
    }

    function testEdge_ReceiveFundsUnregisteredHash160Reverts() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(FastPathIdentity.Hash160NotRegistered.selector);
        identity.receiveFunds{value: 1 ether}(hash160_2); // not registered
    }

    function testEdge_ReceiveFundsDirectEvmPreferredReverts() public {
        _registerDirect(hash160_1, user1);
        // Default preference is DirectEVM — should revert
        vm.deal(user2, 1 ether);
        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.DirectEvmPreferred.selector);
        identity.receiveFunds{value: 1 ether}(hash160_1);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: receiveTokens boundary conditions
    // ════════════════════════════════════════════════════════

    function testEdge_ReceiveTokensZeroAmountReverts() public {
        _registerDirect(hash160_1, user1);
        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.ZeroAmount.selector);
        identity.receiveTokens(hash160_1, address(0x1234), 0);
    }

    function testEdge_ReceiveTokensZeroTokenReverts() public {
        _registerDirect(hash160_1, user1);
        vm.prank(user1);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.prank(user2);
        vm.expectRevert(FastPathIdentity.InvalidToken.selector);
        identity.receiveTokens(hash160_1, address(0), 100);
    }

    // ════════════════════════════════════════════════════════
    // EDGE: setRelinkCooldown minimum
    // ════════════════════════════════════════════════════════

    function testEdge_CooldownBelowMinimumReverts() public {
        vm.prank(owner);
        vm.expectRevert(FastPathIdentity.CooldownTooSmall.selector);
        identity.setRelinkCooldown(3599); // 1 hour - 1 second
    }

    function testEdge_CooldownExactMinimumAllowed() public {
        vm.prank(owner);
        identity.setRelinkCooldown(1 hours);
        assertEq(identity.relinkCooldown(), 1 hours);
    }
}

// ════════════════════════════════════════════════════════
// ATTACK CONTRACTS
// ════════════════════════════════════════════════════════

contract ReentrantReceiver {
    FastPathIdentity public target;
    uint256 public attackCount;

    constructor(FastPathIdentity _target) {
        target = _target;
    }

    function attack() external {
        target.withdrawPendingFunds();
    }

    receive() external payable {
        attackCount++;
        if (attackCount < 3) {
            // Try to re-enter
            try target.withdrawPendingFunds() {} catch {}
        }
    }
}
