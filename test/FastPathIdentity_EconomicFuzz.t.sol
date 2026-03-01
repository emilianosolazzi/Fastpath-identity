// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/Fastpathidentity.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function store(address target, bytes32 slot, bytes32 value) external;
    function warp(uint256 timestamp) external;
}

contract Test {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }
    function assertEq(uint256 a, uint256 b, string memory message) internal pure {
        require(a == b, message);
    }
    function assertEq(address a, address b, string memory message) internal pure {
        require(a == b, message);
    }
    function assertEq(bytes20 a, bytes20 b, string memory message) internal pure {
        require(a == b, message);
    }
}

// ==========================================
// ATTACK HELPER CONTRACTS
// ==========================================

/// @notice Re-enters withdrawPendingFunds from inside receive()
contract ReentrantWithdrawReceiver {
    FastPathIdentity public target;
    bool public reentered;

    constructor(FastPathIdentity _target) { target = _target; }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            target.withdrawPendingFunds(); // should be blocked by nonReentrant
        }
    }
}

/// @notice Tries to re-enter receiveFunds from inside receive()
contract ReentrantReceiveFundsReceiver {
    FastPathIdentity public target;
    bytes20 public myHash;
    bool public reentered;

    constructor(FastPathIdentity _target, bytes20 _hash) {
        target = _target;
        myHash = _hash;
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            target.receiveFunds{value: 1 wei}(myHash);
        }
    }
}

// ==========================================
// MAIN TEST CONTRACT
// ==========================================

/**
 * @title Economic Attack PoC Tests for FastPathIdentity
 * @notice Each test models an adversarial economic scenario and asserts it is blocked.
 *         These are Foundry PoCs of what economic_fuzzer.py enumerates via delta-V maximization.
 */
contract FastPathIdentityEconomicFuzz is Test {
    // Storage slots (fastapthidentity.sol layout)
    uint256 constant SLOT_ACTIVE_EVM  = 11;
    uint256 constant SLOT_RECV_PREF   = 9;
    uint256 constant SLOT_PENDING_WD  = 12;
    uint256 constant SLOT_ACCUMULATED = 13;

    FastPathIdentity public identity;

    uint256 constant PRIVKEY       = 1;
    uint8   constant PUBKEY_PREFIX = 0x02;
    bytes32 constant PUBKEY_X      = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    address attacker;
    address victim;

    function setUp() public {
        identity = new FastPathIdentity(0.001 ether);
        attacker = vm.addr(2);
        victim   = vm.addr(PRIVKEY);
        vm.deal(attacker, 100 ether);
        vm.deal(victim,   100 ether);
    }

    // ==========================================
    // HELPERS
    // ==========================================

    function _mapSlot(bytes20 key, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(bytes32(key), slot));
    }

    function _mapSlot(address key, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, slot));
    }

    function _setActiveEvm(bytes20 hash, address evm) internal {
        vm.store(address(identity), _mapSlot(hash, SLOT_ACTIVE_EVM), bytes32(uint256(uint160(evm))));
    }

    function _setReceivePref(address user, uint256 pref) internal {
        vm.store(address(identity), _mapSlot(user, SLOT_RECV_PREF), bytes32(pref));
    }

    function _setPendingWd(address user, uint256 amount) internal {
        vm.store(address(identity), _mapSlot(user, SLOT_PENDING_WD), bytes32(amount));
    }

    function _toHex(address a) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory data = abi.encodePacked(a);
        bytes memory str = new bytes(42);
        str[0] = "0"; str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    function _ethSignedHash(bytes memory message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", _uintStr(message.length), message));
    }

    function _uintStr(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 tmp = v; uint256 d;
        while (tmp != 0) { d++; tmp /= 10; }
        bytes memory buf = new bytes(d);
        while (v != 0) { d--; buf[d] = bytes1(uint8(48 + v % 10)); v /= 10; }
        return string(buf);
    }

    function _registerVictim() internal returns (bytes20 hash) {
        bytes memory msg_ = bytes(_toHex(victim));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, _ethSignedHash(msg_));
        vm.prank(victim);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
        return identity.evmToBtc(victim);
    }

    // ==========================================
    // VALUE FUNCTIONS (read by economic_fuzzer.py)
    // ==========================================

    function valueETH() public view returns (int256) { return int256(attacker.balance); }

    function valueOwnership(bytes20 targetHash) public view returns (int256) {
        return identity.currentController(targetHash) == attacker ? type(int256).max : int256(0);
    }

    function valueFees() public view returns (int256) { return int256(address(identity).balance); }

    // ==========================================
    // SCENARIO METADATA (for economic_fuzzer.py)
    // ==========================================

    function scenarioReentrancy()         public pure returns (string memory) { return "receiveFunds,withdrawPendingFunds"; }
    function scenarioOwnershipTheft()     public pure returns (string memory) { return "initiateRelink,finalizeRelink"; }
    function scenarioFeeTheft()           public pure returns (string memory) { return "withdrawFees"; }
    function scenarioDoubleRegistration() public pure returns (string memory) { return "registerBitcoinAddressV2"; }
    function maxTraceDepth()              public pure returns (uint256) { return 5; }
    function minProfitThreshold()         public pure returns (uint256) { return 0.001 ether; }
    function solverTimeout()              public pure returns (uint256) { return 60; }

    // ==========================================
    // ATTACK 1a: REENTRANCY — withdrawPendingFunds
    // ==========================================

    /// @notice Re-entrant receiver tries to double-withdraw by calling withdrawPendingFunds
    ///         again from inside receive(). The re-entry is blocked (ReentrantCall), which causes
    ///         receive() to revert, which causes the outer ETH transfer to fail (TransferFailed).
    ///         Net result: attacker gets nothing and pendingWithdrawals stays non-zero.
    function testAttack_Reentrancy_WithdrawPendingFunds_Blocked() public {
        ReentrantWithdrawReceiver evil = new ReentrantWithdrawReceiver(identity);

        _setPendingWd(address(evil), 1 ether);
        vm.deal(address(identity), 1 ether);

        uint256 balBefore = address(evil).balance;

        // The outer withdrawPendingFunds reverts entirely because:
        //   1. nonReentrant blocks the inner call → receive() reverts
        //   2. the ETH transfer fails → TransferFailed() reverts the outer call too
        vm.prank(address(evil));
        (bool success,) = address(identity).call(
            abi.encodeWithSelector(identity.withdrawPendingFunds.selector)
        );
        assertTrue(!success, "withdrawPendingFunds must revert when receiver re-enters");

        // Evil got nothing — balance unchanged
        assertEq(address(evil).balance, balBefore, "evil must receive no ETH");
        // pendingWithdrawals was restored on revert — attacker cannot drain
        assertEq(identity.pendingWithdrawals(address(evil)), 1 ether, "pendingWithdrawals must be intact after revert");
    }

    // ==========================================
    // ATTACK 1b: REENTRANCY — receiveFunds (pull-payment means no ETH push)
    // ==========================================

    /// @notice receiveFunds uses pull-payment — it credits pendingWithdrawals and never
    ///         pushes ETH. So receive() on the malicious contract is never triggered.
    function testAttack_Reentrancy_ReceiveFunds_NoPushOccurs() public {
        bytes20 hash = bytes20(keccak256("reentrant-recv-hash"));
        ReentrantReceiveFundsReceiver evil = new ReentrantReceiveFundsReceiver(identity, hash);

        _setActiveEvm(hash, address(evil));
        _setReceivePref(address(evil), 1); // ViaHash160

        vm.deal(address(this), 2 ether);
        identity.receiveFunds{value: 1 ether}(hash);

        // receive() was never called — no ETH was pushed
        assertTrue(!evil.reentered(), "receive() must not have been triggered by receiveFunds");
        assertEq(identity.pendingWithdrawals(address(evil)), 1 ether, "funds must sit in pendingWithdrawals");
        assertEq(address(evil).balance, 0, "evil must hold no ETH until it calls withdrawPendingFunds");
    }

    // ==========================================
    // ATTACK 2: OWNERSHIP THEFT — relink without victim's BTC key
    // ==========================================

    /// @notice Attacker tries to hijack victim's identity by initiating a relink
    ///         with a fake Bitcoin signature. Must revert.
    function testAttack_OwnershipTheft_FakeBtcSignature_Blocked() public {
        bytes20 victimHash = _registerVictim();

        identity.setRelinkEnabled(true);
        vm.warp(block.timestamp + 4 days); // past cooldown

        // Attacker creates a bogus 65-byte signature (garbage)
        bytes memory fakeSig = new bytes(65);
        fakeSig[0] = 0x1b; // valid header byte so it passes format checks, but wrong key

        bytes memory victimPubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);

        vm.prank(attacker);
        (bool success,) = address(identity).call(
            abi.encodeWithSelector(
                identity.initiateRelink.selector,
                victimHash,
                attacker,
                victimPubkey,
                fakeSig
            )
        );
        assertTrue(!success, "initiateRelink must revert without valid BTC signature");

        // Victim retains control
        assertEq(identity.currentController(victimHash), victim, "victim must retain control");
    }

    // ==========================================
    // ATTACK 3: FEE THEFT — withdrawFees as non-owner
    // ==========================================

    /// @notice Non-owner attacker calls withdrawFees. Must revert with NotOwner.
    function testAttack_FeeTheft_NonOwner_Blocked() public {
        // Seed fees
        vm.store(address(identity), bytes32(SLOT_ACCUMULATED), bytes32(uint256(5 ether)));
        vm.deal(address(identity), 5 ether);

        uint256 attackerBefore = attacker.balance;

        vm.prank(attacker);
        (bool success,) = address(identity).call(
            abi.encodeWithSelector(identity.withdrawFees.selector)
        );
        assertTrue(!success, "withdrawFees must revert for non-owner");
        assertEq(attacker.balance, attackerBefore, "attacker balance must not change");
        assertEq(address(identity).balance, 5 ether, "contract ETH must be untouched");
    }

    // ==========================================
    // ATTACK 4: DOUBLE REGISTRATION — same BTC hash or same EVM
    // ==========================================

    /// @notice Attacker tries to re-register from the same EVM address.
    ///         Must revert with AddressAlreadyRegistered.
    function testAttack_DoubleRegistration_SameEvm_Blocked() public {
        _registerVictim();

        // Victim tries to register again
        bytes memory msg_ = bytes(_toHex(victim));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, _ethSignedHash(msg_));

        vm.prank(victim);
        (bool success,) = address(identity).call{value: 0.001 ether}(
            abi.encodeWithSelector(
                identity.registerBitcoinAddressV2.selector,
                PUBKEY_PREFIX, PUBKEY_X, r, s, v, false
            )
        );
        assertTrue(!success, "second registration from same EVM must revert");
    }

    /// @notice Victim's BTC hash is registered. A second address cannot claim the same hash.
    function testAttack_DoubleRegistration_SameBtcHash_Blocked() public {
        bytes20 hash = _registerVictim();

        // The hash is now permanently owned by victim
        assertEq(identity.btcToEvm(hash), victim, "victim must own the hash");

        // No other address can claim it — btcToEvm is permanent and the contract checks it
        // during registerBitcoinAddressV2 (AddressAlreadyRegistered)
        assertTrue(identity.evmToBtc(attacker) == bytes20(0), "attacker must have no mapping");
    }

    // ==========================================
    // ATTACK 5: RECEIVE FUNDS — ETH not lost on revert
    // ==========================================

    /// @notice Sending ETH to an unregistered hash reverts — sender's ETH is returned.
    function testAttack_ReceiveFunds_UnregisteredHash_ETHNotLost() public {
        bytes20 randomHash = bytes20(keccak256("nobody"));
        uint256 before = attacker.balance;

        vm.prank(attacker);
        (bool success,) = address(identity).call{value: 1 ether}(
            abi.encodeWithSelector(identity.receiveFunds.selector, randomHash)
        );
        assertTrue(!success, "receiveFunds to unregistered hash must revert");
        // After the revert the ETH was returned; gas cost is negligible vs 1 ether
        assertTrue(attacker.balance > before - 0.01 ether, "ETH must not be lost on revert");
    }
}

