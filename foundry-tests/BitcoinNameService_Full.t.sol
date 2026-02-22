// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "../empty_src/BitcoinNameService.sol";

/**
 * @title Bitcoin Name Service — Full Test Suite
 * @notice 47 tests covering registration, resolution, expiry, renewal,
 *         release, text records, clearText, token fees, subdomains,
 *         access control, relink integration, name validation, and edge cases.
 *
 * @dev Uses a MockFastPathIdentity to simulate the hash160 → EVM mapping
 *      without deploying the full FastPathIdentity contract.
 */

// ═══════════════════════════════════════════════════════════════════
// MOCK: Simulates FastPathIdentity for isolated BNS testing
// ═══════════════════════════════════════════════════════════════════

contract MockFastPathIdentity is IFastPathIdentity {
    mapping(bytes20 => address) private _controllers;

    function setController(bytes20 hash160, address controller) external {
        _controllers[hash160] = controller;
    }

    function currentController(bytes20 btcHash160) external view override returns (address) {
        return _controllers[btcHash160];
    }

    function activeEvm(bytes20 btcHash160) external view override returns (address) {
        return _controllers[btcHash160];
    }
}

// ═══════════════════════════════════════════════════════════════════
// MOCK: Simple ERC-20 token for testing WBTC-style fee payment
// ═══════════════════════════════════════════════════════════════════

contract MockWBTC {
    string public name = "Wrapped Bitcoin";
    string public symbol = "WBTC";
    uint8 public decimals = 8;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract BitcoinNameService_FullTest is Test {
    BitcoinNameService public bns;
    MockFastPathIdentity public mockIdentity;

    address public alice;
    address public bob;
    address public charlie;
    address public deployer;

    bytes20 constant ALICE_HASH160   = bytes20(uint160(0xA11CE));
    bytes20 constant BOB_HASH160     = bytes20(uint160(0xB0B));
    bytes20 constant CHARLIE_HASH160 = bytes20(uint160(0xC4A711E));
    bytes20 constant ORPHAN_HASH160  = bytes20(uint160(0xDEAD));

    uint256 constant FEE = 0.01 ether;

    function setUp() public {
        deployer = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");

        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.deal(charlie, 10 ether);

        // Deploy mock identity and register hash160s
        mockIdentity = new MockFastPathIdentity();
        mockIdentity.setController(ALICE_HASH160, alice);
        mockIdentity.setController(BOB_HASH160, bob);
        mockIdentity.setController(CHARLIE_HASH160, charlie);
        // ORPHAN_HASH160 intentionally has no controller (address(0))

        // Deploy BNS
        bns = new BitcoinNameService(address(mockIdentity), FEE);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 1: Basic name registration
    // ═══════════════════════════════════════════════════════════

    function test_Register_Basic() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        (address evmAddr, bytes20 hash160) = bns.resolve("satoshi");
        assertEq(evmAddr, alice, "Should resolve to Alice's EVM address");
        assertEq(hash160, ALICE_HASH160, "Should return Alice's hash160");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 2: Reverse resolution
    // ═══════════════════════════════════════════════════════════

    function test_ReverseResolution() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        string memory name = bns.reverseOf(ALICE_HASH160);
        assertEq(name, "satoshi", "Reverse should return 'satoshi'");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 3: Non-controller cannot register
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_NotController() public {
        vm.prank(bob);
        vm.expectRevert(BitcoinNameService.NotController.selector);
        bns.register{value: FEE}("stolen", ALICE_HASH160); // Bob tries Alice's hash160
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 4: Duplicate name reverts
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_NameTaken() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(bob);
        vm.expectRevert(BitcoinNameService.NameAlreadyTaken.selector);
        bns.register{value: FEE}("satoshi", BOB_HASH160); // Same name, different hash160
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 5: One name per hash160
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_Hash160AlreadyHasName() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.Hash160AlreadyHasName.selector);
        bns.register{value: FEE}("nakamoto", ALICE_HASH160); // Same hash160, different name
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 6: Name too short
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_TooShort() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NameTooShort.selector);
        bns.register{value: FEE}("ab", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 7: Name too long
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_TooLong() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NameTooLong.selector);
        bns.register{value: FEE}("abcdefghijklmnopqrstuvwxyz1234567", ALICE_HASH160); // 33 chars
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 8: Invalid characters rejected
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_InvalidChars() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BitcoinNameService.InvalidCharacter.selector, 3));
        bns.register{value: FEE}("sat.oshi", ALICE_HASH160); // dot at position 3
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 9: Leading hyphen rejected
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_LeadingHyphen() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BitcoinNameService.InvalidCharacter.selector, 0));
        bns.register{value: FEE}("-satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 10: Trailing hyphen rejected
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_TrailingHyphen() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BitcoinNameService.InvalidCharacter.selector, 7));
        bns.register{value: FEE}("satoshi-", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 11: Consecutive hyphens rejected
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_ConsecutiveHyphens() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BitcoinNameService.InvalidCharacter.selector, 4));
        bns.register{value: FEE}("sat--oshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 12: Uppercase rejected
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_Uppercase() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BitcoinNameService.InvalidCharacter.selector, 0));
        bns.register{value: FEE}("Satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 13: Insufficient fee reverts
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_InsufficientFee() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.InsufficientFee.selector);
        bns.register{value: FEE - 1}("satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 14: Unregistered hash160 (no identity) reverts
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_IdentityNotRegistered() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.IdentityNotRegistered.selector);
        bns.register{value: FEE}("phantom", ORPHAN_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 15: Text records — set and read
    // ═══════════════════════════════════════════════════════════

    function test_TextRecords_SetAndRead() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.startPrank(alice);
        bns.setText("satoshi", "avatar", "https://example.com/avatar.png");
        bns.setText("satoshi", "url", "https://bitcoin.org");
        bns.setText("satoshi", "description", "Bitcoin creator");
        vm.stopPrank();

        assertEq(bns.text("satoshi", "avatar"), "https://example.com/avatar.png");
        assertEq(bns.text("satoshi", "url"), "https://bitcoin.org");
        assertEq(bns.text("satoshi", "description"), "Bitcoin creator");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 16: Text records — non-controller cannot set
    // ═══════════════════════════════════════════════════════════

    function test_TextRecords_RevertIf_NotController() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(bob);
        vm.expectRevert(BitcoinNameService.NotController.selector);
        bns.setText("satoshi", "avatar", "hacked");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 17: Name expiry blocks resolution
    // ═══════════════════════════════════════════════════════════

    function test_Expiry_BlocksResolution() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Fast-forward past expiry (1 year + 1 second)
        vm.warp(block.timestamp + 365 days + 1);

        vm.expectRevert(BitcoinNameService.NameExpired.selector);
        bns.resolve("satoshi");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 18: Renewal extends expiry
    // ═══════════════════════════════════════════════════════════

    function test_Renew_ExtendsExpiry() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Warp to 1 day before expiry
        vm.warp(block.timestamp + 364 days);

        vm.prank(alice);
        bns.renew{value: FEE}("satoshi");

        // Should now resolve for another full year from original expiry
        vm.warp(block.timestamp + 366 days); // well past original expiry
        (address evmAddr,) = bns.resolve("satoshi");
        assertEq(evmAddr, alice, "Should still resolve after renewal");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 19: Renewal during grace period works
    // ═══════════════════════════════════════════════════════════

    function test_Renew_DuringGracePeriod() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Warp into grace period (expired + 15 days, within 30-day grace)
        vm.warp(block.timestamp + 365 days + 15 days);

        vm.prank(alice);
        bns.renew{value: FEE}("satoshi");

        // Resolution should work now (renewed from current time since past expiry)
        (address evmAddr,) = bns.resolve("satoshi");
        assertEq(evmAddr, alice);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 20: Renewal past grace period reverts
    // ═══════════════════════════════════════════════════════════

    function test_Renew_RevertIf_PastGracePeriod() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Warp past grace period (expiry + 31 days)
        vm.warp(block.timestamp + 365 days + 31 days);

        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NameExpired.selector);
        bns.renew{value: FEE}("satoshi");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 21: Release makes name available
    // ═══════════════════════════════════════════════════════════

    function test_Release_MakesNameAvailable() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.release("satoshi");

        // Now Bob can register the same name
        vm.prank(bob);
        bns.register{value: FEE}("satoshi", BOB_HASH160);

        (address evmAddr,) = bns.resolve("satoshi");
        assertEq(evmAddr, bob, "Bob should now own 'satoshi'");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 22: Reverse clears after release
    // ═══════════════════════════════════════════════════════════

    function test_Release_ClearsReverse() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.release("satoshi");

        string memory name = bns.reverseOf(ALICE_HASH160);
        assertEq(bytes(name).length, 0, "Reverse should be empty after release");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 23: Relink integration — new controller inherits management
    // ═══════════════════════════════════════════════════════════

    function test_Relink_NewControllerInheritsNameManagement() public {
        // Alice registers name
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Simulate FastPathIdentity relink: Alice → Charlie for ALICE_HASH160
        mockIdentity.setController(ALICE_HASH160, charlie);

        // Alice can no longer manage the name
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NotController.selector);
        bns.setText("satoshi", "avatar", "old-alice");

        // Charlie CAN manage the name now
        vm.prank(charlie);
        bns.setText("satoshi", "avatar", "new-charlie");
        assertEq(bns.text("satoshi", "avatar"), "new-charlie");

        // Resolution now returns Charlie
        (address evmAddr,) = bns.resolve("satoshi");
        assertEq(evmAddr, charlie, "Should resolve to new controller after relink");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 24: resolveAll returns full record
    // ═══════════════════════════════════════════════════════════

    function test_ResolveAll() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.startPrank(alice);
        bns.setText("satoshi", "avatar", "https://img.test/a.png");
        bns.setText("satoshi", "url", "https://bitcoin.org");
        bns.setText("satoshi", "description", "The creator");
        vm.stopPrank();

        (
            address evmAddr,
            bytes20 hash160,
            uint256 registeredAt,
            uint256 expiresAt,
            string memory avatar,
            string memory url,
            string memory description
        ) = bns.resolveAll("satoshi");

        assertEq(evmAddr, alice);
        assertEq(hash160, ALICE_HASH160);
        assertGt(registeredAt, 0);
        assertEq(expiresAt, registeredAt + 365 days);
        assertEq(avatar, "https://img.test/a.png");
        assertEq(url, "https://bitcoin.org");
        assertEq(description, "The creator");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 25: available() returns correct status
    // ═══════════════════════════════════════════════════════════

    function test_Available_AllStates() public {
        // Available — never registered
        (bool avail, string memory reason) = bns.available("satoshi");
        assertTrue(avail, "Should be available initially");
        assertEq(reason, "Available");

        // Taken — just registered
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);
        (avail, reason) = bns.available("satoshi");
        assertFalse(avail, "Should be taken");
        assertEq(reason, "Taken");

        // In grace period — expired but within 30 days
        vm.warp(block.timestamp + 365 days + 15 days);
        (avail, reason) = bns.available("satoshi");
        assertFalse(avail, "Should be in grace period");
        assertEq(reason, "In grace period");

        // Expired — past grace period
        vm.warp(block.timestamp + 16 days); // total: 365 + 31 days
        (avail, reason) = bns.available("satoshi");
        assertTrue(avail, "Should be available after grace expires");
        assertEq(reason, "Expired");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 26: Re-registration after full expiry
    // ═══════════════════════════════════════════════════════════

    function test_Reregister_AfterFullExpiry() public {
        // Alice registers
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Expire past grace period
        vm.warp(block.timestamp + 365 days + 31 days);

        // Bob takes the name
        vm.prank(bob);
        bns.register{value: FEE}("satoshi", BOB_HASH160);

        (address evmAddr, bytes20 hash160) = bns.resolve("satoshi");
        assertEq(evmAddr, bob);
        assertEq(hash160, BOB_HASH160);

        // Alice's reverse is cleared
        string memory aliceReverse = bns.reverseOf(ALICE_HASH160);
        assertEq(bytes(aliceReverse).length, 0, "Old owner's reverse should be cleared");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 27: Fee withdrawal by owner
    // ═══════════════════════════════════════════════════════════

    function test_WithdrawFees() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(bob);
        bns.register{value: FEE}("nakamoto", BOB_HASH160);

        uint256 balBefore = deployer.balance;
        bns.withdrawFees(); // called by deployer (owner)
        uint256 balAfter = deployer.balance;

        assertEq(balAfter - balBefore, 2 * FEE, "Should withdraw both fees");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 28: Non-owner cannot withdraw
    // ═══════════════════════════════════════════════════════════

    function test_WithdrawFees_RevertIf_NotOwner() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NotOwner.selector);
        bns.withdrawFees();
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 29: Zero hash160 reverts
    // ═══════════════════════════════════════════════════════════

    function test_Register_RevertIf_ZeroHash160() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ZeroHash160.selector);
        bns.register{value: FEE}("satoshi", bytes20(0));
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 30: Valid name with hyphens and digits
    // ═══════════════════════════════════════════════════════════

    function test_Register_ValidComplexName() public {
        vm.prank(alice);
        bns.register{value: FEE}("my-btc-addr-2026", ALICE_HASH160);

        (address evmAddr,) = bns.resolve("my-btc-addr-2026");
        assertEq(evmAddr, alice);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 31: resolveToHash160 works independently
    // ═══════════════════════════════════════════════════════════

    function test_ResolveToHash160() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bytes20 hash160 = bns.resolveToHash160("satoshi");
        assertEq(hash160, ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 32: reverseOf returns empty for expired name
    // ═══════════════════════════════════════════════════════════

    function test_ReverseOf_EmptyWhenExpired() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.warp(block.timestamp + 365 days + 1);

        string memory name = bns.reverseOf(ALICE_HASH160);
        assertEq(bytes(name).length, 0, "Reverse should be empty for expired name");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 33: Expired text records inaccessible
    // ═══════════════════════════════════════════════════════════

    function test_TextRecords_RevertIf_Expired() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.setText("satoshi", "avatar", "pic.png");

        vm.warp(block.timestamp + 365 days + 1);

        vm.expectRevert(BitcoinNameService.NameExpired.selector);
        bns.text("satoshi", "avatar");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 34: Registration fee can be updated
    // ═══════════════════════════════════════════════════════════

    function test_SetFee() public {
        uint256 newFee = 0.05 ether;
        bns.setRegistrationFee(newFee);
        assertEq(bns.registrationFee(), newFee);

        // Old fee should now fail
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.InsufficientFee.selector);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // New fee works
        vm.prank(alice);
        bns.register{value: newFee}("satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 35: Minimum length boundary (exactly 3 chars)
    // ═══════════════════════════════════════════════════════════

    function test_Register_ExactMinLength() public {
        vm.prank(alice);
        bns.register{value: FEE}("abc", ALICE_HASH160);

        (address evmAddr,) = bns.resolve("abc");
        assertEq(evmAddr, alice);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 36: clearText deletes a text record
    // ═══════════════════════════════════════════════════════════

    function test_ClearText() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.setText("satoshi", "avatar", "pic.png");

        assertEq(bns.text("satoshi", "avatar"), "pic.png");

        vm.prank(alice);
        bns.clearText("satoshi", "avatar");

        assertEq(bns.text("satoshi", "avatar"), "", "Should be empty after clear");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 37: clearText — non-controller reverts
    // ═══════════════════════════════════════════════════════════

    function test_ClearText_RevertIf_NotController() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.setText("satoshi", "avatar", "pic.png");

        vm.prank(bob);
        vm.expectRevert(BitcoinNameService.NotController.selector);
        bns.clearText("satoshi", "avatar");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 38: Release cleans up text records
    // ═══════════════════════════════════════════════════════════

    function test_Release_CleansTextRecords() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.startPrank(alice);
        bns.setText("satoshi", "avatar", "pic.png");
        bns.setText("satoshi", "url", "https://example.com");
        bns.setText("satoshi", "description", "Hello world");
        bns.release("satoshi");
        vm.stopPrank();

        // Re-register the name (proves it was released)
        vm.prank(bob);
        bns.register{value: FEE}("satoshi", BOB_HASH160);

        // Old text records should NOT bleed through to new owner
        // (they were deleted on release)
        assertEq(bns.text("satoshi", "avatar"), "");
        assertEq(bns.text("satoshi", "url"), "");
        assertEq(bns.text("satoshi", "description"), "");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 39: Token registration with WBTC
    // ═══════════════════════════════════════════════════════════

    function test_RegisterWithToken() public {
        MockWBTC wbtc = new MockWBTC();

        // Use a WBTC-scale fee (0.001 WBTC = 100_000 sats)
        uint256 tokenFee = 100_000;
        bns.setRegistrationFee(tokenFee);
        bns.setFeeToken(address(wbtc));

        // Give Alice some WBTC and approve
        wbtc.mint(alice, 1e8); // 1 WBTC
        vm.prank(alice);
        wbtc.approve(address(bns), tokenFee);

        // Register with token
        vm.prank(alice);
        bns.registerWithToken("satoshi", ALICE_HASH160);

        (address evmAddr,) = bns.resolve("satoshi");
        assertEq(evmAddr, alice, "Should resolve after token registration");
        assertEq(wbtc.balanceOf(address(bns)), tokenFee, "BNS should hold the fee");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 40: Token registration reverts when no fee token set
    // ═══════════════════════════════════════════════════════════

    function test_RegisterWithToken_RevertIf_NoFeeToken() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.TokenNotAccepted.selector);
        bns.registerWithToken("satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 41: Withdraw token fees
    // ═══════════════════════════════════════════════════════════

    function test_WithdrawTokenFees() public {
        MockWBTC wbtc = new MockWBTC();
        uint256 tokenFee = 100_000;
        bns.setRegistrationFee(tokenFee);
        bns.setFeeToken(address(wbtc));

        wbtc.mint(alice, 1e8);
        vm.prank(alice);
        wbtc.approve(address(bns), tokenFee);

        vm.prank(alice);
        bns.registerWithToken("satoshi", ALICE_HASH160);

        uint256 balBefore = wbtc.balanceOf(deployer);
        bns.withdrawTokenFees(address(wbtc));
        uint256 balAfter = wbtc.balanceOf(deployer);

        assertEq(balAfter - balBefore, tokenFee, "Owner should receive token fees");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 42: Subdomain registration
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_Register() public {
        // Alice registers "satoshi"
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Alice creates wallet.satoshi.btc → BOB_HASH160
        mockIdentity.setController(BOB_HASH160, bob);
        vm.prank(alice);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);

        // Resolve wallet.satoshi.btc
        (address evmAddr, bytes20 hash160) = bns.resolveSubdomain("satoshi", "wallet");
        assertEq(evmAddr, bob, "Subdomain should resolve to Bob");
        assertEq(hash160, BOB_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 43: Subdomain — non-parent-owner reverts
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_RevertIf_NotParentOwner() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Bob tries to create a subdomain under Alice's name
        vm.prank(bob);
        vm.expectRevert(BitcoinNameService.ParentNameNotOwned.selector);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 44: Subdomain — duplicate reverts
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_RevertIf_AlreadyTaken() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);

        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.SubdomainAlreadyTaken.selector);
        bns.registerSubdomain("satoshi", "wallet", CHARLIE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 45: Subdomain release
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_Release() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);

        vm.prank(alice);
        bns.releaseSubdomain("satoshi", "wallet");

        // Should no longer resolve
        vm.expectRevert(BitcoinNameService.SubdomainNotRegistered.selector);
        bns.resolveSubdomain("satoshi", "wallet");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 46: Subdomain on expired parent reverts
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_RevertIf_ParentExpired() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);

        // Expire parent
        vm.warp(block.timestamp + 365 days + 1);

        vm.expectRevert(BitcoinNameService.NameExpired.selector);
        bns.resolveSubdomain("satoshi", "wallet");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 47: Relink parent — new controller manages subdomains
    // ═══════════════════════════════════════════════════════════

    function test_Subdomain_RelinkParent_NewControllerManages() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.prank(alice);
        bns.registerSubdomain("satoshi", "wallet", BOB_HASH160);

        // Relink ALICE_HASH160 → Charlie
        mockIdentity.setController(ALICE_HASH160, charlie);

        // Alice can no longer manage subdomains
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ParentNameNotOwned.selector);
        bns.registerSubdomain("satoshi", "vault", CHARLIE_HASH160);

        // Charlie can
        vm.prank(charlie);
        bns.registerSubdomain("satoshi", "vault", CHARLIE_HASH160);

        (address evmAddr,) = bns.resolveSubdomain("satoshi", "vault");
        assertEq(evmAddr, charlie);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 48: MAX_TEXT_KEYS cap prevents unbounded growth
    // ═══════════════════════════════════════════════════════════

    function test_TextRecords_RevertIf_TooManyKeys() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.startPrank(alice);
        // Fill all 20 slots
        for (uint256 i = 0; i < 20; i++) {
            bns.setText("satoshi", string(abi.encodePacked("key-", vm.toString(i))), "value");
        }

        // 21st key should revert
        vm.expectRevert(BitcoinNameService.TooManyTextRecords.selector);
        bns.setText("satoshi", "key-overflow", "nope");
        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 49: Updating existing key does NOT consume a new slot
    // ═══════════════════════════════════════════════════════════

    function test_TextRecords_UpdateExistingKey_NoNewSlot() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        vm.startPrank(alice);
        // Fill all 20 slots
        for (uint256 i = 0; i < 20; i++) {
            bns.setText("satoshi", string(abi.encodePacked("key-", vm.toString(i))), "value");
        }

        // Updating an existing key should work (no new push)
        bns.setText("satoshi", "key-0", "updated-value");
        vm.stopPrank();

        assertEq(bns.text("satoshi", "key-0"), "updated-value");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 50: Pause blocks registration
    // ═══════════════════════════════════════════════════════════

    function test_Pause_BlocksRegistration() public {
        bns.pause();
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 51: Pause blocks renewal
    // ═══════════════════════════════════════════════════════════

    function test_Pause_BlocksRenewal() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bns.pause();
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.renew{value: FEE}("satoshi");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 52: Pause blocks registerWithToken
    // ═══════════════════════════════════════════════════════════

    function test_Pause_BlocksRegisterWithToken() public {
        MockWBTC wbtc = new MockWBTC();
        address tokenAddr = address(wbtc);
        bns.setFeeToken(tokenAddr);
        uint256 tokenFee = 100_000;
        bns.setRegistrationFee(tokenFee);

        wbtc.mint(alice, 1_000_000);
        vm.prank(alice);
        wbtc.approve(address(bns), 1_000_000);

        bns.pause();
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.registerWithToken("satoshi", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 53: Pause blocks setText
    // ═══════════════════════════════════════════════════════════

    function test_Pause_BlocksSetText() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bns.pause();
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.setText("satoshi", "avatar", "img.png");
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 54: Pause blocks subdomain registration
    // ═══════════════════════════════════════════════════════════

    function test_Pause_BlocksSubdomainRegistration() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bns.pause();
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.registerSubdomain("satoshi", "wallet", ALICE_HASH160);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 55: Unpause restores functionality
    // ═══════════════════════════════════════════════════════════

    function test_Unpause_RestoresFunctionality() public {
        bns.pause();

        // Registration blocked
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.ContractPaused.selector);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        // Unpause
        bns.unpause();

        // Registration works again
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);
        (address resolved,) = bns.resolve("satoshi");
        assertEq(resolved, alice);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 56: Only owner can pause/unpause
    // ═══════════════════════════════════════════════════════════

    function test_Pause_RevertIf_NotOwner() public {
        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NotOwner.selector);
        bns.pause();

        vm.prank(alice);
        vm.expectRevert(BitcoinNameService.NotOwner.selector);
        bns.unpause();
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 57: Excess ETH refunded on register
    // ═══════════════════════════════════════════════════════════

    function test_ExcessETH_RefundedOnRegister() public {
        uint256 excess = 0.05 ether;
        uint256 sent = FEE + excess;
        uint256 balanceBefore = alice.balance;

        vm.prank(alice);
        bns.register{value: sent}("satoshi", ALICE_HASH160);

        // Alice should have paid exactly FEE, excess refunded
        uint256 balanceAfter = alice.balance;
        assertEq(balanceBefore - balanceAfter, FEE);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 58: Exact ETH works (no refund needed)
    // ═══════════════════════════════════════════════════════════

    function test_ExactETH_NoRefundNeeded() public {
        uint256 balanceBefore = alice.balance;

        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        uint256 balanceAfter = alice.balance;
        assertEq(balanceBefore - balanceAfter, FEE);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 59: Excess ETH refunded on renew
    // ═══════════════════════════════════════════════════════════

    function test_ExcessETH_RefundedOnRenew() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        uint256 excess = 0.02 ether;
        uint256 sent = FEE + excess;
        uint256 balanceBefore = alice.balance;

        vm.prank(alice);
        bns.renew{value: sent}("satoshi");

        uint256 balanceAfter = alice.balance;
        assertEq(balanceBefore - balanceAfter, FEE);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 60: Read-only functions work while paused
    // ═══════════════════════════════════════════════════════════

    function test_Pause_ReadOnlyFunctionsStillWork() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bns.pause();

        // All read functions should still work
        (address resolved,) = bns.resolve("satoshi");
        assertEq(resolved, alice);
        assertEq(bns.resolveToHash160("satoshi"), ALICE_HASH160);
        assertEq(bns.reverseOf(ALICE_HASH160), "satoshi");
        assertEq(bns.paused(), true);
    }

    // ═══════════════════════════════════════════════════════════
    // TEST 61: Release still works while paused (owner should always be able to clean up)
    // ═══════════════════════════════════════════════════════════

    function test_Pause_ReleaseStillWorks() public {
        vm.prank(alice);
        bns.register{value: FEE}("satoshi", ALICE_HASH160);

        bns.pause();

        // Release is not gated by whenNotPaused — controller can always clean up
        vm.prank(alice);
        bns.release("satoshi");

        // Name is now available (release succeeded despite pause)
        (bool isAvailable,) = bns.available("satoshi");
        assertTrue(isAvailable);
    }

    // ═══════════════════════════════════════════════════════════
    // RECEIVE — let deployer accept ETH withdrawals
    // ═══════════════════════════════════════════════════════════

    receive() external payable {}
}

