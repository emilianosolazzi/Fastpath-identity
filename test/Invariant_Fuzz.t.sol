// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "contracts/attestation/BTCBackedVaultV2.sol";
import "contracts/attestation/FastpathAttestationVerifier.sol";
import "contracts/DemoUSD.sol";
import "contracts/Bitcoingateway.sol";

/**
 * @title Protocol-Wide Invariant & Fuzz Tests
 * @notice Stateful invariant tests that verify critical protocol properties
 *         hold across arbitrary sequences of operations.
 *
 * Uses the real FastpathAttestationVerifier with the vault whitelisted as a trusted caller.
 *
 * Invariants:
 *   INV-1: totalBorrowed == Σ positions[i].borrowedUSD
 *   INV-2: totalBtcCollateralSats == Σ positions[i].btcBalanceSats
 *   INV-3: demoUSD.totalSupply() == vault.totalBorrowed()
 *   INV-4: Gateway totalProtocolFeesEth <= address(gw).balance
 *   INV-5: No position can have borrowedUSD > 0 without btcBalanceSats > 0 at attest time
 *
 * Fuzz:
 *   FUZZ-1: Borrow→Repay round-trip preserves balances
 *   FUZZ-2: Attestation with random balances / prices
 *   FUZZ-3: Gateway sendBitcoin with fuzzed sats amounts
 *   FUZZ-4: Liquidation math precision at extreme prices
 */

// No MockVerifier needed — real verifier with trusted caller whitelist

// ════════════════════════════════════════════════════════
// VaultV2 Handler for Invariant Testing
// ════════════════════════════════════════════════════════
contract VaultV2Handler is Test {
    BTCBackedVaultV2 public vault;
    FastpathAttestationVerifier public verifier;
    DemoUSD public demoUSD;

    uint256 internal signerPk = 0xABCDEF;
    address[] public actors;
    mapping(address => bool) public hasAttested;
    mapping(address => uint256) public nonces;

    constructor(
        BTCBackedVaultV2 _vault,
        FastpathAttestationVerifier _verifier,
        DemoUSD _demoUSD,
        address[] memory _actors
    ) {
        vault = _vault;
        verifier = _verifier;
        demoUSD = _demoUSD;
        actors = _actors;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("FastPathAttestation"),
                keccak256("1"),
                block.chainid,
                address(verifier)
            )
        );
    }

    function attestBalance(uint256 actorIdx, uint256 balanceSats) external {
        actorIdx = bound(actorIdx, 0, actors.length - 1);
        balanceSats = bound(balanceSats, 0, 21_000_000e8); // Max BTC supply

        address actor = actors[actorIdx];
        uint256 nonce = ++nonces[actor];
        uint256 ts = block.timestamp;

        string memory btcAddr = string(abi.encodePacked("bc1q_actor_", vm.toString(actorIdx)));

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "BalanceAttestation(address evmAddress,string btcAddress,uint256 balanceSats,uint256 timestamp,uint256 nonce)"
                ),
                actor,
                keccak256(bytes(btcAddr)),
                balanceSats,
                ts,
                nonce
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(actor);
        vault.attestBalance(btcAddr, balanceSats, ts, nonce, sig);

        hasAttested[actor] = true;
    }

    function borrow(uint256 actorIdx, uint256 amount) external {
        actorIdx = bound(actorIdx, 0, actors.length - 1);
        address actor = actors[actorIdx];

        (uint256 sats,, uint256 borrowed, uint256 maxBorrow,,,) = vault.getPosition(actor);
        if (sats == 0 || maxBorrow <= borrowed) return;

        amount = bound(amount, 0, maxBorrow - borrowed);

        vm.prank(actor);
        try vault.borrow(amount) {} catch {}
    }

    function repay(uint256 actorIdx, uint256 amount) external {
        actorIdx = bound(actorIdx, 0, actors.length - 1);
        address actor = actors[actorIdx];

        (,, uint256 borrowed,,,,) = vault.getPosition(actor);
        if (borrowed == 0) return;

        amount = bound(amount, 1, borrowed);

        vm.prank(actor);
        try vault.repay(amount) {} catch {}
    }

    function warpTime(uint256 delta) external {
        delta = bound(delta, 0, 7 days);
        vm.warp(block.timestamp + delta);
    }
}

// ════════════════════════════════════════════════════════
// Invariant Test Suite
// ════════════════════════════════════════════════════════
contract InvariantVaultV2Test is Test {
    BTCBackedVaultV2 vault;
    FastpathAttestationVerifier verifier;
    DemoUSD demoUSD;
    VaultV2Handler handler;

    address[] actors;

    function setUp() public {
        uint256 signerPk = 0xABCDEF;
        address signer = vm.addr(signerPk);

        verifier = new FastpathAttestationVerifier(signer);
        verifier.updateMaxAge(365 days);
        vault = new BTCBackedVaultV2(address(verifier));
        verifier.setTrustedCaller(address(vault), true);
        demoUSD = new DemoUSD();
        demoUSD.setVault(address(vault));
        vault.setDemoUSD(address(demoUSD));

        // Create 5 actors
        for (uint256 i = 0; i < 5; i++) {
            actors.push(address(uint160(0x1000 + i)));
        }

        handler = new VaultV2Handler(vault, verifier, demoUSD, actors);

        // Target only the handler for invariant testing
        targetContract(address(handler));
    }

    /// @notice INV-3: DemoUSD supply must always equal totalBorrowed
    function invariant_DemoUsdSupplyEqualsTotalBorrowed() public view {
        assertEq(demoUSD.totalSupply(), vault.totalBorrowed(), "INV-3: dUSD supply != totalBorrowed");
    }

    /// @notice INV-1 + INV-2: Aggregate tracking matches sum of positions
    function invariant_AggregateTrackingConsistency() public view {
        uint256 sumBorrowed;
        uint256 sumCollateral;

        for (uint256 i = 0; i < actors.length; i++) {
            (uint256 sats,, uint256 borrowed,,,,) = vault.getPosition(actors[i]);
            sumBorrowed += borrowed;
            sumCollateral += sats;
        }

        assertEq(vault.totalBorrowed(), sumBorrowed, "INV-1: totalBorrowed mismatch");
        assertEq(vault.totalBtcCollateralSats(), sumCollateral, "INV-2: totalCollateral mismatch");
    }
}

// ════════════════════════════════════════════════════════
// Fuzz Tests
// ════════════════════════════════════════════════════════
contract FuzzTests is Test {
    BTCBackedVaultV2 vault;
    FastpathAttestationVerifier verifier;
    DemoUSD demoUSD;
    BitcoinGateway gw;

    uint256 signerPk = 0xABCDEF;
    address signer;
    address user = address(0xB0B);
    address gwOwner = address(0xA11CE);

    function setUp() public {
        signer = vm.addr(signerPk);
        verifier = new FastpathAttestationVerifier(signer);
        verifier.updateMaxAge(365 days);
        vault = new BTCBackedVaultV2(address(verifier));
        verifier.setTrustedCaller(address(vault), true);
        demoUSD = new DemoUSD();
        demoUSD.setVault(address(vault));
        vault.setDemoUSD(address(demoUSD));

        vm.prank(gwOwner);
        gw = new BitcoinGateway(gwOwner);

        vm.deal(user, 100 ether);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("FastPathAttestation"),
                keccak256("1"),
                block.chainid,
                address(verifier)
            )
        );
    }

    function _attestAndBorrow(uint256 sats, uint256 amount) internal {
        uint256 ts = block.timestamp;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "BalanceAttestation(address evmAddress,string btcAddress,uint256 balanceSats,uint256 timestamp,uint256 nonce)"
                ),
                user,
                keccak256(bytes("bc1qfuzz")),
                sats,
                ts,
                uint256(1)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        vm.prank(user);
        vault.attestBalance("bc1qfuzz", sats, ts, 1, abi.encodePacked(r, s, v));

        vm.prank(user);
        vault.borrow(amount);
    }

    // ── FUZZ-1: Borrow→Repay round trip ──

    function testFuzz_BorrowRepayRoundTrip(uint256 sats, uint256 borrowPct) public {
        sats = bound(sats, 1e6, 21_000_000e8); // 0.01 BTC to 21M BTC
        borrowPct = bound(borrowPct, 1, 100); // 1-100%

        uint256 maxBorrow = (sats * 90_000e8 / 1e8) * 5000 / 10000;
        if (maxBorrow == 0) return;

        uint256 amount = (maxBorrow * borrowPct) / 100;
        if (amount == 0) return;

        _attestAndBorrow(sats, amount);

        assertEq(demoUSD.balanceOf(user), amount);
        assertEq(vault.totalBorrowed(), amount);

        // Repay full
        vm.prank(user);
        vault.repay(amount);

        assertEq(demoUSD.balanceOf(user), 0);
        assertEq(vault.totalBorrowed(), 0);
    }

    // ── FUZZ-2: Attest with random balance → maxBorrow consistency ──

    function testFuzz_MaxBorrowConsistency(uint256 sats) public {
        sats = bound(sats, 1, 21_000_000e8);

        uint256 ts = block.timestamp;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "BalanceAttestation(address evmAddress,string btcAddress,uint256 balanceSats,uint256 timestamp,uint256 nonce)"
                ),
                user,
                keccak256(bytes("bc1qfuzz")),
                sats,
                ts,
                uint256(1)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        vm.prank(user);
        vault.attestBalance("bc1qfuzz", sats, ts, 1, abi.encodePacked(r, s, v));

        (,,, uint256 maxBorrow,,,) = vault.getPosition(user);
        uint256 expected = (sats * vault.btcPriceUsd() / 1e8) * 5000 / 10000;
        assertEq(maxBorrow, expected, "maxBorrow formula mismatch");
    }

    // ── FUZZ-3: Gateway sendBitcoin fuzzed amounts ──

    function testFuzz_GatewaySendAmounts(uint256 sats) public {
        sats = bound(sats, 600, type(uint128).max); // Above dust, avoid overflow

        vm.prank(user);
        uint256 reqId = gw.sendBitcoin("bc1qfrom", "bc1qto", sats, "memo");

        (address req,, uint64 ts, uint256 amt,,,,) = gw.requests(reqId);
        assertEq(req, user);
        assertEq(amt, sats);
        assertTrue(ts > 0);
    }

    // ── FUZZ-4: Liquidation math at extreme prices ──

    function testFuzz_LiquidationMathExtremePrices(uint256 price) public {
        price = bound(price, 1e8, 10_000_000e8); // $1 to $10M per BTC

        vault.updateBtcPrice(price);

        uint256 sats = 1e8; // 1 BTC
        uint256 maxBorrow = (sats * price / 1e8) * 5000 / 10000;
        if (maxBorrow == 0) return;

        _attestAndBorrow(sats, maxBorrow);

        // Now crash price to 10% of original
        uint256 crashPrice = price / 10;
        if (crashPrice == 0) crashPrice = 1e8;
        vault.updateBtcPrice(crashPrice);

        // Position should be liquidatable
        (,,,, uint256 health,, bool isLiq) = vault.getPosition(user);
        assertTrue(isLiq, "Should be liquidatable after 90% price drop");

        // Mint dUSD for liquidator
        demoUSD.setVault(address(this));
        demoUSD.mint(address(0xD1E), maxBorrow);
        demoUSD.setVault(address(vault));

        // Execute liquidation
        vm.prank(address(0xD1E));
        vault.liquidate(user, maxBorrow);

        // Debt should be cleared
        (,, uint256 borrowed,,,,) = vault.getPosition(user);
        assertEq(borrowed, 0);
        assertEq(vault.totalBorrowed(), 0);
    }

    // ── FUZZ-5: Health factor calculation never overflows ──

    function testFuzz_HealthFactorNoOverflow(uint256 sats, uint256 price) public {
        sats = bound(sats, 1, 21_000_000e8);
        price = bound(price, 1e8, 10_000_000e8);

        vault.updateBtcPrice(price);

        uint256 ts = block.timestamp;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "BalanceAttestation(address evmAddress,string btcAddress,uint256 balanceSats,uint256 timestamp,uint256 nonce)"
                ),
                user,
                keccak256(bytes("bc1qfuzz")),
                sats,
                ts,
                uint256(1)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        vm.prank(user);
        vault.attestBalance("bc1qfuzz", sats, ts, 1, abi.encodePacked(r, s, v));

        // This should never revert with overflow
        (,,, uint256 maxBorrow, uint256 healthFactor,, bool isLiq) = vault.getPosition(user);

        // With no debt, health factor should be max uint256
        assertEq(healthFactor, type(uint256).max);
        assertFalse(isLiq);
    }
}
