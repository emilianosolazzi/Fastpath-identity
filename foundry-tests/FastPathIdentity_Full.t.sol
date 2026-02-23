// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/fastapthidentity.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function expectRevert(bytes calldata) external;
    function expectEmit(bool, bool, bool, bool) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function assume(bool condition) external;
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function warp(uint256 timestamp) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
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

contract MockDiscountNFT is IDiscountNFT {
    mapping(address => bool) public discount;

    function setDiscount(address user, bool value) external {
        discount[user] = value;
    }

    function hasDiscount(address user) external view returns (bool) {
        return discount[user];
    }
}

/// @dev Malicious receiver that attempts to consume all forwarded gas.
///      Used to verify the 2300-gas cap in receiveFunds prevents gas-bomb griefing.
contract GasBombReceiver {
    uint256 public x;
    receive() external payable {
        // Storage write costs 5000+ gas, guaranteed to exceed 2300 stipend
        x = x + 1;
    }
}

/// @dev NFT that reverts in hasDiscount — tests try/catch protection
contract MaliciousDiscountNFT is IDiscountNFT {
    function hasDiscount(address) external pure returns (bool) {
        revert("malicious NFT");
    }
}

/// @dev Minimal ERC-20 mock that returns true on transferFrom.
///      SafeERC20.safeTransferFrom only needs transferFrom(address,address,uint256)->bool.
contract MockTokenTrue {
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
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract PayableReceiver {
    receive() external payable {}
}

contract ReentrantReceiver {
    FastPathIdentity public identity;
    bytes20 public hash;
    bool public reentered;

    constructor(FastPathIdentity _identity, bytes20 _hash) {
        identity = _identity;
        hash = _hash;
    }

    receive() external payable {
        if (!reentered && address(this).balance >= 1) {
            try identity.receiveFunds{value: 1}(hash) {
                // no-op
            } catch {
                reentered = true;
            }
        }
    }
}

contract FastPathIdentityHarness is FastPathIdentity {
    constructor() FastPathIdentity(0) {}

    function exposeEncodeCompactSize(uint256 n) external pure returns (bytes memory) {
        return _encodeCompactSize(n);
    }

    function exposeDecompress(bytes memory comp) external pure returns (bytes memory) {
        return decompressCompressedSecp256k1Mem(comp);
    }

    function exposePubkeyToXY(bytes memory pubkey) external pure returns (bytes memory) {
        return _pubkeyToXYMem(pubkey);
    }

    function exposeEthAddressFromXY(bytes memory xy) external pure returns (address) {
        return ethAddressFromXY(xy);
    }

    function exposeBtcHash160FromPubkey(bytes memory pubkey) external pure returns (bytes20) {
        return btcHash160FromPubkeyMem(pubkey);
    }

    function exposeModSqrt(uint256 a, uint256 p) external pure returns (uint256) {
        return modSqrt(a, p);
    }

    function exposeExpMod(uint256 base, uint256 exp, uint256 mod) external pure returns (uint256) {
        return expMod(base, exp, mod);
    }
}

contract FastPathIdentityFullTest is Test {
    FastPathIdentity private identity;
    address private owner = address(0xA11CE);
    
    // secp256k1 generator pubkey (privkey = 1)
    uint256 private constant PRIVKEY = 1;
    uint8 private constant PUBKEY_PREFIX = 2;
    bytes32 private constant PUBKEY_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    bytes private constant PUBKEY_UNCOMP = hex"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    /// @dev secp256k1 curve order n, used to compute high-s = n - s for malleability tests
    uint256 private constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes20 private hash160 = bytes20(keccak256("test-btc-hash160"));

    function setUp() public {
        vm.prank(owner);
        identity = new FastPathIdentity(0.001 ether);
    }

    // ==========================================
    // REGISTRATION TESTS
    // ==========================================

    function testRegisterV2_Succeeds_EthSigned() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        assertEq(identity.evmToBtc(signer), expected, "mapping not set");
    }

    function testRegisterV2_Succeeds_BitcoinStyle() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _bitcoinSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        assertEq(identity.evmToBtc(signer), expected, "mapping not set (btc style)");
    }

    function testRegisterV1_Succeeds_EthSigned() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddress{value: 0.001 ether}(PUBKEY_UNCOMP, sig, message);

        bytes20 expected = _btcHash160FromPubkeyMem(PUBKEY_UNCOMP);
        assertEq(identity.evmToBtc(signer), expected, "mapping not set v1");
    }

    function testRegisterV1_Succeeds_Pubkey64() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        bytes memory pubkey64 = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            pubkey64[i] = PUBKEY_UNCOMP[i + 1];
        }

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey64, sig, message);

        bytes20 expected = _btcHash160FromPubkeyMem(pubkey64);
        assertEq(identity.evmToBtc(signer), expected, "mapping not set v1 (64)");
    }

    function testRegisterV1_InvalidSignature() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(PUBKEY_UNCOMP, sig, message);
    }

    function testRegisterV1_Succeeds_BitcoinStyleCompact() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _bitcoinSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(bytes1(uint8(27 + (v - 27))), r, s);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddress{value: 0.001 ether}(PUBKEY_UNCOMP, sig, message);

        bytes20 expected = _btcHash160FromPubkeyMem(PUBKEY_UNCOMP);
        assertEq(identity.evmToBtc(signer), expected, "mapping not set v1 btc style");
    }

    /// @notice V1 registration with 33-byte compressed pubkey should succeed
    function testRegisterV1_Succeeds_CompressedPubkey() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkeyComp, sig, message);

        bytes20 expectedHash = _btcHash160FromPubkeyMem(pubkeyComp);
        assertEq(identity.evmToBtc(signer), expectedHash, "mapping not set v1 compressed");
    }

    /// @notice Overpaying (msg.value > fee) should succeed — excess stays in accumulatedFees
    function testRegisterV2_ExcessFeeAccepted() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 2 ether);
        vm.prank(signer);
        // Pay 0.5 ether for a 0.001 ether fee — should not revert
        identity.registerBitcoinAddressV2{value: 0.5 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        // Full msg.value goes to accumulatedFees
        assertEq(identity.accumulatedFees(), 0.5 ether, "excess fee not accumulated");
    }

    /// @notice V1 message of exactly 42 bytes ("0x" + 40 hex) should succeed — boundary test
    function testRegisterV1_MessageBoundary_42bytes() public {
        address signer = vm.addr(PRIVKEY);
        // _toHex produces exactly 42 bytes: "0x" + 40 hex chars for 20-byte address
        bytes memory message = bytes(_toHex(signer));
        assertEq(message.length, 42, "message should be exactly 42 bytes");

        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        // Should succeed — 42 is within the <= 42 bound
        identity.registerBitcoinAddress{value: 0.001 ether}(PUBKEY_UNCOMP, sig, message);

        bytes20 expectedHash = _btcHash160FromPubkeyMem(PUBKEY_UNCOMP);
        assertEq(identity.evmToBtc(signer), expectedHash, "42-byte message registration failed");
    }

    /// @notice Decompressing a 0x03-prefixed key produces an ODD Y that is on the secp256k1 curve.
    ///         Uses PUBKEY_X (known valid) with prefix 0x03 to directly hit the odd-Y branch.
    function testCryptoHelper_Decompress03_ProducesOddY() public {
        FastPathIdentityHarness harness = new FastPathIdentityHarness();
        // Same X as privkey 1, but force prefix 0x03 — decompression must pick the odd root
        bytes memory comp03 = abi.encodePacked(bytes1(0x03), PUBKEY_X);
        bytes memory uncompressed = harness.exposeDecompress(comp03);

        // Must return a 65-byte uncompressed key starting with 0x04
        assertEq(uncompressed.length, 65, "decompressed length must be 65");
        assertEq(uint8(uncompressed[0]), 0x04, "must start with 0x04");

        // Y is bytes 33-64; its last bit must be 1 (odd) for prefix 0x03
        uint8 yLastByte = uint8(uncompressed[64]);
        assertTrue((yLastByte & 1) == 1, "0x03 prefix must produce odd Y");

        // Y must satisfy Y^2 = X^3 + 7 mod p (on-curve check)
        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 xUint = uint256(PUBKEY_X);
        uint256 yUint;
        for (uint256 i = 0; i < 32; i++) {
            yUint = (yUint << 8) | uint8(uncompressed[33 + i]);
        }
        uint256 lhs = mulmod(yUint, yUint, p);
        uint256 rhs = addmod(mulmod(xUint, mulmod(xUint, xUint, p), p), 7, p);
        assertEq(lhs, rhs, "decompressed 0x03 Y must satisfy secp256k1 curve equation");
    }

    function testRegisterV2_InsufficientFee() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InsufficientFee.selector));
        identity.registerBitcoinAddressV2{value: 0}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }

    function testRegisterV2_InvalidPubkeyPrefix() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(4, PUBKEY_X, r, s, v, false);
    }

    function testRegisterV1_InvalidMessage() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory badMessage = bytes("0x00");
        bytes memory sig = new bytes(65);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidMessage.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(PUBKEY_UNCOMP, sig, badMessage);
    }

    function testRegisterV2_InvalidSignature() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        // Sign with different key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }

    function testRegisterV2_DuplicateEvm() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 2 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.AddressAlreadyRegistered.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }

    function testRegisterV2_DuplicateHash() public {
        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        _setBtcToEvm(expected, address(0xBEEF));

        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.AddressAlreadyRegistered.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }

    function testRegisterV2_DiscountFee() public {
        MockDiscountNFT nft = new MockDiscountNFT();
        vm.prank(owner);
        identity.setDiscountNFT(address(nft));

        address signer = vm.addr(PRIVKEY);
        nft.setDiscount(signer, true);

        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.0009 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }

    function testSetDiscountNFT_OnlyOwner() public {
        MockDiscountNFT nft = new MockDiscountNFT();
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.setDiscountNFT(address(nft));
    }

    /// @notice Malicious NFT that reverts in hasDiscount must not brick registration (try/catch)
    function testDiscountNFT_MaliciousReverts_DoesNotBrickRegistration() public {
        MaliciousDiscountNFT badNft = new MaliciousDiscountNFT();
        vm.prank(owner);
        identity.setDiscountNFT(address(badNft));

        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        // Full fee required — try/catch swallows the revert, no discount applied
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expectedHash = _btcHash160FromPubkeyMem(pubkeyComp);
        assertEq(identity.evmToBtc(signer), expectedHash, "registration should succeed despite malicious NFT");
    }

    /// @notice NFT returns false → no discount → full fee required
    function testDiscountNFT_NoDiscount_FullFeeRequired() public {
        MockDiscountNFT nft = new MockDiscountNFT();
        vm.prank(owner);
        identity.setDiscountNFT(address(nft));

        address signer = vm.addr(PRIVKEY);
        // nft.discount[signer] defaults to false — no discount

        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        // 90% of 0.001 = 0.0009 should be insufficient when no discount
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InsufficientFee.selector));
        identity.registerBitcoinAddressV2{value: 0.0009 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }
    
    function testSetRegistrationFee() public {
        vm.prank(owner);
        identity.setRegistrationFee(0.002 ether);
        assertEq(identity.registrationFee(), 0.002 ether, "fee not updated");
    }
    
    function testSetRegistrationFee_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.setRegistrationFee(0.002 ether);
    }

    function testSetRegistrationFee_FeeTooHigh() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.FeeTooHigh.selector));
        identity.setRegistrationFee(1.1 ether);
    }
    
    function testWithdrawFees() public {
        // Set accumulatedFees (slot 13) and deal matching ETH to contract
        vm.store(address(identity), bytes32(uint256(13)), bytes32(uint256(1 ether)));
        vm.deal(address(identity), 1 ether);
        uint256 ownerBalBefore = owner.balance;
        
        vm.prank(owner);
        identity.withdrawFees();
        
        assertTrue(owner.balance == ownerBalBefore + 1 ether, "fees not withdrawn");
        assertEq(identity.accumulatedFees(), 0, "accumulatedFees not cleared");
    }
    
    function testWithdrawFees_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.withdrawFees();
    }
    
    function testWithdrawFees_NoFeesReverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NoFeesToWithdraw.selector));
        identity.withdrawFees();
    }

    function testWithdrawFees_AccumulatesFromBothV1AndV2() public {
        // Register via V2 to accumulate fees
        address signer1 = vm.addr(PRIVKEY);
        bytes memory message1 = bytes(_toHex(signer1));
        bytes32 digest1 = _ethSignedMessageHash(message1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PRIVKEY, digest1);

        vm.deal(signer1, 1 ether);
        vm.prank(signer1);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r1, s1, v1, false);

        // Verify fees accumulated
        assertEq(identity.accumulatedFees(), 0.001 ether, "V2 fee not accumulated");

        // Owner withdraws
        uint256 ownerBalBefore = owner.balance;
        vm.prank(owner);
        identity.withdrawFees();

        assertEq(owner.balance, ownerBalBefore + 0.001 ether, "owner should receive V2 fee");
        assertEq(identity.accumulatedFees(), 0, "accumulatedFees should be zero");
    }

    /// @notice After withdraw succeeds, second call reverts with NoFeesToWithdraw
    function testWithdrawFees_ClearsToZero_ThenReverts() public {
        // Register to accumulate fees
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        // First withdraw succeeds
        vm.prank(owner);
        identity.withdrawFees();
        assertEq(identity.accumulatedFees(), 0, "fees should be zero after withdraw");

        // Second withdraw reverts
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NoFeesToWithdraw.selector));
        identity.withdrawFees();
    }

    // ==========================================
    // TRANSFER OWNERSHIP TESTS
    // ==========================================

    function testTransferOwnership_TwoStep() public {
        address newOwner = address(0x0000000000000000000000000000000000000aBc);
        vm.prank(owner);
        identity.transferOwnership(newOwner);

        // Owner not changed yet (two-step)
        assertEq(identity.owner(), owner, "owner should not change yet");
        assertEq(identity.pendingOwner(), newOwner, "pendingOwner not set");

        // New owner accepts
        vm.prank(newOwner);
        identity.acceptOwnership();
        assertEq(identity.owner(), newOwner, "ownership not transferred");
    }

    function testTransferOwnership_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.transferOwnership(address(0x0000000000000000000000000000000000000aBc));
    }

    function testTransferOwnership_ZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.ZeroAddress.selector));
        identity.transferOwnership(address(0));
    }

    function testAcceptOwnership_NotPendingOwner() public {
        address newOwner = address(0x0000000000000000000000000000000000000aBc);
        vm.prank(owner);
        identity.transferOwnership(newOwner);

        // Random address tries to accept — should fail
        vm.prank(address(0x0000000000000000000000000000000000000Bad));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotPendingOwner.selector));
        identity.acceptOwnership();

        // Owner unchanged
        assertEq(identity.owner(), owner, "owner should not change");
    }

    /// @notice Second transferOwnership overwrites the pending owner
    function testTransferOwnership_OverwritesPendingOwner() public {
        address first = address(0x0000000000000000000000000000000000000aBc);
        address second = address(0x0000000000000000000000000000000000000deF);

        vm.prank(owner);
        identity.transferOwnership(first);
        assertEq(identity.pendingOwner(), first, "first pending not set");

        vm.prank(owner);
        identity.transferOwnership(second);
        assertEq(identity.pendingOwner(), second, "second pending not set");

        // First can no longer accept
        vm.prank(first);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotPendingOwner.selector));
        identity.acceptOwnership();

        // Second can accept
        vm.prank(second);
        identity.acceptOwnership();
        assertEq(identity.owner(), second, "second should be owner");
    }

    function testTransferOwnership_NewOwnerCanAct() public {
        address newOwner = address(0x0000000000000000000000000000000000000aBc);
        vm.prank(owner);
        identity.transferOwnership(newOwner);

        vm.prank(newOwner);
        identity.acceptOwnership();

        // Old owner can no longer act
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.setRegistrationFee(999);

        // New owner can act
        vm.prank(newOwner);
        identity.setRegistrationFee(999);
        assertEq(identity.registrationFee(), 999, "new owner could not set fee");
    }

    // ==========================================
    // RELINK TESTS
    // ==========================================
    
    function testToggleRelink() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);
        assertTrue(identity.relinkEnabled(), "relink not enabled");
        
        vm.prank(owner);
        identity.setRelinkEnabled(false);
        assertTrue(!identity.relinkEnabled(), "relink not disabled");
    }
    
    function testSetRelinkCooldown() public {
        vm.prank(owner);
        identity.setRelinkCooldown(7 days);
        assertEq(identity.relinkCooldown(), 7 days, "cooldown not set");
    }
    
    function testSetRelinkCooldown_MinimumEnforced() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.CooldownTooSmall.selector));
        identity.setRelinkCooldown(59 minutes);
    }
    
    function testInitiateRelink_DisabledByDefault() public {
        // Set up registered hash
        _setBtcToEvm(hash160, address(this));
        
        bytes memory dummyPubkey = hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111";
        // 65 bytes: 32(r) + 32(s) + 1(v) = exactly what the contract expects
        bytes memory dummySig = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b";
        
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.RelinkDisabled.selector));
        identity.initiateRelink(hash160, address(0x0000000000000000000000000000000000000002), dummyPubkey, dummySig);
    }

    function testInitiateRelink_ZeroHashReverts() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory dummyPubkey = hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111";
        // 65 bytes: 32(r) + 32(s) + 1(v) = exactly what the contract expects
        bytes memory dummySig = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b";

        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.ZeroHash160.selector));
        identity.initiateRelink(bytes20(0), address(0x0000000000000000000000000000000000000002), dummyPubkey, dummySig);
    }

    function testRelinkFlow_Succeeds_EthSigned() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);

        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        assertEq(identity.evmToBtc(newEvm), expected, "new EVM not mapped");
    }

    function testFrontRunRelinkFinalize() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);

        bytes memory pubkeyComp = _pubkeyComp();
        bytes20 expected = _expectedHash160();

        vm.warp(3 days + 1);

        bytes memory sig = _signForEvm(newEvm);

        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);

        // Front-run: newEvm registers another BTC identity before finalize
        _setEvmToBtc(newEvm, bytes20(keccak256("front-run")));

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NewEvmAlreadyRegistered.selector));
        identity.finalizeRelink(expected);
    }

    function testHasControl() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        assertTrue(identity.hasControl(signer), "owner should have control");
        assertTrue(!identity.hasControl(address(0x0000000000000000000000000000000000000002)), "other should not have control");
    }

    function testHasControlAfterRelink() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);

        bytes memory pubkeyComp = _pubkeyComp();
        bytes20 expected = _expectedHash160();

        vm.warp(3 days + 1);

        bytes memory sig = _signForEvm(newEvm);

        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        assertTrue(!identity.hasControl(oldEvm), "old EVM should not have control");
        assertTrue(identity.hasControl(newEvm), "new EVM should have control");
        assertEq(identity.evmToBtc(oldEvm), expected, "old EVM mapping should remain");
    }

    function testCurrentControllerPublic() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);

        bytes20 expected = _expectedHash160();
        assertEq(identity.currentController(expected), oldEvm, "controller should be old EVM");

        vm.warp(3 days + 1);
        bytes memory sig = _signForEvm(newEvm);
        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, _pubkeyComp(), sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        assertEq(identity.currentController(expected), newEvm, "controller should be new EVM");
    }

    function testFundsFollowRelink() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);
        bytes20 expected = _expectedHash160();

        vm.warp(3 days + 1);
        bytes memory sig = _signForEvm(newEvm);
        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, _pubkeyComp(), sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        vm.prank(newEvm);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 1}(expected);

        // Funds credited to newEvm's pendingWithdrawals, not oldEvm
        assertEq(identity.pendingWithdrawals(oldEvm), 0, "old EVM should not have pending funds");
        assertEq(identity.pendingWithdrawals(newEvm), 1, "new EVM should have pending funds");
    }

    function testInitiateRelink_CooldownActive() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        _setLastLinkTime(expected, block.timestamp);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.CooldownActive.selector));
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);
    }

    function testInitiateRelink_NewEvmAlreadyRegistered() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        _setEvmToBtc(newEvm, bytes20(keccak256("other")));
        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NewEvmAlreadyRegistered.selector));
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);
    }

    function testInitiateRelink_InvalidPubkey() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        bytes memory wrongPubkey = hex"021111111111111111111111111111111111111111111111111111111111111111";
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, wrongPubkey, sig);
    }

    function testInitiateRelink_InvalidPubkeyLengthReverts() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        bytes memory badPubkey;

        badPubkey = new bytes(0);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, badPubkey, sig);

        badPubkey = new bytes(1);
        badPubkey[0] = 0x02;
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, badPubkey, sig);

        badPubkey = new bytes(32);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, badPubkey, sig);

        badPubkey = new bytes(34);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, badPubkey, sig);

        badPubkey = new bytes(66);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(expected, newEvm, badPubkey, sig);
    }

    function testInitiateRelink_InvalidSignature() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);
    }

    function testInitiateRelink_PendingExists() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        _setPendingRelink(expected, newEvm, block.timestamp + 10, true);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        bytes memory sig = abi.encodePacked(r, s, bytes1(v));

        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.PendingRelinkExists.selector));
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);
    }

    function testFinalizeRelink_NoPending() public {
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.PendingRelinkMissing.selector));
        identity.finalizeRelink(bytes20(keccak256("none")));
    }

    function testFinalizeRelink_CooldownActive() public {
        bytes20 expected = bytes20(keccak256("hash"));
        address newEvm = vm.addr(2);
        _setPendingRelink(expected, newEvm, block.timestamp + 1000, true);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.CooldownActive.selector));
        identity.finalizeRelink(expected);
    }

    function testFinalizeRelink_AddressNotRegistered() public {
        bytes20 expected = bytes20(keccak256("hash"));
        address newEvm = vm.addr(2);
        _setPendingRelink(expected, newEvm, block.timestamp - 1, true);
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.AddressNotRegistered.selector));
        identity.finalizeRelink(expected);
    }

    function testFinalizeRelink_NewEvmAlreadyRegistered() public {
        bytes20 expected = bytes20(keccak256("hash"));
        address newEvm = vm.addr(2);
        _setPendingRelink(expected, newEvm, block.timestamp - 1, true);
        _setBtcToEvm(expected, address(0x0000000000000000000000000000000000000001));
        _setEvmToBtc(newEvm, bytes20(keccak256("other")));
        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NewEvmAlreadyRegistered.selector));
        identity.finalizeRelink(expected);
    }

    function testFinalizeRelink_OnlyPendingNewEvm() public {
        bytes20 expected = bytes20(keccak256("hash"));
        address newEvm = vm.addr(2);
        address attacker = address(0x0000000000000000000000000000000000000099);
        _setPendingRelink(expected, newEvm, block.timestamp - 1, true);
        _setBtcToEvm(expected, address(0x0000000000000000000000000000000000000001));
        vm.prank(attacker);
        vm.expectRevert("Only pending new owner");
        identity.finalizeRelink(expected);
    }

    function testCancelRelink_NotOwner() public {
        bytes20 expected = bytes20(keccak256("hash"));
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address other = address(0x0000000000000000000000000000000000000002);
        _setBtcToEvm(expected, oldEvm);
        _setPendingRelink(expected, vm.addr(2), block.timestamp + 1, true);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotCurrentOwner.selector));
        identity.cancelRelink(expected);
    }

    function testCancelRelink_NoPending() public {
        bytes20 expected = bytes20(keccak256("hash"));
        _setBtcToEvm(expected, address(this));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.PendingRelinkMissing.selector));
        identity.cancelRelink(expected);
    }

    function testCancelRelink_Succeeds() public {
        bytes20 expected = bytes20(keccak256("cancel-hash"));
        address currentOwner = address(0x0000000000000000000000000000000000000001);
        address pendingNewEvm = vm.addr(2);

        // _setBtcToEvm sets both btcToEvm (slot 6) AND activeEvm (slot 11).
        // cancelRelink checks activeEvm, so both must be set.
        _setBtcToEvm(expected, currentOwner);
        _setPendingRelink(expected, pendingNewEvm, block.timestamp + 1000, true);

        // Verify pending exists
        (bool hasPending,,,) = identity.getRelinkStatus(expected);
        assertTrue(hasPending, "pending should exist before cancel");

        vm.prank(currentOwner);
        identity.cancelRelink(expected);

        // Verify pending cleared
        (bool hasPendingAfter,,,) = identity.getRelinkStatus(expected);
        assertTrue(!hasPendingAfter, "pending should be cleared after cancel");
    }
    
    // NOTE: Full relink flow requires valid BTC signatures, omitted for now
    // Coverage will still be low until registration tests with valid signatures are added

    // ==========================================
    // EMERGENCY STOP TESTS
    // ==========================================
    
    function testEmergencyDisableRelink() public {
        vm.prank(owner);
        identity.emergencyDisableRelink(true);
        assertTrue(identity.emergencyStop(), "emergency not activated");
    }

    function testEmergencyStop_BlocksInitiateRelink() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);
        vm.prank(owner);
        identity.emergencyDisableRelink(true);

        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory sig = new bytes(65);
        vm.expectRevert("Emergency stop active");
        identity.initiateRelink(hash160, address(0x0000000000000000000000000000000000000002), pubkey, sig);
    }

    function testEmergencyStop_BlocksFinalizeRelink() public {
        bytes20 expected = bytes20(keccak256("emergency-finalize"));
        address newEvm = vm.addr(2);
        _setBtcToEvm(expected, address(0x0000000000000000000000000000000000000001));
        _setPendingRelink(expected, newEvm, block.timestamp - 1, true);

        vm.prank(owner);
        identity.emergencyDisableRelink(true);

        vm.prank(newEvm);
        vm.expectRevert("Emergency stop active");
        identity.finalizeRelink(expected);
    }

    function testEmergencyStop_BlocksCancelRelink() public {
        bytes20 expected = bytes20(keccak256("emergency-cancel"));
        address currentOwner = address(0x0000000000000000000000000000000000000001);
        _setBtcToEvm(expected, currentOwner);
        _setPendingRelink(expected, vm.addr(2), block.timestamp + 1000, true);

        vm.prank(owner);
        identity.emergencyDisableRelink(true);

        vm.prank(currentOwner);
        vm.expectRevert("Emergency stop active");
        identity.cancelRelink(expected);
    }

    /// @notice Emergency can be disabled, and then relink operations resume
    function testEmergencyStop_CanBeDisabled() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        // Enable emergency
        vm.prank(owner);
        identity.emergencyDisableRelink(true);
        assertTrue(identity.emergencyStop(), "emergency should be active");

        // Disable emergency
        vm.prank(owner);
        identity.emergencyDisableRelink(false);
        assertTrue(!identity.emergencyStop(), "emergency should be disabled");

        // Now relink operations should proceed — test that cancelRelink can be called
        bytes20 expected = bytes20(keccak256("emergency-resume"));
        address currentOwner = address(0x0000000000000000000000000000000000000001);
        _setBtcToEvm(expected, currentOwner);
        _setPendingRelink(expected, vm.addr(2), block.timestamp + 1000, true);

        vm.prank(currentOwner);
        identity.cancelRelink(expected); // should not revert

        (bool hasPending,,,) = identity.getRelinkStatus(expected);
        assertTrue(!hasPending, "cancel should succeed after emergency disabled");
    }

    // ==========================================
    // CRYPTO HELPER TESTS (COVERAGE)
    // ==========================================

    function testEncodeCompactSizeVariants() public {
        FastPathIdentityHarness harness = new FastPathIdentityHarness();

        bytes memory a = harness.exposeEncodeCompactSize(10);
        assertEq(uint256(uint8(a[0])), 10, "compact small");

        bytes memory b = harness.exposeEncodeCompactSize(300);
        assertEq(uint256(uint8(b[0])), 0xfd, "compact 16 prefix");
        assertEq(uint256(uint8(b[1])), 0x2c, "compact 16 lo");
        assertEq(uint256(uint8(b[2])), 0x01, "compact 16 hi");

        bytes memory c = harness.exposeEncodeCompactSize(70000);
        assertEq(uint256(uint8(c[0])), 0xfe, "compact 32 prefix");

        bytes memory d = harness.exposeEncodeCompactSize(uint256(type(uint32).max) + 1);
        assertEq(uint256(uint8(d[0])), 0xff, "compact 64 prefix");
    }

    function testDecompressCompressedPubkey() public {
        FastPathIdentityHarness harness = new FastPathIdentityHarness();
        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory uncompressed = harness.exposeDecompress(pubkeyComp);
        assertEq(uint256(uint8(uncompressed[0])), 0x04, "uncompressed prefix");
        assertEq(uint256(uncompressed.length), 65, "uncompressed length");
    }

    function testPubkeyToXYMem_InvalidLength() public {
        FastPathIdentityHarness harness = new FastPathIdentityHarness();
        bytes memory bad = hex"01";
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        harness.exposePubkeyToXY(bad);
    }

    function testEthAddressFromXYMatchesPrivKey() public {
        FastPathIdentityHarness harness = new FastPathIdentityHarness();
        bytes memory xy = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            xy[i] = PUBKEY_UNCOMP[i + 1];
        }
        address derived = harness.exposeEthAddressFromXY(xy);
        assertEq(derived, vm.addr(PRIVKEY), "eth address mismatch");
    }

    // ==========================================
    // SECURITY: LOW-S ENFORCEMENT (EIP-2)
    // ==========================================

    /// @notice V2 eth-signed registration must reject high-s signatures
    function testRegisterV2_HighS_Reverts_EthSigned() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        // Flip s to high-s: highS = n - s (always > HALF_ORDER)
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = (v == 27) ? uint8(28) : uint8(27);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.SignatureSMustBeLowOrder.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, highS, flippedV, false);
    }

    /// @notice V2 bitcoin-style registration must reject high-s signatures
    function testRegisterV2_HighS_Reverts_BitcoinSigned() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _bitcoinSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = (v == 27) ? uint8(28) : uint8(27);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.SignatureSMustBeLowOrder.selector));
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, highS, flippedV, true);
    }

    /// @notice V1 registration (expanded format r||s||v) must reject high-s via _splitExpanded
    function testRegisterV1_HighS_ExpandedFormat_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        // Create high-s
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = (v == 27) ? uint8(28) : uint8(27);

        // Expanded format: r (32) || s (32) || v (1) — total 65 bytes
        bytes memory sig = abi.encodePacked(r, highS, bytes1(flippedV));
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.SignatureSMustBeLowOrder.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, sig, message);
    }

    /// @notice V1 registration (compact format header||r||s) must reject high-s via _splitCompact
    function testRegisterV1_HighS_CompactFormat_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _bitcoinSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        // Create high-s
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        // Compact format header: 27 + recId (recId derived from v)
        uint8 recId = v - 27;
        uint8 header = 27 + recId;

        // Compact format: header (1) || r (32) || s (32) — total 65 bytes
        bytes memory sig = abi.encodePacked(bytes1(header), r, highS);
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.SignatureSMustBeLowOrder.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, sig, message);
    }

    /// @notice initiateRelink must reject high-s signatures
    function testInitiateRelink_HighS_Reverts() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkeyComp = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes20 expected = _btcHash160FromPubkeyMem(pubkeyComp);
        address oldEvm = address(0x0000000000000000000000000000000000000001);
        address newEvm = vm.addr(2);

        _setBtcToEvm(expected, oldEvm);
        _setEvmToBtc(oldEvm, expected);
        vm.warp(3 days + 1);

        bytes memory message = bytes(_toHex(newEvm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        // Flip s to high-s in expanded format
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = (v == 27) ? uint8(28) : uint8(27);
        bytes memory sig = abi.encodePacked(r, highS, bytes1(flippedV));

        vm.prank(newEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.SignatureSMustBeLowOrder.selector));
        identity.initiateRelink(expected, newEvm, pubkeyComp, sig);
    }

    // ==========================================
    // SECURITY: CALLDATA BOUNDS (V1 REGISTRATION)
    // ==========================================

    /// @notice registerBitcoinAddress must reject pubkey > 65 bytes
    function testRegisterV1_OversizedPubkey_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory sig = new bytes(65);
        bytes memory message = bytes(_toHex(signer));

        // 66 bytes — just above the 65-byte max
        bytes memory bigPubkey = new bytes(66);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(bigPubkey, sig, message);
    }

    /// @notice registerBitcoinAddress must reject pubkey of 200 bytes (griefing payload)
    function testRegisterV1_GriefingPubkey_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory sig = new bytes(65);
        bytes memory message = bytes(_toHex(signer));

        bytes memory hugePubkey = new bytes(200);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(hugePubkey, sig, message);
    }

    /// @notice registerBitcoinAddress must reject signature != 65 bytes (too short)
    function testRegisterV1_ShortSignature_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory message = bytes(_toHex(signer));

        bytes memory shortSig = new bytes(64);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, shortSig, message);
    }

    /// @notice registerBitcoinAddress must reject signature != 65 bytes (too long)
    function testRegisterV1_LongSignature_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory message = bytes(_toHex(signer));

        bytes memory longSig = new bytes(66);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, longSig, message);
    }

    /// @notice registerBitcoinAddress must reject message > 42 bytes
    function testRegisterV1_OversizedMessage_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory sig = new bytes(65);

        // 43 bytes — one byte over the 42-byte max ("0x" + 40 hex chars)
        bytes memory bigMessage = new bytes(43);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidMessage.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, sig, bigMessage);
    }

    /// @notice registerBitcoinAddress must reject large griefing message payload
    function testRegisterV1_GriefingMessage_Reverts() public {
        address signer = vm.addr(PRIVKEY);
        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
        bytes memory sig = new bytes(65);

        // 10000 bytes — would waste gas hashing if not rejected early
        bytes memory hugeMessage = new bytes(10000);

        vm.deal(signer, 1 ether);
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidMessage.selector));
        identity.registerBitcoinAddress{value: 0.001 ether}(pubkey, sig, hugeMessage);
    }

    // ==========================================
    // SECURITY: CALLDATA BOUNDS (RELINK)
    // ==========================================

    /// @notice initiateRelink must reject pubkey > 65 bytes before touching storage
    function testInitiateRelink_OversizedPubkey_Reverts() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory bigPubkey = new bytes(66);
        bytes memory sig = new bytes(65);

        // No storage setup needed — the early bounds check fires before any SLOAD
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidPublicKey.selector));
        identity.initiateRelink(hash160, address(0x0000000000000000000000000000000000000002), bigPubkey, sig);
    }

    /// @notice initiateRelink must reject signature != 65 bytes
    function testInitiateRelink_WrongSigLength_Reverts() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        bytes memory pubkey = abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);

        bytes memory shortSig = new bytes(64);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.initiateRelink(hash160, address(0x0000000000000000000000000000000000000002), pubkey, shortSig);

        bytes memory longSig = new bytes(66);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.InvalidSignature.selector));
        identity.initiateRelink(hash160, address(0x0000000000000000000000000000000000000002), pubkey, longSig);
    }

    // ==========================================
    // SECURITY: PULL-PAYMENT SECURITY
    // ==========================================

    /// @notice With pull-payment, receiveFunds credits pendingWithdrawals — gas bomb is irrelevant
    function testReceiveFunds_GasBombReceiver_PullPayment() public {
        GasBombReceiver bomb = new GasBombReceiver();
        address bombAddr = address(bomb);

        bytes20 testHash = bytes20(keccak256("gas-bomb-test"));
        _setBtcToEvm(testHash, bombAddr);

        vm.prank(bombAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // receiveFunds credits pendingWithdrawals without sending ETH
        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 1 ether}(testHash);

        assertEq(identity.pendingWithdrawals(bombAddr), 1 ether, "pending balance should be credited");
        assertEq(bombAddr.balance, 0, "no ETH should be pushed");
    }

    /// @notice receiveFunds credits pendingWithdrawals; EOA withdraws via withdrawPendingFunds
    function testReceiveFunds_EOA_PullPayment() public {
        address eoaReceiver = address(0x000000000000000000000000000000000000ABC0);

        bytes20 testHash = bytes20(keccak256("eoa-receiver-test"));
        _setBtcToEvm(testHash, eoaReceiver);

        vm.prank(eoaReceiver);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 0.5 ether}(testHash);

        // Funds credited, not sent
        assertEq(identity.pendingWithdrawals(eoaReceiver), 0.5 ether, "pending balance wrong");

        // EOA pulls funds
        uint256 balBefore = eoaReceiver.balance;
        vm.prank(eoaReceiver);
        identity.withdrawPendingFunds();

        assertEq(eoaReceiver.balance, balBefore + 0.5 ether, "EOA should receive funds after withdraw");
        assertEq(identity.pendingWithdrawals(eoaReceiver), 0, "pending should be cleared");
    }

    // ==========================================
    // PULL-PAYMENT TESTS
    // ==========================================

    function testWithdrawPendingFunds_CorrectAmount() public {
        PayableReceiver receiver = new PayableReceiver();
        address receiverAddr = address(receiver);

        bytes20 testHash = bytes20(keccak256("pull-payment-test"));
        _setBtcToEvm(testHash, receiverAddr);

        vm.prank(receiverAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 1 ether}(testHash);

        // Balance not moved yet
        assertTrue(receiverAddr.balance == 0, "should not push ETH");
        assertTrue(identity.pendingWithdrawals(receiverAddr) == 1 ether, "pending balance wrong");

        // Receiver pulls
        vm.prank(receiverAddr);
        identity.withdrawPendingFunds();

        assertTrue(receiverAddr.balance == 1 ether, "withdraw failed");
        assertTrue(identity.pendingWithdrawals(receiverAddr) == 0, "pending balance not cleared");
    }

    function testWithdrawPendingFunds_ReentrancyBlocked() public {
        bytes20 testHash = bytes20(keccak256("reentrancy-withdraw-test"));
        ReentrantReceiver receiver = new ReentrantReceiver(identity, testHash);
        address receiverAddr = address(receiver);

        _setBtcToEvm(testHash, receiverAddr);

        vm.prank(receiverAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 1 ether}(testHash);

        vm.prank(receiverAddr);
        // Reentrancy attempt from receive() should hit the nonReentrant lock
        identity.withdrawPendingFunds();
        assertTrue(receiver.reentered(), "reentrancy should be blocked");
    }

    function testWithdrawPendingFunds_NothingToWithdraw() public {
        vm.expectRevert(bytes("No pending funds"));
        identity.withdrawPendingFunds();
    }

    function testAccumulatedFees_SeparateFromUserDeposits() public {
        PayableReceiver receiver = new PayableReceiver();
        address receiverAddr = address(receiver);

        bytes20 testHash = bytes20(keccak256("fee-separation-test"));
        _setBtcToEvm(testHash, receiverAddr);

        vm.prank(receiverAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), 2 ether);
        identity.receiveFunds{value: 1 ether}(testHash);

        // Owner cannot drain user deposits via withdrawFees
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NoFeesToWithdraw.selector));
        identity.withdrawFees(); // should revert — no registration fees accumulated

        // User deposit untouched
        assertTrue(identity.pendingWithdrawals(receiverAddr) == 1 ether,
            "user deposit should be safe");
    }

    function testWithdrawPendingFunds_MultipleDeposits() public {
        PayableReceiver receiver = new PayableReceiver();
        address receiverAddr = address(receiver);

        bytes20 testHash = bytes20(keccak256("multi-deposit-test"));
        _setBtcToEvm(testHash, receiverAddr);

        vm.prank(receiverAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // Multiple deposits accumulate
        vm.deal(address(this), 3 ether);
        identity.receiveFunds{value: 1 ether}(testHash);
        identity.receiveFunds{value: 0.5 ether}(testHash);
        identity.receiveFunds{value: 0.25 ether}(testHash);

        assertEq(identity.pendingWithdrawals(receiverAddr), 1.75 ether, "accumulated pending wrong");

        // Single withdrawal gets all
        vm.prank(receiverAddr);
        identity.withdrawPendingFunds();

        assertEq(receiverAddr.balance, 1.75 ether, "withdraw total wrong");
        assertEq(identity.pendingWithdrawals(receiverAddr), 0, "pending not cleared");
    }

    // ==========================================
    // RECEIVEFUNDS / RECEIVETOKENS EDGE CASES
    // ==========================================

    function testReceiveFunds_ZeroValue_Reverts() public {
        _setBtcToEvm(hash160, address(0x0000000000000000000000000000000000000001));

        vm.expectRevert(bytes("Cannot send zero value"));
        identity.receiveFunds{value: 0}(hash160);
    }

    function testReceiveTokens_ZeroAmount_Reverts() public {
        _setBtcToEvm(hash160, address(0x0000000000000000000000000000000000000001));

        vm.expectRevert(bytes("Cannot send zero amount"));
        identity.receiveTokens(hash160, address(0x0000000000000000000000000000000000000001), 0);
    }

    function testReceiveTokens_ZeroToken_Reverts() public {
        _setBtcToEvm(hash160, address(0x0000000000000000000000000000000000000001));

        vm.expectRevert(bytes("Invalid token address"));
        identity.receiveTokens(hash160, address(0), 1);
    }

    function testReceiveFunds_UnregisteredHash_Reverts() public {
        bytes20 unknownHash = bytes20(keccak256("nobody-here"));
        vm.deal(address(this), 1 ether);

        vm.expectRevert(bytes("Hash160 not registered"));
        identity.receiveFunds{value: 1 wei}(unknownHash);
    }

    /// @notice receiveTokens succeeds end-to-end with MockTokenTrue
    function testReceiveTokens_Succeeds() public {
        address receiver = address(0x000000000000000000000000000000000000cafE);
        _setBtcToEvm(hash160, receiver);

        vm.prank(receiver);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        MockTokenTrue token = new MockTokenTrue();
        token.mint(address(this), 1000);
        token.approve(address(identity), 1000);

        identity.receiveTokens(hash160, address(token), 500);

        assertEq(token.balanceOf(receiver), 500, "receiver should have tokens");
        assertEq(token.balanceOf(address(this)), 500, "sender should have remainder");
    }

    // ==========================================
    // RECEIVE PREFERENCE TESTS
    // ==========================================

    /// @notice Preference can be toggled back from ViaHash160 to DirectEVM
    function testSetReceivePreference_CanSwitchBack() public {
        // Default is DirectEVM (0). Switch to ViaHash160.
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);
        assertTrue(
            identity.receivePreference(address(this)) == FastPathIdentity.ReceivePreference.ViaHash160,
            "should be ViaHash160"
        );

        // Switch back to DirectEVM
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.DirectEVM);
        assertTrue(
            identity.receivePreference(address(this)) == FastPathIdentity.ReceivePreference.DirectEVM,
            "should be DirectEVM again"
        );
    }

    // ==========================================
    // GETRELINKSTATUS TESTS
    // ==========================================

    /// @notice getRelinkStatus with no pending relink returns cooldownRemaining from lastLinkTime
    function testGetRelinkStatus_NoPending_ReturnsCooldownRemaining() public {
        bytes20 testHash = bytes20(keccak256("relink-status-test"));

        // Set lastLinkTime to now
        _setLastLinkTime(testHash, block.timestamp);

        (bool hasPending, address pendingNewEvm, uint256 unlockTime, uint256 cooldownRemaining) =
            identity.getRelinkStatus(testHash);

        assertTrue(!hasPending, "should have no pending");
        assertEq(pendingNewEvm, address(0), "pendingNewEvm should be zero");
        assertEq(unlockTime, 0, "unlockTime should be zero");
        // relinkCooldown is 3 days, lastLinkTime is now, so cooldownRemaining should be ~3 days
        assertEq(cooldownRemaining, identity.relinkCooldown(), "cooldown should equal relinkCooldown");
    }

    /// @notice getRelinkStatus with expired cooldown returns 0 cooldownRemaining
    function testGetRelinkStatus_NoPending_ExpiredCooldown() public {
        bytes20 testHash = bytes20(keccak256("relink-status-expired"));

        // Set lastLinkTime far in the past
        _setLastLinkTime(testHash, 1);
        vm.warp(10 days);

        (bool hasPending,,, uint256 cooldownRemaining) =
            identity.getRelinkStatus(testHash);

        assertTrue(!hasPending, "should have no pending");
        assertEq(cooldownRemaining, 0, "cooldown should be expired");
    }

    // ==========================================
    // RELINK INVARIANT TESTS
    // ==========================================

    /// @notice btcToEvm is IMMUTABLE — after relink it must still point to the original registrant
    function testRelink_BtcToEvmNeverChanges() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);
        bytes20 expected = _expectedHash160();

        // Before relink
        assertEq(identity.btcToEvm(expected), oldEvm, "btcToEvm should be oldEvm before relink");

        vm.warp(3 days + 1);
        bytes memory sig = _signForEvm(newEvm);
        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, _pubkeyComp(), sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        // After relink — btcToEvm MUST still point to original registrant
        assertEq(identity.btcToEvm(expected), oldEvm, "btcToEvm must NEVER change after relink");
        // But currentController should be newEvm
        assertEq(identity.currentController(expected), newEvm, "controller should be newEvm");
    }

    /// @notice After finalizing a relink, immediately initiating another should hit CooldownActive
    function testRelinkCooldown_EnforcedBetweenFinalizations() public {
        vm.prank(owner);
        identity.setRelinkEnabled(true);

        address oldEvm = vm.addr(PRIVKEY);
        address newEvm = vm.addr(2);

        _registerWithPrivkey(oldEvm);
        bytes20 expected = _expectedHash160();

        vm.warp(3 days + 1);
        bytes memory sig = _signForEvm(newEvm);
        vm.prank(newEvm);
        identity.initiateRelink(expected, newEvm, _pubkeyComp(), sig);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(newEvm);
        identity.finalizeRelink(expected);

        // Immediately try to initiate another relink — should fail with CooldownActive
        address thirdEvm = vm.addr(3);
        bytes memory sig2 = _signForEvm(thirdEvm);
        vm.prank(thirdEvm);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.CooldownActive.selector));
        identity.initiateRelink(expected, thirdEvm, _pubkeyComp(), sig2);
    }

    // ==========================================
    // FUZZ TESTS
    // ==========================================

    /// @notice Fuzz: accumulatedFees tracks msg.value exactly from real registrations
    function testFuzz_AccumulatedFeesMatchRegistration(uint96 feeAmount) public {
        // Fee must be between registrationFee and MAX_REGISTRATION_FEE
        vm.assume(feeAmount >= 0.001 ether && feeAmount <= 1 ether);

        // Set fee to a value that the fuzzed amount always covers
        vm.prank(owner);
        identity.setRegistrationFee(0.001 ether);

        address signer = vm.addr(PRIVKEY);
        bytes memory message = bytes(_toHex(signer));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(signer, uint256(feeAmount) + 1 ether);
        vm.prank(signer);
        identity.registerBitcoinAddressV2{value: feeAmount}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);

        assertEq(identity.accumulatedFees(), uint256(feeAmount), "accumulatedFees must equal msg.value");
    }

    /// @notice Fuzz: owner withdrawFees never touches pendingWithdrawals
    function testFuzz_PendingWithdrawalsNeverDrainedByOwner(uint96 depositAmount) public {
        vm.assume(depositAmount > 0 && depositAmount <= 10 ether);

        PayableReceiver receiver = new PayableReceiver();
        address receiverAddr = address(receiver);

        bytes20 testHash = bytes20(keccak256("fuzz-pending"));
        _setBtcToEvm(testHash, receiverAddr);

        vm.prank(receiverAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        vm.deal(address(this), uint256(depositAmount));
        identity.receiveFunds{value: depositAmount}(testHash);

        // Owner tries to withdraw fees — should revert (no registration fees accumulated)
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NoFeesToWithdraw.selector));
        identity.withdrawFees();

        // User deposit untouched
        assertEq(identity.pendingWithdrawals(receiverAddr), uint256(depositAmount),
            "pendingWithdrawals must be preserved");
    }

    // ==========================================
    // HELPER FUNCTIONS
    // ==========================================

    function _pubkeyComp() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(PUBKEY_PREFIX), PUBKEY_X);
    }

    function _expectedHash160() internal pure returns (bytes20) {
        return _btcHash160FromPubkeyMem(_pubkeyComp());
    }

    function _signForEvm(address evm) internal returns (bytes memory) {
        bytes memory message = bytes(_toHex(evm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);
        return abi.encodePacked(r, s, bytes1(v));
    }

    function _registerWithPrivkey(address evm) internal {
        bytes memory message = bytes(_toHex(evm));
        bytes32 digest = _ethSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVKEY, digest);

        vm.deal(evm, 1 ether);
        vm.prank(evm);
        identity.registerBitcoinAddressV2{value: 0.001 ether}(PUBKEY_PREFIX, PUBKEY_X, r, s, v, false);
    }
    
    /// @dev Sets BOTH btcToEvm (slot 6) AND activeEvm (slot 11) for the given hash160.
    ///      cancelRelink, receiveFunds, and currentController all check activeEvm (slot 11),
    ///      so both slots must be set for tests that touch those code paths.
    ///      If you refactor this to only set one slot, several tests will give false positives.
    function _setBtcToEvm(bytes20 hash, address evm) internal {
        bytes32 slot = keccak256(abi.encode(hash, uint256(6)));
        vm.store(address(identity), slot, bytes32(uint256(uint160(evm))));

        bytes32 activeSlot = keccak256(abi.encode(hash, uint256(11)));
        vm.store(address(identity), activeSlot, bytes32(uint256(uint160(evm))));
    }
    
    function _setEvmToBtc(address evm, bytes20 hash) internal {
        bytes32 slot = keccak256(abi.encode(evm, uint256(7)));
        vm.store(address(identity), slot, bytes32(hash));
    }

    function _setLastLinkTime(bytes20 hash, uint256 time) internal {
        bytes32 slot = keccak256(abi.encode(hash, uint256(8)));
        vm.store(address(identity), slot, bytes32(time));
    }

    function _setPendingRelink(bytes20 hash, address newEvm, uint256 unlockTime, bool exists) internal {
        bytes32 base = keccak256(abi.encode(hash, uint256(10)));
        vm.store(address(identity), base, bytes32(uint256(uint160(newEvm))));
        vm.store(address(identity), bytes32(uint256(base) + 1), bytes32(unlockTime));
        vm.store(address(identity), bytes32(uint256(base) + 2), bytes32(uint256(exists ? 1 : 0)));
    }

    function _ethSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", _toString(s.length), s));
    }

    function _bitcoinSignedMessageHash(bytes memory message) internal pure returns (bytes32) {
        bytes memory data = abi.encodePacked(
            "\x18Bitcoin Signed Message:\n",
            _encodeCompactSize(message.length),
            message
        );
        bytes32 h1 = sha256(data);
        return sha256(abi.encodePacked(h1));
    }

    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function _toHex(address account) internal pure returns (string memory) {
        return _toHexBytes(abi.encodePacked(account));
    }

    function _toHexBytes(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    function _btcHash160FromPubkeyMem(bytes memory pubkey) internal pure returns (bytes20) {
        bytes memory full;
        if (pubkey.length == 65) {
            full = new bytes(65);
            for (uint256 i = 0; i < 65; i++) full[i] = pubkey[i];
        } else if (pubkey.length == 64) {
            full = new bytes(65);
            full[0] = 0x04;
            for (uint256 i = 0; i < 64; i++) full[i + 1] = pubkey[i];
        } else if (pubkey.length == 33) {
            full = new bytes(33);
            for (uint256 i = 0; i < 33; i++) full[i] = pubkey[i];
        } else {
            revert("InvalidPublicKey");
        }
        bytes32 sha = sha256(full);
        return ripemd160(abi.encodePacked(sha));
    }

    function _encodeCompactSize(uint256 n) internal pure returns (bytes memory) {
        if (n < 253) {
            bytes memory out = new bytes(1);
            out[0] = bytes1(uint8(n));
            return out;
        }
        if (n <= type(uint16).max) {
            bytes memory out = new bytes(3);
            out[0] = 0xfd;
            out[1] = bytes1(uint8(n));
            out[2] = bytes1(uint8(n >> 8));
            return out;
        }
        if (n <= type(uint32).max) {
            bytes memory out = new bytes(5);
            out[0] = 0xfe;
            out[1] = bytes1(uint8(n));
            out[2] = bytes1(uint8(n >> 8));
            out[3] = bytes1(uint8(n >> 16));
            out[4] = bytes1(uint8(n >> 24));
            return out;
        }
        bytes memory out8 = new bytes(9);
        out8[0] = 0xff;
        out8[1] = bytes1(uint8(n));
        out8[2] = bytes1(uint8(n >> 8));
        out8[3] = bytes1(uint8(n >> 16));
        out8[4] = bytes1(uint8(n >> 24));
        out8[5] = bytes1(uint8(n >> 32));
        out8[6] = bytes1(uint8(n >> 40));
        out8[7] = bytes1(uint8(n >> 48));
        out8[8] = bytes1(uint8(n >> 56));
        return out8;
    }
}
