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
    
    function testWithdrawFees() public {
        // Send some fees to contract
        vm.deal(address(identity), 1 ether);
        uint256 ownerBalBefore = owner.balance;
        
        vm.prank(owner);
        identity.withdrawFees();
        
        assertTrue(owner.balance == ownerBalBefore + 1 ether, "fees not withdrawn");
        assertTrue(address(identity).balance == 0, "contract not empty");
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

    // ==========================================
    // TRANSFER OWNERSHIP TESTS
    // ==========================================

    function testTransferOwnership_Succeeds() public {
        address newOwner = address(0x0000000000000000000000000000000000000aBc);
        vm.prank(owner);
        identity.transferOwnership(newOwner);
        assertEq(identity.owner(), newOwner, "ownership not transferred");
    }

    function testTransferOwnership_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FastPathIdentity.NotOwner.selector));
        identity.transferOwnership(address(0x0000000000000000000000000000000000000aBc));
    }

    function testTransferOwnership_ZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Zero address");
        identity.transferOwnership(address(0));
    }

    function testTransferOwnership_NewOwnerCanAct() public {
        address newOwner = address(0x0000000000000000000000000000000000000aBc);
        vm.prank(owner);
        identity.transferOwnership(newOwner);

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

        uint256 oldBal = oldEvm.balance;
        uint256 newBal = newEvm.balance;

        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 1}(expected);

        assertEq(oldEvm.balance, oldBal, "old EVM should not receive funds");
        assertEq(newEvm.balance, newBal + 1, "new EVM should receive funds");
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
    // SECURITY: GAS-CAPPED RECEIVEFUNDS
    // ==========================================

    /// @notice receiveFunds must fail when receiver's receive() exceeds 2300 gas stipend
    function testReceiveFunds_GasBombReceiver_Fails() public {
        // Deploy malicious receiver that does a storage write in receive()
        GasBombReceiver bomb = new GasBombReceiver();
        address bombAddr = address(bomb);

        // Register the gas-bomb contract as the active controller for a hash160
        bytes20 testHash = bytes20(keccak256("gas-bomb-test"));
        _setBtcToEvm(testHash, bombAddr);

        // Set receive preference to ViaHash160
        vm.prank(bombAddr);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        // receiveFunds should revert because the receiver's storage write exceeds 2300 gas
        vm.deal(address(this), 1 ether);
        vm.expectRevert("ETH transfer failed");
        identity.receiveFunds{value: 1 ether}(testHash);
    }

    /// @notice receiveFunds to EOA receiver should still work with 2300 gas cap
    function testReceiveFunds_EOA_Succeeds() public {
        address eoaReceiver = address(0x000000000000000000000000000000000000ABC0);

        bytes20 testHash = bytes20(keccak256("eoa-receiver-test"));
        _setBtcToEvm(testHash, eoaReceiver);

        vm.prank(eoaReceiver);
        identity.setReceivePreference(FastPathIdentity.ReceivePreference.ViaHash160);

        uint256 balBefore = eoaReceiver.balance;
        vm.deal(address(this), 1 ether);
        identity.receiveFunds{value: 0.5 ether}(testHash);

        assertEq(eoaReceiver.balance, balBefore + 0.5 ether, "EOA should receive funds with gas-capped call");
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
    
    function _setBtcToEvm(bytes20 hash, address evm) internal {
        bytes32 slot = keccak256(abi.encode(hash, uint256(5)));
        vm.store(address(identity), slot, bytes32(uint256(uint160(evm))));

        bytes32 activeSlot = keccak256(abi.encode(hash, uint256(10)));
        vm.store(address(identity), activeSlot, bytes32(uint256(uint160(evm))));
    }
    
    function _setEvmToBtc(address evm, bytes20 hash) internal {
        bytes32 slot = keccak256(abi.encode(evm, uint256(6)));
        vm.store(address(identity), slot, bytes32(hash));
    }

    function _setLastLinkTime(bytes20 hash, uint256 time) internal {
        bytes32 slot = keccak256(abi.encode(hash, uint256(7)));
        vm.store(address(identity), slot, bytes32(time));
    }

    function _setPendingRelink(bytes20 hash, address newEvm, uint256 unlockTime, bool exists) internal {
        bytes32 base = keccak256(abi.encode(hash, uint256(9)));
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

