// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IDiscountNFT {
    function hasDiscount(address user) external view returns (bool);
}

/**
 * @dev Minimal interface for BitIDRewardDistributor — only what FastPathIdentity needs
 */
interface IBitIDRewardDistributor {
    function reward(address user, uint8 action) external;
}

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title FastPathIdentity by Emiliano Solazzi 2026
 * @author FastPath/proof160 Protocol official release
 * @notice Permanent registry for Bitcoin <-> EVM address mapping with secure relink functionality.
 * @dev Part of the FastPath Protocol. Implements gas optimizations and security best practices.
 */
contract FastPathIdentity {
    using SafeERC20 for IERC20;
    // Custom Errors
    error NotOwner();
    error InsufficientFee();
    error AddressAlreadyRegistered();
    error AddressNotRegistered();
    error InvalidSignature();
    error InvalidMessage();
    error InvalidPublicKey();
    error TransferFailed();
    error ReentrantCall();
    error RelinkDisabled();
    error CooldownActive();
    error PendingRelinkExists();
    error PendingRelinkMissing();
    error NewEvmAlreadyRegistered();
    error NotCurrentOwner();
    error CooldownTooSmall();
    error NoFeesToWithdraw();
    error ZeroHash160();
    error SignatureSMustBeLowOrder();
    error FeeTooHigh();
    error NotPendingOwner();
    error ZeroAddress();

    /// @dev secp256k1 curve order n divided by 2, used to enforce low-s signatures (EIP-2).
    ///      Any signature with s > HALF_ORDER is malleable and must be rejected.
    uint256 private constant HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Cap on registration fee to prevent owner from bricking registrations
    uint256 public constant MAX_REGISTRATION_FEE = 1 ether;

    // State variables
    address public owner;
    address public pendingOwner;
    uint256 public registrationFee;
    address public discountNFT;
    bool private locked; // Reentrancy guard
    bool public relinkEnabled;
    uint256 public relinkCooldown;
    bool public emergencyStop;

    /// @notice BitID reward distributor — zero address means rewards are disabled
    IBitIDRewardDistributor public rewardDistributor;

    /// @dev Action index for IDENTITY_REGISTRATION in BitIDRewardDistributor
    uint8 private constant _IDENTITY_REGISTRATION_ACTION = 0;

    // Mappings
    /// @notice IMMUTABLE mapping from Bitcoin Hash160 (bytes20) to EVM address (first registrant forever).
    /// @dev This is a permanent historical record. NEVER modified after initial registration.
    ///      After relink, this still returns the ORIGINAL registrant, NOT the current controller.
    ///      Use currentController() or hasControl() for current ownership verification.
    mapping(bytes20 => address) public btcToEvm;
    
    /// @notice HISTORICAL mapping from EVM address to Bitcoin Hash160 (NOT cleared on relink).
    /// @dev After relink, BOTH old and new EVM addresses will have entries pointing to the same btcHash160.
    ///      This preserves audit trail of all associations. Do NOT use this alone to verify current ownership.
    ///      ALWAYS use hasControl() or currentController() for current ownership verification.
    mapping(address => bytes20) public evmToBtc;

    /// @notice Timestamp of the last completed link/relink for a Bitcoin Hash160
    mapping(bytes20 => uint256) public lastLinkTime;
    
    // Fund receiving preferences
    enum ReceivePreference { DirectEVM, ViaHash160 }
    /// @notice User's preference for receiving funds (default: DirectEVM)
    mapping(address => ReceivePreference) public receivePreference;

    /// @notice Pending relink requests keyed by Bitcoin Hash160
    struct PendingRelink {
        address newEvm;
        uint256 unlockTime;
        bool exists;
    }

    mapping(bytes20 => PendingRelink) public pendingRelinks;
    /// @notice CURRENT controller for a Bitcoin Hash160 — the authoritative source of who controls it NOW.
    /// @dev This is the ONLY mapping that changes on relink. Use currentController() to read externally.
    ///      Three-layer model: btcToEvm (immutable origin) | evmToBtc (historical) | activeEvm (current authority)
    mapping(bytes20 => address) private activeEvm;

    /// @notice Pull-payment balances: ETH credited via receiveFunds, claimable by receiver
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice Protocol fees accumulated from registrations (separate from user deposits)
    uint256 public accumulatedFees;
    
    // Events
    event BitcoinAddressRegistered(address indexed user, bytes20 btcHash160, uint256 feePaid);
    event FeeUpdated(uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event RelinkInitiated(bytes20 indexed btcHash160, address indexed newEvm, uint256 unlockTime);
    event RelinkCompleted(bytes20 indexed btcHash160, address indexed oldEvm, address indexed newEvm);
    event RelinkCancelled(bytes20 indexed btcHash160, address indexed cancelledBy);
    event RelinkCooldownUpdated(uint256 newCooldown);
    event RelinkToggled(bool enabled);
    event FundsReceived(bytes20 indexed btcHash160, address indexed receiver, uint256 amount, address token);
    event PendingFundsDeposited(bytes20 indexed btcHash160, address indexed receiver, uint256 amount);
    event PendingFundsWithdrawn(address indexed receiver, uint256 amount);
    event ReceivePreferenceUpdated(address indexed user, ReceivePreference preference);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event EmergencyStopToggled(bool disabled);
    event DiscountNFTUpdated(address indexed nft);
    event RewardDistributorUpdated(address indexed oldDistributor, address indexed newDistributor);

    constructor(uint256 _fee) payable {
        owner = msg.sender;
        registrationFee = _fee;
        locked = false;
        relinkEnabled = false; // Disabled by default - immutability guaranteed
        relinkCooldown = 3 days;
        emergencyStop = false;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (locked) revert ReentrantCall();
        locked = true;
        _;
        locked = false;
    }

    modifier noEmergency() {
        require(!emergencyStop, "Emergency stop active");
        _;
    }

    /**
     * @notice Register a Bitcoin address permanently using a cryptographic signature.
     * @dev Verifies that the caller owns the Bitcoin private key.
     * @param pubkey The uncompressed (65 bytes) or compressed (33 bytes) Bitcoin public key.
     * @param signature The signature (65 bytes) proving ownership.
     * @param message The message that was signed. MUST be the hex string of msg.sender (e.g. "0x123...").
     */
    function registerBitcoinAddress(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes calldata message
    ) external payable nonReentrant {
        // Early calldata length bounds to prevent griefing with oversized inputs.
        // pubkey: 33 (compressed) or 64/65 (uncompressed). signature: always 65.
        // message: "0x" + 40 hex chars = 42 bytes max for an EVM address string.
        if (pubkey.length > 65) revert InvalidPublicKey();
        if (signature.length != 65) revert InvalidSignature();
        if (message.length > 42) revert InvalidMessage();

        uint256 requiredFee = registrationFee;
        if (discountNFT != address(0)) {
            try IDiscountNFT(discountNFT).hasDiscount(msg.sender) returns (bool hasDisc) {
                if (hasDisc) requiredFee = (requiredFee * 90) / 100; // 10% discount
            } catch {} // Malicious/broken NFT cannot brick registration
        }
        if (msg.value < requiredFee) revert InsufficientFee();

        // Enforce one-time registration per EVM address.
        // (Prevents repeated txs / repeated events even if mapping would be unchanged.)
        if (evmToBtc[msg.sender] != bytes20(0)) revert AddressAlreadyRegistered();

        // 1. Verify Message binds msg.sender
        // We expect the message to be the lowercase hex string of msg.sender
        string memory expectedMessage = toHex(msg.sender);
        if (keccak256(message) != keccak256(bytes(expectedMessage))) {
            revert InvalidMessage();
        }

        // 2. Verify Signature
        if (!_authenticateSignatureOnly(pubkey, signature, message)) {
            revert InvalidSignature();
        }
        
        // 3. Derive BTC Address
        bytes20 btcHash160 = btcHash160FromPubkey(pubkey);
        if (btcHash160 == bytes20(0)) revert ZeroHash160();

        // 4. Check if already registered
        address existingOwner = btcToEvm[btcHash160];
        if (existingOwner != address(0)) revert AddressAlreadyRegistered();

        // 5. Update Mappings
        btcToEvm[btcHash160] = msg.sender;
        evmToBtc[msg.sender] = btcHash160;
        lastLinkTime[btcHash160] = block.timestamp;
        activeEvm[btcHash160] = msg.sender;
        accumulatedFees += msg.value;

        emit BitcoinAddressRegistered(msg.sender, btcHash160, msg.value);

        // Mint BitID registration reward — non-blocking: distributor failure must never
        // prevent a valid registration from being recorded.
        IBitIDRewardDistributor _distributor = rewardDistributor;
        if (address(_distributor) != address(0)) {
            try _distributor.reward(msg.sender, _IDENTITY_REGISTRATION_ACTION) {} catch {}
        }
    }

    /**
     * @notice Register a Bitcoin address permanently (V2, fixed-width calldata).
     * @dev Same authentication as registerBitcoinAddress, but avoids dynamic bytes calldata that
     *      can cause poor UX / Ledger blind-signing issues.
     *
    * @param pubkeyPrefix First byte of compressed pubkey (0x02 or 0x03).
    * @param pubkeyX X coordinate (32 bytes) of compressed pubkey.
     * @param r Signature r.
     * @param s Signature s.
     * @param v Signature v (27/28 or 0/1).
     * @param bitcoinStyle If true, verifies against Bitcoin Signed Message digest; otherwise verifies
     *        against Ethereum Signed Message digest.
     */
    function registerBitcoinAddressV2(
        uint8 pubkeyPrefix,
        bytes32 pubkeyX,
        bytes32 r,
        bytes32 s,
        uint8 v,
        bool bitcoinStyle
    ) external payable nonReentrant {
        uint256 requiredFee = registrationFee;
        if (discountNFT != address(0)) {
            try IDiscountNFT(discountNFT).hasDiscount(msg.sender) returns (bool hasDisc) {
                if (hasDisc) requiredFee = (requiredFee * 90) / 100; // 10% discount
            } catch {} // Malicious/broken NFT cannot brick registration
        }
        if (msg.value < requiredFee) revert InsufficientFee();

        // Enforce one-time registration per EVM address.
        if (evmToBtc[msg.sender] != bytes20(0)) revert AddressAlreadyRegistered();

        // Message is always the lowercase hex string of msg.sender
        bytes memory message = bytes(toHex(msg.sender));

        // Derive expected signer from pubkey
        if (pubkeyPrefix != 2 && pubkeyPrefix != 3) {
            revert InvalidPublicKey();
        }
        bytes memory pubkeyDyn = abi.encodePacked(bytes1(pubkeyPrefix), pubkeyX);
        address expectedSigner = ethAddressFromXY(_pubkeyToXYMem(pubkeyDyn));

        // Normalize v
        uint8 vv = v;
        if (vv < 27) vv += 27;
        if (vv != 27 && vv != 28) {
            revert InvalidSignature();
        }

        // Enforce low-s to prevent ECDSA malleability (EIP-2)
        if (uint256(s) > HALF_ORDER) revert SignatureSMustBeLowOrder();

        bytes32 digest = bitcoinStyle
            ? toBitcoinSignedMessageHashMem(message)
            : toEthSignedMessageHashMem(message);

        if (ecrecover(digest, vv, r, s) != expectedSigner) {
            revert InvalidSignature();
        }

        bytes20 btcHash160 = btcHash160FromPubkeyMem(pubkeyDyn);
        if (btcHash160 == bytes20(0)) revert ZeroHash160();

        address existingOwner = btcToEvm[btcHash160];
        if (existingOwner != address(0)) revert AddressAlreadyRegistered();

        btcToEvm[btcHash160] = msg.sender;
        evmToBtc[msg.sender] = btcHash160;
        lastLinkTime[btcHash160] = block.timestamp;
        activeEvm[btcHash160] = msg.sender;
        accumulatedFees += msg.value;

        emit BitcoinAddressRegistered(msg.sender, btcHash160, msg.value);

        // Mint BitID registration reward — non-blocking
        IBitIDRewardDistributor _distributor = rewardDistributor;
        if (address(_distributor) != address(0)) {
            try _distributor.reward(msg.sender, _IDENTITY_REGISTRATION_ACTION) {} catch {}
        }
    }

    function setRegistrationFee(uint256 _fee) external onlyOwner {
        if (_fee > MAX_REGISTRATION_FEE) revert FeeTooHigh();
        registrationFee = _fee;
        emit FeeUpdated(_fee);
    }

    function setDiscountNFT(address _nft) external onlyOwner {
        discountNFT = _nft;
        emit DiscountNFTUpdated(_nft);
    }

    /**
     * @notice Set the BitID reward distributor contract.
     * @dev Pass zero address to disable rewards entirely.
     *      The distributor must have this contract whitelisted via
     *      BitIDRewardDistributor.setCaller(address(this), true) before rewards flow.
     * @param newDistributor Address of deployed BitIDRewardDistributor, or zero to disable
     */
    function setRewardDistributor(address newDistributor) external onlyOwner {
        address old = address(rewardDistributor);
        if (old == newDistributor) return;
        rewardDistributor = IBitIDRewardDistributor(newDistributor);
        emit RewardDistributorUpdated(old, newDistributor);
    }

    function withdrawFees() external onlyOwner nonReentrant {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert NoFeesToWithdraw();

        // Zero before external call (CEI pattern)
        accumulatedFees = 0;

        emit FeesWithdrawn(owner, amount);

        (bool success, ) = owner.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Initiate ownership transfer (two-step to prevent typo lockout).
     * @dev Callable only by the current owner. New owner must call acceptOwnership().
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /**
     * @notice Accept pending ownership transfer.
     * @dev Callable only by the pending owner set via transferOwnership().
     */
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // ==========================================
    // Relink Controls
    // ==========================================

    /**
     * @notice Owner can enable/disable relink feature.
     * @dev When disabled, BTC→EVM mappings are PERMANENTLY immutable.
     *      When enabled, only allows EVM ownership change, NOT BTC reassignment.
     */
    function setRelinkEnabled(bool enabled) external onlyOwner {
        relinkEnabled = enabled;
        emit RelinkToggled(enabled);
    }

    function setRelinkCooldown(uint256 cooldown) external onlyOwner {
        if (cooldown < 1 hours) revert CooldownTooSmall();
        relinkCooldown = cooldown;
        emit RelinkCooldownUpdated(cooldown);
    }

    function emergencyDisableRelink(bool disable) external onlyOwner {
        emergencyStop = disable;
        emit EmergencyStopToggled(disable);
    }

    // ==========================================
    // Relink Flow (two-phase, Bitcoin-auth)
    // ==========================================

    function initiateRelink(
        bytes20 btcHash160,
        address newEvm,
        bytes calldata pubkey,
        bytes calldata signature
    ) external noEmergency {
        // Early calldata length bounds to prevent griefing
        if (pubkey.length > 65) revert InvalidPublicKey();
        if (signature.length != 65) revert InvalidSignature();

        if (btcHash160 == bytes20(0)) revert ZeroHash160();
        if (!relinkEnabled) revert RelinkDisabled();

        address currentOwner = btcToEvm[btcHash160];
        if (currentOwner == address(0)) revert AddressNotRegistered();

        require(newEvm != address(0), "Zero address");
        require(newEvm == msg.sender, "Must be new EVM owner");

        // Prevent overlapping requests
        if (pendingRelinks[btcHash160].exists) revert PendingRelinkExists();

        // New EVM must not already control a different BTC identity
        if (evmToBtc[newEvm] != bytes20(0)) revert NewEvmAlreadyRegistered();

        // Ensure cooldown since last finalized link
        if (block.timestamp < lastLinkTime[btcHash160] + relinkCooldown) revert CooldownActive();

        // Confirm the provided pubkey maps to the claimed BTC hash160
        if (btcHash160FromPubkey(pubkey) != btcHash160) revert InvalidPublicKey();

        // Require Bitcoin signature over the lowercase hex string of the NEW EVM address
        // Convert to memory first since _authenticateSignatureOnly needs calldata
        bytes memory msgMem = bytes(toHex(newEvm));
        
        // Create a temporary calldata slice - we'll pass it inline
        // Since we can't convert memory to calldata, use a memory-compatible verification
        if (!_verifySignatureFromMemory(pubkey, signature, msgMem)) revert InvalidSignature();

        uint256 unlockTime = block.timestamp + relinkCooldown;
        pendingRelinks[btcHash160] = PendingRelink({
            newEvm: newEvm,
            unlockTime: unlockTime,
            exists: true
        });

        emit RelinkInitiated(btcHash160, newEvm, unlockTime);
    }

    function finalizeRelink(bytes20 btcHash160) external noEmergency {
        PendingRelink memory pending = pendingRelinks[btcHash160];
        if (!pending.exists) revert PendingRelinkMissing();
        require(msg.sender == pending.newEvm, "Only pending new owner");
        if (block.timestamp < pending.unlockTime) revert CooldownActive();

        address oldEvm = btcToEvm[btcHash160];
        if (oldEvm == address(0)) revert AddressNotRegistered();

        // Ensure the destination EVM address is still free
        if (evmToBtc[pending.newEvm] != bytes20(0)) revert NewEvmAlreadyRegistered();

        // CRITICAL: BTC→EVM mapping is PERMANENT
        // The BTC address (btcHash160) ALWAYS stays registered to its ORIGINAL owner (oldEvm)
        // This maintains the immutability guarantee.
        //
        // What relink DOES change:
        // - The NEW EVM address (pending.newEvm) now controls access to the BTC address
        // - This is ONLY a permission change, not a reassignment
        //
        // What relink DOES NOT change:
        // - btcToEvm[btcHash160] stays as oldEvm forever (immutable record)
        //
        // OLD behavior (BROKEN):
        //   evmToBtc[oldEvm] = bytes20(0);
        //   btcToEvm[btcHash160] = pending.newEvm;  // <-- THIS BROKE IMMUTABILITY
        //
        // NEW behavior (FIXED):
        // Only update the EVM→BTC for the new owner
        evmToBtc[pending.newEvm] = btcHash160;
        activeEvm[btcHash160] = pending.newEvm;
        
        // DO NOT modify btcToEvm[btcHash160] - it's permanent
        // DO NOT clear evmToBtc[oldEvm] - history is important
        
        lastLinkTime[btcHash160] = block.timestamp;

        delete pendingRelinks[btcHash160];

        emit RelinkCompleted(btcHash160, oldEvm, pending.newEvm);
    }

    function cancelRelink(bytes20 btcHash160) external noEmergency {
        address currentOwner = activeEvm[btcHash160];
        if (currentOwner == address(0)) revert AddressNotRegistered();
        if (msg.sender != currentOwner) revert NotCurrentOwner();
        if (!pendingRelinks[btcHash160].exists) revert PendingRelinkMissing();

        delete pendingRelinks[btcHash160];

        emit RelinkCancelled(btcHash160, msg.sender);
    }

    function getRelinkStatus(bytes20 btcHash160) external view returns (
        bool hasPending,
        address pendingNewEvm,
        uint256 unlockTime,
        uint256 cooldownRemaining
    ) {
        PendingRelink memory pending = pendingRelinks[btcHash160];
        hasPending = pending.exists;
        pendingNewEvm = pending.newEvm;
        unlockTime = pending.unlockTime;

        if (pending.exists) {
            cooldownRemaining = pending.unlockTime > block.timestamp
                ? pending.unlockTime - block.timestamp
                : 0;
        } else {
            uint256 nextTime = lastLinkTime[btcHash160] + relinkCooldown;
            cooldownRemaining = nextTime > block.timestamp ? nextTime - block.timestamp : 0;
        }
    }

    /// @notice Returns true if the EVM address currently has control over its mapped BTC identity.
    /// @dev Because relinks preserve historical mappings, use this to check active control.
    function hasControl(address evm) external view returns (bool) {
        bytes20 btc = evmToBtc[evm];
        return btc != bytes20(0) && activeEvm[btc] == evm;
    }

    /// @notice Returns the current EVM controller for a BTC hash160 (changes on relink).
    function currentController(bytes20 btcHash160) external view returns (address) {
        return activeEvm[btcHash160];
    }

    // ==========================================
    // FUND RECEIVING VIA HASH160
    // ==========================================

    /// @notice Set user's preference for receiving funds (DirectEVM or ViaHash160)
    function setReceivePreference(ReceivePreference preference) external {
        require(receivePreference[msg.sender] != preference, "Preference already set");
        receivePreference[msg.sender] = preference;
        emit ReceivePreferenceUpdated(msg.sender, preference);
    }

    /// @notice Deposit ETH for a hash160 receiver (pull-payment pattern)
    /// @dev ETH is credited to the receiver's pendingWithdrawals balance.
    ///      Receiver calls withdrawPendingFunds() to claim.
    ///      This avoids the 2300 gas stipend limitation that breaks multisigs,
    ///      Safes, and contracts with non-trivial receive() functions.
    function receiveFunds(bytes20 btcHash160) external payable nonReentrant {
        if (btcHash160 == bytes20(0)) revert ZeroHash160();
        require(msg.value > 0, "Cannot send zero value");
        address receiver = activeEvm[btcHash160];
        require(receiver != address(0), "Hash160 not registered");
        require(receivePreference[receiver] == ReceivePreference.ViaHash160, "User prefers direct EVM receiving");

        pendingWithdrawals[receiver] += msg.value;

        emit PendingFundsDeposited(btcHash160, receiver, msg.value);
    }

    /// @notice Withdraw all pending ETH deposited via receiveFunds
    /// @dev Pull-payment: receiver initiates the transfer, no gas limit issues.
    ///      Works with EOAs, multisigs, Safes, and any contract.
    function withdrawPendingFunds() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending funds");

        // Zero balance before external call (CEI pattern)
        pendingWithdrawals[msg.sender] = 0;

        emit PendingFundsWithdrawn(msg.sender, amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /// @notice Receive ERC20 tokens via hash160 (only if user opted in)
    function receiveTokens(bytes20 btcHash160, address token, uint256 amount) external nonReentrant {
        if (btcHash160 == bytes20(0)) revert ZeroHash160();
        require(amount > 0, "Cannot send zero amount");
        require(token != address(0), "Invalid token address");
        address receiver = activeEvm[btcHash160];
        require(receiver != address(0), "Hash160 not registered");
        require(receivePreference[receiver] == ReceivePreference.ViaHash160, "User prefers direct EVM receiving");

        // Emit event before external call (CEI pattern)
        emit FundsReceived(btcHash160, receiver, amount, token);

        // Transfer tokens from msg.sender to receiver
        IERC20(token).safeTransferFrom(msg.sender, receiver, amount);
    }

    // ==========================================
    // Cryptographic Helper Functions
    // ==========================================

    function _authenticateSignatureOnly(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes calldata message
    ) internal pure returns (bool) {
        if (pubkey.length != 65 && pubkey.length != 64 && pubkey.length != 33) return false;
        if (signature.length != 65) return false;

        // Safety check for compressed key prefix to avoid revert in decompression
        if (pubkey.length == 33) {
            uint8 prefix = uint8(pubkey[0]);
            if (prefix != 0x02 && prefix != 0x03) return false;
        }

        address expectedSigner = ethAddressFromXY(_pubkeyToXY(pubkey));

        // Attempt 1: Bitcoin Signed Message (Compact Format: Header, R, S)
        // Header is at sig[0]. Standard headers are 27-34.
        uint8 header = uint8(signature[0]);
        if (header >= 27 && header <= 34) {
            (bytes32 r, bytes32 s, uint8 v) = _splitCompact(signature);
            bytes32 digest = toBitcoinSignedMessageHash(message);
            if (ecrecover(digest, v, r, s) == expectedSigner) return true;
        }

        // Attempt 2: Ethereum Signed Message (Expanded Format: R, S, V)
        // V is at sig[64]. Standard V is 27, 28 (or 0, 1).
        uint8 vLast = uint8(signature[64]);
        if (vLast == 0 || vLast == 1 || vLast == 27 || vLast == 28) {
            (bytes32 r, bytes32 s, uint8 v) = _splitExpanded(signature);
            bytes32 digest = toEthSignedMessageHash(message);
            if (ecrecover(digest, v, r, s) == expectedSigner) return true;
        }

        return false;
    }

    function _verifySignatureFromMemory(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes memory message
    ) internal pure returns (bool) {
        if (pubkey.length != 65 && pubkey.length != 64 && pubkey.length != 33) return false;
        if (signature.length != 65) return false;

        // Safety check for compressed key prefix
        if (pubkey.length == 33) {
            uint8 prefix = uint8(pubkey[0]);
            if (prefix != 0x02 && prefix != 0x03) return false;
        }

        address expectedSigner = ethAddressFromXY(_pubkeyToXY(pubkey));

        // Attempt Bitcoin Signed Message
        uint8 header = uint8(signature[0]);
        if (header >= 27 && header <= 34) {
            (bytes32 r, bytes32 s, uint8 v) = _splitCompact(signature);
            bytes32 digest = toBitcoinSignedMessageHashMem(message);
            if (ecrecover(digest, v, r, s) == expectedSigner) return true;
        }

        // Attempt Ethereum Signed Message
        uint8 vLast = uint8(signature[64]);
        if (vLast == 0 || vLast == 1 || vLast == 27 || vLast == 28) {
            (bytes32 r, bytes32 s, uint8 v) = _splitExpanded(signature);
            bytes32 digest = toEthSignedMessageHashMem(message);
            if (ecrecover(digest, v, r, s) == expectedSigner) return true;
        }

        return false;
    }

    function _splitCompact(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        uint8 header = uint8(sig[0]);
        uint8 recId = (header - 27) & 3;
        v = 27 + recId;
        assembly {
            r := calldataload(add(sig.offset, 1))
            s := calldataload(add(sig.offset, 33))
        }
        // Enforce low-s to prevent ECDSA malleability (EIP-2)
        if (uint256(s) > HALF_ORDER) revert SignatureSMustBeLowOrder();
    }

    function _splitExpanded(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        uint8 vLast = uint8(sig[64]);
        v = vLast;
        if (v < 27) v += 27;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
        }
        // Enforce low-s to prevent ECDSA malleability (EIP-2)
        if (uint256(s) > HALF_ORDER) revert SignatureSMustBeLowOrder();
    }

    function _pubkeyToXY(bytes calldata pubkey) internal pure returns (bytes memory xy) {
        if (pubkey.length == 65) {
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = pubkey[i + 1];
        } else if (pubkey.length == 64) {
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = pubkey[i];
        } else if (pubkey.length == 33) {
            bytes memory uncompressed = decompressCompressedSecp256k1(pubkey);
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = uncompressed[i + 1];
        } else {
            revert InvalidPublicKey();
        }
    }
    
    function _pubkeyToXYMem(bytes memory pubkey) internal pure returns (bytes memory xy) {
        if (pubkey.length == 65) {
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = pubkey[i + 1];
        } else if (pubkey.length == 64) {
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = pubkey[i];
        } else if (pubkey.length == 33) {
            bytes memory uncompressed = decompressCompressedSecp256k1Mem(pubkey);
            xy = new bytes(64);
            for (uint256 i = 0; i < 64; i++) xy[i] = uncompressed[i + 1];
        } else {
            revert InvalidPublicKey();
        }
    }

    function decompressCompressedSecp256k1(bytes calldata comp) internal pure returns (bytes memory uncompressed) {
        if (comp.length != 33) revert InvalidPublicKey();
        uint8 prefix = uint8(comp[0]);
        if (prefix != 0x02 && prefix != 0x03) revert InvalidPublicKey();
        
        bytes32 x;
        assembly { x := calldataload(add(comp.offset, 1)) }
        
        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 xUint = uint256(x);
        uint256 y2 = addmod(mulmod(xUint, mulmod(xUint, xUint, p), p), 7, p);
        uint256 y = modSqrt(y2, p);
        
        if ((y & 1) != (prefix & 1)) {
            y = p - y;
        }
        
        uncompressed = new bytes(65);
        uncompressed[0] = 0x04;
        for (uint256 i = 0; i < 32; i++) {
            uncompressed[i + 1] = comp[i + 1];
        }
        for (uint256 i = 0; i < 32; i++) {
            uncompressed[i + 33] = bytes1(uint8(y >> (8 * (31 - i))));
        }
    }

    function decompressCompressedSecp256k1Mem(bytes memory comp) internal pure returns (bytes memory uncompressed) {
        if (comp.length != 33) revert InvalidPublicKey();
        uint8 prefix = uint8(comp[0]);
        if (prefix != 0x02 && prefix != 0x03) revert InvalidPublicKey();

        bytes32 x;
        // bytes memory layout: [len (32 bytes)] [data...]
        // x should be bytes[1..32] (skip prefix byte at index 0)
        assembly {
            x := mload(add(comp, 33))
        }

        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 xUint = uint256(x);
        uint256 y2 = addmod(mulmod(xUint, mulmod(xUint, xUint, p), p), 7, p);
        uint256 y = modSqrt(y2, p);

        if ((y & 1) != (prefix & 1)) {
            y = p - y;
        }

        uncompressed = new bytes(65);
        uncompressed[0] = 0x04;
        for (uint256 i = 0; i < 32; i++) {
            uncompressed[i + 1] = comp[i + 1];
        }
        for (uint256 i = 0; i < 32; i++) {
            uncompressed[i + 33] = bytes1(uint8(y >> (8 * (31 - i))));
        }
    }

    function modSqrt(uint256 a, uint256 p) internal pure returns (uint256) {
        return expMod(a, (p + 1) / 4, p);
    }

    function expMod(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = mulmod(result, base, mod);
            }
            base = mulmod(base, base, mod);
            exp /= 2;
        }
    }

    function ethAddressFromXY(bytes memory xy) internal pure returns (address) {
        bytes32 h = keccak256(xy);
        return address(uint160(uint256(h)));
    }

    function btcHash160FromPubkey(bytes calldata pubkey) internal pure returns (bytes20) {
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
            revert InvalidPublicKey();
        }
        bytes32 sha = sha256(full);
        return ripemd160(abi.encodePacked(sha));
    }
    
    // Memory variants for V2 (constructed bytes)
    function btcHash160FromPubkeyMem(bytes memory pubkey) internal pure returns (bytes20) {
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
            revert InvalidPublicKey();
        }
        bytes32 sha = sha256(full);
        return ripemd160(abi.encodePacked(sha));
    }

    function toBitcoinSignedMessageHash(bytes calldata message) internal pure returns (bytes32) {
        bytes memory data = abi.encodePacked(
            "\x18Bitcoin Signed Message:\n",
            _encodeCompactSize(message.length),
            message
        );
        bytes32 h1 = sha256(data);
        return sha256(abi.encodePacked(h1));
    }
    
    function toBitcoinSignedMessageHashMem(bytes memory message) internal pure returns (bytes32) {
        bytes memory data = abi.encodePacked(
            "\x18Bitcoin Signed Message:\n",
            _encodeCompactSize(message.length),
            message
        );
        bytes32 h1 = sha256(data);
        return sha256(abi.encodePacked(h1));
    }

    function toEthSignedMessageHash(bytes calldata s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", _toString(s.length), s));
    }
    
    function toEthSignedMessageHashMem(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", _toString(s.length), s));
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

    function toHex(address account) internal pure returns (string memory) {
        return toHex(abi.encodePacked(account));
    }

    function toHex(bytes memory data) internal pure returns (string memory) {
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
}
