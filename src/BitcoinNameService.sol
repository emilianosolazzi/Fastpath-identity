// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title BNS — Bitcoin Name Service V2, rewardDistributor active
 * @author Emiliano Solazzi — 2026
 * @notice Human-readable names for Bitcoin hash160 identities, like ENS for Bitcoin addresses
 *
 * @dev Resolution chain:
 *      "satoshi.btc"  →  bytes20 hash160  →  EVM address (via FastPathIdentity)
 *
 *      This creates a three-hop resolution:
 *        1. BNS:              name → hash160
 *        2. FastPathIdentity: hash160 → EVM address
 *        3. Standard EVM:     EVM address → balances, contracts, etc.
 *
 *      Only the current controller of a hash160 (per FastPathIdentity) can register
 *      or manage a name for it. Names are permanent — they survive FastPathIdentity
 *      relinks. If the hash160 gets relinked to a new EVM address, the NEW controller
 *      automatically inherits name management rights.
 *
 * RELINK BEHAVIOR (security-relevant):
 *      When a hash160 is relinked via FastPathIdentity.relink(), the NEW controller
 *      inherits ALL name management rights: renew, release, setText, clearText, and
 *      subdomain management. The PREVIOUS controller loses all access immediately.
 *      This is by design — the name belongs to the Bitcoin identity (hash160), not
 *      to any specific EVM address. Users should understand that relinking their
 *      identity transfers all BNS privileges to the new controller.
 *
 * NAMING RULES:
 *      - 3–32 lowercase alphanumeric characters + hyphens
 *      - No leading/trailing hyphens, no consecutive hyphens
 *      - Suffix ".btc" is implicit (not stored)
 *      - One name per hash160, one hash160 per name (bijection)
 *
 * FEATURES:
 *      - Forward resolution:  resolve("satoshi") → hash160 → EVM address
 *      - Reverse resolution:  reverseOf(hash160) → "satoshi"
 *      - Text records:        key-value metadata (avatar, url, description, etc.)
 *      - Expiry & renewal:    names expire after 1 year, renewable by controller
 *      - Transfer:            controller can release name, register new one
 */

interface IFastPathIdentity {
    function currentController(bytes20 btcHash160) external view returns (address);
}

interface IBitID {
    function burnFrom(address from, uint256 amount) external;
}

/// @dev ABI-compatible with BitIDRewardDistributor.reward(address, Action)
///      Enum Action compiles to uint8: BNS_REGISTRATION = 1, BNS_RENEWAL = 2
interface IBitIDRewardDistributor {
    function reward(address user, uint8 action) external;
}

contract BitcoinNameService {
    // ══════════════════════════════════════════════════════════════
    // ERRORS
    // ══════════════════════════════════════════════════════════════

    error NotOwner();
    error InsufficientFee();
    error NoFeesToWithdraw();
    error TransferFailed();
    error IdentityNotRegistered();
    error SubdomainAlreadyTaken();
    error ParentNameNotOwned();
    error SubdomainNotRegistered();
    error TokenNotAccepted();
    error TooManyTextRecords();
    error ContractPaused();
    error RefundFailed();
    error ReentrancyDetected();
    error ReclaimWindowActive();
    error Hash160AlreadyHasSubdomain();
    error FeeTooHigh();
    error NotPendingOwner();
    error NameTooShort();
    error NameTooLong();
    error InvalidCharacter(uint256 position);
    error LeadingHyphen();
    error TrailingHyphen();
    error ConsecutiveHyphens();
    error MustUseRegisterOrRenew();
    // ── names
    error NameNotRegistered();
    error NameAlreadyTaken();
    error NameExpired();
    error NotController();
    // ── misc
    error ZeroAddress();
    error ZeroHash160();
    error Hash160AlreadyHasName();

    // ══════════════════════════════════════════════════════════════
    // CONSTANTS
    // ══════════════════════════════════════════════════════════════

    uint256 public constant MIN_NAME_LENGTH = 3;
    uint256 public constant MAX_NAME_LENGTH = 32;
    uint256 public constant REGISTRATION_PERIOD = 365 days;
    uint256 public constant GRACE_PERIOD = 30 days; // After expiry, original owner can still renew
    uint256 public constant RECLAIM_PERIOD = 14 days; // After grace, previous owner has priority to re-register
    uint256 public constant MAX_TEXT_KEYS = 20; // Cap text records per name to bound release() gas
    uint256 public constant MAX_ETH_FEE = 1 ether;              // Cap on ETH fee changes (M3)
    uint256 public constant MAX_TOKEN_FEE = 1_000_000_000;       // Cap on ERC-20 token fee (1,000 WBTC at 8 decimals)
    uint256 public constant MAX_BITID_FEE = 10_000_00000000;     // 10,000 BitID cap (8 decimals) (M3)

    /// @notice Contract version for on-chain verification
    string public constant VERSION = "1.0.0";

    /// @dev Reward action IDs matching BitIDRewardDistributor.Action enum
    uint8 private constant _REWARD_BNS_REGISTRATION = 1;
    uint8 private constant _REWARD_BNS_RENEWAL = 2;

    // ══════════════════════════════════════════════════════════════
    // STATE
    // ══════════════════════════════════════════════════════════════

    IFastPathIdentity public immutable identity;
    address public owner;
    address public pendingOwner;
    /// @notice Registration fee in ETH (wei)
    uint256 public registrationFee;
    /// @notice Renewal fee in ETH (wei)
    uint256 public renewalFee;
    /// @notice Registration fee in ERC-20 token units — stored in token-native decimals
    ///         (e.g., 1_000_000 = 0.01 WBTC at 8 decimals). Set independently from registrationFee.
    uint256 public registrationFeeToken;
    /// @notice Renewal fee in ERC-20 token units. Set independently from renewalFee.
    uint256 public renewalFeeToken;
    /// @notice Accepted ERC-20 for fee payment (address(0) = ETH only)
    IERC20 public feeToken;
    bool public paused;
    uint256 private _reentrancyLock = 1; // 1 = unlocked, 2 = locked

    /// @notice BitID token for burning on registration/renewal
    IBitID public bitid;
    /// @notice BitID required to register a .btc name
    uint256 public registrationBitIDFee;
    /// @notice BitID required to renew a .btc name
    uint256 public renewalBitIDFee;

    /// @notice Reward distributor for minting BitID on registration/renewal (optional)
    IBitIDRewardDistributor public rewardDistributor;

    /// @notice Forward resolution: nameHash → registration record
    struct NameRecord {
        bytes20 hash160;       // The Bitcoin identity this name points to
        uint256 registeredAt;
        uint256 expiresAt;
        bool exists;
    }
    mapping(bytes32 => NameRecord) private _names;

    /// @notice Reverse resolution: hash160 → name string
    mapping(bytes20 => string) private _reverse;

    /// @notice Text records: nameHash → key → value
    mapping(bytes32 => mapping(string => string)) private _textRecords;

    /// @notice The original plaintext for each nameHash (for enumeration/display)
    mapping(bytes32 => string) private _nameStrings;

    /// @notice Subdomains: parentNameHash → subLabel → hash160
    mapping(bytes32 => mapping(bytes32 => bytes20)) private _subdomains;

    /// @notice Reverse subdomain: hash160 → (parentNameHash, subLabel)
    mapping(bytes20 => bytes32) private _subdomainParent;
    mapping(bytes20 => string) private _subdomainLabel;

    /// @notice Tracks which parent registration epoch a subdomain was created under (L3)
    mapping(bytes32 => mapping(bytes32 => uint256)) private _subdomainParentRegisteredAt;

    /// @notice Tracked text keys per name (for cleanup on release)
    mapping(bytes32 => string[]) private _textKeys;

    // ══════════════════════════════════════════════════════════════
    // EVENTS
    // ══════════════════════════════════════════════════════════════

    event NameRegistered(string indexed name, bytes20 indexed hash160, uint256 expiresAt);
    event NameRenewed(string indexed name, bytes20 indexed hash160, uint256 newExpiresAt);
    event NameReleased(string indexed name, bytes20 indexed hash160);
    event TextRecordSet(bytes32 indexed nameHash, string key, string value);
    event TextRecordCleared(bytes32 indexed nameHash, string key);
    event RegistrationFeeUpdated(uint256 newFee);
    event RenewalFeeUpdated(uint256 newFee);
    event RegistrationFeeTokenUpdated(uint256 newFee);
    event RenewalFeeTokenUpdated(uint256 newFee);
    event FeeTokenUpdated(address token);
    event SubdomainRegistered(bytes32 indexed parentNameHash, string subLabel, bytes20 indexed hash160);
    event SubdomainReleased(bytes32 indexed parentNameHash, string subLabel);
    event Paused(address account);
    event Unpaused(address account);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event BitIDUpdated(address indexed bitid);
    event BitIDRegistrationFeeUpdated(uint256 fee);
    event BitIDRenewalFeeUpdated(uint256 fee);
    event RewardDistributorUpdated(address indexed distributor);

    // ══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════

    /**
     * @param _identity        FastPathIdentity contract (must be deployed)
     * @param _registrationFee Initial ETH fee for name registration (capped at MAX_ETH_FEE)
     * @param _renewalFee      Initial ETH fee for name renewal (capped at MAX_ETH_FEE)
     */
    constructor(address _identity, uint256 _registrationFee, uint256 _renewalFee) {
        if (_identity == address(0)) revert ZeroAddress();
        if (_registrationFee > MAX_ETH_FEE) revert FeeTooHigh();
        if (_renewalFee > MAX_ETH_FEE) revert FeeTooHigh();
        identity = IFastPathIdentity(_identity);
        owner = msg.sender;
        registrationFee = _registrationFee;
        renewalFee = _renewalFee;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ══════════════════════════════════════════════════════════════
    // MODIFIERS
    // ══════════════════════════════════════════════════════════════

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @dev Prevents reentrancy on functions that transfer tokens/ETH
    modifier nonReentrant() {
        if (_reentrancyLock == 2) revert ReentrancyDetected();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @dev Checks that msg.sender is the current FastPathIdentity controller of the hash160
    modifier onlyController(bytes20 hash160) {
        if (hash160 == bytes20(0)) revert ZeroHash160();
        address controller = identity.currentController(hash160);
        if (controller == address(0)) revert IdentityNotRegistered();
        if (controller != msg.sender) revert NotController();
        _;
    }

    // ══════════════════════════════════════════════════════════════
    // REGISTRATION
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Register a human-readable name for your Bitcoin hash160 identity
     * @dev Requires both ETH fee and BitID burn (if enabled)
     * @param name The name to register (3–32 chars, lowercase alphanumeric + hyphens)
     * @param hash160 Your Bitcoin hash160 (must be registered in FastPathIdentity)
     */
    function register(string calldata name, bytes20 hash160)
        external
        payable
        onlyController(hash160)
        whenNotPaused
        nonReentrant
    {
        if (msg.value < registrationFee) revert InsufficientFee();

        // Validate name format BEFORE external calls (saves gas on invalid names)
        _validateName(name);

        // Burn BitID if configured
        if (address(bitid) != address(0) && registrationBitIDFee > 0) {
            bitid.burnFrom(msg.sender, registrationBitIDFee);
        }

        _registerInternal(name, hash160);

        // Refund excess ETH (before external reward call — checks-effects-interactions)
        _refundExcess();

        // Best-effort reward — registration succeeds even if reward fails (last — external call)
        _tryReward(_REWARD_BNS_REGISTRATION);
    }

    /**
     * @notice Register a name paying with the accepted ERC-20 token (e.g., WBTC)
     * @dev Caller must have approved this contract for at least `registrationFeeToken` tokens
     *      AND approved BitID for at least `registrationBitIDFee` (if enabled).
     *      Token amounts are in token-native decimals — NOT the same as `registrationFee` (ETH/wei).
     * @param name The name to register
     * @param hash160 Your Bitcoin hash160
     */
    function registerWithToken(string calldata name, bytes20 hash160)
        external
        onlyController(hash160)
        whenNotPaused
        nonReentrant
    {
        if (address(feeToken) == address(0)) revert TokenNotAccepted();

        // Validate name format BEFORE external calls
        _validateName(name);

        if (registrationFeeToken > 0) {
            SafeERC20.safeTransferFrom(IERC20(address(feeToken)), msg.sender, address(this), registrationFeeToken);
        }

        // Burn BitID if configured
        if (address(bitid) != address(0) && registrationBitIDFee > 0) {
            bitid.burnFrom(msg.sender, registrationBitIDFee);
        }

        _registerInternal(name, hash160);

        // Best-effort reward
        _tryReward(_REWARD_BNS_REGISTRATION);
    }

    /**
     * @notice Renew a name for another year
     * @dev Requires both ETH fee and BitID burn (if enabled)
     * @param name The name to renew
     */
    function renew(string calldata name) external payable whenNotPaused nonReentrant {
        if (msg.value < renewalFee) revert InsufficientFee();

        // Validate name format FIRST (before any storage reads)
        _validateName(name);
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();

        // Validate controller BEFORE external calls (saves gas on unauthorized callers)
        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        // Must not be past grace period
        if (block.timestamp > record.expiresAt + GRACE_PERIOD) {
            revert NameExpired();
        }

        // Burn BitID if configured (after all validation passes)
        if (address(bitid) != address(0) && renewalBitIDFee > 0) {
            bitid.burnFrom(msg.sender, renewalBitIDFee);
        }

        // Extend from current expiry (not from now — prevents gaming)
        uint256 baseTime = record.expiresAt > block.timestamp ? record.expiresAt : block.timestamp;
        record.expiresAt = baseTime + REGISTRATION_PERIOD;

        emit NameRenewed(name, record.hash160, record.expiresAt);

        // Refund excess ETH (before external reward call — checks-effects-interactions)
        uint256 excess = msg.value - renewalFee;
        if (excess > 0) {
            (bool success, ) = msg.sender.call{value: excess}("");
            if (!success) revert RefundFailed();
        }

        // Best-effort reward (last — external call to distributor)
        _tryReward(_REWARD_BNS_RENEWAL);
    }

    /**
     * @notice Renew a name paying with the accepted ERC-20 token
     * @dev Caller must have approved this contract for at least `renewalFeeToken` tokens
     *      AND approved BitID for at least `renewalBitIDFee` (if enabled).
     *      Token amounts are in token-native decimals — NOT the same as `renewalFee` (ETH/wei).
     * @param name The name to renew
     */
    function renewWithToken(string calldata name) external whenNotPaused nonReentrant {
        if (address(feeToken) == address(0)) revert TokenNotAccepted();

        // Validate name format FIRST
        _validateName(name);
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();

        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        if (block.timestamp > record.expiresAt + GRACE_PERIOD) {
            revert NameExpired();
        }

        if (renewalFeeToken > 0) {
            SafeERC20.safeTransferFrom(IERC20(address(feeToken)), msg.sender, address(this), renewalFeeToken);
        }

        // Burn BitID if configured
        if (address(bitid) != address(0) && renewalBitIDFee > 0) {
            bitid.burnFrom(msg.sender, renewalBitIDFee);
        }

        uint256 baseTime = record.expiresAt > block.timestamp ? record.expiresAt : block.timestamp;
        record.expiresAt = baseTime + REGISTRATION_PERIOD;

        emit NameRenewed(name, record.hash160, record.expiresAt);

        // Best-effort reward (last — external call to distributor)
        _tryReward(_REWARD_BNS_RENEWAL);
    }

    /**
     * @notice Release a name (makes it available for others)
     * @param name The name to release
     */
    function release(string calldata name) external whenNotPaused nonReentrant {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();

        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        bytes20 hash160 = record.hash160;

        // Clean up text records (gas refund on SSTORE zero)
        string[] storage keys = _textKeys[nameHash];
        uint256 keysLength = keys.length;
        for (uint256 i = 0; i < keysLength; i++) {
            delete _textRecords[nameHash][keys[i]];
        }
        delete _textKeys[nameHash];

        delete _reverse[hash160];
        delete _names[nameHash];
        delete _nameStrings[nameHash];

        emit NameReleased(name, hash160);
    }

    // ══════════════════════════════════════════════════════════════
    // TEXT RECORDS (like ENS text records)
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Set a text record for a name (avatar, url, description, email, etc.)
     * @param name The name to set the record on
     * @param key The record key (e.g., "avatar", "url", "description")
     * @param value The record value
     */
    function setText(string calldata name, string calldata key, string calldata value) external whenNotPaused {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();

        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        // Track key if it's new (for cleanup on release)
        if (bytes(_textRecords[nameHash][key]).length == 0 && bytes(value).length > 0) {
            if (_textKeys[nameHash].length >= MAX_TEXT_KEYS) revert TooManyTextRecords();
            _textKeys[nameHash].push(key);
        }

        _textRecords[nameHash][key] = value;

        emit TextRecordSet(nameHash, key, value);
    }

    /**
     * @notice Delete a text record for a name
     * @param name The name
     * @param key The record key to delete
     */
    function clearText(string calldata name, string calldata key) external whenNotPaused {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();

        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        delete _textRecords[nameHash][key];
        _removeTextKey(nameHash, key);

        emit TextRecordCleared(nameHash, key);
    }

    // ══════════════════════════════════════════════════════════════
    // RESOLUTION (the core utility)
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Resolve a name to an EVM address (the main entry point)
     * @dev Full resolution chain: name → hash160 → EVM address
     * @param name The human-readable name (without .btc suffix)
     * @return evmAddress The current EVM controller address
     * @return hash160 The Bitcoin hash160 identity
     */
    function resolve(string calldata name) external view returns (address evmAddress, bytes20 hash160) {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();

        hash160 = record.hash160;
        evmAddress = identity.currentController(hash160);
    }

    /**
     * @notice Resolve a name to just the hash160 (no FastPathIdentity call)
     * @param name The human-readable name
     * @return hash160 The Bitcoin hash160 identity
     */
    function resolveToHash160(string calldata name) external view returns (bytes20 hash160) {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();
        return record.hash160;
    }

    /**
     * @notice Reverse resolution: hash160 → name
     * @param hash160 The Bitcoin hash160
     * @return name The human-readable name (empty string if none)
     */
    function reverseOf(bytes20 hash160) external view returns (string memory name) {
        name = _reverse[hash160];
        if (bytes(name).length > 0) {
            // Verify name is still active
            bytes32 nameHash = keccak256(bytes(name));
            NameRecord storage record = _names[nameHash];
            if (!record.exists || block.timestamp > record.expiresAt) {
                return "";
            }
        }
    }

    /**
     * @notice Full resolution: name → all data in one call
     * @param name The human-readable name
     */
    function resolveAll(string calldata name) external view returns (
        address evmAddress,
        bytes20 hash160,
        uint256 registeredAt,
        uint256 expiresAt,
        string memory avatar,
        string memory url,
        string memory description
    ) {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();

        hash160 = record.hash160;
        evmAddress = identity.currentController(hash160);
        registeredAt = record.registeredAt;
        expiresAt = record.expiresAt;
        avatar = _textRecords[nameHash]["avatar"];
        url = _textRecords[nameHash]["url"];
        description = _textRecords[nameHash]["description"];
    }

    /**
     * @notice Read a text record
     * @param name The name
     * @param key The record key
     * @return value The record value
     */
    function text(string calldata name, string calldata key) external view returns (string memory value) {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();
        return _textRecords[nameHash][key];
    }

    /**
     * @notice Check if a name is available for registration
     * @param name The name to check
     * @return available True if the name can be registered
     * @return reason Human-readable reason if not available
     */
    function available(string calldata name) external view returns (bool, string memory reason) {
        // Validate format first (must match _validateName exactly)
        bytes memory b = bytes(name);
        if (b.length < MIN_NAME_LENGTH) return (false, "Too short (min 3)");
        if (b.length > MAX_NAME_LENGTH) return (false, "Too long (max 32)");

        bool prevHyphen = false;
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            bool isHyphen = (c == 0x2d);
            bool valid = (c >= 0x61 && c <= 0x7a) || // a-z
                         (c >= 0x30 && c <= 0x39) || // 0-9
                         isHyphen;                     // hyphen
            if (!valid) return (false, "Invalid character");
            if (isHyphen && prevHyphen) return (false, "Consecutive hyphens");
            prevHyphen = isHyphen;
        }
        if (b[0] == 0x2d || b[b.length - 1] == 0x2d) return (false, "No leading/trailing hyphens");

        bytes32 nameHash = keccak256(b);
        NameRecord storage record = _names[nameHash];

        if (!record.exists) return (true, "Available");
        if (block.timestamp > record.expiresAt + GRACE_PERIOD + RECLAIM_PERIOD) return (true, "Expired");
        if (block.timestamp > record.expiresAt + GRACE_PERIOD) return (false, "In reclaim window (previous owner priority)");
        if (block.timestamp > record.expiresAt) return (false, "In grace period");
        return (false, "Taken");
    }

    // ══════════════════════════════════════════════════════════════
    // ADMIN
    // ══════════════════════════════════════════════════════════════

    function setRegistrationFee(uint256 _fee) external onlyOwner {
        if (_fee > MAX_ETH_FEE) revert FeeTooHigh();
        registrationFee = _fee;
        emit RegistrationFeeUpdated(_fee);
    }

    function setRenewalFee(uint256 _fee) external onlyOwner {
        if (_fee > MAX_ETH_FEE) revert FeeTooHigh();
        renewalFee = _fee;
        emit RenewalFeeUpdated(_fee);
    }

    /**
     * @notice Set the ERC-20 token registration fee in token-native units
     * @dev NOT capped by MAX_ETH_FEE — token decimals differ from ETH.
     *      Example: 1_000_000 = 0.01 WBTC (8 decimals).
     *      Separate from `registrationFee` (ETH) to prevent decimal mismatch.
     */
    function setRegistrationFeeToken(uint256 _fee) external onlyOwner {
        if (_fee > MAX_TOKEN_FEE) revert FeeTooHigh();
        registrationFeeToken = _fee;
        emit RegistrationFeeTokenUpdated(_fee);
    }

    /**
     * @notice Set the ERC-20 token renewal fee in token-native units
     * @dev Same decimal caveat as setRegistrationFeeToken.
     */
    function setRenewalFeeToken(uint256 _fee) external onlyOwner {
        if (_fee > MAX_TOKEN_FEE) revert FeeTooHigh();
        renewalFeeToken = _fee;
        emit RenewalFeeTokenUpdated(_fee);
    }

    function withdrawFees() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoFeesToWithdraw();
        (bool success, ) = owner.call{value: balance}("");
        if (!success) revert TransferFailed();
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /**
     * @notice Accept pending ownership transfer (two-step prevents typo lockout)
     */
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    /**
     * @notice Set the accepted ERC-20 token for fee payment (e.g., WBTC)
     * @param token The ERC-20 token address (address(0) to disable token payments)
     */
    function setFeeToken(address token) external onlyOwner {
        feeToken = IERC20(token);
        emit FeeTokenUpdated(token);
    }

    /**
     * @notice Withdraw accumulated ERC-20 fee token balance
     * @dev Restricted to configured feeToken only — prevents arbitrary token sweeps (L5)
     */
    function withdrawTokenFees() external onlyOwner nonReentrant {
        if (address(feeToken) == address(0)) revert TokenNotAccepted();
        uint256 balance = feeToken.balanceOf(address(this));
        if (balance == 0) revert NoFeesToWithdraw();
        SafeERC20.safeTransfer(IERC20(address(feeToken)), owner, balance);
    }
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /**
     * @notice Set the BitID token address for burning on registration/renewal
     * @param _bitid The BitID token contract address (address(0) to disable)
     */
    function setBitID(address _bitid) external onlyOwner {
        bitid = IBitID(_bitid);
        emit BitIDUpdated(_bitid);
    }

    /**
     * @notice Set BitID fee for name registration
     * @param fee Amount of BitID required to register a name (8 decimals)
     */
    function setRegistrationBitIDFee(uint256 fee) external onlyOwner {
        if (fee > MAX_BITID_FEE) revert FeeTooHigh();
        registrationBitIDFee = fee;
        emit BitIDRegistrationFeeUpdated(fee);
    }

    /**
     * @notice Set BitID fee for name renewal
     * @param fee Amount of BitID required to renew a name (8 decimals)
     */
    function setRenewalBitIDFee(uint256 fee) external onlyOwner {
        if (fee > MAX_BITID_FEE) revert FeeTooHigh();
        renewalBitIDFee = fee;
        emit BitIDRenewalFeeUpdated(fee);
    }

    /**
     * @notice Set the reward distributor for minting BitID on registration/renewal
     * @dev BNS must be registered as an authorized caller on the distributor:
     *      distributor.setCaller(address(bns), true)
     *      Set to address(0) to disable rewards.
     * @param _distributor BitIDRewardDistributor address
     */
    function setRewardDistributor(address _distributor) external onlyOwner {
        rewardDistributor = IBitIDRewardDistributor(_distributor);
        emit RewardDistributorUpdated(_distributor);
    }

    // ══════════════════════════════════════════════════════════════
    // SUBDOMAINS (wallet.satoshi.btc)
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Register a subdomain under a name you control
     * @dev Only the controller of the PARENT name's hash160 can create subdomains
     * @param parentName The parent name (e.g., "satoshi")
     * @param subLabel The subdomain label (e.g., "wallet" → wallet.satoshi.btc)
     * @param hash160 The Bitcoin hash160 identity for the subdomain
     */
    function registerSubdomain(
        string calldata parentName,
        string calldata subLabel,
        bytes20 hash160
    ) external whenNotPaused nonReentrant {
        if (hash160 == bytes20(0)) revert ZeroHash160();

        bytes32 parentHash = keccak256(bytes(parentName));
        NameRecord storage parent = _names[parentHash];
        if (!parent.exists) revert NameNotRegistered();
        if (block.timestamp > parent.expiresAt) revert NameExpired();

        // Only parent's controller can create subdomains
        address controller = identity.currentController(parent.hash160);
        if (controller != msg.sender) revert ParentNameNotOwned();

        // Validate sublabel (same rules as names)
        _validateName(subLabel);

        bytes32 subHash = keccak256(bytes(subLabel));

        // Allow overwriting stale subdomains from previous registration epochs
        if (_subdomains[parentHash][subHash] != bytes20(0)) {
            if (_subdomainParentRegisteredAt[parentHash][subHash] == parent.registeredAt) {
                revert SubdomainAlreadyTaken(); // Same epoch → actually taken
            }
            // Stale from previous epoch — clean up old reverse mappings
            bytes20 oldHash160 = _subdomains[parentHash][subHash];
            delete _subdomainParent[oldHash160];
            delete _subdomainLabel[oldHash160];
        }

        // M4: Check hash160 isn't already assigned to an active subdomain elsewhere
        if (_subdomainParent[hash160] != bytes32(0)) {
            bytes32 existingParentHash = _subdomainParent[hash160];
            bytes32 existingSubHash = keccak256(bytes(_subdomainLabel[hash160]));
            NameRecord storage existingParent = _names[existingParentHash];
            if (existingParent.exists &&
                block.timestamp <= existingParent.expiresAt &&
                _subdomainParentRegisteredAt[existingParentHash][existingSubHash] == existingParent.registeredAt) {
                revert Hash160AlreadyHasSubdomain();
            }
        }

        _subdomains[parentHash][subHash] = hash160;
        _subdomainParent[hash160] = parentHash;
        _subdomainLabel[hash160] = subLabel;
        _subdomainParentRegisteredAt[parentHash][subHash] = parent.registeredAt;

        emit SubdomainRegistered(parentHash, subLabel, hash160);
    }

    /**
     * @notice Release a subdomain
     * @param parentName The parent name
     * @param subLabel The subdomain label to release
     */
    function releaseSubdomain(string calldata parentName, string calldata subLabel) external nonReentrant {
        bytes32 parentHash = keccak256(bytes(parentName));
        NameRecord storage parent = _names[parentHash];
        if (!parent.exists) revert NameNotRegistered();

        address controller = identity.currentController(parent.hash160);
        if (controller != msg.sender) revert ParentNameNotOwned();

        bytes32 subHash = keccak256(bytes(subLabel));
        bytes20 hash160 = _subdomains[parentHash][subHash];
        if (hash160 == bytes20(0)) revert SubdomainNotRegistered();

        // L3: Verify subdomain is from current registration epoch
        if (_subdomainParentRegisteredAt[parentHash][subHash] != parent.registeredAt) {
            revert SubdomainNotRegistered();
        }

        delete _subdomains[parentHash][subHash];
        delete _subdomainParent[hash160];
        delete _subdomainLabel[hash160];
        delete _subdomainParentRegisteredAt[parentHash][subHash];

        emit SubdomainReleased(parentHash, subLabel);
    }

    /**
     * @notice Resolve a subdomain to an EVM address
     * @param parentName The parent name (e.g., "satoshi")
     * @param subLabel The subdomain label (e.g., "wallet")
     * @return evmAddress The EVM address of the subdomain's hash160
     * @return hash160 The subdomain's Bitcoin hash160
     */
    function resolveSubdomain(
        string calldata parentName,
        string calldata subLabel
    ) external view returns (address evmAddress, bytes20 hash160) {
        bytes32 parentHash = keccak256(bytes(parentName));
        NameRecord storage parent = _names[parentHash];
        if (!parent.exists) revert NameNotRegistered();
        if (block.timestamp > parent.expiresAt) revert NameExpired();

        bytes32 subHash = keccak256(bytes(subLabel));
        hash160 = _subdomains[parentHash][subHash];
        if (hash160 == bytes20(0)) revert SubdomainNotRegistered();

        // L3: Invalidate subdomains from a previous registration epoch
        if (_subdomainParentRegisteredAt[parentHash][subHash] != parent.registeredAt) {
            revert SubdomainNotRegistered();
        }

        evmAddress = identity.currentController(hash160);
    }

    // ══════════════════════════════════════════════════════════════
    // INTERNAL: NAME VALIDATION & REGISTRATION
    // ══════════════════════════════════════════════════════════════

    /// @dev Refunds any ETH sent above the registration fee
    function _refundExcess() internal {
        uint256 excess = msg.value - registrationFee;
        if (excess > 0) {
            (bool success, ) = msg.sender.call{value: excess}("");
            if (!success) revert RefundFailed();
        }
    }

    function _validateName(string calldata name) internal pure {
        bytes memory b = bytes(name);
        uint256 len = b.length;

        if (len < MIN_NAME_LENGTH) revert NameTooShort();
        if (len > MAX_NAME_LENGTH) revert NameTooLong();

        bool prevHyphen = false;
        for (uint256 i = 0; i < len; i++) {
            bytes1 c = b[i];

            bool isLower = (c >= 0x61 && c <= 0x7a); // a-z
            bool isDigit = (c >= 0x30 && c <= 0x39); // 0-9
            bool isHyphen = (c == 0x2d);               // -

            if (!isLower && !isDigit && !isHyphen) revert InvalidCharacter(i);

            // No leading hyphen
            if (i == 0 && isHyphen) revert LeadingHyphen();
            // No trailing hyphen
            if (i == len - 1 && isHyphen) revert TrailingHyphen();
            // No consecutive hyphens
            if (isHyphen && prevHyphen) revert ConsecutiveHyphens();

            prevHyphen = isHyphen;
        }
    }

    /// @dev Cleans up all text records for a name (prevents stale data on re-registration)
    function _cleanupTextRecords(bytes32 nameHash) internal {
        string[] storage keys = _textKeys[nameHash];
        uint256 keysLength = keys.length;
        for (uint256 i = 0; i < keysLength; i++) {
            delete _textRecords[nameHash][keys[i]];
        }
        delete _textKeys[nameHash];
    }

    /// @dev Removes a single key from _textKeys array (swap-and-pop, O(n) with n ≤ MAX_TEXT_KEYS)
    function _removeTextKey(bytes32 nameHash, string calldata key) internal {
        string[] storage keys = _textKeys[nameHash];
        bytes32 keyHash = keccak256(bytes(key));
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; i++) {
            if (keccak256(bytes(keys[i])) == keyHash) {
                keys[i] = keys[len - 1];
                keys.pop();
                return;
            }
        }
    }

    /**
     * @dev Best-effort reward: calls the distributor to mint BitID to msg.sender.
     *      Wrapped in try/catch so registration/renewal NEVER reverts due to
     *      distributor issues (cooldown, budget, misconfiguration, or unset).
     * @param action Reward action ID matching BitIDRewardDistributor.Action enum
     */
    function _tryReward(uint8 action) internal {
        IBitIDRewardDistributor dist = rewardDistributor;
        if (address(dist) != address(0)) {
            try dist.reward(msg.sender, action) {} catch {}
        }
    }

    /**
     * @dev Shared registration logic for ETH and token-based registration
     */
    function _registerInternal(string calldata name, bytes20 hash160) internal {
        bytes32 nameHash = keccak256(bytes(name));

        // Check name availability (allow re-registration of expired names past grace + reclaim period)
        NameRecord storage existing = _names[nameHash];
        if (existing.exists) {
            if (block.timestamp < existing.expiresAt + GRACE_PERIOD) {
                revert NameAlreadyTaken();
            }
            // H1: Reclaim window — previous controller gets priority before open registration
            if (block.timestamp < existing.expiresAt + GRACE_PERIOD + RECLAIM_PERIOD) {
                address previousController = identity.currentController(existing.hash160);
                if (previousController != msg.sender) revert ReclaimWindowActive();
            }
            // Expired past grace + reclaim — clean up ALL stale data from old owner
            delete _reverse[existing.hash160];
            _cleanupTextRecords(nameHash);
        }

        // Check this hash160 doesn't already have an active name
        bytes memory currentReverse = bytes(_reverse[hash160]);
        if (currentReverse.length > 0) {
            // Verify the existing name is actually still active
            bytes32 currentNameHash = keccak256(currentReverse);
            NameRecord storage currentRecord = _names[currentNameHash];
            if (currentRecord.exists && block.timestamp < currentRecord.expiresAt) {
                revert Hash160AlreadyHasName();
            }
            // Old name expired — clean it up including text records
            _cleanupTextRecords(currentNameHash);
            delete _names[currentNameHash];
            delete _nameStrings[currentNameHash];
        }

        // Register
        uint256 expiresAt = block.timestamp + REGISTRATION_PERIOD;
        _names[nameHash] = NameRecord({
            hash160: hash160,
            registeredAt: block.timestamp,
            expiresAt: expiresAt,
            exists: true
        });
        _reverse[hash160] = name;
        _nameStrings[nameHash] = name;

        emit NameRegistered(name, hash160, expiresAt);
    }

    // ══════════════════════════════════════════════════════════════
    // FALLBACK
    // ══════════════════════════════════════════════════════════════

    /// @dev Reject accidental ETH sends outside register()/renew()
    receive() external payable {
        revert MustUseRegisterOrRenew();
    }
}
