// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title BNS — Bitcoin Name Service
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
    function activeEvm(bytes20 btcHash160) external view returns (address);
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract BitcoinNameService {
    // ══════════════════════════════════════════════════════════════
    // ERRORS
    // ══════════════════════════════════════════════════════════════

    error NameTooShort();
    error NameTooLong();
    error InvalidCharacter(uint256 position);
    error NameAlreadyTaken();
    error NameNotRegistered();
    error NotController();
    error Hash160AlreadyHasName();
    error ZeroHash160();
    error NameExpired();
    error NameNotExpired();
    error NotOwner();
    error InsufficientFee();
    error NoFeesToWithdraw();
    error TransferFailed();
    error IdentityNotRegistered();
    error SubdomainAlreadyTaken();
    error ParentNameNotOwned();
    error SubdomainNotRegistered();
    error TokenNotAccepted();
    error TokenTransferFailed();
    error TooManyTextRecords();
    error ContractPaused();
    error RefundFailed();
    error ReentrancyDetected();

    // ══════════════════════════════════════════════════════════════
    // CONSTANTS
    // ══════════════════════════════════════════════════════════════

    uint256 public constant MIN_NAME_LENGTH = 3;
    uint256 public constant MAX_NAME_LENGTH = 32;
    uint256 public constant REGISTRATION_PERIOD = 365 days;
    uint256 public constant GRACE_PERIOD = 30 days; // After expiry, original owner can still renew
    uint256 public constant MAX_TEXT_KEYS = 20; // Cap text records per name to bound release() gas

    // ══════════════════════════════════════════════════════════════
    // STATE
    // ══════════════════════════════════════════════════════════════

    IFastPathIdentity public immutable identity;
    address public owner;
    uint256 public registrationFee;
    IERC20 public feeToken; // Optional: pay fees in WBTC or any ERC-20 (address(0) = ETH only)
    bool public paused;
    uint256 private _reentrancyLock = 1; // 1 = unlocked, 2 = locked

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

    /// @notice Tracked text keys per name (for cleanup on release)
    mapping(bytes32 => string[]) private _textKeys;

    // ══════════════════════════════════════════════════════════════
    // EVENTS
    // ══════════════════════════════════════════════════════════════

    event NameRegistered(string indexed nameIndexed, bytes20 indexed hash160, string name, uint256 expiresAt);
    event NameRenewed(string indexed nameIndexed, bytes20 indexed hash160, string name, uint256 newExpiresAt);
    event NameReleased(string indexed nameIndexed, bytes20 indexed hash160, string name);
    event TextRecordSet(bytes32 indexed nameHash, string key, string value);
    event TextRecordCleared(bytes32 indexed nameHash, string key);
    event FeeUpdated(uint256 newFee);
    event FeeTokenUpdated(address token);
    event SubdomainRegistered(bytes32 indexed parentNameHash, string subLabel, bytes20 indexed hash160);
    event SubdomainReleased(bytes32 indexed parentNameHash, string subLabel);
    event Paused(address account);
    event Unpaused(address account);

    // ══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════

    constructor(address _identity, uint256 _fee) {
        identity = IFastPathIdentity(_identity);
        owner = msg.sender;
        registrationFee = _fee;
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
     * @param name The name to register (3–32 chars, lowercase alphanumeric + hyphens)
     * @param hash160 Your Bitcoin hash160 (must be registered in FastPathIdentity)
     */
    function register(string calldata name, bytes20 hash160)
        external
        payable
        onlyController(hash160)
        whenNotPaused
    {
        if (msg.value < registrationFee) revert InsufficientFee();

        // Validate name format
        _validateName(name);
        _registerInternal(name, hash160);

        // Refund excess ETH
        _refundExcess();
    }

    /**
     * @notice Register a name paying with the accepted ERC-20 token (e.g., WBTC)
     * @dev Caller must have approved this contract for at least registrationFee tokens
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
        if (registrationFee > 0) {
            bool success = feeToken.transferFrom(msg.sender, address(this), registrationFee);
            if (!success) revert TokenTransferFailed();
        }

        _validateName(name);
        _registerInternal(name, hash160);
    }

    /**
     * @notice Renew a name for another year
     * @param name The name to renew
     */
    function renew(string calldata name) external payable whenNotPaused {
        if (msg.value < registrationFee) revert InsufficientFee();

        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();

        // Only controller can renew
        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        // Must not be past grace period
        if (block.timestamp > record.expiresAt + GRACE_PERIOD) {
            revert NameExpired();
        }

        // Extend from current expiry (not from now — prevents gaming)
        uint256 baseTime = record.expiresAt > block.timestamp ? record.expiresAt : block.timestamp;
        record.expiresAt = baseTime + REGISTRATION_PERIOD;

        emit NameRenewed(name, record.hash160, name, record.expiresAt);

        // Refund excess ETH
        _refundExcess();
    }

    /**
     * @notice Release a name (makes it available for others)
     * @param name The name to release
     */
    function release(string calldata name) external {
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

        emit NameReleased(name, hash160, name);
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
    function clearText(string calldata name, string calldata key) external {
        bytes32 nameHash = keccak256(bytes(name));
        NameRecord storage record = _names[nameHash];
        if (!record.exists) revert NameNotRegistered();
        if (block.timestamp > record.expiresAt) revert NameExpired();

        address controller = identity.currentController(record.hash160);
        if (controller != msg.sender) revert NotController();

        delete _textRecords[nameHash][key];

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
        // Validate format first
        bytes memory b = bytes(name);
        if (b.length < MIN_NAME_LENGTH) return (false, "Too short (min 3)");
        if (b.length > MAX_NAME_LENGTH) return (false, "Too long (max 32)");

        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            bool valid = (c >= 0x61 && c <= 0x7a) || // a-z
                         (c >= 0x30 && c <= 0x39) || // 0-9
                         (c == 0x2d);                  // hyphen
            if (!valid) return (false, "Invalid character");
        }
        if (b[0] == 0x2d || b[b.length - 1] == 0x2d) return (false, "No leading/trailing hyphens");

        bytes32 nameHash = keccak256(b);
        NameRecord storage record = _names[nameHash];

        if (!record.exists) return (true, "Available");
        if (block.timestamp > record.expiresAt + GRACE_PERIOD) return (true, "Expired");
        if (block.timestamp > record.expiresAt) return (false, "In grace period");
        return (false, "Taken");
    }

    // ══════════════════════════════════════════════════════════════
    // ADMIN
    // ══════════════════════════════════════════════════════════════

    function setRegistrationFee(uint256 _fee) external onlyOwner {
        registrationFee = _fee;
        emit FeeUpdated(_fee);
    }

    function withdrawFees() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoFeesToWithdraw();
        (bool success, ) = owner.call{value: balance}("");
        if (!success) revert TransferFailed();
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
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
     * @notice Withdraw accumulated ERC-20 token fees
     * @param token The token to withdraw
     */
    function withdrawTokenFees(address token) external onlyOwner nonReentrant {
        IERC20 t = IERC20(token);
        uint256 balance = t.balanceOf(address(this));
        if (balance == 0) revert NoFeesToWithdraw();
        bool success = t.transfer(owner, balance);
        if (!success) revert TokenTransferFailed();
    }
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
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
    ) external whenNotPaused {
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
        if (_subdomains[parentHash][subHash] != bytes20(0)) revert SubdomainAlreadyTaken();

        _subdomains[parentHash][subHash] = hash160;
        _subdomainParent[hash160] = parentHash;
        _subdomainLabel[hash160] = subLabel;

        emit SubdomainRegistered(parentHash, subLabel, hash160);
    }

    /**
     * @notice Release a subdomain
     * @param parentName The parent name
     * @param subLabel The subdomain label to release
     */
    function releaseSubdomain(string calldata parentName, string calldata subLabel) external {
        bytes32 parentHash = keccak256(bytes(parentName));
        NameRecord storage parent = _names[parentHash];
        if (!parent.exists) revert NameNotRegistered();

        address controller = identity.currentController(parent.hash160);
        if (controller != msg.sender) revert ParentNameNotOwned();

        bytes32 subHash = keccak256(bytes(subLabel));
        bytes20 hash160 = _subdomains[parentHash][subHash];
        if (hash160 == bytes20(0)) revert SubdomainNotRegistered();

        delete _subdomains[parentHash][subHash];
        delete _subdomainParent[hash160];
        delete _subdomainLabel[hash160];

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
            if (i == 0 && isHyphen) revert InvalidCharacter(0);
            // No trailing hyphen
            if (i == len - 1 && isHyphen) revert InvalidCharacter(i);
            // No consecutive hyphens
            if (isHyphen && prevHyphen) revert InvalidCharacter(i);

            prevHyphen = isHyphen;
        }
    }

    /**
     * @dev Shared registration logic for ETH and token-based registration
     */
    function _registerInternal(string calldata name, bytes20 hash160) internal {
        bytes32 nameHash = keccak256(bytes(name));

        // Check name availability (allow re-registration of expired names past grace period)
        NameRecord storage existing = _names[nameHash];
        if (existing.exists) {
            if (block.timestamp < existing.expiresAt + GRACE_PERIOD) {
                revert NameAlreadyTaken();
            }
            // Expired past grace period — clear old reverse record
            delete _reverse[existing.hash160];
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
            // Old name expired — clean it up
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

        emit NameRegistered(name, hash160, name, expiresAt);
    }
}

