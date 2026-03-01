// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IBitID {
    function mint(address to, uint256 amount) external;
    function mintableSupply() external view returns (uint256);
}

interface IFastPathIdentity {
    function evmToBtc(address evm) external view returns (bytes20);
    function currentController(bytes20 btcHash160) external view returns (address);
}

/**
 * @title BitIDRewardDistributor
 * @author Emiliano Solazzi — 2026
 * @notice Central reward hub for the FastPath / Proof160 protocol.
 *         Protocol contracts call `reward(user, actionType)` to mint
 *         BitID tokens based on a configurable schedule.
 *
 * @dev Flow:
 *      1. Owner deploys this contract, pointing at BitID and FastPathIdentity
 *      2. Owner calls `bitid.addMinter(address(this))` to authorize this distributor
 *      3. Owner configures reward amounts per action via `setReward()`
 *      4. Owner authorizes caller contracts via `setCaller()`
 *      5. Protocol contracts call `reward(user, actionType)` on successful actions
 *      6. This contract mints BitID to the user
 *
 *      Safety:
 *        - Per-user cooldown per action type prevents farming
 *        - Global epoch budget prevents runaway minting
 *        - Only whitelisted callers can trigger rewards
 *        - Recipient must have a Proof160 identity (optional, toggleable)
 */
contract BitIDRewardDistributor is Ownable, ReentrancyGuard {
    // ══════════════════════════════════════════════════════════════
    // ERRORS
    // ══════════════════════════════════════════════════════════════

    error ZeroAddress();
    error ZeroHash160();
    error ControllerMismatch();
    error UnknownAction();
    error CooldownActive();
    error EpochBudgetExhausted();
    error NotAuthorizedCaller();
    error IdentityRequired();
    error RewardDisabled();

    // ══════════════════════════════════════════════════════════════
    // TYPES
    // ══════════════════════════════════════════════════════════════

    /// @notice Predefined protocol action types
    enum Action {
        IDENTITY_REGISTRATION, // 0 — Proof160 registration
        BNS_REGISTRATION, // 1 — Bitcoin Name Service name mint
        BNS_RENEWAL, // 2 — BNS name renewal
        GATEWAY_RELAY, // 3 — BTC→EVM relay confirmation
        FIRST_TRANSFER, // 4 — Onboarding bonus (first Gateway use)
        REFERRAL // 5 — Referred a new registrant
    }

    struct RewardConfig {
        uint256 amount; // BitID per action (8 decimals)
        uint256 cooldown; // Seconds before same user can earn again for this action
        bool enabled; // Master switch per action
    }

    // ══════════════════════════════════════════════════════════════
    // STATE
    // ══════════════════════════════════════════════════════════════

    IBitID public bitid;
    IFastPathIdentity public identity;

    /// @notice Reward configuration per action type
    mapping(Action => RewardConfig) public rewards;

    /// @notice Last reward timestamp per user per action (cooldown enforcement)
    mapping(address => mapping(Action => uint256)) public lastRewarded;

    /// @notice Total BitID distributed per user (lifetime)
    mapping(address => uint256) public totalEarned;

    /// @notice Contracts authorized to call reward()
    mapping(address => bool) public authorizedCallers;

    /// @notice When true, recipient must have a Proof160 identity to receive rewards
    bool public requireIdentity;

    /// @notice Tracks whether an EVM address has claimed their registration reward
    mapping(address => bool) public registrationRewardClaimed;

    /// @notice Epoch-based budget: max tokens mintable per epoch
    uint256 public epochBudget;
    /// @notice Duration of each epoch in seconds
    uint256 public epochDuration;
    /// @notice Timestamp when the current epoch started
    uint256 public epochStart;
    /// @notice Tokens minted in the current epoch
    uint256 public epochMinted;

    // ══════════════════════════════════════════════════════════════
    // EVENTS
    // ══════════════════════════════════════════════════════════════

    event Rewarded(address indexed user, Action indexed action, uint256 amount);
    event OwnerRewarded(address indexed user, uint256 amount);
    event RegistrationRewardClaimed(address indexed user, bytes20 indexed btcHash160, uint256 amount);
    event RewardConfigured(Action indexed action, uint256 amount, uint256 cooldown, bool enabled);
    event CallerAuthorized(address indexed caller);
    event CallerRevoked(address indexed caller);
    event EpochBudgetSet(uint256 budget, uint256 duration);
    event IdentityRequirementToggled(bool required);

    // ══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════

    /**
     * @param _bitid   Address of the deployed BitID token
     * @param _identity Address of the deployed FastPathIdentity contract
     * @dev ⚠️  DEPLOYER BECOMES CALLER: The deployer (msg.sender) is automatically
     *      authorized as a caller in the constructor for testing convenience.
     *      MUST be revoked via setCaller(deployer, false) once protocol contracts
     *      are wired up and mainnet is ready. Leaving an EOA as a permanent caller
     *      is a critical centralization risk.
     */
    constructor(address _bitid, address _identity) Ownable(msg.sender) {
        if (_bitid == address(0) || _identity == address(0)) revert ZeroAddress();

        bitid = IBitID(_bitid);
        identity = IFastPathIdentity(_identity);

        // ── Default reward schedule (all amounts in 8-decimal base units) ──
        //
        //  Action                      Amount          Cooldown
        //  ─────────────────────────  ──────────────  ─────────
        //  Proof160 registration       160 BITID       once (max cooldown)
        //  BNS name registration        16 BITID       1 day
        //  BNS renewal                   8 BITID       1 day
        //  Gateway relay                 1 BITID       none
        //  First transfer               32 BITID       once
        //  Referral                     10 BITID       1 hour

        rewards[Action.IDENTITY_REGISTRATION] = RewardConfig(160 * 1e8, type(uint256).max, true);
        rewards[Action.BNS_REGISTRATION] = RewardConfig(16 * 1e8, 1 days, true);
        rewards[Action.BNS_RENEWAL] = RewardConfig(8 * 1e8, 1 days, true);
        rewards[Action.GATEWAY_RELAY] = RewardConfig(1 * 1e8, 0, true);
        rewards[Action.FIRST_TRANSFER] = RewardConfig(32 * 1e8, type(uint256).max, true);
        rewards[Action.REFERRAL] = RewardConfig(10 * 1e8, 1 hours, true);

        // Default epoch: 1M BITID per week
        epochBudget = 1_000_000 * 1e8;
        epochDuration = 7 days;
        epochStart = block.timestamp;

        // Owner is always an authorized caller (for manual/test rewards)
        authorizedCallers[msg.sender] = true;
        emit CallerAuthorized(msg.sender);
    }

    // ══════════════════════════════════════════════════════════════
    // CORE — REWARD
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Mint BitID to a user for completing a protocol action
     * @param user   Recipient address
     * @param action The protocol action that was completed
     */
    function reward(address user, Action action) external nonReentrant {
        if (!authorizedCallers[msg.sender]) revert NotAuthorizedCaller();
        if (user == address(0)) revert ZeroAddress();

        RewardConfig memory cfg = rewards[action];
        if (!cfg.enabled) revert RewardDisabled();
        if (cfg.amount == 0) revert UnknownAction();

        // Identity check (optional)
        if (requireIdentity) {
            if (identity.evmToBtc(user) == bytes20(0)) revert IdentityRequired();
        }

        // Cooldown check — handle type(uint256).max overflow for "once only" actions
        uint256 last = lastRewarded[user][action];
        if (last != 0) {
            // For type(uint256).max cooldown (one-time actions), reject second call cleanly
            // For normal cooldowns, enforce the time window
            if (cfg.cooldown == type(uint256).max || block.timestamp < last + cfg.cooldown) {
                revert CooldownActive();
            }
        }

        // Epoch budget check — roll over if needed
        _checkEpoch();
        if (epochMinted + cfg.amount > epochBudget) revert EpochBudgetExhausted();

        // State updates before external call
        lastRewarded[user][action] = block.timestamp;
        epochMinted += cfg.amount;
        totalEarned[user] += cfg.amount;

        // Mint (external call to BitID)
        bitid.mint(user, cfg.amount);

        emit Rewarded(user, action, cfg.amount);
    }

    /**
     * @notice Owner can reward any address directly — useful for testing,
     *         retroactive rewards, or manual treasury operations.
     * @dev ⚠️  POWERFUL: This bypasses all identity checks, cooldowns, and rate limits.
     *      The owner role has unlimited minting rights over 90% of the protocol supply.
     *      MUST be transferred to a multisig + timelock contract before mainnet.
     * @param user   Recipient
     * @param amount Exact amount to mint (8 decimals)
     */
    function ownerReward(address user, uint256 amount) external onlyOwner nonReentrant {
        if (user == address(0)) revert ZeroAddress();

        _checkEpoch();
        if (epochMinted + amount > epochBudget) revert EpochBudgetExhausted();

        epochMinted += amount;
        totalEarned[user] += amount;

        bitid.mint(user, amount);

        emit OwnerRewarded(user, amount);
    }

    /**
     * @notice Self-service claim for registration reward — users can claim once after registering
     * @dev Non-blocking: registration reward is capped by epoch budget only (no cooldown on this action).
     *      User must have registered (evmToBtc[msg.sender] must be non-zero) and not claimed before.
     *      Reward amount comes from IDENTITY_REGISTRATION config (typically 160 BITID).
     * @param btcHash160 The Bitcoin Hash160 to verify ownership
     */
    function claimRegistrationReward(bytes20 btcHash160) external nonReentrant {
        if (btcHash160 == bytes20(0)) revert ZeroHash160();
        if (registrationRewardClaimed[msg.sender]) revert CooldownActive(); // Already claimed

        // Verify caller owns this BTC identity
        if (identity.evmToBtc(msg.sender) != btcHash160) revert IdentityRequired();
        if (identity.currentController(btcHash160) != msg.sender) revert ControllerMismatch();

        // Verify action is enabled
        RewardConfig memory cfg = rewards[Action.IDENTITY_REGISTRATION];
        if (!cfg.enabled) revert RewardDisabled();
        if (cfg.amount == 0) revert UnknownAction();

        // Check epoch budget
        _checkEpoch();
        if (epochMinted + cfg.amount > epochBudget) revert EpochBudgetExhausted();

        // Mark as claimed before external call
        registrationRewardClaimed[msg.sender] = true;
        epochMinted += cfg.amount;
        totalEarned[msg.sender] += cfg.amount;

        // Mint reward
        bitid.mint(msg.sender, cfg.amount);

        emit RegistrationRewardClaimed(msg.sender, btcHash160, cfg.amount);
    }

    // ══════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Configure reward for an action type
     * @param action   The action to configure
     * @param amount   BitID per trigger (8 decimals)
     * @param cooldown Seconds between rewards for the same user
     * @param enabled  Enable/disable this reward
     */
    function setReward(Action action, uint256 amount, uint256 cooldown, bool enabled) external onlyOwner {
        rewards[action] = RewardConfig(amount, cooldown, enabled);
        emit RewardConfigured(action, amount, cooldown, enabled);
    }

    /**
     * @notice Authorize a protocol contract to call reward()
     * @param caller Contract address (e.g., FastPathIdentity, BNS, Gateway)
     */
    function setCaller(address caller, bool authorized) external onlyOwner {
        if (caller == address(0)) revert ZeroAddress();
        authorizedCallers[caller] = authorized;
        if (authorized) {
            emit CallerAuthorized(caller);
        } else {
            emit CallerRevoked(caller);
        }
    }

    /**
     * @notice Set epoch budget parameters
     * @dev ⚠️  WARNING: Calling this mid-epoch will reset epochMinted to 0, effectively granting
     *      a fresh full budget immediately. This is a significant admin lever that could strand
     *      rewards if called carelessly. Only adjust at natural epoch boundaries when possible.
     * @param budget   Max BitID mintable per epoch (8 decimals)
     * @param duration Epoch length in seconds
     */
    function setEpochBudget(uint256 budget, uint256 duration) external onlyOwner {
        epochBudget = budget;
        epochDuration = duration;
        // Reset epoch
        epochStart = block.timestamp;
        epochMinted = 0;
        emit EpochBudgetSet(budget, duration);
    }

    /**
     * @notice Toggle identity requirement for reward recipients
     */
    function setRequireIdentity(bool required) external onlyOwner {
        requireIdentity = required;
        emit IdentityRequirementToggled(required);
    }

    /**
     * @notice Update contract references
     */
    function setBitID(address _bitid) external onlyOwner {
        if (_bitid == address(0)) revert ZeroAddress();
        bitid = IBitID(_bitid);
    }

    function setIdentity(address _identity) external onlyOwner {
        if (_identity == address(0)) revert ZeroAddress();
        identity = IFastPathIdentity(_identity);
    }

    // ══════════════════════════════════════════════════════════════
    // VIEWS
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Check if a user can be rewarded for a specific action right now
     * @return canReward True if reward would succeed
     * @return reason    Human-readable reason if canReward is false
     */
    function canBeRewarded(address user, Action action) external view returns (bool canReward, string memory reason) {
        RewardConfig memory cfg = rewards[action];

        if (!cfg.enabled) return (false, "Action disabled");
        if (cfg.amount == 0) return (false, "No reward configured");

        if (requireIdentity && identity.evmToBtc(user) == bytes20(0)) {
            return (false, "No Proof160 identity");
        }

        uint256 last = lastRewarded[user][action];
        if (last != 0) {
            if (cfg.cooldown == type(uint256).max || block.timestamp < last + cfg.cooldown) {
                return (false, "Cooldown active");
            }
        }

        // Check epoch budget (approximate — doesn't roll epoch forward)
        uint256 currentMinted = epochMinted;
        if (block.timestamp >= epochStart + epochDuration) {
            currentMinted = 0; // Would reset on actual call
        }
        if (currentMinted + cfg.amount > epochBudget) {
            return (false, "Epoch budget exhausted");
        }

        return (true, "");
    }

    /**
     * @notice Remaining epoch budget
     */
    function epochRemaining() external view returns (uint256) {
        if (block.timestamp >= epochStart + epochDuration) return epochBudget;
        return epochBudget > epochMinted ? epochBudget - epochMinted : 0;
    }

    /**
     * @notice Seconds until user's cooldown expires for a given action
     * @return 0 if no cooldown is active, or type(uint256).max for one-time actions
     */
    function cooldownRemaining(address user, Action action) external view returns (uint256) {
        uint256 last = lastRewarded[user][action];
        if (last == 0) return 0;
        uint256 cooldown = rewards[action].cooldown;
        if (cooldown == type(uint256).max) return type(uint256).max; // Already used, always blocked
        uint256 expires = last + cooldown;
        return block.timestamp >= expires ? 0 : expires - block.timestamp;
    }

    // ══════════════════════════════════════════════════════════════
    // INTERNAL
    // ══════════════════════════════════════════════════════════════

    /// @dev Roll epoch forward if the current one has elapsed
    function _checkEpoch() internal {
        if (block.timestamp >= epochStart + epochDuration) {
            epochStart = block.timestamp;
            epochMinted = 0;
        }
    }
}
