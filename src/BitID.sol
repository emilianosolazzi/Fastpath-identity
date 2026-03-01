// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IFastPathIdentity {
    function currentController(bytes20 btcHash160) external view returns (address);
    function evmToBtc(address evm) external view returns (bytes20);
}

/**
 * @title BitID — Identity Token for the FastPath / Proof160 Protocol
 * @author Emiliano Solazzi — 2026
 * @notice Utility token for the Bitcoin identity layer. Minted by authorized
 *         protocol contracts (vaults, gateways, reward distributors) and
 *         gated by on-chain Bitcoin identity verification.
 *
 * @dev Architecture:
 *      - ERC-20 + EIP-2612 Permit (gasless approvals)
 *      - Multi-minter model: owner can authorize multiple protocol contracts
 *      - Hard supply cap: 160,000,000 BITID (8 decimals, mirrors BTC precision)
 *      - Identity-gated transfers: optional mode requiring Proof160 registration
 *
 *      Token economics:
 *        - Minted as protocol rewards (identity registration, BNS activity, relay fees)
 *        - Burned on premium operations (name registration, governance staking)
 *        - Cap ensures scarcity; multi-minter ensures composability
 *
 *      Why 8 decimals:
 *        Bitcoin uses 8 decimal places (1 BTC = 100,000,000 satoshis).
 *        BitID mirrors this for intuitive cross-chain UX.
 */
contract BitID is ERC20, ERC20Permit, Ownable {
    // ══════════════════════════════════════════════════════════════
    // ERRORS
    // ══════════════════════════════════════════════════════════════

    error NotMinter();
    error ZeroAddress();
    error SupplyCapExceeded();
    error IdentityRequired();
    error ControllerMismatch();
    error AlreadyMinter();
    error NotActiveMinter();
    error OwnerMintCapExceeded();
    error AlreadyWhitelisted();
    error NotWhitelisted();
    error IdentityLocked();
    error NotContract();

    // ══════════════════════════════════════════════════════════════
    // CONSTANTS
    // ══════════════════════════════════════════════════════════════

    /// @notice Maximum supply: 160,000,000 BITID (8 decimals)
    /// @dev 160M chosen to echo Hash160 — the cryptographic primitive at the core of the protocol.
    uint256 public constant MAX_SUPPLY = 160_000_000 * 1e8;

    /// @notice Maximum owner-mintable: 16,000,000 BITID (10% of cap)
    /// @dev Limits founder/treasury allocation. Remaining 90% minted via reward distributor.
    uint256 public constant OWNER_MINT_CAP = 16_000_000 * 1e8;

    // ══════════════════════════════════════════════════════════════
    // STATE
    // ══════════════════════════════════════════════════════════════

    /// @notice FastPathIdentity contract for on-chain identity checks
    IFastPathIdentity public identity;

    /// @notice Authorized minters (vaults, gateways, reward contracts)
    mapping(address => bool) public minters;

    /// @notice When true, transfers require both sender and receiver to have a Proof160 identity
    bool public identityGated;

    /// @notice When true, identity gating also verifies active controller (not just historical registration)
    bool public verifyController;

    /// @notice Whitelisted contracts exempt from identity gating (DEXs, routers, pools)
    mapping(address => bool) public transferWhitelist;

    /// @notice Running total of owner-minted tokens (capped at OWNER_MINT_CAP)
    uint256 public ownerMinted;

    /// @notice Once true, identity contract reference can never be changed
    bool public identityLocked;

    /// @notice Number of currently authorized minters
    uint256 public minterCount;

    // ══════════════════════════════════════════════════════════════
    // EVENTS
    // ══════════════════════════════════════════════════════════════

    event MinterAdded(address indexed minter);
    event MinterRemoved(address indexed minter);
    event IdentityUpdated(address indexed newIdentity);
    event IdentityGateToggled(bool enabled, address indexed toggler);
    event ControllerVerificationToggled(bool enabled, address indexed toggler);
    event TransferWhitelistUpdated(address indexed addr, bool whitelisted);
    event IdentityPermanentlyLocked(address indexed identity, address indexed locker);
    event Minted(address indexed to, uint256 amount, address indexed minter);
    event Burned(address indexed from, uint256 amount);
    event BurnedFrom(address indexed from, uint256 amount, address indexed spender);

    // ══════════════════════════════════════════════════════════════
    // MODIFIERS
    // ══════════════════════════════════════════════════════════════

    modifier onlyMinter() {
        if (!minters[msg.sender]) revert NotMinter();
        _;
    }

    // ══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════

    /**
     * @param _identity Address of the deployed FastPathIdentity (Proof160) contract
     */
    constructor(address _identity) ERC20("BitID", "BITID") ERC20Permit("BitID") Ownable(msg.sender) {
        if (_identity == address(0)) revert ZeroAddress();
        identity = IFastPathIdentity(_identity);
        emit IdentityUpdated(_identity);
    }

    // ══════════════════════════════════════════════════════════════
    // ERC-20 OVERRIDES
    // ══════════════════════════════════════════════════════════════

    /// @notice 8 decimals to mirror Bitcoin's satoshi precision
    function decimals() public pure override returns (uint8) {
        return 8;
    }

    /**
     * @dev Hook that enforces identity gating on transfers when enabled.
     *      Minting (from == address(0)) and burning (to == address(0)) are always allowed.
     *      Whitelisted contracts (DEXs, routers) are exempt.
     *      Contracts (code.length > 0) are exempt unless verifyController is on.
     *      When verifyController is enabled, also checks that the address is the
     *      current active controller of its registered Hash160 identity.
     */
    function _update(address from, address to, uint256 amount) internal override {
        if (identityGated) {
            // Skip check for mints and burns
            if (from != address(0) && to != address(0)) {
                _checkIdentity(from);
                _checkIdentity(to);
            }
        }
        super._update(from, to, amount);
    }

    /**
     * @dev Validate that an address passes identity gating. Reverts if not.
     *      Uses _validateIdentity internally to share logic with isIdentityValid().
     */
    function _checkIdentity(address addr) internal view {
        (bool valid, IdentityFailure failure,) = _validateIdentity(addr);
        if (!valid) {
            if (failure == IdentityFailure.WrongController) revert ControllerMismatch();
            revert IdentityRequired();
        }
    }

    /// @dev Identity validation failure reason — typed, not string-based
    enum IdentityFailure {
        None,
        NotRegistered,
        WrongController
    }

    /**
     * @dev Shared identity validation logic used by both _checkIdentity (reverts)
     *      and isIdentityValid (returns). Single source of truth — no drift bugs.
     * @return valid True if address passes all identity checks
     * @return failure Typed failure reason (None if valid)
     * @return reason Human-readable reason for off-chain consumers
     */
    function _validateIdentity(address addr)
        private
        view
        returns (bool valid, IdentityFailure failure, string memory reason)
    {
        // Whitelisted addresses always pass (DEXs, routers, pools)
        if (transferWhitelist[addr]) return (true, IdentityFailure.None, "");

        // Contracts are exempt from identity checks (DEX compatibility)
        // unless verifyController is explicitly enabled
        if (addr.code.length > 0 && !verifyController) return (true, IdentityFailure.None, "Contract exempt");

        // Must have a registered Proof160 identity
        bytes20 btc = identity.evmToBtc(addr);
        if (btc == bytes20(0)) return (false, IdentityFailure.NotRegistered, "No Proof160 identity");

        // Optionally verify active controller (not just historical registration)
        if (verifyController) {
            if (identity.currentController(btc) != addr) {
                return (false, IdentityFailure.WrongController, "Not active controller");
            }
        }
        return (true, IdentityFailure.None, "");
    }

    // ══════════════════════════════════════════════════════════════
    // MINTING & BURNING
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Mint BITID to a recipient (only authorized minters)
     * @param to Recipient address
     * @param amount Amount to mint (8 decimals)
     */
    function mint(address to, uint256 amount) external onlyMinter {
        if (to == address(0)) revert ZeroAddress();
        if (totalSupply() + amount > MAX_SUPPLY) revert SupplyCapExceeded();
        _mint(to, amount);
        emit Minted(to, amount, msg.sender);
    }

    /**
     * @notice Owner direct mint — for treasury allocation, testing, or bootstrapping
     * @dev Capped at OWNER_MINT_CAP (10% of MAX_SUPPLY) to maintain credible neutrality.
     *      Remaining 90% of supply is reserved for reward distributor minting.
     *      NOTE: Minting bypasses identity gating by design (from == address(0) in _update).
     *      This allows bootstrapping balances for unregistered addresses even in strict mode.
     * @param to Recipient address (can be msg.sender for self-mint)
     * @param amount Amount to mint (8 decimals)
     */
    function ownerMint(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (ownerMinted + amount > OWNER_MINT_CAP) revert OwnerMintCapExceeded();
        if (totalSupply() + amount > MAX_SUPPLY) revert SupplyCapExceeded();
        ownerMinted += amount;
        _mint(to, amount);
        emit Minted(to, amount, msg.sender);
    }

    /**
     * @notice Burn BITID from caller's balance
     * @param amount Amount to burn (8 decimals)
     */
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
        emit Burned(msg.sender, amount);
    }

    /**
     * @notice Burn BITID from an account (requires allowance)
     * @param from Address to burn from
     * @param amount Amount to burn
     */
    function burnFrom(address from, uint256 amount) external {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
        emit BurnedFrom(from, amount, msg.sender);
    }

    // ══════════════════════════════════════════════════════════════
    // MINTER MANAGEMENT
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Authorize a protocol contract to mint BITID
     * @param minter Address of the vault, gateway, or reward contract
     */
    function addMinter(address minter) external onlyOwner {
        if (minter == address(0)) revert ZeroAddress();
        if (minters[minter]) revert AlreadyMinter();
        minters[minter] = true;
        minterCount++;
        emit MinterAdded(minter);
    }

    /**
     * @notice Revoke minting rights from a contract
     * @param minter Address to remove
     */
    function removeMinter(address minter) external onlyOwner {
        if (minter == address(0)) revert ZeroAddress();
        if (!minters[minter]) revert NotActiveMinter();
        minters[minter] = false;
        minterCount--;
        emit MinterRemoved(minter);
    }

    // ══════════════════════════════════════════════════════════════
    // ADMIN
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Update the FastPathIdentity contract reference
     * @dev Reverts if identity has been permanently locked via lockIdentity().
     * @param _identity New identity contract address
     */
    function setIdentity(address _identity) external onlyOwner {
        if (identityLocked) revert IdentityLocked();
        if (_identity == address(0)) revert ZeroAddress();
        identity = IFastPathIdentity(_identity);
        emit IdentityUpdated(_identity);
    }

    /**
     * @notice Permanently lock the identity contract reference — ONE WAY, IRREVERSIBLE
     * @dev After calling this, setIdentity() will always revert.
     *      Use this once you're confident the identity contract is final.
     *      This eliminates the largest centralization lever in the token.
     */
    function lockIdentity() external onlyOwner {
        if (identityLocked) revert IdentityLocked();
        identityLocked = true;
        emit IdentityPermanentlyLocked(address(identity), msg.sender);
    }

    /**
     * @notice Toggle identity-gated transfers
     * @dev When enabled, EOA senders and receivers must have a registered Proof160 identity.
     *      Minting, burning, and whitelisted/contract addresses are exempt.
     * @param enabled True to require identity for transfers
     */
    function setIdentityGated(bool enabled) external onlyOwner {
        identityGated = enabled;
        emit IdentityGateToggled(enabled, msg.sender);
    }

    /**
     * @notice Toggle active controller verification
     * @dev ⚠️  STRICT MODE WARNING: When enabled alongside identityGated, EVERY address
     *      (including contracts) must have an active Proof160 identity AND be the current
     *      controller — unless explicitly whitelisted. This effectively makes BITID a
     *      fully permissioned token. DEX pairs, routers, and aggregators MUST be
     *      whitelisted before enabling this, or all DeFi transfers will revert.
     * @param enabled True to verify active controller on transfers
     */
    function setVerifyController(bool enabled) external onlyOwner {
        verifyController = enabled;
        emit ControllerVerificationToggled(enabled, msg.sender);
    }

    /**
     * @notice Whitelist or de-whitelist a contract for identity-gated transfers
     * @dev Only contract addresses (code.length > 0) can be whitelisted.
     *      Use this for DEX pairs, routers, aggregators that can't have Proof160 identities.
     * @param addr Contract address to whitelist
     * @param whitelisted True to exempt from identity checks
     */
    function setTransferWhitelist(address addr, bool whitelisted) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        if (addr.code.length == 0) revert NotContract();
        if (whitelisted && transferWhitelist[addr]) revert AlreadyWhitelisted();
        if (!whitelisted && !transferWhitelist[addr]) revert NotWhitelisted();
        transferWhitelist[addr] = whitelisted;
        emit TransferWhitelistUpdated(addr, whitelisted);
    }

    // ══════════════════════════════════════════════════════════════
    // VIEWS
    // ══════════════════════════════════════════════════════════════

    /**
     * @notice Check if an address would pass the identity gate right now
     * @dev Shares validation logic with _checkIdentity via _validateIdentity() — no drift.
     * @param addr Address to check
     * @return valid True if the address can send/receive when identity gating is on
     * @return reason Human-readable reason if invalid
     */
    function isIdentityValid(address addr) external view returns (bool valid, string memory reason) {
        (bool v,, string memory r) = _validateIdentity(addr);
        return (v, r);
    }

    /**
     * @notice Remaining tokens that can be minted before hitting the cap
     * @return remaining Mintable supply in base units (8 decimals)
     */
    function mintableSupply() external view returns (uint256 remaining) {
        uint256 current = totalSupply();
        return current >= MAX_SUPPLY ? 0 : MAX_SUPPLY - current;
    }

    /**
     * @notice Remaining owner-mintable tokens before hitting the 10% cap
     * @return remaining Owner mint budget left
     */
    function ownerMintableRemaining() external view returns (uint256 remaining) {
        return ownerMinted >= OWNER_MINT_CAP ? 0 : OWNER_MINT_CAP - ownerMinted;
    }

    /**
     * @notice Remaining supply available to protocol minters (excludes owner's budget)
     * @dev More accurate than mintableSupply() for protocol contracts estimating headroom.
     *      Formula: MAX_SUPPLY - totalSupply() - (OWNER_MINT_CAP - ownerMinted)
     * @return remaining Protocol-mintable supply in base units (8 decimals)
     */
    function protocolMintableSupply() external view returns (uint256 remaining) {
        uint256 total = totalSupply();
        uint256 ownerBudgetLeft = ownerMinted >= OWNER_MINT_CAP ? 0 : OWNER_MINT_CAP - ownerMinted;
        uint256 globalLeft = total >= MAX_SUPPLY ? 0 : MAX_SUPPLY - total;
        return globalLeft > ownerBudgetLeft ? globalLeft - ownerBudgetLeft : 0;
    }

    /**
     * @notice Full token info in a single call
     */
    function getInfo()
        external
        view
        returns (
            string memory name_,
            string memory symbol_,
            uint8 decimals_,
            uint256 totalSupply_,
            uint256 maxSupply_,
            uint256 mintable_,
            bool identityGated_,
            address identity_
        )
    {
        uint256 current = totalSupply();
        return (
            name(),
            symbol(),
            decimals(),
            current,
            MAX_SUPPLY,
            current >= MAX_SUPPLY ? 0 : MAX_SUPPLY - current,
            identityGated,
            address(identity)
        );
    }
}
