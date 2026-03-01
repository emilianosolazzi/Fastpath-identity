// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./FastpathAttestationVerifier.sol";

/// @notice Chainlink-compatible price feed interface
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

interface IDemoUSD_V2 {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @title BTCBackedVaultV2
 * @notice Attested-collateral lending vault backed by Bitcoin balance proofs from FastPath API
 *
 * @dev TRUST MODEL:
 *      This is an attested collateral lending system. Collateral validity depends
 *      entirely on FastPath attestation integrity. The BTC is NOT locked or bridged;
 *      the system relies on the FastPath signer truthfully reporting balances.
 *
 *      If the FastPath signer is compromised, misreports balances, or goes offline,
 *      the vault's security guarantees degrade. Users and integrators must understand
 *      this trust assumption.
 *
 *      This is NOT: non-custodial BTC locking, SPV-verified collateral, or trustless bridging.
 *      This IS: attested collateral lending — a legitimate but trust-dependent design.
 *
 * Flow:
 *   1. User calls FastPath API:
 *      POST https://api.nativebtc.org/v1/attest/balance
 *      Body: { evmAddress: "0x...", btcAddress: "bc1q...", chainId: 1 }
 *
 *   2. API checks on-chain BTC balance, returns signed attestation:
 *      { signature: "0x...", message: { balanceSats: 150000000, timestamp, nonce } }
 *
 *   3. User calls attestBalance() with the attestation data
 *
 *   4. Contract verifies the signature came from the trusted FastPath signer
 *      and credits the user's position based on their REAL Bitcoin holdings
 *
 *   5. User borrows against attested balance (freshness enforced)
 *
 *   6. If health factor drops below 100, anyone can liquidate the position
 *
 * Example: User has 1.5 BTC (150,000,000 sats)
 *   → At $90,000/BTC, collateral value = $135,000
 *   → 50% LTV → can borrow up to 67,500 dUSD
 */
contract BTCBackedVaultV2 is Ownable, ReentrancyGuard {
    // ── Dependencies ───────────────────────────────────────────
    FastpathAttestationVerifier public immutable verifier;
    IDemoUSD_V2 public demoUSD;

    // ── Parameters ─────────────────────────────────────────────
    uint256 public constant LTV_BPS = 5000; // 50% LTV
    uint256 public constant BPS_DENOMINATOR = 10000;
    uint256 public constant SATS_PER_BTC = 1e8;

    /// @notice Maximum age (seconds) an attestation can be for borrowing
    /// @dev Prevents borrowing against stale balance proofs (e.g., user moved BTC after attesting)
    uint256 public constant MAX_ATTEST_AGE = 1 hours;

    /// @notice Liquidation incentive in basis points (5% bonus to liquidator)
    uint256 public constant LIQUIDATION_BONUS_BPS = 500;

    /// @notice Health factor threshold below which a position can be liquidated (100 = 1:1)
    uint256 public constant LIQUIDATION_THRESHOLD = 100;

    /// @notice BTC price in USD (scaled by 1e8 for precision)
    /// @dev Set to address(0) to use manual price; set to Chainlink feed for production
    AggregatorV3Interface public priceFeed;

    /// @notice Fallback manual BTC price (used when priceFeed is not set)
    uint256 public btcPriceUsdManual = 90_000 * 1e8; // $90,000.00000000

    // ── Positions ──────────────────────────────────────────────

    struct Position {
        uint256 btcBalanceSats; // Attested Bitcoin balance (satoshis)
        string btcAddress; // The Bitcoin address
        uint256 borrowedUSD; // DemoUSD borrowed (18 decimals)
        uint256 lastAttestTime; // When balance was last attested
    }

    mapping(address => Position) public positions;

    // ── Stats ──────────────────────────────────────────────────
    uint256 public totalBtcCollateralSats;
    uint256 public totalBorrowed;
    uint256 public totalUsers;

    // ── Events ─────────────────────────────────────────────────
    event BalanceAttested(address indexed user, string btcAddress, uint256 balanceSats);
    event Borrowed(address indexed user, uint256 amount, uint256 btcCollateralSats);
    event Repaid(address indexed user, uint256 amount);
    event Liquidated(address indexed user, address indexed liquidator, uint256 debtRepaid, uint256 collateralSeized);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);
    event PriceFeedUpdated(address indexed oldFeed, address indexed newFeed);

    // ── Errors ─────────────────────────────────────────────────
    error NoAttestation();
    error ExceedsLTV();
    error RepaymentExceedsDebt();
    error AttestationTooOld();
    error PositionHealthy();
    error InvalidPriceFeed();
    error NothingToLiquidate();

    // ── Constructor ────────────────────────────────────────────

    /// @param _verifier Address of deployed FastpathAttestationVerifier
    constructor(address _verifier) Ownable(msg.sender) {
        verifier = FastpathAttestationVerifier(_verifier);
    }

    function setDemoUSD(address _demoUSD) external onlyOwner {
        demoUSD = IDemoUSD_V2(_demoUSD);
    }

    /// @notice Set Chainlink BTC/USD price feed (set to address(0) to use manual price)
    function setPriceFeed(address _priceFeed) external onlyOwner {
        emit PriceFeedUpdated(address(priceFeed), _priceFeed);
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    /// @notice Update manual BTC price (only used when priceFeed is not set)
    function updateBtcPrice(uint256 _priceUsd8Decimals) external onlyOwner {
        emit PriceUpdated(btcPriceUsdManual, _priceUsd8Decimals);
        btcPriceUsdManual = _priceUsd8Decimals;
    }

    /// @notice Get the current BTC price in USD (8 decimals)
    /// @dev Uses Chainlink if configured, otherwise falls back to manual price
    function btcPriceUsd() public view returns (uint256) {
        if (address(priceFeed) != address(0)) {
            (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
            if (price <= 0) revert InvalidPriceFeed();
            // Chainlink staleness check (1 hour)
            if (block.timestamp - updatedAt > 1 hours) revert InvalidPriceFeed();
            return uint256(price);
        }
        return btcPriceUsdManual;
    }

    // ── Core Functions ─────────────────────────────────────────

    /**
     * @notice Submit a Bitcoin balance proof from FastPath API
     * @dev This verifies the EIP-712 signature and records the user's BTC balance.
     *      Users can then borrow against this balance.
     *
     * @param btcAddress   The Bitcoin address whose balance was attested
     * @param balanceSats  Balance in satoshis (from API response)
     * @param timestamp    Attestation timestamp (from API response)
     * @param nonce        Attestation nonce (from API response)
     * @param signature    EIP-712 signature (from API response)
     */
    function attestBalance(
        string calldata btcAddress,
        uint256 balanceSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        // The verifier checks: signature, expiry, nonce, and that evmAddress == msg.sender
        verifier.verifyBalance(msg.sender, btcAddress, balanceSats, timestamp, nonce, signature);

        Position storage pos = positions[msg.sender];

        if (pos.btcBalanceSats == 0 && balanceSats > 0) {
            totalUsers++;
        }

        // Update collateral tracking
        totalBtcCollateralSats = totalBtcCollateralSats - pos.btcBalanceSats + balanceSats;

        pos.btcBalanceSats = balanceSats;
        pos.btcAddress = btcAddress;
        pos.lastAttestTime = timestamp;

        emit BalanceAttested(msg.sender, btcAddress, balanceSats);
    }

    /**
     * @notice Borrow DemoUSD against attested Bitcoin balance
     * @param amount Amount of DemoUSD to borrow (18 decimals)
     *
     * Example with 1.5 BTC at $90,000:
     *   balanceSats = 150_000_000
     *   collateralValueUsd = 150_000_000 * 90_000e8 / 1e8 = 13_500_000e18 ($135,000)
     *   maxBorrow = 13_500_000e18 * 5000 / 10000 = 6_750_000e18 ($67,500)
     */
    function borrow(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        if (pos.btcBalanceSats == 0) revert NoAttestation();

        // ── Freshness enforcement ──────────────────────────────
        // Prevents borrowing against stale attestations.
        // Without this, a user could attest 2 BTC, move it, wait, and borrow against nothing.
        if (block.timestamp - pos.lastAttestTime > MAX_ATTEST_AGE) {
            revert AttestationTooOld();
        }

        uint256 maxBorrow = _maxBorrow(pos.btcBalanceSats);
        if (pos.borrowedUSD + amount > maxBorrow) revert ExceedsLTV();

        pos.borrowedUSD += amount;
        totalBorrowed += amount;

        demoUSD.mint(msg.sender, amount);

        emit Borrowed(msg.sender, amount, pos.btcBalanceSats);
    }

    /**
     * @notice Repay borrowed DemoUSD
     * @param amount Amount to repay (18 decimals)
     */
    function repay(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        if (amount > pos.borrowedUSD) revert RepaymentExceedsDebt();

        pos.borrowedUSD -= amount;
        totalBorrowed -= amount;

        demoUSD.burn(msg.sender, amount);

        emit Repaid(msg.sender, amount);
    }

    // ── Liquidation ────────────────────────────────────────────

    /**
     * @notice Liquidate an undercollateralized position
     * @dev Anyone can call this when a position's health factor drops below 100.
     *      The liquidator repays the borrower's debt and receives a 5% bonus
     *      in collateral credit (the collateral is attested BTC, so the "seizing"
     *      reduces the borrower's recorded balance and credits the liquidator).
     *
     *      Stale attestations (older than MAX_ATTEST_AGE) also make a position
     *      liquidatable — this penalizes users who fail to re-attest.
     *
     * @param borrower The address of the position to liquidate
     * @param repayAmount The amount of dUSD the liquidator will repay
     */
    function liquidate(address borrower, uint256 repayAmount) external nonReentrant {
        Position storage pos = positions[borrower];
        if (pos.borrowedUSD == 0) revert NothingToLiquidate();

        uint256 maxBorrow = _maxBorrow(pos.btcBalanceSats);
        bool isStale = (block.timestamp - pos.lastAttestTime > MAX_ATTEST_AGE);

        // Position must be unhealthy OR attestation must be stale
        uint256 healthFactor = pos.borrowedUSD > 0 ? (maxBorrow * 100) / pos.borrowedUSD : type(uint256).max;

        if (healthFactor >= LIQUIDATION_THRESHOLD && !isStale) revert PositionHealthy();
        if (repayAmount > pos.borrowedUSD) repayAmount = pos.borrowedUSD;

        // Calculate collateral to seize (in sats) with liquidation bonus
        // collateralSats = (repayAmount * SATS_PER_BTC * (10000 + bonus)) / (btcPriceUsd() * 10000)
        uint256 currentPrice = btcPriceUsd();
        uint256 collateralSats =
            (repayAmount * SATS_PER_BTC * (BPS_DENOMINATOR + LIQUIDATION_BONUS_BPS)) / (currentPrice * BPS_DENOMINATOR);

        // Cap seizure at available collateral
        if (collateralSats > pos.btcBalanceSats) {
            collateralSats = pos.btcBalanceSats;
        }

        // Update borrower position
        pos.borrowedUSD -= repayAmount;
        pos.btcBalanceSats -= collateralSats;
        totalBorrowed -= repayAmount;
        totalBtcCollateralSats -= collateralSats;

        // Liquidator pays the debt by burning their dUSD
        demoUSD.burn(msg.sender, repayAmount);

        emit Liquidated(borrower, msg.sender, repayAmount, collateralSats);
    }

    // ── View Functions ─────────────────────────────────────────

    /**
     * @notice Get full position details
     */
    function getPosition(address user)
        external
        view
        returns (
            uint256 btcBalanceSats,
            string memory btcAddress,
            uint256 borrowedUSD,
            uint256 maxBorrowUSD,
            uint256 healthFactor,
            uint256 lastAttestTime,
            bool isLiquidatable
        )
    {
        Position memory pos = positions[user];
        btcBalanceSats = pos.btcBalanceSats;
        btcAddress = pos.btcAddress;
        borrowedUSD = pos.borrowedUSD;
        maxBorrowUSD = _maxBorrow(pos.btcBalanceSats);
        lastAttestTime = pos.lastAttestTime;

        if (pos.borrowedUSD > 0) {
            healthFactor = (maxBorrowUSD * 100) / pos.borrowedUSD;
        } else {
            healthFactor = type(uint256).max;
        }

        // Position is liquidatable if health is below threshold OR attestation is stale
        bool isStale = (block.timestamp - pos.lastAttestTime > MAX_ATTEST_AGE);
        isLiquidatable = pos.borrowedUSD > 0 && (healthFactor < LIQUIDATION_THRESHOLD || isStale);
    }

    /**
     * @notice Get vault statistics
     */
    function getStats()
        external
        view
        returns (uint256 _totalBtcSats, uint256 _totalBorrowed, uint256 _totalUsers, uint256 _btcPriceUsd)
    {
        return (totalBtcCollateralSats, totalBorrowed, totalUsers, btcPriceUsd());
    }

    /**
     * @notice Get the trusted signer address (from the verifier)
     */
    function getTrustedSigner() external view returns (address) {
        return verifier.trustedSigner();
    }

    // ── Internal ───────────────────────────────────────────────

    function _maxBorrow(uint256 sats) internal view returns (uint256) {
        // collateralValueUsd (18 decimals) = sats * btcPriceUsd / SATS_PER_BTC
        uint256 collateralValueUsd = (sats * btcPriceUsd()) / SATS_PER_BTC;
        return (collateralValueUsd * LTV_BPS) / BPS_DENOMINATOR;
    }
}

