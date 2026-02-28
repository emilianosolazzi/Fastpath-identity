// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./FastpathAttestationVerifier.sol";

interface IDemoUSD_V2 {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title BTCBackedVaultV2
 * @notice Lending vault backed by REAL Bitcoin balance proofs from FastPath API
 * @dev Unlike V1 (which only required identity registration), V2 verifies
 *      actual Bitcoin balance via signed attestations from api.nativebtc.org.
 *
 * Flow:
 *   1. User calls FastPath API:
 *      POST https://api.nativebtc.org/v1/attest/balance
 *      Body: { evmAddress: "0x...", btcAddress: "bc1q...", chainId: 1 }
 *
 *   2. API checks on-chain BTC balance, returns signed attestation:
 *      { signature: "0x...", message: { balanceSats: 150000000, timestamp, nonce } }
 *
 *   3. User calls depositWithProof() with the attestation data
 *
 *   4. Contract verifies the signature came from the trusted FastPath signer
 *      and credits the user's position based on their REAL Bitcoin holdings
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
    uint256 public constant LTV_BPS = 5000;           // 50% LTV
    uint256 public constant BPS_DENOMINATOR = 10000;
    uint256 public constant SATS_PER_BTC = 1e8;

    /// @notice BTC price in USD (scaled by 1e8 for precision)
    /// @dev In production, use a Chainlink price feed. For demo: $90,000
    uint256 public btcPriceUsd = 90_000 * 1e8;        // $90,000.00000000

    // ── Positions ──────────────────────────────────────────────

    struct Position {
        uint256 btcBalanceSats;    // Attested Bitcoin balance (satoshis)
        string  btcAddress;        // The Bitcoin address
        uint256 borrowedUSD;       // DemoUSD borrowed (18 decimals)
        uint256 lastAttestTime;    // When balance was last attested
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
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    // ── Errors ─────────────────────────────────────────────────
    error NoAttestation();
    error ExceedsLTV();
    error RepaymentExceedsDebt();
    error AttestationTooOld();

    // ── Constructor ────────────────────────────────────────────

    /// @param _verifier Address of deployed FastpathAttestationVerifier
    constructor(address _verifier) Ownable(msg.sender) {
        verifier = FastpathAttestationVerifier(_verifier);
    }

    function setDemoUSD(address _demoUSD) external onlyOwner {
        demoUSD = IDemoUSD_V2(_demoUSD);
    }

    /// @notice Update BTC price (owner-only for demo; use Chainlink in production)
    function updateBtcPrice(uint256 _priceUsd8Decimals) external onlyOwner {
        emit PriceUpdated(btcPriceUsd, _priceUsd8Decimals);
        btcPriceUsd = _priceUsd8Decimals;
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
        verifier.verifyBalance(
            msg.sender,
            btcAddress,
            balanceSats,
            timestamp,
            nonce,
            signature
        );

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

    // ── View Functions ─────────────────────────────────────────

    /**
     * @notice Get full position details
     */
    function getPosition(address user) external view returns (
        uint256 btcBalanceSats,
        string memory btcAddress,
        uint256 borrowedUSD,
        uint256 maxBorrowUSD,
        uint256 healthFactor,
        uint256 lastAttestTime
    ) {
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
    }

    /**
     * @notice Get vault statistics
     */
    function getStats() external view returns (
        uint256 _totalBtcSats,
        uint256 _totalBorrowed,
        uint256 _totalUsers,
        uint256 _btcPriceUsd
    ) {
        return (totalBtcCollateralSats, totalBorrowed, totalUsers, btcPriceUsd);
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
        uint256 collateralValueUsd = (sats * btcPriceUsd) / SATS_PER_BTC;
        return (collateralValueUsd * LTV_BPS) / BPS_DENOMINATOR;
    }
}

