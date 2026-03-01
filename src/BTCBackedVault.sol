// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IFastPathIdentity {
    function evmToBtc(address evm) external view returns (bytes20);
}

interface IDemoUSD {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title BTCBackedVault
 * @notice Demo lending vault that requires Bitcoin identity registration
 * @dev Users must have a registered Hash160 in FastPathIdentity to borrow
 *
 * Flow:
 * 1. User registers Bitcoin identity via FastPathIdentity
 * 2. User deposits ETH as collateral
 * 3. User can borrow DemoUSD up to 50% LTV
 * 4. User repays to unlock collateral
 */
contract BTCBackedVault is Ownable, ReentrancyGuard {
    IFastPathIdentity public immutable identityContract;
    IDemoUSD public demoUSD;

    // 50% LTV (borrow up to half of collateral value)
    uint256 public constant LTV_BPS = 5000; // 50% in basis points
    uint256 public constant BPS_DENOMINATOR = 10000;

    // Demo showcase address (pre-registered Bitcoin identity)
    address public constant DEMO_ADDRESS = 0x62393949CEe0531DAd16f2863A58C75B45753D61;
    bytes20 public constant DEMO_HASH160 = bytes20(0x36Ef5Cff87cf31B1211d3482f6Fda7eE94C3D5db);

    // Secondary demo/showcase address (user-provided identity)
    address public showcaseAddress;
    bytes20 public showcaseHash160;
    string public showcaseBtcAddress;

    struct Position {
        uint256 collateralETH; // ETH deposited
        uint256 borrowedUSD; // DemoUSD borrowed
        bytes20 btcHash160; // Linked Bitcoin identity
    }

    mapping(address => Position) public positions;

    // Stats
    uint256 public totalCollateral;
    uint256 public totalBorrowed;
    uint256 public totalUsers;

    // Events
    event Deposited(address indexed user, uint256 amount, bytes20 btcHash160);
    event Borrowed(address indexed user, uint256 amount);
    event Repaid(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Liquidated(address indexed user, address indexed liquidator, uint256 debtRepaid, uint256 collateralSeized);

    // Errors
    error NotRegistered();
    error InsufficientCollateral();
    error ExceedsLTV();
    error NothingToWithdraw();
    error RepaymentExceedsDebt();
    error TransferFailed();
    error PositionHealthy();
    error InsufficientLiquidatorBalance();

    constructor(address _identityContract) Ownable(msg.sender) {
        identityContract = IFastPathIdentity(_identityContract);
    }

    function setDemoUSD(address _demoUSD) external onlyOwner {
        demoUSD = IDemoUSD(_demoUSD);
    }

    /**
     * @notice Set a showcase/secondary demo address with its Bitcoin identity
     * @dev Owner can set any address as showcase to demonstrate the vault
     */
    function setShowcaseIdentity(address _evmAddr, bytes20 _hash160, string calldata _btcAddr) external onlyOwner {
        showcaseAddress = _evmAddr;
        showcaseHash160 = _hash160;
        showcaseBtcAddress = _btcAddr;
    }

    /**
     * @notice Check if an address has a registered Bitcoin identity
     */
    function isRegistered(address user) public view returns (bool) {
        bytes20 hash160 = identityContract.evmToBtc(user);
        return hash160 != bytes20(0);
    }

    /**
     * @notice Get the Bitcoin Hash160 for an address
     */
    function getBtcIdentity(address user) public view returns (bytes20) {
        return identityContract.evmToBtc(user);
    }

    /**
     * @notice Deposit ETH as collateral (requires Bitcoin identity)
     */
    function deposit() external payable nonReentrant {
        bytes20 hash160 = identityContract.evmToBtc(msg.sender);
        if (hash160 == bytes20(0)) revert NotRegistered();

        if (positions[msg.sender].collateralETH == 0) {
            totalUsers++;
        }

        positions[msg.sender].collateralETH += msg.value;
        positions[msg.sender].btcHash160 = hash160;
        totalCollateral += msg.value;

        emit Deposited(msg.sender, msg.value, hash160);
    }

    /**
     * @notice Borrow DemoUSD against collateral
     * @param amount Amount of DemoUSD to borrow (18 decimals)
     */
    function borrow(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        if (pos.btcHash160 == bytes20(0)) revert NotRegistered();

        // Calculate max borrow (50% of collateral in USD terms)
        // Simplified: 1 ETH = 2000 USD for demo purposes
        uint256 collateralValueUSD = (pos.collateralETH * 2000 * 1e18) / 1e18;
        uint256 maxBorrow = (collateralValueUSD * LTV_BPS) / BPS_DENOMINATOR;

        if (pos.borrowedUSD + amount > maxBorrow) revert ExceedsLTV();

        pos.borrowedUSD += amount;
        totalBorrowed += amount;

        demoUSD.mint(msg.sender, amount);

        emit Borrowed(msg.sender, amount);
    }

    /**
     * @notice Repay borrowed DemoUSD
     * @param amount Amount to repay
     */
    function repay(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        if (amount > pos.borrowedUSD) revert RepaymentExceedsDebt();

        pos.borrowedUSD -= amount;
        totalBorrowed -= amount;

        demoUSD.burn(msg.sender, amount);

        emit Repaid(msg.sender, amount);
    }

    /**
     * @notice Withdraw collateral (must maintain LTV)
     * @param amount Amount of ETH to withdraw
     */
    function withdraw(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        if (amount > pos.collateralETH) revert InsufficientCollateral();

        // Check LTV after withdrawal
        uint256 remainingCollateral = pos.collateralETH - amount;
        uint256 remainingValueUSD = (remainingCollateral * 2000 * 1e18) / 1e18;
        uint256 maxBorrow = (remainingValueUSD * LTV_BPS) / BPS_DENOMINATOR;

        if (pos.borrowedUSD > maxBorrow) revert ExceedsLTV();

        pos.collateralETH -= amount;
        totalCollateral -= amount;

        if (pos.collateralETH == 0 && pos.borrowedUSD == 0) {
            totalUsers--;
        }

        (bool success,) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice Liquidate an unhealthy position (health factor < 100)
     * @dev Liquidator repays user's debt and receives 50% of their collateral as bonus
     * @param user Address of the position to liquidate
     *
     * Example: User has 1 ETH collateral, borrowed 1500 dUSD
     * - Max borrow at 50% LTV = 1000 dUSD (1 ETH * $2000 * 50%)
     * - Health factor = 1000 * 100 / 1500 = 66 (unhealthy!)
     * - Liquidator pays 1500 dUSD, receives 0.5 ETH (~$1000 value)
     */
    function liquidate(address user) external nonReentrant {
        Position storage pos = positions[user];

        // Calculate health factor
        uint256 collateralValueUSD = (pos.collateralETH * 2000 * 1e18) / 1e18;
        uint256 maxBorrowUSD = (collateralValueUSD * LTV_BPS) / BPS_DENOMINATOR;

        uint256 healthFactor;
        if (pos.borrowedUSD > 0) {
            healthFactor = (maxBorrowUSD * 100) / pos.borrowedUSD;
        } else {
            revert PositionHealthy(); // No debt = can't liquidate
        }

        if (healthFactor >= 100) revert PositionHealthy();

        uint256 debt = pos.borrowedUSD;

        // Liquidator must have enough dUSD to repay
        if (demoUSD.balanceOf(msg.sender) < debt) revert InsufficientLiquidatorBalance();

        // Liquidator receives 50% of collateral (bonus for clearing bad debt)
        uint256 collateralToLiquidator = pos.collateralETH / 2;
        uint256 collateralRemaining = pos.collateralETH - collateralToLiquidator;

        // Clear the position
        pos.borrowedUSD = 0;
        pos.collateralETH = collateralRemaining;
        totalBorrowed -= debt;
        totalCollateral -= collateralToLiquidator;

        // Burn liquidator's dUSD (repays debt)
        demoUSD.burn(msg.sender, debt);

        // Send collateral to liquidator
        (bool success,) = msg.sender.call{value: collateralToLiquidator}("");
        if (!success) revert TransferFailed();

        emit Liquidated(user, msg.sender, debt, collateralToLiquidator);
    }

    /**
     * @notice Get full position details for a user
     */
    function getPosition(address user)
        external
        view
        returns (
            uint256 collateralETH,
            uint256 borrowedUSD,
            bytes20 btcHash160,
            uint256 maxBorrowUSD,
            uint256 healthFactor
        )
    {
        Position memory pos = positions[user];
        collateralETH = pos.collateralETH;
        borrowedUSD = pos.borrowedUSD;
        btcHash160 = pos.btcHash160;

        uint256 collateralValueUSD = (collateralETH * 2000 * 1e18) / 1e18;
        maxBorrowUSD = (collateralValueUSD * LTV_BPS) / BPS_DENOMINATOR;

        if (borrowedUSD > 0) {
            healthFactor = (maxBorrowUSD * 100) / borrowedUSD; // 100 = healthy, <100 = liquidatable
        } else {
            healthFactor = type(uint256).max;
        }
    }

    /**
     * @notice Get demo showcase data
     */
    function getDemoShowcase()
        external
        view
        returns (address demoUser, bytes20 demoHash160, string memory segwitAddress)
    {
        // Return showcase if set, otherwise return hardcoded demo
        if (showcaseAddress != address(0)) {
            return (showcaseAddress, showcaseHash160, showcaseBtcAddress);
        }
        return (DEMO_ADDRESS, DEMO_HASH160, "bc1qxmh4elu8eucmzggaxjp0dld8a62v84wm4evgxg");
    }

    /**
     * @notice Get vault statistics
     */
    function getStats() external view returns (uint256 _totalCollateral, uint256 _totalBorrowed, uint256 _totalUsers) {
        return (totalCollateral, totalBorrowed, totalUsers);
    }

    receive() external payable {
        // Accept ETH transfers
    }
}

