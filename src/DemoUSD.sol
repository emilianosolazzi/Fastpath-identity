// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DemoUSD for Proof160 / Hash160
 * @notice A demo stablecoin for showcasing BTC-backed lending
 * @dev Only the BTCBackedVault can mint/burn. Uses 18 decimals (standard).
 *
 * This token demonstrates how a stablecoin can be minted against
 * Bitcoin collateral verified via FastPath Identity (Hash160).
 *
 * Flow:
 * 1. User registers BTC identity via FastPathIdentity contract
 * 2. User deposits ETH collateral to BTCBackedVault
 * 3. Vault mints DemoUSD to user (up to 50% LTV)
 * 4. User repays DemoUSD to unlock collateral
 * 5. Vault burns the repaid DemoUSD
 */
contract DemoUSD is ERC20, Ownable {
    address public vault;

    // Events for transparency and demo visibility
    event VaultUpdated(address indexed oldVault, address indexed newVault);
    event Minted(address indexed to, uint256 amount, uint256 newBalance);
    event Burned(address indexed from, uint256 amount, uint256 newBalance);

    // Custom errors (gas efficient)
    error OnlyVault();
    error ZeroAddress();

    modifier onlyVault() {
        if (msg.sender != vault) revert OnlyVault();
        _;
    }

    constructor() ERC20("Demo USD", "dUSD") Ownable(msg.sender) {
        // Uses 18 decimals (ERC20 default) - standard for DeFi compatibility
    }

    /**
     * @notice Set the vault address that can mint/burn
     * @param _vault Address of the BTCBackedVault contract
     */
    function setVault(address _vault) external onlyOwner {
        if (_vault == address(0)) revert ZeroAddress();
        emit VaultUpdated(vault, _vault);
        vault = _vault;
    }

    /**
     * @notice Mint DemoUSD to a user (only callable by vault)
     * @param to Recipient address
     * @param amount Amount to mint (18 decimals)
     */
    function mint(address to, uint256 amount) external onlyVault {
        _mint(to, amount);
        emit Minted(to, amount, balanceOf(to));
    }

    /**
     * @notice Burn DemoUSD from a user (only callable by vault)
     * @param from Address to burn from
     * @param amount Amount to burn (18 decimals)
     */
    function burn(address from, uint256 amount) external onlyVault {
        _burn(from, amount);
        emit Burned(from, amount, balanceOf(from));
    }

    /**
     * @notice Get contract info for demo UI
     * @return name_ Token name
     * @return symbol_ Token symbol
     * @return decimals_ Token decimals
     * @return totalSupply_ Current total supply
     * @return vault_ Current vault address
     */
    function getInfo()
        external
        view
        returns (string memory name_, string memory symbol_, uint8 decimals_, uint256 totalSupply_, address vault_)
    {
        return (name(), symbol(), decimals(), totalSupply(), vault);
    }
}

