// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IFastpathAttestation
 * @notice Interface for contracts that verify FastPath API attestations
 * @dev Import this interface to verify Bitcoin balance and ownership proofs
 *      signed by the FastPath attestation signer.
 *
 * Integration steps:
 *   1. Deploy FastpathAttestationVerifier (or inherit it)
 *   2. Set trustedSigner to the address from GET /v1/attest/signer
 *   3. Users call POST /v1/attest/balance or /v1/attest/ownership
 *   4. Users submit the signature + message params to your contract
 *   5. Your contract calls verifyBalance() / verifyOwnership()
 */
interface IFastpathAttestation {
    /// @notice Verify a signed Bitcoin balance attestation
    /// @param evmAddress   The EVM address claiming the BTC balance
    /// @param btcAddress   The Bitcoin address whose balance was checked
    /// @param balanceSats  Balance in satoshis
    /// @param timestamp    When the attestation was created (unix seconds)
    /// @param nonce        Unique nonce (prevents replay)
    /// @param signature    EIP-712 signature from the FastPath signer
    /// @return valid       True if the signature is authentic and unexpired
    function verifyBalance(
        address evmAddress,
        string calldata btcAddress,
        uint256 balanceSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool valid);

    /// @notice Verify a signed Bitcoin UTXO ownership attestation
    /// @param evmAddress   The EVM address claiming ownership
    /// @param btcAddress   The Bitcoin address that owns the UTXO
    /// @param utxoTxid     UTXO transaction ID (hex string)
    /// @param utxoIndex    UTXO output index (vout)
    /// @param amountSats   UTXO value in satoshis
    /// @param timestamp    When the attestation was created
    /// @param nonce        Unique nonce
    /// @param signature    EIP-712 signature from the FastPath signer
    /// @return valid       True if the signature is authentic and unexpired
    function verifyOwnership(
        address evmAddress,
        string calldata btcAddress,
        string calldata utxoTxid,
        uint32 utxoIndex,
        uint256 amountSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool valid);

    /// @notice Get the trusted signer address
    function trustedSigner() external view returns (address);

    /// @notice Check if a nonce has been used (replay protection)
    function usedNonces(uint256 nonce) external view returns (bool);
}

