// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title FastpathAttestationVerifier by Emiliano Solazzi 2026
 * @notice Verifies EIP-712 signed attestations from the FastPath Bitcoin API
 * @dev Inherit this contract or deploy standalone and reference via IFastpathAttestation
 *
 * The FastPath API (api.nativebtc.org) signs Bitcoin balance and UTXO ownership
 * data using an isolated derived key. This contract verifies those signatures
 * on-chain, enabling smart contracts to act on real Bitcoin data.
 *
 * Security model:
 *   - EIP-712 typed signatures (not raw hashes) — phishing resistant
 *   - Nonce replay protection — each attestation can only be used once
 *   - Timestamp expiry — attestations expire after MAX_AGE seconds
 *   - Signer rotation — owner can update trustedSigner if key is compromised
 *
 * Usage:
 *   1. User calls FastPath API: POST /v1/attest/balance
 *   2. API returns { signature, message: { evmAddress, btcAddress, balanceSats, timestamp, nonce } }
 *   3. User calls your contract with the signature + message fields
 *   4. Your contract calls verifyBalance() which checks the signature
 */
contract FastpathAttestationVerifier is Ownable, EIP712 {
    using ECDSA for bytes32;

    // ── State ──────────────────────────────────────────────────

    /// @notice The address whose signatures we trust (FastPath API signer)
    address public trustedSigner;

    /// @notice Maximum age of an attestation in seconds (default: 5 minutes)
    uint256 public maxAge = 300;

    /// @notice Nonces that have been consumed (replay protection)
    mapping(uint256 => bool) public usedNonces;

    /// @notice Contracts trusted to call verify* on behalf of users (e.g. BTCBackedVaultV2)
    mapping(address => bool) public trustedCallers;

    // ── EIP-712 Type Hashes ────────────────────────────────────

    bytes32 private constant BALANCE_TYPEHASH = keccak256(
        "BalanceAttestation(address evmAddress,string btcAddress,uint256 balanceSats,uint256 timestamp,uint256 nonce)"
    );

    bytes32 private constant OWNERSHIP_TYPEHASH = keccak256(
        "OwnershipAttestation(address evmAddress,string btcAddress,string utxoTxid,uint32 utxoIndex,uint256 amountSats,uint256 timestamp,uint256 nonce)"
    );

    // ── Events ─────────────────────────────────────────────────

    event SignerUpdated(address indexed oldSigner, address indexed newSigner);
    event MaxAgeUpdated(uint256 oldMaxAge, uint256 newMaxAge);
    event BalanceVerified(address indexed evmAddress, string btcAddress, uint256 balanceSats, uint256 nonce);
    event OwnershipVerified(
        address indexed evmAddress, string btcAddress, string utxoTxid, uint32 utxoIndex, uint256 nonce
    );
    event TrustedCallerUpdated(address indexed caller, bool trusted);

    // ── Errors ─────────────────────────────────────────────────

    error InvalidSignature();
    error AttestationExpired();
    error NonceAlreadyUsed();
    error SignerNotSet();
    error AddressMismatch();
    error ZeroAddress();

    // ── Constructor ────────────────────────────────────────────

    /// @param _trustedSigner The FastPath API attestation signer address
    ///        Get this from: GET https://api.nativebtc.org/v1/attest/signer
    constructor(address _trustedSigner) Ownable(msg.sender) EIP712("FastPathAttestation", "1") {
        if (_trustedSigner == address(0)) revert ZeroAddress();
        trustedSigner = _trustedSigner;
    }

    // ── Admin ──────────────────────────────────────────────────

    /// @notice Update the trusted signer (key rotation)
    function updateSigner(address _newSigner) external onlyOwner {
        if (_newSigner == address(0)) revert ZeroAddress();
        emit SignerUpdated(trustedSigner, _newSigner);
        trustedSigner = _newSigner;
    }

    /// @notice Update attestation max age
    function updateMaxAge(uint256 _maxAge) external onlyOwner {
        emit MaxAgeUpdated(maxAge, _maxAge);
        maxAge = _maxAge;
    }

    /// @notice Add or remove a trusted caller (e.g. BTCBackedVaultV2)
    /// @dev Trusted callers may invoke verifyBalance/verifyOwnership on behalf of users,
    ///      bypassing the msg.sender == evmAddress check.
    function setTrustedCaller(address caller, bool trusted) external onlyOwner {
        if (caller == address(0)) revert ZeroAddress();
        trustedCallers[caller] = trusted;
        emit TrustedCallerUpdated(caller, trusted);
    }

    // ── Verification ───────────────────────────────────────────

    /**
     * @notice Verify a Bitcoin balance attestation from FastPath API
     * @param evmAddress   Must match msg.sender (user proving their own balance)
     * @param btcAddress   The Bitcoin address whose balance was attested
     * @param balanceSats  Attested balance in satoshis
     * @param timestamp    Attestation creation time (unix)
     * @param nonce        One-time nonce
     * @param signature    EIP-712 signature from the FastPath signer
     * @return valid       True if signature is valid, fresh, and unused
     */
    function verifyBalance(
        address evmAddress,
        string calldata btcAddress,
        uint256 balanceSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) public virtual returns (bool valid) {
        if (trustedSigner == address(0)) revert SignerNotSet();
        // Allow trusted callers (e.g. VaultV2) to verify on behalf of users
        if (evmAddress != msg.sender && !trustedCallers[msg.sender]) revert AddressMismatch();
        if (block.timestamp > timestamp + maxAge) revert AttestationExpired();
        if (usedNonces[nonce]) revert NonceAlreadyUsed();

        // Build EIP-712 struct hash
        bytes32 structHash = keccak256(
            abi.encode(BALANCE_TYPEHASH, evmAddress, keccak256(bytes(btcAddress)), balanceSats, timestamp, nonce)
        );

        // Build full EIP-712 digest
        bytes32 digest = _hashTypedDataV4(structHash);

        // Recover signer
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != trustedSigner) revert InvalidSignature();

        // Mark nonce as used
        usedNonces[nonce] = true;

        emit BalanceVerified(evmAddress, btcAddress, balanceSats, nonce);
        return true;
    }

    /**
     * @notice Verify a Bitcoin UTXO ownership attestation
     * @param evmAddress   Must match msg.sender
     * @param btcAddress   Bitcoin address that owns the UTXO
     * @param utxoTxid     Transaction ID of the UTXO
     * @param utxoIndex    Output index (vout)
     * @param amountSats   UTXO amount in satoshis
     * @param timestamp    Attestation timestamp
     * @param nonce        One-time nonce
     * @param signature    EIP-712 signature
     * @return valid       True if valid
     */
    function verifyOwnership(
        address evmAddress,
        string calldata btcAddress,
        string calldata utxoTxid,
        uint32 utxoIndex,
        uint256 amountSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) public returns (bool valid) {
        if (trustedSigner == address(0)) revert SignerNotSet();
        if (evmAddress != msg.sender && !trustedCallers[msg.sender]) revert AddressMismatch();
        if (block.timestamp > timestamp + maxAge) revert AttestationExpired();
        if (usedNonces[nonce]) revert NonceAlreadyUsed();

        bytes32 structHash = keccak256(
            abi.encode(
                OWNERSHIP_TYPEHASH,
                evmAddress,
                keccak256(bytes(btcAddress)),
                keccak256(bytes(utxoTxid)),
                utxoIndex,
                amountSats,
                timestamp,
                nonce
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != trustedSigner) revert InvalidSignature();

        usedNonces[nonce] = true;

        emit OwnershipVerified(evmAddress, btcAddress, utxoTxid, utxoIndex, nonce);
        return true;
    }

    /**
     * @notice View-only signature check (does NOT consume nonce)
     * @dev Useful for off-chain verification or UI previews
     */
    function checkBalanceSignature(
        address evmAddress,
        string calldata btcAddress,
        uint256 balanceSats,
        uint256 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) external view returns (bool valid, address recovered) {
        bytes32 structHash = keccak256(
            abi.encode(BALANCE_TYPEHASH, evmAddress, keccak256(bytes(btcAddress)), balanceSats, timestamp, nonce)
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        recovered = ECDSA.recover(digest, signature);
        valid = (recovered == trustedSigner) && !usedNonces[nonce] && (block.timestamp <= timestamp + maxAge);
    }
}

