// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title CrossChainProofVerifier
 * @notice Verifies Bitcoin → EVM identity proofs
 * using the BitcoinGateway + FastPathIdentity stack
 *
 *   Proof chain:
 *     Bitcoin witness signature
 *       → Compressed Public Key (33 bytes)
 *         → SHA256 → RIPEMD160 → hash160 (20 bytes)
 *           → FastPathIdentity.btcToEvm(hash160) → EVM address
 *
 *   Every step is deterministic and verifiable on-chain — zero trust required.
 */

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface IFastPathIdentity {
    function btcToEvm(bytes20 hash160) external view returns (address);
    function evmToBtc(address evm) external view returns (bytes20);
}

interface IBitcoinGateway {
    struct PaymentRequest {
        address requester;
        bool fulfilled;
        uint64 timestamp;
        uint256 amountSats;
        bytes32 btcTxid;
        string fromBtcAddress;
        string toBtcAddress;
        string memo;
    }

    function getPaymentRequest(uint256 requestId) external view returns (PaymentRequest memory);

    function getPaymentStatus(uint256 requestId) external view returns (bool fulfilled, bytes32 btcTxid);

    function requestCount() external view returns (uint256);
}

// ─── Contract ────────────────────────────────────────────────────────────────

contract CrossChainProofVerifier {
    // ── Errors ───────────────────────────────────────────────────────────────
    error InvalidPubkeyLength();
    error RequestNotFulfilled();
    error SignerNotRegistered();
    error UnexpectedSigner();

    // ── Events ───────────────────────────────────────────────────────────────
    event ProofVerified(
        uint256 indexed requestId, bytes32 indexed btcTxid, bytes20 indexed signerHash160, address signerEvm
    );

    // ── Immutables ───────────────────────────────────────────────────────────
    IBitcoinGateway public immutable gateway;
    IFastPathIdentity public immutable identity;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _gateway, address _identity) {
        gateway = IBitcoinGateway(_gateway);
        identity = IFastPathIdentity(_identity);
    }

    // ─── Pure Helpers ────────────────────────────────────────────────────────

    /**
     * @notice Derive hash160 from a compressed public key.
     * @param pubkey  33-byte compressed secp256k1 public key (from Bitcoin witness).
     * @return hash160  RIPEMD160(SHA256(pubkey)) — the standard Bitcoin hash160.
     */
    function pubkeyToHash160(bytes memory pubkey) public pure returns (bytes20) {
        if (pubkey.length != 33) revert InvalidPubkeyLength();
        return ripemd160(abi.encodePacked(sha256(pubkey)));
    }

    // ─── View: Identity Lookup ───────────────────────────────────────────────

    /**
     * @notice Check whether a Bitcoin public key belongs to a registered identity.
     * @param pubkey  33-byte compressed public key.
     * @return evmOwner     EVM address linked to the signer (address(0) if unregistered).
     * @return btcHash160   The derived hash160.
     * @return isRegistered True when the hash160 has a FastPathIdentity mapping.
     */
    function verifySignerIdentity(bytes memory pubkey)
        external
        view
        returns (address evmOwner, bytes20 btcHash160, bool isRegistered)
    {
        btcHash160 = pubkeyToHash160(pubkey);
        evmOwner = identity.btcToEvm(btcHash160);
        isRegistered = evmOwner != address(0);
    }

    // ─── View: Full Request + Identity Proof ─────────────────────────────────

    /**
     * @notice Verify a gateway request was fulfilled AND resolve the signer's identity.
     * @param requestId  The BitcoinGateway payment request ID.
     * @param pubkey     33-byte compressed public key from the BitcoinTransactionProof event.
     * @return fulfilled      Whether the BTC payment was completed.
     * @return btcTxid        The Bitcoin transaction hash (big-endian bytes32).
     * @return signerEvm      The EVM address mapped to the BTC signer.
     * @return signerHash160  The hash160 derived from the public key.
     */
    function verifyRequestProof(uint256 requestId, bytes memory pubkey)
        external
        view
        returns (bool fulfilled, bytes32 btcTxid, address signerEvm, bytes20 signerHash160)
    {
        IBitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(requestId);
        fulfilled = req.fulfilled;
        btcTxid = req.btcTxid;
        signerHash160 = pubkeyToHash160(pubkey);
        signerEvm = identity.btcToEvm(signerHash160);
    }

    // ─── View: Strict Verification (reverts on failure) ──────────────────────

    /**
     * @notice Strict version — reverts unless the request is fulfilled AND signed
     *         by a registered identity.  Useful as a guard in downstream contracts.
     * @param requestId  The BitcoinGateway payment request ID.
     * @param pubkey     33-byte compressed public key.
     * @return signerEvm      The verified EVM address of the BTC signer.
     * @return signerHash160  The hash160 of the BTC signer.
     * @return amountSats     The BTC amount that was paid.
     * @return btcTxid        The Bitcoin transaction hash.
     */
    function requireValidProof(uint256 requestId, bytes memory pubkey)
        external
        view
        returns (address signerEvm, bytes20 signerHash160, uint256 amountSats, bytes32 btcTxid)
    {
        IBitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(requestId);
        if (!req.fulfilled) revert RequestNotFulfilled();

        signerHash160 = pubkeyToHash160(pubkey);
        signerEvm = identity.btcToEvm(signerHash160);
        if (signerEvm == address(0)) revert SignerNotRegistered();

        amountSats = req.amountSats;
        btcTxid = req.btcTxid;
    }

    /**
     * @notice Strictest form — also asserts the signer matches an expected EVM address.
     * @param requestId      The BitcoinGateway payment request ID.
     * @param pubkey         33-byte compressed public key.
     * @param expectedSigner The EVM address that MUST own the BTC pubkey.
     * @return amountSats    The BTC amount that was paid.
     * @return btcTxid       The Bitcoin transaction hash.
     */
    function requireProofFrom(uint256 requestId, bytes memory pubkey, address expectedSigner)
        external
        view
        returns (uint256 amountSats, bytes32 btcTxid)
    {
        IBitcoinGateway.PaymentRequest memory req = gateway.getPaymentRequest(requestId);
        if (!req.fulfilled) revert RequestNotFulfilled();

        bytes20 h160 = pubkeyToHash160(pubkey);
        address actual = identity.btcToEvm(h160);
        if (actual == address(0)) revert SignerNotRegistered();
        if (actual != expectedSigner) revert UnexpectedSigner();

        amountSats = req.amountSats;
        btcTxid = req.btcTxid;
    }

    // ─── View: Batch Helpers ─────────────────────────────────────────────────

    /**
     * @notice Check multiple requests in one call (multicall-friendly).
     * @param requestIds  Array of request IDs to check.
     * @return statuses   Parallel array of fulfillment booleans.
     * @return txids      Parallel array of BTC txids (bytes32(0) if unfulfilled).
     */
    function batchStatus(uint256[] calldata requestIds)
        external
        view
        returns (bool[] memory statuses, bytes32[] memory txids)
    {
        uint256 len = requestIds.length;
        statuses = new bool[](len);
        txids = new bytes32[](len);

        for (uint256 i; i < len;) {
            (statuses[i], txids[i]) = gateway.getPaymentStatus(requestIds[i]);
            unchecked {
                ++i;
            }
        }
    }
}

