// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

interface IFastPathIdentityAtomicSwap {
    function currentController(bytes20 btcHash160) external view returns (address);
}

/// @title FastPathAtomicSwapCoordinator
/// @notice Canonical on-chain coordinator for hash160-based cross-chain atomic-swap-style flows.
/// @dev This contract verifies EIP-712 consent signatures against FastPathIdentity.currentController(),
///      records one shared hashlock and deadlines, and lets trusted executors report external-chain
///      funding, release, and refund outcomes. It does NOT custody BTC/TRON/native-chain assets.
contract FastPathAtomicSwapCoordinator is AccessControl, EIP712 {
    using ECDSA for bytes32;

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    bytes32 private constant CONSENT_TYPEHASH = keccak256(
        "AtomicSwapConsent(bytes20 userHash160,bytes20 counterpartyHash160,string sellChain,string buyChain,string sellAmount,string buyAmount,bytes32 hashlock,bytes16 nonce,uint256 deadline)"
    );

    error ZeroAddress();
    error InvalidIdentity();
    error InvalidSignature();
    error InvalidConsent();
    error ConsentExpired();
    error NonceAlreadyUsed();
    error SwapAlreadyExists();
    error InvalidDeadlines();
    error InvalidSwap();
    error WrongStatus();
    error DeadlinePassed();
    error DeadlineNotReached();
    error InvalidLeg();
    error InvalidSecret();
    error AlreadyMarked();
    error Unauthorized();

    enum SwapStatus {
        None,
        Open,
        Active,
        Revealed,
        Completed,
        Refunding,
        Refunded,
        Cancelled
    }

    struct Consent {
        bytes20 userHash160;
        bytes20 counterpartyHash160;
        string sellChain;
        string buyChain;
        string sellAmount;
        string buyAmount;
        bytes32 hashlock;
        bytes16 nonce;
        uint256 deadline;
    }

    struct SwapTerms {
        uint64 legAFundDeadline;
        uint64 legBFundDeadline;
        uint64 revealDeadline;
        uint64 refundAtA;
        uint64 refundAtB;
    }

    struct SignedConsent {
        Consent consent;
        bytes signature;
    }

    struct Swap {
        bytes20 partyAHash160;
        bytes20 partyBHash160;
        address partyAControllerSnapshot;
        address partyBControllerSnapshot;
        string sellChainA;
        string buyChainA;
        string sellAmountA;
        string buyAmountA;
        string sellChainB;
        string buyChainB;
        string sellAmountB;
        string buyAmountB;
        bytes32 hashlock;
        bytes16 nonce;
        uint64 consentDeadline;
        uint64 legAFundDeadline;
        uint64 legBFundDeadline;
        uint64 revealDeadline;
        uint64 refundAtA;
        uint64 refundAtB;
        bool legAFunded;
        bool legBFunded;
        bool legAReleased;
        bool legBReleased;
        bool legARefunded;
        bool legBRefunded;
        bytes32 revealedSecret;
        SwapStatus status;
    }

    IFastPathIdentityAtomicSwap public immutable IDENTITY;

    mapping(bytes32 => Swap) private _swaps;
    mapping(bytes20 => mapping(bytes16 => bool)) public nonceUsed;

    event SwapCreated(
        bytes32 indexed swapId,
        bytes20 indexed partyAHash160,
        bytes20 indexed partyBHash160,
        address partyAController,
        address partyBController,
        bytes32 hashlock,
        bytes16 nonce
    );

    event LegFunded(bytes32 indexed swapId, uint8 indexed leg, bytes32 externalTxRef);
    event SecretRevealed(bytes32 indexed swapId, bytes32 secret);
    event LegReleased(bytes32 indexed swapId, uint8 indexed leg, bytes32 externalTxRef);
    event LegRefunded(bytes32 indexed swapId, uint8 indexed leg, bytes32 externalTxRef);
    event SwapCompleted(bytes32 indexed swapId);
    event SwapCancelled(bytes32 indexed swapId);

    constructor(address identityAddress, address admin, address executor) EIP712("FastPathAtomicSwap", "1") {
        if (identityAddress == address(0) || admin == address(0) || executor == address(0)) {
            revert ZeroAddress();
        }

        IDENTITY = IFastPathIdentityAtomicSwap(identityAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(EXECUTOR_ROLE, executor);
    }

    function getSwap(bytes32 swapId) external view returns (Swap memory) {
        return _swaps[swapId];
    }

    function createSwapFromConsents(
        SignedConsent calldata partyA,
        SignedConsent calldata partyB,
        SwapTerms calldata terms
    ) external returns (bytes32 swapId) {
        Consent calldata consentA = partyA.consent;
        Consent calldata consentB = partyB.consent;

        _validateConsentPair(consentA, consentB);
        _validateTerms(consentA.deadline, consentB.deadline, terms);

        address currentA = IDENTITY.currentController(consentA.userHash160);
        address currentB = IDENTITY.currentController(consentB.userHash160);

        if (currentA == address(0) || currentB == address(0)) revert InvalidIdentity();
        if (_recoverConsentSigner(consentA, partyA.signature) != currentA) revert InvalidSignature();
        if (_recoverConsentSigner(consentB, partyB.signature) != currentB) revert InvalidSignature();

        if (nonceUsed[consentA.userHash160][consentA.nonce]) revert NonceAlreadyUsed();
        if (nonceUsed[consentB.userHash160][consentB.nonce]) revert NonceAlreadyUsed();

        swapId = computeSwapId(
            consentA.userHash160,
            consentB.userHash160,
            consentA.hashlock,
            consentA.nonce
        );

        if (_swaps[swapId].status != SwapStatus.None) revert SwapAlreadyExists();

        nonceUsed[consentA.userHash160][consentA.nonce] = true;
        nonceUsed[consentB.userHash160][consentB.nonce] = true;

        _storeSwap(swapId, consentA, consentB, terms, currentA, currentB);

        emit SwapCreated(
            swapId,
            consentA.userHash160,
            consentB.userHash160,
            currentA,
            currentB,
            consentA.hashlock,
            consentA.nonce
        );
    }

    function _storeSwap(
        bytes32 swapId,
        Consent calldata consentA,
        Consent calldata consentB,
        SwapTerms calldata terms,
        address currentA,
        address currentB
    ) internal {
        uint64 consentDeadline = uint64(
            consentA.deadline < consentB.deadline ? consentA.deadline : consentB.deadline
        );

        _swaps[swapId] = Swap({
            partyAHash160: consentA.userHash160,
            partyBHash160: consentB.userHash160,
            partyAControllerSnapshot: currentA,
            partyBControllerSnapshot: currentB,
            sellChainA: consentA.sellChain,
            buyChainA: consentA.buyChain,
            sellAmountA: consentA.sellAmount,
            buyAmountA: consentA.buyAmount,
            sellChainB: consentB.sellChain,
            buyChainB: consentB.buyChain,
            sellAmountB: consentB.sellAmount,
            buyAmountB: consentB.buyAmount,
            hashlock: consentA.hashlock,
            nonce: consentA.nonce,
            consentDeadline: consentDeadline,
            legAFundDeadline: terms.legAFundDeadline,
            legBFundDeadline: terms.legBFundDeadline,
            revealDeadline: terms.revealDeadline,
            refundAtA: terms.refundAtA,
            refundAtB: terms.refundAtB,
            legAFunded: false,
            legBFunded: false,
            legAReleased: false,
            legBReleased: false,
            legARefunded: false,
            legBRefunded: false,
            revealedSecret: bytes32(0),
            status: SwapStatus.Open
        });
    }

    function markLegFunded(bytes32 swapId, uint8 leg, bytes32 externalTxRef)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        Swap storage s = _requireSwap(swapId);

        if (s.status != SwapStatus.Open && s.status != SwapStatus.Active) revert WrongStatus();
        if (block.timestamp > _fundDeadlineForLeg(s, leg)) revert DeadlinePassed();

        if (leg == 0) {
            if (s.legAFunded) revert AlreadyMarked();
            s.legAFunded = true;
        } else if (leg == 1) {
            if (s.legBFunded) revert AlreadyMarked();
            s.legBFunded = true;
        } else {
            revert InvalidLeg();
        }

        if (s.legAFunded && s.legBFunded) {
            s.status = SwapStatus.Active;
        }

        emit LegFunded(swapId, leg, externalTxRef);
    }

    function revealSecret(bytes32 swapId, bytes32 secret) external {
        Swap storage s = _requireSwap(swapId);

        // TSI-FPC-003 mitigation: only swap parties or a trusted executor may reveal.
        // Prevents any third party from permanently bricking the refund paths.
        if (
            msg.sender != s.partyAControllerSnapshot &&
            msg.sender != s.partyBControllerSnapshot &&
            !hasRole(EXECUTOR_ROLE, msg.sender)
        ) revert Unauthorized();

        if (s.status != SwapStatus.Active && s.status != SwapStatus.Revealed) revert WrongStatus();
        if (block.timestamp > s.revealDeadline) revert DeadlinePassed();
        if (sha256(abi.encodePacked(secret)) != s.hashlock) revert InvalidSecret();

        s.revealedSecret = secret;
        s.status = SwapStatus.Revealed;

        emit SecretRevealed(swapId, secret);
    }

    function markLegReleased(bytes32 swapId, uint8 leg, bytes32 externalTxRef)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        Swap storage s = _requireSwap(swapId);

        // TSI-FPC-002 mitigation: releases require an on-chain secret reveal first.
        // Removing Active from allowed statuses enforces the hashlock guarantee.
        if (s.status != SwapStatus.Revealed) revert WrongStatus();

        if (leg == 0) {
            if (s.legAReleased) revert AlreadyMarked();
            s.legAReleased = true;
        } else if (leg == 1) {
            if (s.legBReleased) revert AlreadyMarked();
            s.legBReleased = true;
        } else {
            revert InvalidLeg();
        }

        if (s.legAReleased && s.legBReleased) {
            s.status = SwapStatus.Completed;
            emit SwapCompleted(swapId);
        }

        emit LegReleased(swapId, leg, externalTxRef);
    }

    function markLegRefunded(bytes32 swapId, uint8 leg, bytes32 externalTxRef)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        Swap storage s = _requireSwap(swapId);

        if (s.status == SwapStatus.Completed || s.status == SwapStatus.Cancelled || s.status == SwapStatus.Refunded) {
            revert WrongStatus();
        }
        if (s.revealedSecret != bytes32(0)) revert WrongStatus();

        if (leg == 0) {
            // TSI-FPC-004 mitigation: a leg that was released cannot also be refunded.
            if (s.legAReleased) revert WrongStatus();
            if (block.timestamp < s.refundAtA) revert DeadlineNotReached();
            if (s.legARefunded) revert AlreadyMarked();
            s.legARefunded = true;
        } else if (leg == 1) {
            // TSI-FPC-004 mitigation: same guard for leg B.
            if (s.legBReleased) revert WrongStatus();
            if (block.timestamp < s.refundAtB) revert DeadlineNotReached();
            if (s.legBRefunded) revert AlreadyMarked();
            s.legBRefunded = true;
        } else {
            revert InvalidLeg();
        }

        s.status = SwapStatus.Refunding;

        if ((s.legARefunded || !s.legAFunded) && (s.legBRefunded || !s.legBFunded)) {
            s.status = SwapStatus.Refunded;
        }

        emit LegRefunded(swapId, leg, externalTxRef);
    }

    function cancelExpiredSwap(bytes32 swapId) external {
        Swap storage s = _requireSwap(swapId);

        if (s.status != SwapStatus.Open) revert WrongStatus();
        // TSI-FPC-001 mitigation: once any external-chain leg has been funded,
        // cancellation is blocked. The refund path (markLegRefunded) handles recovery.
        if (s.legAFunded || s.legBFunded) revert WrongStatus();
        if (
            block.timestamp <= s.consentDeadline &&
            block.timestamp <= s.legAFundDeadline &&
            block.timestamp <= s.legBFundDeadline
        ) {
            revert DeadlineNotReached();
        }

        s.status = SwapStatus.Cancelled;
        emit SwapCancelled(swapId);
    }

    function computeSwapId(
        bytes20 partyAHash160,
        bytes20 partyBHash160,
        bytes32 hashlock,
        bytes16 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(partyAHash160, partyBHash160, hashlock, nonce));
    }

    function hashConsent(Consent calldata consent) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CONSENT_TYPEHASH,
                    consent.userHash160,
                    consent.counterpartyHash160,
                    keccak256(bytes(consent.sellChain)),
                    keccak256(bytes(consent.buyChain)),
                    keccak256(bytes(consent.sellAmount)),
                    keccak256(bytes(consent.buyAmount)),
                    consent.hashlock,
                    consent.nonce,
                    consent.deadline
                )
            )
        );
    }

    function _recoverConsentSigner(Consent calldata consent, bytes calldata sig)
        internal
        view
        returns (address)
    {
        return ECDSA.recover(hashConsent(consent), sig);
    }

    function _validateConsentPair(Consent calldata a, Consent calldata b) internal view {
        if (a.userHash160 == bytes20(0) || b.userHash160 == bytes20(0)) revert InvalidConsent();
        if (a.counterpartyHash160 == bytes20(0) || b.counterpartyHash160 == bytes20(0)) revert InvalidConsent();

        if (a.counterpartyHash160 != b.userHash160) revert InvalidConsent();
        if (b.counterpartyHash160 != a.userHash160) revert InvalidConsent();

        if (a.hashlock != b.hashlock) revert InvalidConsent();
        if (a.nonce != b.nonce) revert InvalidConsent();

        if (keccak256(bytes(a.sellChain)) != keccak256(bytes(b.buyChain))) revert InvalidConsent();
        if (keccak256(bytes(a.buyChain)) != keccak256(bytes(b.sellChain))) revert InvalidConsent();

        if (keccak256(bytes(a.sellAmount)) != keccak256(bytes(b.buyAmount))) revert InvalidConsent();
        if (keccak256(bytes(a.buyAmount)) != keccak256(bytes(b.sellAmount))) revert InvalidConsent();

        if (a.deadline < block.timestamp || b.deadline < block.timestamp) revert ConsentExpired();
    }

    function _validateTerms(
        uint256 deadlineA,
        uint256 deadlineB,
        SwapTerms calldata terms
    ) internal pure {
        uint256 consentDeadline = deadlineA < deadlineB ? deadlineA : deadlineB;

        if (
            terms.legAFundDeadline == 0 ||
            terms.legBFundDeadline == 0 ||
            terms.revealDeadline == 0 ||
            terms.refundAtA == 0 ||
            terms.refundAtB == 0
        ) revert InvalidDeadlines();

        if (consentDeadline > terms.legAFundDeadline) revert InvalidDeadlines();
        if (terms.legAFundDeadline > terms.legBFundDeadline) revert InvalidDeadlines();
        if (terms.legBFundDeadline > terms.revealDeadline) revert InvalidDeadlines();
        if (terms.revealDeadline > terms.refundAtA) revert InvalidDeadlines();
        if (terms.refundAtA >= terms.refundAtB) revert InvalidDeadlines();
    }

    function _fundDeadlineForLeg(Swap storage s, uint8 leg) internal view returns (uint64) {
        if (leg == 0) return s.legAFundDeadline;
        if (leg == 1) return s.legBFundDeadline;
        revert InvalidLeg();
    }

    function _requireSwap(bytes32 swapId) internal view returns (Swap storage s) {
        s = _swaps[swapId];
        if (s.status == SwapStatus.None) revert InvalidSwap();
    }
}
