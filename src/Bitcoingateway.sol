// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @dev Minimal interface for BitIDRewardDistributor — only what BitcoinGateway needs
 */
interface IBitIDRewardDistributor {
    function reward(address user, uint8 action) external;
}

/**
 * @title BitcoinGateway v.1.4.0
 * @author FastPath-Hash160 by - Emiliano Solazzi
 * @notice On-chain registry for Bitcoin payment intents with proof recording.
 * @dev Bitcoin sends happen peer-to-peer on the Bitcoin network. This contract records the
 *      intent (fromBtcAddress, toBtcAddress, sats) and the fulfillment proof (btcTxid, pubkey).
 *      No ETH is locked. The registered user pays a small ETH fee at fulfillment time that goes to protocol.
 *
 * Security considerations:
 * - All external calls use checks-effects-interactions (CEI) pattern
 * - Zero address validation on all address inputs
 * - Reentrancy protection via ReentrancyGuard + state updates before external calls
 * - Blacklist system for malicious actors
 * - Custom errors for gas-efficient reverts
 * - Minimum BTC dust limit enforced for security
 */
contract BitcoinGateway is ReentrancyGuard {
    // ══════════════════════════════════════════════════════════════════════════════
    // CUSTOM ERRORS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Thrown when caller is not the contract owner
    error NotOwner();

    /// @notice Thrown when contract is paused
    error ContractPaused();

    /// @notice Thrown when amount is zero
    error ZeroAmount();

    /// @notice Thrown when from BTC address is empty
    error EmptyFromAddress();

    /// @notice Thrown when to BTC address is empty
    error EmptyToAddress();

    /// @notice Thrown when request ID is invalid
    error InvalidRequest();

    /// @notice Thrown when payment is already fulfilled
    error AlreadyFulfilled();

    /// @notice Thrown when BTC txid is invalid
    error InvalidTxid();

    /// @notice Thrown when proof length is not 64 bytes
    error InvalidProofLength();

    /// @notice Thrown when fingerprint is already registered
    error FingerprintAlreadyRegistered();

    /// @notice Thrown when user is already registered
    error UserAlreadyRegistered();

    /// @notice Thrown when user is not registered
    error UserNotRegistered();

    /// @notice Thrown when address is blacklisted
    error AddressBlacklisted();

    /// @notice Thrown when BTC amount is below dust limit
    error BtcAmountBelowDust();

    /// @notice Thrown when address is zero
    error ZeroAddress();

    /// @notice Thrown when ETH transfer fails
    error TransferFailed();

    /// @notice Thrown when insufficient protocol fees
    error InsufficientFees();

    /// @notice Thrown when fee recipient is zero
    error ZeroFeeRecipient();

    /// @notice Thrown when ETH sent is below the minimum proof fee
    error InsufficientProofFee();

    /// @notice Thrown when new proof fee is outside [MIN_PROOF_FEE, MAX_PROOF_FEE]
    error ProofFeeOutOfRange();

    // ══════════════════════════════════════════════════════════════════════════════
    // STATE VARIABLES
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Contract owner with admin privileges
    address public owner;

    /// @notice Address that receives protocol fees
    address public feeRecipient;

    /// @notice Total payment requests created
    uint256 public requestCount;

    /// @notice Contract pause state
    bool public paused;

    /// @notice Blacklisted addresses mapping
    mapping(address user => bool isBlacklisted) public blacklisted;

    /// @notice Fingerprint to registered user address mapping
    mapping(bytes32 fingerprint => address userAddress) public fingerprintToUser;

    /// @notice Registered user address to fingerprint mapping
    mapping(address userAddress => bytes32 fingerprint) public userToFingerprint;

    /// @notice Request ID to the user who submitted proof (recorded at fulfillment)
    mapping(uint256 requestId => address prover) public requestToProver;

    /// @notice Total protocol fees accumulated in ETH
    uint256 public totalProtocolFeesEth;

    /// @notice BitID reward distributor — zero address means rewards are disabled
    IBitIDRewardDistributor public rewardDistributor;

    /// @notice Minimum ETH required to submit a Bitcoin proof
    uint256 public proofFee;

    // ══════════════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @dev Minimum BTC amount (dust limit) - Bitcoin security anchor
    uint256 private constant _MIN_BTC_DUST = 600;

    /// @dev BitIDRewardDistributor action index for a gateway relay (GATEWAY_RELAY = 3)
    uint8 private constant _GATEWAY_RELAY_ACTION = 3;

    /// @dev Minimum configurable proof fee (0.0002 ETH)
    uint256 public constant MIN_PROOF_FEE = 0.0002 ether;

    /// @dev Maximum configurable proof fee (0.001 ETH)
    uint256 public constant MAX_PROOF_FEE = 0.001 ether;

    // ══════════════════════════════════════════════════════════════════════════════
    // STRUCTS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Payment request data structure
     * @dev Struct is packed for gas efficiency:
     *      Slot 0: requester (20) + fulfilled (1) + timestamp (8) = 29 bytes
     *      Slot 1: amountSats (32)
     *      Slot 2: btcTxid (32)
     *      Slot 3+: strings (dynamic)
     */
    struct PaymentRequest {
        address requester; // 20 bytes |
        bool fulfilled; //  1 byte  | slot 0 (29 bytes packed)
        uint64 timestamp; //  8 bytes |
        uint256 amountSats; // slot 1
        bytes32 btcTxid; // slot 2
        string fromBtcAddress; // slot 3+
        string toBtcAddress; // slot 4+
        string memo; // slot 5+
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // MAPPINGS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Payment requests by ID
    mapping(uint256 requestId => PaymentRequest request) public requests;

    // ══════════════════════════════════════════════════════════════════════════════
    // EVENTS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Emitted when a Bitcoin payment is requested
    event BitcoinPaymentRequested(
        uint256 indexed requestId,
        string indexed fromBtcAddress,
        string indexed toBtcAddress,
        uint256 amountSats,
        address requester
    );

    /// @notice Emitted when a Bitcoin payment is completed
    event BitcoinPaymentCompleted(
        uint256 indexed requestId,
        bytes32 indexed btcTxid,
        string fromBtcAddress,
        string toBtcAddress,
        uint256 amountSats
    );

    /// @notice Emitted with proof of Bitcoin transaction
    event BitcoinTransactionProof(uint256 indexed requestId, bytes publicKey, bytes32 indexed btcTxid, bytes proof);

    /// @notice Emitted when pause state changes
    event PauseStateChanged(bool indexed isPaused);

    /// @notice Emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when a user registers their machine
    event UserRegistered(address indexed userAddress, bytes32 indexed fingerprint);

    /// @notice Emitted when a user unregisters their machine
    event UserUnregistered(address indexed userAddress, bytes32 indexed fingerprint);

    /// @notice Emitted when blacklist status changes
    event AddressBlacklistedUpdated(address indexed addr, bool indexed isBlacklisted);

    /// @notice Emitted when protocol fees are withdrawn
    event ProtocolFeesWithdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when fee recipient is updated
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    /// @notice Emitted when the reward distributor is updated
    event RewardDistributorUpdated(address indexed oldDistributor, address indexed newDistributor);

    /// @notice Emitted when the proof fee is updated
    event ProofFeeUpdated(uint256 oldFee, uint256 newFee);

    // ══════════════════════════════════════════════════════════════════════════════
    // MODIFIERS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Restricts function to contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Ensures contract is not paused
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @notice Ensures caller is not blacklisted
    modifier notBlacklisted() {
        if (blacklisted[msg.sender]) revert AddressBlacklisted();
        _;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Initializes the BitcoinGateway contract
     * @param initialFeeRecipient Initial fee recipient address (cannot be zero)
     */
    constructor(address initialFeeRecipient) {
        if (initialFeeRecipient == address(0)) revert ZeroFeeRecipient();

        feeRecipient = initialFeeRecipient;
        owner = msg.sender;
        proofFee = MIN_PROOF_FEE;

        emit OwnershipTransferred(address(0), msg.sender);
        emit FeeRecipientUpdated(address(0), initialFeeRecipient);
        emit ProofFeeUpdated(0, MIN_PROOF_FEE);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - CORE
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a Bitcoin payment intent on-chain.
     * @dev No ETH is locked. The actual BTC send happens on the Bitcoin network.
     *      The registered user picks up this event and executes the BTC send,
     *      then calls submitBitcoinProof to record the proof.
     * @param fromBtcAddress Source Bitcoin address
     * @param toBtcAddress Destination Bitcoin address
     * @param amountSats Amount in satoshis to send (minimum 600)
     * @param memo Optional memo for the transaction
     * @return requestId Unique identifier for the created record
     */
    function sendBitcoin(
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats,
        string calldata memo
    ) external whenNotPaused notBlacklisted returns (uint256 requestId) {
        return _sendBitcoinInternal(fromBtcAddress, toBtcAddress, amountSats, memo);
    }

    /**
     * @dev Internal function to handle Bitcoin send requests
     */
    function _sendBitcoinInternal(
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats,
        string calldata memo
    ) internal returns (uint256 requestId) {
        _validateSendInputs(fromBtcAddress, toBtcAddress, amountSats);

        requestId = requestCount;
        unchecked {
            requestCount = requestId + 1;
        }

        _storeRequest(requestId, fromBtcAddress, toBtcAddress, amountSats, memo);

        emit BitcoinPaymentRequested(requestId, fromBtcAddress, toBtcAddress, amountSats, msg.sender);
    }

    /**
     * @dev Validate send inputs including dust limit
     */
    function _validateSendInputs(string calldata fromBtcAddress, string calldata toBtcAddress, uint256 amountSats)
        private
        pure
    {
        if (bytes(fromBtcAddress).length == 0) revert EmptyFromAddress();
        if (bytes(toBtcAddress).length == 0) revert EmptyToAddress();
        if (amountSats < _MIN_BTC_DUST) revert BtcAmountBelowDust();
    }

    /**
     * @dev Store payment request data
     */
    function _storeRequest(
        uint256 requestId,
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats,
        string calldata memo
    ) private {
        PaymentRequest storage req = requests[requestId];
        req.requester = msg.sender;
        req.fromBtcAddress = fromBtcAddress;
        req.toBtcAddress = toBtcAddress;
        req.amountSats = amountSats;
        req.timestamp = uint64(block.timestamp);
        req.memo = memo;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - FULFILLMENT
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Submit proof of a Bitcoin payment (registered user only).
     * @dev Caller must be a registered user. A non-zero ETH fee must be sent
     *      with this call — it goes entirely to the protocol treasury.
     *      The actual BTC send must have already occurred on Bitcoin.
     * @param requestId ID of the request being fulfilled
     * @param btcTxid Bitcoin transaction ID proving the send occurred
     * @param publicKey Public key of the signing user
     * @param proof Cryptographic proof (64 bytes)
     */
    function submitBitcoinProof(uint256 requestId, bytes32 btcTxid, bytes calldata publicKey, bytes calldata proof)
        external
        payable
        nonReentrant
        whenNotPaused
        notBlacklisted
    {
        if (msg.value < proofFee) revert InsufficientProofFee();
        if (userToFingerprint[msg.sender] == bytes32(0)) revert UserNotRegistered();
        _fulfill(requestId, btcTxid, publicKey, proof, msg.sender);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // INTERNAL FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @dev Internal fulfill logic with CEI pattern
     */
    function _fulfill(
        uint256 requestId,
        bytes32 btcTxid,
        bytes calldata publicKey,
        bytes calldata proof,
        address prover
    ) internal {
        // Validation
        uint256 _requestCount = requestCount;
        if (requestId >= _requestCount) revert InvalidRequest();

        PaymentRequest storage req = requests[requestId];
        if (req.fulfilled) revert AlreadyFulfilled();
        if (btcTxid == bytes32(0)) revert InvalidTxid();
        if (proof.length != 64) revert InvalidProofLength();

        // Effects
        req.fulfilled = true;
        req.btcTxid = btcTxid;

        // Record the user who submitted proof for audit trail
        requestToProver[requestId] = prover;

        // Collect fulfillment fee from user into protocol treasury
        unchecked {
            totalProtocolFeesEth += msg.value;
        }

        emit BitcoinPaymentCompleted(requestId, btcTxid, req.fromBtcAddress, req.toBtcAddress, req.amountSats);
        emit BitcoinTransactionProof(requestId, publicKey, btcTxid, proof);

        // Mint BitID reward to the prover — non-blocking: if distributor is not set
        // or the epoch budget is exhausted, the proof still succeeds.
        IBitIDRewardDistributor _distributor = rewardDistributor;
        if (address(_distributor) != address(0)) {
            try _distributor.reward(prover, _GATEWAY_RELAY_ACTION) {} catch {}
        }
    }

    /**
     * @dev Safe ETH transfer with custom error
     */
    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success,) = to.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - USER MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register your machine to become an approved user
     * @param machineFingerprint Unique machine fingerprint
     */
    function registerUser(bytes32 machineFingerprint) external whenNotPaused notBlacklisted {
        if (fingerprintToUser[machineFingerprint] != address(0)) {
            revert FingerprintAlreadyRegistered();
        }
        if (userToFingerprint[msg.sender] != bytes32(0)) {
            revert UserAlreadyRegistered();
        }

        fingerprintToUser[machineFingerprint] = msg.sender;
        userToFingerprint[msg.sender] = machineFingerprint;

        emit UserRegistered(msg.sender, machineFingerprint);
    }

    /**
     * @notice Unregister your machine
     */
    function unregisterUser() external whenNotPaused {
        bytes32 fingerprint = userToFingerprint[msg.sender];
        if (fingerprint == bytes32(0)) revert UserNotRegistered();

        delete fingerprintToUser[fingerprint];
        delete userToFingerprint[msg.sender];

        emit UserUnregistered(msg.sender, fingerprint);
    }

    /**
     * @notice Check if a fingerprint is available for registration
     * @param fingerprint Fingerprint to check
     * @return isAvailable True if available
     */
    function isFingerprintAvailable(bytes32 fingerprint) external view returns (bool isAvailable) {
        return fingerprintToUser[fingerprint] == address(0);
    }

    /**
     * @notice Get registered user address for a fingerprint
     * @param fingerprint Fingerprint to lookup
     * @return userAddress Address of the registered user
     */
    function getUserByFingerprint(bytes32 fingerprint) external view returns (address userAddress) {
        return fingerprintToUser[fingerprint];
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - ADMIN
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set blacklist status for an address
     * @param addr Address to update
     * @param status New blacklist status
     */
    function setBlacklisted(address addr, bool status) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        if (blacklisted[addr] == status) return;
        blacklisted[addr] = status;
        emit AddressBlacklistedUpdated(addr, status);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyOwner {
        if (paused) return;
        paused = true;
        emit PauseStateChanged(true);
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyOwner {
        if (!paused) return;
        paused = false;
        emit PauseStateChanged(false);
    }

    /**
     * @notice Transfer contract ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        if (oldOwner == newOwner) return;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @notice Update the fee recipient address
     * @param newFeeRecipient New fee recipient address
     */
    function updateFeeRecipient(address newFeeRecipient) external onlyOwner {
        if (newFeeRecipient == address(0)) revert ZeroFeeRecipient();
        address oldRecipient = feeRecipient;
        if (oldRecipient == newFeeRecipient) return;
        feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldRecipient, newFeeRecipient);
    }

    /**
     * @notice Set the proof submission fee
     * @dev Must be within [MIN_PROOF_FEE, MAX_PROOF_FEE].
     * @param newFee New minimum ETH required to call submitBitcoinProof
     */
    function setProofFee(uint256 newFee) external onlyOwner {
        if (newFee < MIN_PROOF_FEE || newFee > MAX_PROOF_FEE) revert ProofFeeOutOfRange();
        uint256 old = proofFee;
        if (old == newFee) return;
        proofFee = newFee;
        emit ProofFeeUpdated(old, newFee);
    }

    /**
     * @notice Set the BitID reward distributor contract
     * @dev Pass zero address to disable rewards entirely.
     *      The distributor must have this contract whitelisted as an authorized caller
     *      via BitIDRewardDistributor.setCaller(address(this), true) before rewards flow.
     * @param newDistributor Address of the deployed BitIDRewardDistributor, or zero to disable
     */
    function setRewardDistributor(address newDistributor) external onlyOwner {
        address old = address(rewardDistributor);
        if (old == newDistributor) return;
        rewardDistributor = IBitIDRewardDistributor(newDistributor);
        emit RewardDistributorUpdated(old, newDistributor);
    }

    /**
     * @notice Withdraw accumulated protocol fees
     * @dev Follows CEI pattern. Sends to feeRecipient.
     * @param amount Amount to withdraw
     */
    function withdrawProtocolFees(uint256 amount) external nonReentrant onlyOwner {
        uint256 _totalFees = totalProtocolFeesEth;
        if (amount > _totalFees) revert InsufficientFees();

        unchecked {
            totalProtocolFeesEth = _totalFees - amount;
        }

        address _recipient = feeRecipient;
        _safeTransferETH(_recipient, amount);

        emit ProtocolFeesWithdrawn(_recipient, amount);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - PUBLIC VIEW
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get a payment request by ID
     * @param requestId ID of the request
     * @return request PaymentRequest struct
     */
    function getPaymentRequest(uint256 requestId) external view returns (PaymentRequest memory request) {
        if (requestId >= requestCount) revert InvalidRequest();
        return requests[requestId];
    }

    /**
     * @notice Get payment status
     * @param requestId ID of the request
     * @return fulfilled Whether the payment is fulfilled
     * @return btcTxid Bitcoin transaction ID (bytes32(0) if not fulfilled)
     */
    function getPaymentStatus(uint256 requestId) external view returns (bool fulfilled, bytes32 btcTxid) {
        if (requestId >= requestCount) {
            return (false, bytes32(0));
        }
        PaymentRequest storage req = requests[requestId];
        return (req.fulfilled, req.btcTxid);
    }

    /**
     * @notice Check if a user can send payments
     * @param user Address to check
     * @return canSend True if user can send
     */
    function canUserSend(address user) external view returns (bool canSend) {
        return !paused && !blacklisted[user];
    }

    /**
     * @notice Get the minimum BTC dust limit
     * @return dustLimit Minimum sats required
     */
    function getMinBtcDust() external pure returns (uint256 dustLimit) {
        return _MIN_BTC_DUST;
    }
}
