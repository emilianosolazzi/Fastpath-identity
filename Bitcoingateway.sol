// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title BitcoinGateway v.1.1.0
 * @author FastPath-Hash160 by - Emiliano Solazzi 
 * @notice Public gateway for Bitcoin transaction coordination with ETH fee collection
 * @dev This contract coordinates Bitcoin payment requests with decentralized relayer support
 *      Fees are collected in ETH at fulfillment time and distributed between protocol and relayers
 *      Bitcoin finality is the security anchor - all requests require minimum BTC amount
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
    
    /// @notice Thrown when relayer address is zero
    error ZeroRelayer();
    
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
    
    /// @notice Thrown when trying to mark failed too soon
    error TooSoonToMarkFailed();
    
    /// @notice Thrown when fingerprint is already registered
    error FingerprintAlreadyRegistered();
    
    /// @notice Thrown when relayer is already registered
    error RelayerAlreadyRegistered();
    
    /// @notice Thrown when relayer is not registered
    error RelayerNotRegistered();
    
    /// @notice Thrown when caller is not the assigned relayer
    error NotAssignedRelayer();
    
    /// @notice Thrown when request is not stuck (24h not passed)
    error RequestNotStuck();
    
    /// @notice Thrown when request has expired (past max age)
    error RequestExpired();
    
    /// @notice Thrown when caller is not the requester
    error NotRequester();
    
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

    // ══════════════════════════════════════════════════════════════════════════════
    // STATE VARIABLES
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Contract owner with admin privileges
    address public owner;
    
    /// @notice Address that receives protocol fees
    address public feeRecipient;
    
    /// @notice Default centralized relayer address
    address public relayer;
    
    /// @notice Total payment requests created
    uint256 public requestCount;
    
    /// @notice Contract pause state
    bool public paused;

    /// @notice Blacklisted addresses mapping
    mapping(address user => bool isBlacklisted) public blacklisted;

    /// @notice Fingerprint to relayer address mapping
    mapping(bytes32 fingerprint => address relayerAddress) public fingerprintToRelayer;
    
    /// @notice Relayer address to fingerprint mapping
    mapping(address relayerAddress => bytes32 fingerprint) public relayerToFingerprint;
    
    /// @notice Request ID to fulfilling relayer address (recorded at fulfillment)
    mapping(uint256 requestId => address fulfillingRelayer) public requestToFulfillingRelayer;

    /// @notice Total protocol fees accumulated in ETH
    uint256 public totalProtocolFeesEth;

    // ══════════════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @dev Total fee in basis points (0.25%)
    uint256 private constant _TOTAL_FEE_BPS = 25;
    
    /// @dev Relayer fee portion in basis points (0.17%)
    uint256 private constant _RELAYER_FEE_BPS = 17;
    
    /// @dev Time window for stuck request cancellation
    uint256 private constant _ONE_DAY = 24 hours;
    
    /// @dev Maximum request age before auto-expiration
    uint256 private constant _MAX_REQUEST_AGE = 7 days;
    
    /// @dev Basis points denominator
    uint256 private constant _BPS_DENOMINATOR = 10_000;
    
    /// @dev Minimum BTC amount (dust limit) - Bitcoin security anchor
    uint256 private constant _MIN_BTC_DUST = 600;

    // ══════════════════════════════════════════════════════════════════════════════
    // STRUCTS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Payment request data structure
     * @dev Struct is packed for gas efficiency:
     *      Slot 0: requester (20) + fulfilled (1) + timestamp (8) = 29 bytes
     *      Slot 1: amountSats (32)
     *      Slot 2: amountEth (32)
     *      Slot 3: btcTxid (32)
     *      Slot 4+: strings (dynamic)
     */
    struct PaymentRequest {
        address requester;      // 20 bytes |
        bool fulfilled;         //  1 byte  | slot 0 (29 bytes packed)
        uint64 timestamp;       //  8 bytes |
        uint256 amountSats;     // slot 1
        uint256 amountEth;      // slot 2
        bytes32 btcTxid;        // slot 3
        string fromBtcAddress;  // slot 4+
        string toBtcAddress;    // slot 5+
        string memo;            // slot 6+
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
        uint256 amountEth,
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
    
    /// @notice Emitted when a Bitcoin payment fails
    event BitcoinPaymentFailed(uint256 indexed requestId, string reason);
    
    /// @notice Emitted with proof of Bitcoin transaction
    event BitcoinTransactionProof(
        uint256 indexed requestId,
        bytes publicKey,
        bytes32 indexed btcTxid,
        bytes proof
    );
    
    /// @notice Emitted when pause state changes
    event PauseStateChanged(bool indexed isPaused);
    
    /// @notice Emitted when default relayer is updated
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);
    
    /// @notice Emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    /// @notice Emitted when a relayer registers
    event RelayerRegistered(address indexed relayerAddress, bytes32 indexed fingerprint);
    
    /// @notice Emitted when a relayer unregisters
    event RelayerUnregistered(address indexed relayerAddress, bytes32 indexed fingerprint);
    
    /// @notice Emitted when blacklist status changes
    event AddressBlacklistedUpdated(address indexed addr, bool indexed isBlacklisted);
    
    /// @notice Emitted when protocol fees are withdrawn
    event ProtocolFeesWithdrawn(address indexed recipient, uint256 amount);
    
    /// @notice Emitted when fee recipient is updated
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    
    /// @notice Emitted when ETH is refunded to requester on cancel/expiry
    event RefundIssued(uint256 indexed requestId, address indexed requester, uint256 amount);

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
     * @param initialRelayer Initial default relayer address (cannot be zero)
     * @param initialFeeRecipient Initial fee recipient address (cannot be zero)
     */
    constructor(address initialRelayer, address initialFeeRecipient) payable {
        if (initialRelayer == address(0)) revert ZeroRelayer();
        if (initialFeeRecipient == address(0)) revert ZeroFeeRecipient();

        relayer = initialRelayer;
        feeRecipient = initialFeeRecipient;
        owner = msg.sender;
        
        emit OwnershipTransferred(address(0), msg.sender);
        emit RelayerUpdated(address(0), initialRelayer);
        emit FeeRecipientUpdated(address(0), initialFeeRecipient);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - CORE
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Request a Bitcoin payment (payable in ETH)
     * @dev ETH sent with this call is used for fee calculation at fulfillment.
     *      Minimum 600 sats required for Bitcoin security anchor.
     * @param fromBtcAddress Source Bitcoin address
     * @param toBtcAddress Destination Bitcoin address
     * @param amountSats Amount in satoshis to send (minimum 600)
     * @param memo Optional memo for the transaction
     * @return requestId Unique identifier for the created request
     */
    function sendBitcoin(
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats,
        string calldata memo
    )
        external
        payable
        whenNotPaused
        notBlacklisted
        returns (uint256 requestId)
    {
        if (msg.value == 0) revert ZeroAmount();
        return _sendBitcoinInternal(
            fromBtcAddress,
            toBtcAddress,
            amountSats,
            memo
        );
    }

    /**
     * @dev Internal function to handle Bitcoin send requests
     */
    function _sendBitcoinInternal(
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats,
        string calldata memo
    )
        internal
        returns (uint256 requestId)
    {
        _validateSendInputs(fromBtcAddress, toBtcAddress, amountSats);

        requestId = requestCount;
        unchecked { 
            requestCount = requestId + 1; 
        }

        _storeRequest(requestId, fromBtcAddress, toBtcAddress, amountSats, memo);
        
        emit BitcoinPaymentRequested(
            requestId,
            fromBtcAddress,
            toBtcAddress,
            amountSats,
            msg.value,
            msg.sender
        );
    }

    /**
     * @dev Validate send inputs including dust limit
     */
    function _validateSendInputs(
        string calldata fromBtcAddress,
        string calldata toBtcAddress,
        uint256 amountSats
    ) private pure {
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
        req.amountEth = msg.value;
        req.timestamp = uint64(block.timestamp);
        req.memo = memo;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - FULFILLMENT
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Fulfill a payment request (centralized relayer)
     * @dev Only callable by the default relayer
     * @param requestId ID of the request to fulfill
     * @param btcTxid Bitcoin transaction ID
     * @param publicKey Public key used for signing
     * @param proof Cryptographic proof (64 bytes)
     */
    function fulfillPayment(
        uint256 requestId,
        bytes32 btcTxid,
        bytes calldata publicKey,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        notBlacklisted
    {
        address _relayer = relayer;
        if (msg.sender != _relayer) revert NotAssignedRelayer();
        _fulfill(requestId, btcTxid, publicKey, proof, msg.sender);
    }

    /**
     * @notice Fulfill a payment request (decentralized relayer)
     * @dev Only callable by registered relayers. Relayer is recorded automatically.
     * @param requestId ID of the request to fulfill
     * @param btcTxid Bitcoin transaction ID
     * @param publicKey Public key used for signing
     * @param proof Cryptographic proof (64 bytes)
     */
    function fulfillPaymentAsRelayer(
        uint256 requestId,
        bytes32 btcTxid,
        bytes calldata publicKey,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        notBlacklisted
    {
        if (relayerToFingerprint[msg.sender] == bytes32(0)) revert RelayerNotRegistered();
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
        address fulfillingRelayer
    ) internal {
        // Validation
        uint256 _requestCount = requestCount;
        if (requestId >= _requestCount) revert InvalidRequest();
        
        PaymentRequest storage req = requests[requestId];
        if (req.fulfilled) revert AlreadyFulfilled();
        if (uint256(req.timestamp) + _MAX_REQUEST_AGE < block.timestamp) revert RequestExpired();
        if (btcTxid == bytes32(0)) revert InvalidTxid();
        if (proof.length != 64) revert InvalidProofLength();

        // Effects - update state before external calls (CEI pattern)
        req.fulfilled = true;
        req.btcTxid = btcTxid;
        
        // Record fulfilling relayer for audit trail
        requestToFulfillingRelayer[requestId] = fulfillingRelayer;

        // Calculate and distribute ETH fees
        uint256 ethAmount = req.amountEth;
        uint256 ethFee = (ethAmount * _TOTAL_FEE_BPS) / _BPS_DENOMINATOR;
        
        // Check if fulfiller is a registered relayer
        bool isRegisteredRelayer = relayerToFingerprint[fulfillingRelayer] != bytes32(0);
        
        if (!isRegisteredRelayer || fulfillingRelayer == relayer) {
            // Centralized relayer or unregistered - all fees to protocol
            unchecked {
                totalProtocolFeesEth += ethFee;
            }
        } else {
            // Registered decentralized relayer - split fees
            uint256 relayerFee = (ethFee * _RELAYER_FEE_BPS) / _TOTAL_FEE_BPS;
            
            uint256 protocolFee;
            unchecked {
                protocolFee = ethFee - relayerFee;
                totalProtocolFeesEth += protocolFee;
            }
            
            // Interaction - Transfer relayer fee immediately
            if (relayerFee != 0) {
                _safeTransferETH(fulfillingRelayer, relayerFee);
            }
        }

        emit BitcoinPaymentCompleted(
            requestId, btcTxid, req.fromBtcAddress, req.toBtcAddress, req.amountSats
        );
        emit BitcoinTransactionProof(requestId, publicKey, btcTxid, proof);
    }

    /**
     * @dev Safe ETH transfer with custom error
     */
    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - CANCELLATION
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Cancel a stuck request after 24 hours and refund ETH
     * @dev Only the original requester can cancel. Follows CEI pattern.
     *      Marks request as fulfilled to prevent double-cancel, then refunds ETH.
     * @param requestId ID of the request to cancel
     */
    function cancelStuckRequest(uint256 requestId) external nonReentrant whenNotPaused notBlacklisted {
        uint256 _requestCount = requestCount;
        if (requestId >= _requestCount) revert InvalidRequest();
        
        PaymentRequest storage req = requests[requestId];
        address _requester = req.requester;
        
        if (msg.sender != _requester) revert NotRequester();
        if (req.fulfilled) revert AlreadyFulfilled();

        uint256 _timestamp = uint256(req.timestamp);
        if (block.timestamp < _timestamp + _ONE_DAY) revert RequestNotStuck();

        // Effects - mark as fulfilled before refund (CEI pattern)
        uint256 refundAmount = req.amountEth;
        req.fulfilled = true;
        req.amountEth = 0;

        emit BitcoinPaymentFailed(requestId, "Cancelled by requester (Stuck)");
        emit RefundIssued(requestId, _requester, refundAmount);

        // Interaction - refund ETH to requester
        if (refundAmount != 0) {
            _safeTransferETH(_requester, refundAmount);
        }
    }

    /**
     * @notice Cancel an expired request after 7 days (callable by anyone)
     * @dev Allows anyone to trigger refund for requests past MAX_REQUEST_AGE.
     *      This prevents ETH from being permanently locked in expired requests.
     *      Follows CEI pattern.
     * @param requestId ID of the request to cancel
     */
    function cancelExpiredRequest(uint256 requestId) external nonReentrant whenNotPaused {
        uint256 _requestCount = requestCount;
        if (requestId >= _requestCount) revert InvalidRequest();
        
        PaymentRequest storage req = requests[requestId];
        if (req.fulfilled) revert AlreadyFulfilled();
        if (uint256(req.timestamp) + _MAX_REQUEST_AGE >= block.timestamp) revert RequestNotStuck();

        // Effects - mark as fulfilled before refund (CEI pattern)
        address _requester = req.requester;
        uint256 refundAmount = req.amountEth;
        req.fulfilled = true;
        req.amountEth = 0;

        emit BitcoinPaymentFailed(requestId, "Auto-expired (7 days)");
        emit RefundIssued(requestId, _requester, refundAmount);

        // Interaction - refund ETH to requester
        if (refundAmount != 0) {
            _safeTransferETH(_requester, refundAmount);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - RELAYER MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register as a relayer with a machine fingerprint
     * @param machineFingerprint Unique machine fingerprint
     */
    function registerRelayer(bytes32 machineFingerprint) external whenNotPaused notBlacklisted {
        if (fingerprintToRelayer[machineFingerprint] != address(0)) {
            revert FingerprintAlreadyRegistered();
        }
        if (relayerToFingerprint[msg.sender] != bytes32(0)) {
            revert RelayerAlreadyRegistered();
        }

        fingerprintToRelayer[machineFingerprint] = msg.sender;
        relayerToFingerprint[msg.sender] = machineFingerprint;

        emit RelayerRegistered(msg.sender, machineFingerprint);
    }

    /**
     * @notice Unregister as a relayer
     */
    function unregisterRelayer() external whenNotPaused {
        bytes32 fingerprint = relayerToFingerprint[msg.sender];
        if (fingerprint == bytes32(0)) revert RelayerNotRegistered();

        delete fingerprintToRelayer[fingerprint];
        delete relayerToFingerprint[msg.sender];

        emit RelayerUnregistered(msg.sender, fingerprint);
    }

    /**
     * @notice Check if a fingerprint is available for registration
     * @param fingerprint Fingerprint to check
     * @return isAvailable True if available
     */
    function isFingerprintAvailable(bytes32 fingerprint) external view returns (bool isAvailable) {
        return fingerprintToRelayer[fingerprint] == address(0);
    }

    /**
     * @notice Get relayer address for a fingerprint
     * @param fingerprint Fingerprint to lookup
     * @return relayerAddress Address of the relayer
     */
    function getRelayerByFingerprint(bytes32 fingerprint) external view returns (address relayerAddress) {
        return fingerprintToRelayer[fingerprint];
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
     * @notice Update the default relayer address
     * @param newRelayer New relayer address
     */
    function updateRelayer(address newRelayer) external onlyOwner {
        if (newRelayer == address(0)) revert ZeroRelayer();
        address oldRelayer = relayer;
        if (oldRelayer == newRelayer) return;
        relayer = newRelayer;
        emit RelayerUpdated(oldRelayer, newRelayer);
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
    function getPaymentRequest(uint256 requestId)
        external
        view
        returns (PaymentRequest memory request)
    {
        if (requestId >= requestCount) revert InvalidRequest();
        return requests[requestId];
    }

    /**
     * @notice Get payment status
     * @param requestId ID of the request
     * @return fulfilled Whether the payment is fulfilled
     * @return btcTxid Bitcoin transaction ID (bytes32(0) if not fulfilled)
     */
    function getPaymentStatus(uint256 requestId)
        external
        view
        returns (bool fulfilled, bytes32 btcTxid)
    {
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

    /**
     * @notice Get the maximum request age before auto-expiration
     * @return maxAge Maximum age in seconds
     */
    function getMaxRequestAge() external pure returns (uint256 maxAge) {
        return _MAX_REQUEST_AGE;
    }

    /**
     * @notice Check if a request has expired
     * @param requestId ID of the request
     * @return expired True if the request has passed max age
     */
    function isRequestExpired(uint256 requestId) external view returns (bool expired) {
        if (requestId >= requestCount) revert InvalidRequest();
        PaymentRequest storage req = requests[requestId];
        if (req.fulfilled) return false;
        return uint256(req.timestamp) + _MAX_REQUEST_AGE < block.timestamp;
    }

    /**
     * @dev Allow contract to receive ETH
     */
    receive() external payable {}
}
