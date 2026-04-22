// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title AtomicIntentStrategyRegistry
 * @notice Stable intent IDs for atomic-swap actions, with mutable execution strategy.
 * @dev This contract is intentionally non-custodial and does not transfer funds.
 *      It exists to anchor "what" (business intent) separately from "how" (execution tactic).
 */
contract AtomicIntentStrategyRegistry {
    error NotOwner();
    error NotAuthorized();
    error IntentAlreadyExists();
    error IntentNotFound();
    error IntentExpired();
    error IntentAlreadyFinalized();
    error InvalidInput();

    enum ActionType {
        RevealSecret,
        ReleaseLeg,
        MarkRefund,
        CollectFee
    }

    enum RouteType {
        PublicMempool,
        PrivateRpc,
        Bundle,
        Delayed,
        RelayerLane
    }

    struct Intent {
        address requester;
        bytes32 swapId;
        ActionType actionType;
        uint8 leg;
        bytes32 amountHash;
        bytes32 payloadHash;
        uint256 expiresAt;
        uint256 createdAt;
        bool finalized;
    }

    struct Strategy {
        RouteType route;
        uint32 gasBumpBps;
        uint64 notBefore;
        bytes32 laneId;
        bytes32 tacticHash;
        uint32 version;
    }

    struct ExecutionRecord {
        address executor;
        bytes32 txHash;
        bool success;
        uint64 at;
    }

    address public owner;

    /// @notice Allowed relayers/executors that can update execution state.
    mapping(address => bool) public isRelayer;

    /// @notice Monotonic nonce per requester to derive deterministic unique intent IDs.
    mapping(address => uint256) public requesterNonce;

    mapping(bytes32 => Intent) public intents;
    mapping(bytes32 => Strategy) public strategies;
    mapping(bytes32 => ExecutionRecord) public lastExecution;

    event RelayerSet(address indexed relayer, bool allowed);
    event IntentSubmitted(
        bytes32 indexed requestId,
        address indexed requester,
        bytes32 indexed swapId,
        ActionType actionType,
        uint8 leg,
        uint256 expiresAt
    );
    event StrategyUpdated(
        bytes32 indexed requestId,
        RouteType route,
        uint32 gasBumpBps,
        uint64 notBefore,
        bytes32 laneId,
        bytes32 tacticHash,
        uint32 version,
        address updater
    );
    event ExecutionAttempted(
        bytes32 indexed requestId,
        address indexed executor,
        bytes32 txHash,
        bool success,
        RouteType route,
        uint32 strategyVersion,
        uint64 at
    );
    event IntentFinalized(bytes32 indexed requestId, address indexed executor, bytes32 txHash, uint64 at);
    event IntentCancelled(bytes32 indexed requestId, address indexed requester);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAuthorized(bytes32 requestId) {
        Intent memory intent = intents[requestId];
        if (intent.requester == address(0)) revert IntentNotFound();
        if (msg.sender != intent.requester && msg.sender != owner && !isRelayer[msg.sender]) {
            revert NotAuthorized();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setRelayer(address relayer, bool allowed) external onlyOwner {
        if (relayer == address(0)) revert InvalidInput();
        isRelayer[relayer] = allowed;
        emit RelayerSet(relayer, allowed);
    }

    /**
     * @notice Submit a business intent and receive a stable request ID.
     * @param swapId Swap identifier from your atomic coordinator.
     * @param actionType Business action (reveal/release/refund/fee).
     * @param leg Leg index (0/1 for leg-specific actions, otherwise 0).
     * @param amountHash Hash of normalized amount representation (off-chain canonicalized).
     * @param payloadHash Hash of canonical action payload (off-chain canonicalized).
     * @param expiresAt Deadline after which execution should not proceed.
     */
    function submitIntent(
        bytes32 swapId,
        ActionType actionType,
        uint8 leg,
        bytes32 amountHash,
        bytes32 payloadHash,
        uint256 expiresAt
    ) external returns (bytes32 requestId) {
        if (swapId == bytes32(0) || payloadHash == bytes32(0)) revert InvalidInput();
        if (expiresAt <= block.timestamp) revert InvalidInput();

        uint256 nonce = ++requesterNonce[msg.sender];
        requestId = keccak256(
            abi.encodePacked(
                msg.sender,
                swapId,
                actionType,
                leg,
                amountHash,
                payloadHash,
                expiresAt,
                nonce
            )
        );

        if (intents[requestId].requester != address(0)) revert IntentAlreadyExists();

        intents[requestId] = Intent({
            requester: msg.sender,
            swapId: swapId,
            actionType: actionType,
            leg: leg,
            amountHash: amountHash,
            payloadHash: payloadHash,
            expiresAt: expiresAt,
            createdAt: block.timestamp,
            finalized: false
        });

        // Default strategy; can be changed over time without changing requestId.
        strategies[requestId] = Strategy({
            route: RouteType.PublicMempool,
            gasBumpBps: 0,
            notBefore: uint64(block.timestamp),
            laneId: bytes32(0),
            tacticHash: bytes32(0),
            version: 1
        });

        emit IntentSubmitted(requestId, msg.sender, swapId, actionType, leg, expiresAt);
    }

    /**
     * @notice Update execution strategy for an existing intent while preserving requestId.
     */
    function updateStrategy(
        bytes32 requestId,
        RouteType route,
        uint32 gasBumpBps,
        uint64 notBefore,
        bytes32 laneId,
        bytes32 tacticHash
    ) external onlyAuthorized(requestId) {
        Intent memory intent = intents[requestId];
        if (intent.finalized) revert IntentAlreadyFinalized();
        if (intent.expiresAt <= block.timestamp) revert IntentExpired();
        if (gasBumpBps > 100_000) revert InvalidInput();

        Strategy memory prev = strategies[requestId];
        Strategy memory next = Strategy({
            route: route,
            gasBumpBps: gasBumpBps,
            notBefore: notBefore,
            laneId: laneId,
            tacticHash: tacticHash,
            version: prev.version + 1
        });

        strategies[requestId] = next;
        emit StrategyUpdated(
            requestId,
            route,
            gasBumpBps,
            notBefore,
            laneId,
            tacticHash,
            next.version,
            msg.sender
        );
    }

    /**
     * @notice Relayer/executor records an execution attempt with current strategy version.
     */
    function recordExecutionAttempt(bytes32 requestId, bytes32 txHash, bool success) external {
        if (!isRelayer[msg.sender]) revert NotAuthorized();

        Intent memory intent = intents[requestId];
        if (intent.requester == address(0)) revert IntentNotFound();
        if (intent.finalized) revert IntentAlreadyFinalized();
        if (intent.expiresAt <= block.timestamp) revert IntentExpired();

        Strategy memory strategy = strategies[requestId];
        if (strategy.notBefore > block.timestamp) revert InvalidInput();

        ExecutionRecord memory rec = ExecutionRecord({
            executor: msg.sender,
            txHash: txHash,
            success: success,
            at: uint64(block.timestamp)
        });
        lastExecution[requestId] = rec;

        emit ExecutionAttempted(
            requestId,
            msg.sender,
            txHash,
            success,
            strategy.route,
            strategy.version,
            rec.at
        );
    }

    /**
     * @notice Finalize intent once execution is accepted as complete by authorized relayer.
     */
    function finalizeIntent(bytes32 requestId, bytes32 txHash) external {
        if (!isRelayer[msg.sender]) revert NotAuthorized();

        Intent storage intent = intents[requestId];
        if (intent.requester == address(0)) revert IntentNotFound();
        if (intent.finalized) revert IntentAlreadyFinalized();

        intent.finalized = true;
        uint64 at = uint64(block.timestamp);
        emit IntentFinalized(requestId, msg.sender, txHash, at);
    }

    /**
     * @notice Requester can cancel an intent before finalization.
     */
    function cancelIntent(bytes32 requestId) external {
        Intent storage intent = intents[requestId];
        if (intent.requester == address(0)) revert IntentNotFound();
        if (msg.sender != intent.requester && msg.sender != owner) revert NotAuthorized();
        if (intent.finalized) revert IntentAlreadyFinalized();

        intent.finalized = true;
        emit IntentCancelled(requestId, msg.sender);
    }

    function getIntentWithStrategy(bytes32 requestId)
        external
        view
        returns (Intent memory intent, Strategy memory strategy, ExecutionRecord memory execution)
    {
        intent = intents[requestId];
        if (intent.requester == address(0)) revert IntentNotFound();
        strategy = strategies[requestId];
        execution = lastExecution[requestId];
    }
}

