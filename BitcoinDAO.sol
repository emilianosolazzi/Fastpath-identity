// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IProof160 {
    function evmToBtc(address evm) external view returns (bytes20);
}

/**
 * @title BitcoinDAO
 * @notice Governance contract where voting power = real Bitcoin holdings (not wrapped tokens)
 * @dev Uses FastPathIdentity to link EVM addresses to Bitcoin Hash160, then reads BTC balance from oracle
 */
contract BitcoinDAO {
    IProof160 public identityContract;
    address public oracle;

    struct Proposal {
        string description;
        uint256 yesVotes;      // Satoshis voting yes
        uint256 noVotes;       // Satoshis voting no
        uint256 endTime;
        bool executed;
        address proposer;
    }

    // Proposal storage
    mapping(uint256 => Proposal) public proposals;
    uint256 public nextProposalId;
    
    // Bitcoin Hash160 -> Balance in Satoshis (Oracle Data)
    mapping(bytes20 => uint256) public btcBalances;
    
    // Proposal ID -> Bitcoin Hash160 -> Has Voted
    mapping(uint256 => mapping(bytes20 => bool)) public hasVoted;

    // Events
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string description, uint256 endTime);
    event VoteCast(address indexed voter, bytes20 btcHash160, uint256 indexed proposalId, uint256 weight, bool support);
    event BalanceUpdated(bytes20 btcHash160, uint256 newBalance);
    event ProposalExecuted(uint256 indexed proposalId, bool passed);

    constructor(address _identity, address _oracle) {
        identityContract = IProof160(_identity);
        oracle = _oracle;
    }

    // ─────────────────────────────────────────────────────────────
    // PROPOSAL MANAGEMENT
    // ─────────────────────────────────────────────────────────────

    function createProposal(string memory description, uint256 votingDays) external returns (uint256) {
        require(votingDays > 0 && votingDays <= 30, "Voting period: 1-30 days");
        
        uint256 proposalId = nextProposalId++;
        proposals[proposalId] = Proposal({
            description: description,
            yesVotes: 0,
            noVotes: 0,
            endTime: block.timestamp + (votingDays * 1 days),
            executed: false,
            proposer: msg.sender
        });

        emit ProposalCreated(proposalId, msg.sender, description, proposals[proposalId].endTime);
        return proposalId;
    }

    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(bytes(p.description).length > 0, "Proposal does not exist");
        require(block.timestamp < p.endTime, "Voting ended");
        
        // 1. Verify Identity Link
        bytes20 btcHash160 = identityContract.evmToBtc(msg.sender);
        require(btcHash160 != bytes20(0), "No Bitcoin identity linked");
        
        // 2. Check Double Voting
        require(!hasVoted[proposalId][btcHash160], "Already voted");

        // 3. Get Voting Power (Real Bitcoin Balance in Satoshis)
        uint256 weight = btcBalances[btcHash160];
        require(weight > 0, "No Bitcoin balance recorded");

        // 4. Cast Vote
        if (support) {
            p.yesVotes += weight;
        } else {
            p.noVotes += weight;
        }
        hasVoted[proposalId][btcHash160] = true;

        emit VoteCast(msg.sender, btcHash160, proposalId, weight, support);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(bytes(p.description).length > 0, "Proposal does not exist");
        require(block.timestamp >= p.endTime, "Voting not ended");
        require(!p.executed, "Already executed");

        p.executed = true;
        bool passed = p.yesVotes > p.noVotes;

        emit ProposalExecuted(proposalId, passed);
    }

    // ─────────────────────────────────────────────────────────────
    // ORACLE / BALANCE MANAGEMENT
    // ─────────────────────────────────────────────────────────────

    /// @notice Update BTC balance for a Hash160 (oracle or demo)
    function updateBalance(bytes20 btcHash160, uint256 balanceSatoshis) external {
        // For sandbox demo, we allow anyone to update
        // In production: require(msg.sender == oracle, "Only oracle");
        btcBalances[btcHash160] = balanceSatoshis;
        emit BalanceUpdated(btcHash160, balanceSatoshis);
    }

    /// @notice Demo helper: set balance for a user by their EVM address (converts BTC to satoshis)
    function demoSetup(address user, uint256 btcAmount) external {
        bytes20 btcHash160 = identityContract.evmToBtc(user);
        require(btcHash160 != bytes20(0), "User has no Bitcoin identity");
        btcBalances[btcHash160] = btcAmount * 1e8; // Convert BTC to satoshis
        emit BalanceUpdated(btcHash160, btcAmount * 1e8);
    }

    // ─────────────────────────────────────────────────────────────
    // VIEW FUNCTIONS
    // ─────────────────────────────────────────────────────────────

    function getProposal(uint256 proposalId) external view returns (
        string memory description,
        uint256 yesVotes,
        uint256 noVotes,
        uint256 endTime,
        bool executed,
        address proposer
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.description, p.yesVotes, p.noVotes, p.endTime, p.executed, p.proposer);
    }

    function getVotingPower(address user) external view returns (uint256) {
        bytes20 btcHash160 = identityContract.evmToBtc(user);
        if (btcHash160 == bytes20(0)) return 0;
        return btcBalances[btcHash160];
    }

    function hasUserVoted(uint256 proposalId, address user) external view returns (bool) {
        bytes20 btcHash160 = identityContract.evmToBtc(user);
        if (btcHash160 == bytes20(0)) return false;
        return hasVoted[proposalId][btcHash160];
    }

    function getProposalCount() external view returns (uint256) {
        return nextProposalId;
    }
}

