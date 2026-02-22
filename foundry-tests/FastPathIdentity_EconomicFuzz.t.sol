// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "contracts/fastapthidentity.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address sender) external;
    function addr(uint256 privateKey) external returns (address);
}

/**
 * @title Economic Fuzzing Test for FastPathIdentity
 * @notice Defines value functions for adversarial profit optimization
 * @dev Used by economic_fuzzer.py to detect exploits via ΔV maximization
 */
contract FastPathIdentityEconomicFuzz {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    
    FastPathIdentity public identity;
    address public attacker = address(0x1337);
    address public victim = address(0xDEAD);
    
    function setUp() public {
        identity = new FastPathIdentity(0.001 ether);
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }
    
    // ==========================================
    // VALUE FUNCTIONS (Economic Fuzzer reads these)
    // ==========================================
    
    /// @notice Primary value function: attacker's ETH balance
    /// @dev This is what the economic optimizer maximizes: ΔV(attacker)
    function valueETH() public view returns (int256) {
        return int256(attacker.balance);
    }
    
    /// @notice Alternative: ownership theft value
    /// @dev Returns MAX_INT if attacker controls target identity, else 0
    function valueOwnership(bytes20 targetHash) public view returns (int256) {
        address controller = identity.currentController(targetHash);
        return (controller == attacker) ? type(int256).max : int256(0);
    }
    
    /// @notice Alternative: registration fee theft
    /// @dev Value = accumulated fees that attacker can drain
    function valueFees() public view returns (int256) {
        return int256(address(identity).balance);
    }
    
    // ==========================================
    // ATTACK PARAMETERS (Symbolic variables)
    // ==========================================
    
    /// @notice Declares attacker-controlled parameters for SMT solver
    /// @dev Economic fuzzer creates symbolic variables for these
    function attackParamsReceiveFunds() public pure returns (string[] memory) {
        string[] memory params = new string[](2);
        params[0] = "btcHash160:bytes20";
        params[1] = "amount:uint256";
        return params;
    }
    
    function attackParamsRelink() public pure returns (string[] memory) {
        string[] memory params = new string[](4);
        params[0] = "btcHash160:bytes20";
        params[1] = "newEvm:address";
        params[2] = "pubkey:bytes";
        params[3] = "signature:bytes";
        return params;
    }
    
    function attackParamsRegistration() public pure returns (string[] memory) {
        string[] memory params = new string[](5);
        params[0] = "pubkeyPrefix:uint8";
        params[1] = "pubkeyX:bytes32";
        params[2] = "r:bytes32";
        params[3] = "s:bytes32";
        params[4] = "v:uint8";
        return params;
    }
    
    // ==========================================
    // ATTACK SCENARIOS (What to fuzz)
    // ==========================================
    
    /// @notice Scenario 1: Reentrancy in receiveFunds
    /// @dev Try to drain ETH via recursive calls
    function scenarioReentrancy() public pure returns (string memory) {
        return "receiveFunds";
    }
    
    /// @notice Scenario 2: Ownership hijacking via relink
    /// @dev Try to steal control of victim's BTC identity
    function scenarioOwnershipTheft() public pure returns (string memory) {
        return "initiateRelink,finalizeRelink";
    }
    
    /// @notice Scenario 3: Fee drain via owner privilege
    /// @dev Try to escalate to owner and drain fees
    function scenarioFeeTheft() public pure returns (string memory) {
        return "withdrawFees";
    }
    
    /// @notice Scenario 4: Double registration
    /// @dev Try to register same BTC hash twice with different EVM addresses
    function scenarioDoubleRegistration() public pure returns (string memory) {
        return "registerBitcoinAddressV2";
    }
    
    // ==========================================
    // CONFIGURATION
    // ==========================================
    
    /// @notice Max transaction trace depth
    /// @dev Realistic exploits are 2-5 steps, flash loans can be 10+
    function maxTraceDepth() public pure returns (uint256) {
        return 5;
    }
    
    /// @notice Minimum profitable ΔV to report
    /// @dev Only report if attacker gains at least this much
    function minProfitThreshold() public pure returns (uint256) {
        return 0.001 ether;
    }
    
    /// @notice SMT solver timeout (seconds)
    function solverTimeout() public pure returns (uint256) {
        return 60;
    }
    
    // ==========================================
    // HELPER: Manual Exploit PoC (for comparison)
    // ==========================================
    
    /// @notice Manual reentrancy PoC (before economic fuzzer finds it)
    /// @dev This is what the fuzzer should auto-discover
    function testManualReentrancyPoC() public {
        // Setup: register attacker's BTC hash
        bytes20 attackerHash = bytes20(keccak256("attacker-btc"));
        
        // Manually set up state (in real fuzzer, this is symbolic)
        vm.prank(address(this)); // Simulate storage manipulation
        // Would need vm.store to set btcToEvm[attackerHash] = maliciousContract
        
        // Attack: call receiveFunds, trigger reentrancy
        // (This would be auto-generated by economic fuzzer)
    }
}

/**
 * @title Malicious Receiver for Reentrancy Testing
 * @notice Contract that attempts to drain via reentrancy
 */
contract MaliciousReceiver {
    FastPathIdentity public target;
    bytes20 public myHash;
    uint256 public attackCount;
    
    constructor(FastPathIdentity _target, bytes20 _hash) {
        target = _target;
        myHash = _hash;
    }
    
    receive() external payable {
        // Reentrancy attack
        if (attackCount < 10 && address(target).balance > 0) {
            attackCount++;
            target.receiveFunds{value: msg.value}(myHash);
        }
    }
    
    function startAttack() external payable {
        attackCount = 0;
        target.receiveFunds{value: msg.value}(myHash);
    }
}

