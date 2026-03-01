<div align="center">

# Fastpath Identity

**The Bitcoin Identity Layer for EVM — Proof160 Protocol**

*Permanent, cryptographically-verified Bitcoin ↔ EVM address mapping with a full DeFi ecosystem built on top.*

[![CI](https://github.com/emilianosolazzi/Fastpath-identity/actions/workflows/test.yml/badge.svg)](https://github.com/emilianosolazzi/Fastpath-identity/actions/workflows/test.yml)
[![Foundry CI](https://github.com/emilianosolazzi/Fastpath-identity/actions/workflows/foundry-ci.yml/badge.svg)](https://github.com/emilianosolazzi/Fastpath-identity/actions/workflows/foundry-ci.yml)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.30-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Overview

Fastpath Identity implements the **Proof160 Protocol** — a system that creates permanent, on-chain links between Bitcoin addresses and EVM addresses using the Hash160 cryptographic primitive (`RIPEMD160(SHA256(pubkey))`). Every registration is verified by a Bitcoin signature proving private key ownership, meaning **zero trust is required**.

On top of this identity layer, the protocol provides a complete ecosystem: a naming service (`.btc` domains), a utility token, a payment gateway, an attestation-based lending vault, governance, and an early adopter NFT — all gated by Bitcoin identity.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FASTPATH IDENTITY LAYER                        │
│                                                                        │
│  Bitcoin Private Key                                                   │
│    → Compressed Public Key (33 bytes)                                  │
│      → SHA256 → RIPEMD160 → Hash160 (20 bytes)                        │
│        → FastPathIdentity.register() → Permanent EVM mapping           │
│                                                                        │
│  Three mapping layers:                                                 │
│    btcToEvm   (immutable origin)    — who registered first             │
│    evmToBtc   (historical record)   — full audit trail                 │
│    activeEvm  (current controller)  — who controls it NOW              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
          ┌────────────────────┼──────────────────────┐
          │                    │                      │
          ▼                    ▼                      ▼
   ┌──────────────┐  ┌─────────────────┐  ┌──────────────────────┐
   │   BitID       │  │  Bitcoin Name   │  │   BitcoinGateway     │
   │   (ERC-20)    │  │  Service (BNS)  │  │   Payment Intents    │
   │               │  │                 │  │                      │
   │  160M cap     │  │  "name.btc"     │  │  BTC payment proofs  │
   │  8 decimals   │  │  → hash160      │  │  Fingerprint system  │
   │  Identity-    │  │  → EVM addr     │  │  Proof fees in ETH   │
   │  gated xfers  │  │                 │  │                      │
   └──────┬───────┘  └────────┬────────┘  └──────────┬───────────┘
          │                   │                      │
          ▼                   ▼                      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │              BitIDRewardDistributor                          │
   │  Mints BitID for: registration, BNS, gateway relays,       │
   │  onboarding, referrals. Epoch budgets + per-user cooldowns. │
   └──────────────────────────────────────────────────────────────┘
          │
          ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                   ATTESTATION LAYER                          │
   │                                                              │
   │  FastPath API (api.nativebtc.org)                            │
   │    → EIP-712 signed BTC balance proofs                       │
   │    → Nonce replay protection + timestamp expiry              │
   │                                                              │
   │  FastpathAttestationVerifier → BTCBackedVaultV2              │
   │    Real BTC holdings as collateral for DeFi lending          │
   └──────────────────────────────────────────────────────────────┘
```

## Contracts

### Core Identity

| Contract | Description |
|----------|-------------|
| **`FastPathIdentity`** | Permanent Bitcoin ↔ EVM registry. Signature-verified registration, secure 2-step relink with cooldown, fund routing (ETH + ERC-20), emergency stop, discount NFT support. |
| **`FastPathBTC`** | Library for lossless Bitcoin address encoding/decoding. Supports P2PKH, P2SH, Bech32 (SegWit), and Bech32m (Taproot). Packs addresses into 2 storage slots. |

### Token & Rewards

| Contract | Description |
|----------|-------------|
| **`BitID`** | ERC-20 utility token (8 decimals, matching Bitcoin's satoshi precision). 160M hard cap. Multi-minter model, EIP-2612 Permit for gasless approvals, optional identity-gated transfers. Owner mint capped at 10%. |
| **`BitIDRewardDistributor`** | Central reward hub. Mints BitID for 6 protocol actions: identity registration, BNS registration/renewal, gateway relay, onboarding bonus, and referrals. Per-user cooldowns and epoch-based minting budgets prevent farming. |

### Naming

| Contract | Description |
|----------|-------------|
| **`BitcoinNameService`** | Human-readable `.btc` names for Bitcoin identities. Three-hop resolution: `"satoshi.btc" → hash160 → EVM address`. Supports text records (avatar, URL, etc.), subdomains, 1-year expiry with grace period, and payment in ETH, ERC-20, or BitID (burn). |

### Payments & Attestation

| Contract | Description |
|----------|-------------|
| **`BitcoinGateway`** | On-chain registry for Bitcoin payment intents. Records intent (from, to, sats) and fulfillment proof (BTC txid, pubkey). Fingerprint-based user registration, blacklist system, configurable proof fees. |
| **`CrossChainProofVerifier`** | Verifies Bitcoin → EVM identity proofs by deriving Hash160 from a 33-byte compressed public key and resolving it through FastPathIdentity. Deterministic and fully on-chain. |
| **`FastpathAttestationVerifier`** | Verifies EIP-712 signed attestations from the FastPath API (`api.nativebtc.org`). Nonce replay protection, timestamp expiry, signer rotation, and trusted caller delegation. |
| **`IFastpathAttestation`** | Interface for integrating attestation verification into third-party contracts. |

### DeFi

| Contract | Description |
|----------|-------------|
| **`BTCBackedVault`** | Demo lending vault — deposit ETH collateral, borrow DemoUSD at 50% LTV. Requires a registered Bitcoin identity. |
| **`BTCBackedVaultV2`** | Production attested-collateral vault. Users submit FastPath API balance proofs of their **real Bitcoin holdings** and borrow against them. Chainlink price feeds, 50% LTV, liquidation with 5% bonus. Freshness enforcement (1-hour max attestation age). |
| **`DemoUSD`** | Demo stablecoin (dUSD) minted/burned exclusively by the vault for lending showcase. |

### Governance & NFT

| Contract | Description |
|----------|-------------|
| **`BitcoinDAO`** | Governance where voting power equals real Bitcoin holdings (in satoshis) via oracle. Proposal creation, weighted voting, and execution. |
| **`Proof160`** | On-chain SVG NFT collection (160 max supply). Early adopter claim via trusted signer signature verification. Dynamic serial numbers rendered in the SVG. |

## Key Design Decisions

### Three-Layer Mapping Model
- **`btcToEvm`** — Immutable. Records the first EVM address that registered a Hash160. Never modified.
- **`evmToBtc`** — Historical. Both old and new addresses retain entries after relink, preserving a full audit trail.
- **`activeEvm`** — Current authority. The only mapping that changes on relink. All access control flows through `currentController()`.

### Signature Verification
Registration requires proving Bitcoin private key ownership:
1. User signs their EVM address with their Bitcoin key
2. Contract derives Hash160 from the public key: `RIPEMD160(SHA256(pubkey))`
3. Signature is verified on-chain with EIP-2 low-s enforcement
4. Mapping is permanently created

### Relink Security
Identity relink (changing the EVM controller for a Hash160) follows a 2-step process:
1. **Initiate** — The *new* EVM address requests the relink
2. **Finalize** — After a cooldown period (default 3 days), the *new* address confirms
3. The *current* controller can cancel at any time during the cooldown

### Attestation Trust Model
`BTCBackedVaultV2` uses an **attested collateral** model — the FastPath API signs EIP-712 proofs of on-chain Bitcoin balances. This is **not** trustless bridging; it depends on the FastPath signer's integrity. Integrators should understand this trust assumption.

## Project Structure

```
src/
├── Fastpathidentity.sol          # Core identity registry
├── BitID.sol                     # Utility token (ERC-20)
├── BitIDRewardDistributor.sol    # Reward distribution hub
├── BitcoinNameService.sol        # .btc naming service
├── BitcoinGateway.sol            # BTC payment intent registry
├── CrossChainProofVerifier.sol   # Bitcoin → EVM proof verification
├── BitcoinDAO.sol                # Bitcoin-weighted governance
├── BTCBackedVault.sol            # Demo lending vault
├── DemoUSD.sol                   # Demo stablecoin
├── Proof160-NFT.sol              # Early adopter on-chain SVG NFT
├── attestation/
│   ├── FastpathAttestationVerifier.sol  # EIP-712 attestation verification
│   ├── BTCBackedVaultV2.sol             # Production attested lending vault
│   └── IFastpathAttestation.sol         # Attestation interface
└── libraries/
    └── FastpathBTC.sol           # Bitcoin address encoding library

test/
├── FastPathIdentity_Full.t.sol          # 100 tests — identity registration, relink, fund routing
├── FastPathIdentity_Security.t.sol      # 23 tests — reentrancy, access control, edge cases
├── FastPathIdentity_EconomicFuzz.t.sol  # 7 tests — fee economics fuzzing
├── BitcoinGateway.t.sol                 # 60 tests — payment intents, proof submission
├── BitcoinGateway_Security.t.sol        # 35 tests — gateway security & access control
├── BitcoinGatewayReentrancyTest.t.sol   # 2 tests — reentrancy protection
├── BitcoinGateway_EconomicFuzz.t.sol    # Fuzzing for gateway economics
├── BitcoinNameService_Full.t.sol        # 72 tests — BNS registration, resolution, subdomains
├── BTCBackedVaultV2_Security.t.sol      # Vault attestation & liquidation tests
├── Invariant_Fuzz.t.sol                 # Protocol-wide invariant testing
└── FuzzTests                            # Additional fuzz targets
```

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Build

```shell
forge build
```

### Test

```shell
# Run all 323 tests
forge test

# Verbose output
forge test -vvv

# Run specific test suite
forge test --match-contract FastPathIdentityFullTest
```

### Format

```shell
forge fmt
```

### Contract Sizes

```shell
forge build --sizes
```

## Security

- **EIP-2 enforcement** — Low-s signature validation prevents signature malleability
- **Reentrancy protection** — All state-modifying functions use reentrancy guards
- **CEI pattern** — Checks-Effects-Interactions ordering throughout
- **Two-step ownership** — Admin transfers require acceptance by the new owner
- **Emergency stop** — Owner can halt sensitive operations
- **Fee caps** — Registration fees capped at 1 ETH to prevent griefing
- **Epoch budgets** — Reward minting rate-limited per time period
- **Nonce replay protection** — Attestations are single-use
- **Cooldown enforcement** — Relink operations have mandatory waiting periods
- **Pull payments** — Fund routing uses pull-payment pattern to prevent reentrancy

## API Integration

The attestation layer integrates with the FastPath API:

```
# Get the trusted signer address
GET https://api.nativebtc.org/v1/attest/signer

# Request a balance attestation
POST https://api.nativebtc.org/v1/attest/balance
Body: { "evmAddress": "0x...", "btcAddress": "bc1q...", "chainId": 1 }

# Request a UTXO ownership attestation
POST https://api.nativebtc.org/v1/attest/ownership
Body: { "evmAddress": "0x...", "btcAddress": "bc1q...", "utxoTxid": "...", "utxoIndex": 0 }
```

## License

[MIT](LICENSE)

---

<div align="center">

**Built by [Emiliano Solazzi](https://github.com/emilianosolazzi) — 2026**

*FastPath / Proof160 Protocol*

</div>
