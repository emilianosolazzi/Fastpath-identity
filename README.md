<p align="center">
  <img src="assets/bitid-logo.png" alt="BitID Logo" width="160" />
</p>

# FastPath Protocol

**Non-custodial Bitcoin ↔ EVM bridge and identity layer.**

FastPath connects Bitcoin to EVM chains (Ethereum, Arbitrum, Polygon, Base) and Solana through a decentralized relay architecture. The core primitive is **Proof160** — a permanent, cryptographic mapping between Bitcoin Hash160 identities and EVM addresses, verified entirely on-chain.

> **Live at:** [nativebtc.org](https://nativebtc.org)

---

## How It Works

```
Bitcoin Private Key
  → secp256k1 Public Key (33 bytes, compressed)
    → SHA256 → RIPEMD160 → Hash160 (20 bytes)
      → FastPathIdentity contract: hash160 → EVM address
        → On-chain identity, DeFi, governance, naming
```

A user signs a message with their Bitcoin private key. The contract verifies the signature, derives the Hash160 from the public key, and permanently binds it to the caller's EVM address. No oracles, no bridges, no trust assumptions — pure cryptography.

---

## Architecture

FastPath runs **6 services** on a single relayer node:

| Service | Port | Description |
|:--------|:-----|:------------|
| **Relayer API** | 3777 | PSBT creation, Bitcoin ops, Solana integration |
| **Identity Server** | 3778 | EVM ↔ BTC ↔ Solana address resolution |
| **Proxy Shim** | 4444 | `eth_*` → BTC translation (MetaMask compatibility) |
| **Solana Bridge** | 4445 | Solana RPC translation, cross-chain bridge |
| **BTC Relayer** | — | Watches on-chain events, broadcasts signed BTC TXs |
| **Swap Bridge** | 3848 | 2-way BTC ↔ EVM atomic swaps |

### Security Model

- **Non-custodial**: Bitcoin Core runs with `disablewallet=1` — the server holds **zero** private keys
- **PSBT workflow**: Server creates unsigned PSBTs → user signs with Ledger/Sparrow → server broadcasts
- **Multi-source verification**: Bitcoin Core + Mempool.space + Blockstream for TX finality
- **Hardware signing**: Production transactions signed via Ledger through proxy endpoint

---

## Smart Contracts

All contracts target **Solidity 0.8.30** with Foundry. 485 tests pass across 16 test suites.

### Core Contracts

| Contract | Version | Description | Network |
|:---------|:--------|:------------|:--------|
| **FastPathIdentity** | — | Permanent BTC Hash160 ↔ EVM registry with secure relink | Sepolia |
| **BitcoinGateway** | v1.4.0 | Bitcoin payment proof registry. Registered users submit proofs + pay ETH fee (0.0002–0.001 ETH, owner-configurable) | Arbitrum One |
| **CrossChainProofVerifier** | — | Pure view-only BTC → EVM identity proof verification. Any EVM contract can call it. No storage, no admin. | — |
| **BitIDRewardDistributor** | — | Mints BITID tokens to reward protocol actions (registration, naming, proof submission) | — |
| **ZKHash160PrivacyPool** | — | Groth16 ZK-proof privacy pool for anonymous BTC transactions | — |

### Identity Stack

| Contract | Description |
|:---------|:------------|
| **BitcoinNameService (BNS)** | Human-readable names for Hash160 identities (`satoshi.btc`) |
| **Hash160Vault** | DeFi vault using BTC Hash160 as account identifier |
| **Proof160 NFT** | On-chain SVG NFT for early adopter identity holders |

### Reward Actions (BitIDRewardDistributor)

| Action | BITID Minted | Trigger |
|:-------|:-------------|:--------|
| `IDENTITY_REGISTRATION` | 160 | Register BTC Hash160 in FastPathIdentity |
| `BNS_REGISTRATION` | 16 | Register a `.btc` name |
| `BNS_RENEWAL` | 8 | Renew a `.btc` name |
| `GATEWAY_RELAY` | 1 | Submit a Bitcoin payment proof |
| `FIRST_TRANSFER` | 32 | First token transfer |
| `REFERRAL` | 10 | Referral bonus |

### Deployment Order

```
1. FastPathIdentity
2. BitcoinGateway          (requires FastPathIdentity address)
3. BitcoinNameService      (requires FastPathIdentity address)
4. BitIDRewardDistributor  (requires BITID token address)
5. CrossChainProofVerifier (requires FastPathIdentity + BitcoinGateway addresses)

# Wire rewards (6 calls):
distributor.setCaller(identity, true)
distributor.setCaller(bns, true)
distributor.setCaller(gateway, true)
identity.setRewardDistributor(distributor)
bns.setRewardDistributor(distributor)
gateway.setRewardDistributor(distributor)
```

### Companion / Sandbox

| Contract | Description |
|:---------|:------------|
| **BitcoinDAO** | Governance where voting power = real BTC holdings via Hash160 |
| **BTCBackedVault** | Demo lending vault requiring Bitcoin identity registration |
| **CrossChainSafeSwap** | Zero-fee HTLC cross-chain self-swaps with safety guarantees |
| **DemoUSD** | Test stablecoin for sandbox environment |
| **BtcVoucher** | Bitcoin-backed voucher system |

---

## Deployed Addresses

### Arbitrum One (Mainnet)

| Contract | Address |
|:---------|:--------|
| BitcoinGateway | `0xC1cD19BF230ddf86fdB59Dc308D61480057E9d8e` |

### Sepolia (Testnet / Identity)

| Contract | Address |
|:---------|:--------|
| FastPathIdentity (Proof160) | `0x2bAeD4982Aa37c9b7ab5Cd321f4f29e59D9C8757` |
| Proof160 NFT | `0x44b70f74708804457E8e4dE39102F8BcDd788787` |
| BitcoinDAO | `0x8f92abBB1081879a9aCC5E30E28611047a7e7CA2` |
| BTCBackedVault | `0xE62feC78242b28dB89c80dBbf46576DBAd46D35E` |
| PublicBitcoinGateway | `0xc87D98735fc7300A4e708841a6074A2F30495b06` |
| DemoUSD | `0x6227e26f3b705e9e0d395cb9cf501a0190ec0510` |

---

## Key Concepts

### Three-Layer Identity Model

FastPathIdentity uses a three-layer ownership model:

| Layer | Mapping | Mutability | Purpose |
|:------|:--------|:-----------|:--------|
| 1 | `btcToEvm` | **Immutable** | Permanent historical record of original registrant |
| 2 | `evmToBtc` | **Append-only** | Audit trail — both old and new EVM addresses preserved |
| 3 | `activeEvm` | **Mutable** | Current controller (changes on relink) |

After a relink, Layer 1 and 2 still return the original data. Only Layer 3 (`currentController()`) reflects the new owner. Always use `hasControl()` or `currentController()` for authorization checks.

### Bitcoin Name Service (BNS)

Resolution chain: `"satoshi.btc" → Hash160 → EVM address`

- 3–32 char lowercase alphanumeric names + hyphens
- 1-year registration with 30-day grace period
- Text records (avatar, url, description)
- Subdomains (`wallet.satoshi.btc`)
- Bijection: one name per Hash160, one Hash160 per name

### Non-Custodial PSBT Flow

```
User Intent → API creates unsigned PSBT → User signs externally → API broadcasts → Multi-source verification
```

The server never touches private keys. All signing happens on the user's hardware wallet or software wallet.

---


## License

[MIT](LICENSE) — Copyright (c) 2025 BitcoinCab.inc

---

## Author

**Emiliano Solazzi** ([@emilianosolazzi](https://github.com/emilianosolazzi))
