# OmniRPC Multi-Chain Direct RPC & On-Chain Mining Intelligence (Architecture v2)

Direct multi-chain RPC infrastructure and autonomous 5-layer mining protocol radar covering **807+ live blockchains** across EVM (`598`), Cosmos/IBC (`131`), Polkadot/Substrate (`73` via `wss://`), Solana (Helius + PublicNode fallback), Sui (GraphQL), Aptos, Near, TON, and PoW/UTXO networks (`Bitcoin`, `Kaspa`, `Ergo`).

## 5-Layer Architecture v2

1. **Layer 1 — Multi-RPC Failover & Cooldown Rotator (`omnirpc_client.py`)**:
   - Latency-ranked endpoint rotation with exponential backoff circuit breakers on HTTP `429`/`403`/timeouts.
   - Core EVM fallbacks (`llamarpc`, `publicnode`, `mainnet.base.org`, `arb1.arbitrum.io`, `bsc-dataseed`), Helius Solana RPC/DAS with `mainnet-beta.solana.com` & `solana-rpc.publicnode.com` fallbacks, and `rest.cosmos.directory/{slug}` Cosmos fallback.
2. **Layer 2 — On-Chain Mining Scanner (`onchain_mining_scanner.py`)**:
   - Direct block, calldata 4-byte selector (`api.4byte.sourcify.dev` + OpenChain fallback), `Transfer(0x0)` Mint log, Solana `Program` / Helius `getBlock` + `getProgramAccounts`, and Sui/Cosmos/Substrate scanning.
3. **Layer 3 — 7-Source Protocol Profiler & Security Engine (`protocol_profiler.py`)**:
   - Direct `OmniRPC` (`name()`, `symbol()`, `decimals()`, `totalSupply()`, ERC-721/1155, bytecode analysis).
   - **Sourcify v2** (`sourcify.dev/server/v2/contract/...`) & **Blockscout v2** (646 EVM chains).
   - **GoPlus Security** (EVM token/honeypot/mintable/tax audit) & **RugCheck** + **ProgramWatch** + **Helius DAS** (Solana).
   - **DexScreener**, **GeckoTerminal**, and **Jupiter Price v3** live USD price & liquidity enrichment.
   - Live **16-Provider Architecture Health Monitor** (`check_all_apis_health`).
4. **Layer 4 — Persistent Deduplicated Registry (`mining_registry.py`)**:
   - Deduplicated JSON (`mining_registry.json`) & CSV (`mining_registry.csv`) store with camelCase ABI classification (`GameFi`, `PoW / Fair-Mint`, `DeFi / Yield`, `NFT Mint`, `Claim / Airdrop`).
5. **Layer 5 — Local Gateway, 15-Minute Auto-Miner & Dashboards (`omnirpc_server.py`, `dashboard/`)**:
   - `/` (Multi-Chain Gateway) and `/mining` (Autonomous 15-minute Mining Radar + 16-API Health Modal).
