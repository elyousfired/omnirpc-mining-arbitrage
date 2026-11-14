"""
Hourly Multi-Chain PoW, GPU-Mineable & Fair-Mint Scanner (v3).
Discovers authentic user-mineable & GPU Proof-of-Work protocols across ALL blockchains:
  1. Small & Obscure EVM + Cosmos + Substrate + Solana + TON + Sui + Cardano chains
     via rotating OmniRPC block scans (live_rpc_pool.json: 598 EVM, 131 Cosmos, 73 Substrate).
  2. Live GPU PoW ecosystems via WhatToMine (41+ GPU PoW coins) & WoolyPooly (23+ small/alt PoW pools).
  3. Small-chain Blockscout v2 token discovery (excluding testnets).
  4. Multi-chain DexScreener search with dynamic live_rpc_pool chain resolution + testnet rejection.
  5. Strict official website HTML check (Mint UI or GPU PoW Miner guide, NO idle games, NO AI-only miners).
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp

from mining_registry import is_actionable_mining_protocol, load_registry, save_registry, utc_now_iso
from omnirpc_client import OmniRPC
import onchain_mining_scanner
from protocol_profiler import CURATED_MINING_SEEDS, enrich_registry_items_onchain

ROOT = Path(__file__).resolve().parent
BS_CACHE_PATH = ROOT / "blockscout_explorers_cache.json"

TESTNET_SLUGS = {
    "robinhood", "arc", "sepolia", "goerli", "holesky", "amoy",
    "mumbai", "fuji", "chapel", "devnet", "testnet", "mordor",
    "shibuya", "fusespark", "rinkeby", "kovan", "ropsten",
}

TESTNET_NAME_MARKERS = (
    "testnet", "sepolia", "goerli", "holesky", "amoy", "mumbai",
    "devnet", "robinhood", "faucet", "mordor", "shibuya", "spark",
)

BAD_DOMAIN_FRAGMENTS = (
    "github.com", "x.com", "twitter.com", "t.me", "discord.gg",
    "discord.com", "medium.com", "youtube.com", "pump.fun",
    "dexscreener.com", "geckoterminal.com", "coingecko.com",
    "coinmarketcap.com", "linktr.ee", "reddit.com", "wikipedia.org",
    "stonkfun.xyz", "mint.club", "carrd.co", "jettmirqirvonal",
    "proofofbagwork", "dragoncoin.meme", "edenorex.io", "theantminer.xyz",
    "thevirusonton", "proofofcapital.org", "zendawg.io", "globalxetfs.com",
    "nevergiveup.art", "minted.team", "mtonga.com", "toninu.tech",
    "bonkcoin.com", "pump.tires",
    "dynexcoin.org", "firo.org", "zano.org", "ergoplatform.org",
    "confluxnetwork.org", "octa.space", "ethereumclassic.org",
    "clore.ai", "runonflux.io", "aipowergrid.io", "tari.com", "qu.ai",
    "alephium.org", "0xbitcoin.org",
)

# Extra non-EVM / alt-L1 DexScreener slug mappings beyond live_rpc_pool.json
ALT_DEX_CHAIN_MAP: dict[str, tuple[str, str, str, str]] = {
    "ethereum": ("EVM", "1", "Ethereum", "ETH"),
    "base": ("EVM", "8453", "Base", "ETH"),
    "bsc": ("EVM", "56", "BNB Chain", "BNB"),
    "arbitrum": ("EVM", "42161", "Arbitrum", "ETH"),
    "polygon": ("EVM", "137", "Polygon", "POL"),
    "optimism": ("EVM", "10", "Optimism", "ETH"),
    "avalanche": ("EVM", "43114", "Avalanche", "AVAX"),
    "pulsechain": ("EVM", "369", "PulseChain", "PLS"),
    "conflux": ("EVM", "1030", "Conflux eSpace", "CFX"),
    "sonic": ("EVM", "146", "Sonic", "S"),
    "berachain": ("EVM", "80094", "Berachain", "BERA"),
    "abstract": ("EVM", "2741", "Abstract", "ETH"),
    "hyperevm": ("EVM", "999", "HyperEVM", "HYPE"),
    "fantom": ("EVM", "250", "Fantom", "FTM"),
    "scroll": ("EVM", "534352", "Scroll", "ETH"),
    "linea": ("EVM", "59144", "Linea", "ETH"),
    "mantle": ("EVM", "5000", "Mantle", "MNT"),
    "gnosis": ("EVM", "100", "Gnosis", "xDAI"),
    "celo": ("EVM", "42220", "Celo", "CELO"),
    "cronos": ("EVM", "25", "Cronos", "CRO"),
    "core": ("EVM", "1116", "Core", "CORE"),
    "metis": ("EVM", "1088", "Metis", "METIS"),
    "moonbeam": ("EVM", "1284", "Moonbeam", "GLMR"),
    "ethereumclassic": ("EVM", "61", "Ethereum Classic", "ETC"),
    "ethereumpow": ("EVM", "10001", "EthereumPoW", "ETHW"),
    "solana": ("Solana", "solana", "Solana", "SOL"),
    "ton": ("TON", "ton", "TON", "TON"),
    "sui": ("Sui", "sui", "Sui", "SUI"),
    "cardano": ("Cardano", "cardano", "Cardano", "ADA"),
    "tron": ("Tron", "tron", "Tron", "TRX"),
    "aptos": ("Aptos", "aptos", "Aptos", "APT"),
    "near": ("Near", "near", "Near", "NEAR"),
    "xrpl": ("XRPL", "xrpl", "XRPL", "XRP"),
}

SEARCH_QUERIES = [
    "claimrank", "startmint", "titanx", "xen mint", "fair mint",
    "mint to earn", "web3 miner", "mine token", "pulsechain mint", "glaze",
    "transform", "dragonx", "volt", "hyper", "pmint", "mrdn",
    "ore", "drillx", "epow", "pow token", "proof of work", "nonce",
    "burnandmint", "blockreward",
]

# Unambiguous Web3 Connect-Wallet Mint phrases (delegated to JS-bundle inspector in wallet_simulator.py)
MINT_OR_GPU_POW_PHRASES = (
    "connect wallet", "start mining", "mine now", "claim mint", "start mint",
    "claim rank", "proof of work", "proof-of-work", "glaze", "transform",
    "enter auction", "mint now", "nonce", "difficulty",
)

MINT_OR_GPU_POW_WORDS = ("pow", "mint", "mine", "nonce", "difficulty", "claimrank", "minter")

REJECT_SITE_MARKERS = (
    "ai agents mine for you", "autonomous agent mining", "no wallet needed to play",
    "tap to earn", "idle clicker", "domain for sale", "buy this domain",
    "memecoin", "meme coin", "copper miners etf", "global x etf",
    "sportsbook", "casino", "?click=", "music is the meme",
    "stratum+tcp", "hiveos", "lolminer", "rigel", "bzminer", "srbminer",
)


def _is_testnet_chain(slug_or_name: str, cid: Any = "") -> bool:
    blob = f"{slug_or_name} {cid}".lower()
    if str(cid).strip().lower() in ("46630", "arc", "robinhood"):
        return True
    if str(slug_or_name).strip().lower() in TESTNET_SLUGS:
        return True
    return any(m in blob for m in TESTNET_NAME_MARKERS)


def _build_chain_resolver(omni: OmniRPC) -> dict[str, tuple[str, str, str, str]]:
    """Combine live_rpc_pool.json (598 EVM + Cosmos + Substrate) with ALT_DEX_CHAIN_MAP."""
    resolver = dict(ALT_DEX_CHAIN_MAP)
    for c in omni.pool.get("evm", []):
        cname = str(c.get("name") or "")
        cid = str(c.get("chain_id") or "")
        if not cname or not cid or _is_testnet_chain(cname, cid):
            continue
        slug = re.sub(r"[^a-z0-9]+", "", cname.lower())
        sym = str(c.get("native_symbol") or "ETH")
        if slug and slug not in resolver:
            resolver[slug] = ("EVM", cid, cname, sym)
        short_slug = cname.lower().split()[0]
        short_slug = re.sub(r"[^a-z0-9]+", "", short_slug)
        if short_slug and short_slug not in resolver and len(short_slug) >= 3:
            resolver[short_slug] = ("EVM", cid, cname, sym)
    return resolver


def _is_good_project_site(url: str) -> bool:
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return False
    low = url.lower()
    if "?click=" in low or "?ref=" in low:
        return False
    if any(bad in low for bad in BAD_DOMAIN_FRAGMENTS):
        return False
    host = (urlparse(low).hostname or "").strip(".")
    return bool(host and "." in host and len(host) <= 90)


async def _verify_site_mint_or_gpu_pow(
    session: aiohttp.ClientSession,
    url: str,
) -> tuple[bool, str]:
    """Fetch HTML + JS SPA bundles to confirm HTTP 200 + real Web3 Connect-Wallet Mint UI (no L1 CLI sites)."""
    if not _is_good_project_site(url):
        return False, "invalid_domain"
    from wallet_simulator import verify_web3_mint_ui

    ui = await verify_web3_mint_ui(session, url)
    if not ui.get("site_live"):
        return False, str(ui.get("error") or "site_down")
    if ui.get("is_l1_cli_miner"):
        return False, "l1_cli_miner_rejected"
    if ui.get("is_web3_mint_dapp"):
        w_cnt = len(ui.get("wallet_signals") or [])
        m_cnt = len(ui.get("mint_signals") or [])
        return True, f"web3_dapp_w{w_cnt}_m{m_cnt}"
    return False, "no_connect_wallet_mint_ui"


async def _fetch_wtm_and_woolypooly(session: aiohttp.ClientSession) -> dict[str, Any]:
    """Fetch live GPU PoW metadata from WhatToMine & WoolyPooly in 2 lightweight calls."""
    wtm_coins: list[dict[str, Any]] = []
    wooly_pools: list[str] = []
    try:
        async with session.get(
            "https://whattomine.com/coins.json",
            timeout=aiohttp.ClientTimeout(total=9),
        ) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                coins_obj = data.get("coins") if isinstance(data, dict) else {}
                if isinstance(coins_obj, dict):
                    for cname, meta in coins_obj.items():
                        if isinstance(meta, dict) and not meta.get("lagging"):
                            wtm_coins.append({"name": cname, **meta})
    except Exception:
        pass
    try:
        async with session.get(
            "https://api.woolypooly.com/api/stats",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r2:
            if r2.status == 200:
                wdata = await r2.json(content_type=None)
                if isinstance(wdata, list):
                    wooly_pools = [str(x.get("id") or "") for x in wdata if isinstance(x, dict)]
                elif isinstance(wdata, dict):
                    wooly_pools = list(wdata.keys())
    except Exception:
        pass
    return {"wtm_count": len(wtm_coins), "wooly_count": len(wooly_pools), "wtm_coins": wtm_coins}


async def _discover_blockscout_small_chains(
    session: aiohttp.ClientSession,
    max_explorers: int = 24,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Query small non-testnet Blockscout v2 explorers for PoW/Mine/Mint tokens."""
    if not BS_CACHE_PATH.exists():
        return []
    try:
        bs_map: dict[str, str] = json.loads(BS_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

    eligible: list[tuple[str, str]] = []
    for cid, base_url in bs_map.items():
        if not isinstance(base_url, str) or not base_url.startswith("http"):
            continue
        if _is_testnet_chain(base_url, cid):
            continue
        # Focus especially on small/alt EVM chains outside top-3 L1s
        if cid in ("1", "56"):
            continue
        eligible.append((cid, base_url.rstrip("/")))

    if not eligible:
        return []
    start = offset % len(eligible)
    rotated = (eligible[start:] + eligible[:start])[:max_explorers]

    sem = asyncio.Semaphore(8)
    found: list[dict[str, Any]] = []

    async def probe_one(cid: str, base_url: str, q: str) -> None:
        async with sem:
            try:
                async with session.get(
                    f"{base_url}/api/v2/tokens?q={q}",
                    timeout=aiohttp.ClientTimeout(total=6),
                ) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        for tok in (data.get("items") or [])[:5]:
                            addr = str(tok.get("address_hash") or tok.get("address") or "").strip()
                            sym = str(tok.get("symbol") or "").strip()
                            holders = int(tok.get("holders_count") or tok.get("holders") or 0)
                            if not addr or not sym or len(sym) > 15 or holders < 20:
                                continue
                            found.append({"cid": cid, "address": addr, "symbol": sym, "name": str(tok.get("name") or sym), "holders": holders})
            except Exception:
                pass
            # Also query Blockscout v2 verified smart contracts directly for PoW / Miner / FairMint contracts!
            try:
                async with session.get(
                    f"{base_url}/api/v2/smart-contracts?q={q}",
                    timeout=aiohttp.ClientTimeout(total=6),
                ) as r2:
                    if r2.status == 200:
                        d2 = await r2.json(content_type=None)
                        for sc in (d2.get("items") or [])[:5]:
                            addr_obj = sc.get("address") or {}
                            addr = str(addr_obj.get("hash") or sc.get("address_hash") or "").strip()
                            sc_name = str(sc.get("name") or addr_obj.get("name") or "").strip()
                            txc = int(sc.get("transactions_count") or 0)
                            if not addr.startswith("0x") or len(addr) != 42 or txc < 10:
                                continue
                            if any(k in sc_name.lower() for k in ("mine", "mint", "pow", "xen", "titan", "glaze", "claim")):
                                found.append({"cid": cid, "address": addr, "symbol": sc_name[:12], "name": sc_name, "holders": txc})
            except Exception:
                pass

    tasks = []
    for idx, (cid, base_url) in enumerate(rotated):
        q = ("mine", "mint", "pow", "xen")[idx % 4]
        tasks.append(probe_one(cid, base_url, q))
    await asyncio.gather(*tasks)
    return found


async def _discover_dexscreener_candidates(
    session: aiohttp.ClientSession,
    chain_resolver: dict[str, tuple[str, str, str, str]],
    extra_bs_hits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Search DexScreener across all supported chains (small + major) & verify mint/PoW sites."""
    raw_pairs: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(6)

    async def fetch_query(q: str) -> None:
        async with sem:
            try:
                url = f"https://api.dexscreener.com/latest/dex/search?q={q}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status == 200:
                        d = await r.json(content_type=None)
                        raw_pairs.extend(d.get("pairs") or [])
            except Exception:
                pass

    async def fetch_token_addr(addr: str) -> None:
        async with sem:
            try:
                url = f"https://api.dexscreener.com/latest/dex/tokens/{addr}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status == 200:
                        d = await r.json(content_type=None)
                        raw_pairs.extend(d.get("pairs") or [])
            except Exception:
                pass

    await asyncio.gather(
        *(fetch_query(q) for q in SEARCH_QUERIES),
        *(fetch_token_addr(h["address"]) for h in extra_bs_hits[:20]),
    )

    by_token: dict[tuple[str, str], dict[str, Any]] = {}
    for p in raw_pairs:
        chain_slug = str(p.get("chainId") or "").lower()
        if not chain_slug or _is_testnet_chain(chain_slug):
            continue
        resolved = chain_resolver.get(chain_slug)
        if not resolved:
            continue
        base = p.get("baseToken") or {}
        addr = str(base.get("address") or "").strip()
        sym = str(base.get("symbol") or "").strip()
        name = str(base.get("name") or "").strip()
        if not addr or not sym or len(sym) > 15 or _is_testnet_chain(name):
            continue
        if sym.upper() in ("COPXON", "BONK", "JETTON", "TCAT", "TINU", "MTONGA", "POB", "VIRUS"):
            continue
        # Reject wrapped/staked spam or obvious LP garbage unless matched by curated
        liq = float((p.get("liquidity") or {}).get("usd") or 0)
        px = float(p.get("priceUsd") or 0)
        if px <= 0 or liq < 50:
            continue
        info = p.get("info") or {}
        sites = [
            str(w.get("url") or "")
            for w in (info.get("websites") or [])
            if isinstance(w, dict) and _is_good_project_site(str(w.get("url") or ""))
        ]
        if not sites:
            continue
        key = (chain_slug, addr.lower())
        prev = by_token.get(key)
        if prev and float((prev.get("liquidity") or {}).get("usd") or 0) >= liq:
            continue
        by_token[key] = p

    verified: list[dict[str, Any]] = []
    site_sem = asyncio.Semaphore(8)

    async def validate_pair(p: dict[str, Any]) -> None:
        chain_slug = str(p.get("chainId") or "").lower()
        eco, cid, cname, native_sym = chain_resolver[chain_slug]
        base = p.get("baseToken") or {}
        addr = str(base.get("address") or "").strip()
        sym = str(base.get("symbol") or "").strip()
        name = str(base.get("name") or "").strip()
        info = p.get("info") or {}
        sites = [
            str(w.get("url") or "")
            for w in (info.get("websites") or [])
            if isinstance(w, dict) and _is_good_project_site(str(w.get("url") or ""))
        ]
        if not sites:
            return
        async with site_sem:
            ok, reason = await _verify_site_mint_or_gpu_pow(session, sites[0])
        if not ok:
            return
        ptype = "تعدين PoW / Fair-Mint (Connect Wallet + Mint UI)"
        verified.append(
            {
                "ecosystem": eco,
                "chain_id": int(cid) if cid.isdigit() else cid,
                "chain_name": cname,
                "native_symbol": native_sym,
                "address": addr,
                "protocol_name": f"{name} ({sym})",
                "protocol_type": ptype,
                "decoded_functions": ["fair_mint", "mine"],
                "tx_count": max(1, int((p.get("txns") or {}).get("h24", {}).get("buys", 0) or 1)),
                "explorer_url": p.get("url") or "",
                "token_address": addr,
                "is_curated_miner": True,
                "is_standard_token_noise": False,
                "category": "Web3 Connect-Wallet Mint",
                "verification_note": f"Auto-discovered via {chain_slug} ({reason})",
                "market_profile": {
                    "probed": True,
                    "is_verified": True,
                    "websites": sites[:3],
                    "price_usd": p.get("priceUsd"),
                    "liquidity_usd": (p.get("liquidity") or {}).get("usd"),
                    "volume_24h_usd": (p.get("volume") or {}).get("h24"),
                    "dex_url": p.get("url") or "",
                    "dex_id": p.get("dexId") or "",
                    "reward_token_symbol": sym,
                },
            }
        )

    await asyncio.gather(*(validate_pair(p) for p in by_token.values()))
    return verified


async def run_hourly_mint_scan(
    max_evm_chains: int = 180,
    blocks_back: int = 10,
    no_blocks: bool = False,
) -> dict[str, Any]:
    """Run one full cumulative AI Agent discovery & registration cycle (keeps ALL old + adds new)."""
    from ai_mining_agent import run_agent_cycle

    res = await run_agent_cycle(
        max_evm_chains=max_evm_chains,
        blocks_back=blocks_back,
        no_blocks=no_blocks,
    )
    return res["registry"]


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniRPC Hourly All-Chains PoW & GPU-Mint Scanner (AI Agent)")
    parser.add_argument("--max-evm", type=int, default=180, help="Max EVM chains per rotating scan window")
    parser.add_argument("--blocks", type=int, default=10, help="Recent blocks back per EVM RPC")
    parser.add_argument("--no-blocks", action="store_true", help="Skip live block loop and run API/DEX/Blockscout scan")
    args = parser.parse_args()

    reg = asyncio.run(
        run_hourly_mint_scan(max_evm_chains=args.max_evm, blocks_back=args.blocks, no_blocks=args.no_blocks)
    )
    stats = reg.get("last_scan_stats") or {}
    print(json.dumps({"updated_at": reg.get("updated_at"), "stats": stats}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
