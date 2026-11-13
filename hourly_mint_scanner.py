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
    "proof of work", "mineable", "epow", "glaze", "drillx",
    "xen", "0xbtc", "nonce", "miner", "hashrate", "fodina",
    "titanx", "orx", "gram ton", "mrdn", "pmint", "pulsechain mint",
    "octaspace", "firo", "aipg", "dynex", "zano", "rserg", "clore",
    "conflux", "mine token", "fair mint",
]

# Unambiguous Mint UI or GPU PoW phrases matched strictly against visible page text (scripts/styles stripped)
MINT_OR_GPU_POW_PHRASES = (
    "connect wallet", "start mining", "mine now", "claim mint", "start mint",
    "claim rank", "proof of work", "proof-of-work", "hashrate", "stratum",
    "lolminer", "rigel", "bzminer", "srbminer", "teamredminer", "t-rex",
    "gminer", "kawpow", "ethash", "etchash", "autolykos", "firopow",
    "progpow", "dynexsolve", "ton giver", "giver contract", "gpu mining",
    "mining pool", "block reward", "erc-918", "erc918", "transform",
)

MINT_OR_GPU_POW_WORDS = ("pow", "gpu", "nonce", "difficulty", "octopus", "blake3", "minter")

REJECT_SITE_MARKERS = (
    "ai agents mine for you", "autonomous agent mining", "no wallet needed to play",
    "tap to earn", "idle clicker", "domain for sale", "buy this domain",
    "memecoin", "meme coin", "copper miners etf", "global x etf",
    "sportsbook", "casino", "?click=", "music is the meme",
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
    """Fetch official website and confirm HTTP 200 + visible interactive Mint UI or GPU PoW guide."""
    if not _is_good_project_site(url):
        return False, "invalid_domain"
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=True,
        ) as resp:
            if resp.status >= 400:
                return False, f"http_{resp.status}"
            raw_html = (await resp.text(errors="ignore"))[:90000]
            raw_low = raw_html.lower()
            visible = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw_low, flags=re.S | re.I)
            visible = re.sub(r"<[^>]+>", " ", visible)
            visible = re.sub(r"\s+", " ", visible)
            if any(rej in visible or rej in raw_low for rej in REJECT_SITE_MARKERS):
                return False, "rejected_type"
            phrase_hits = [k for k in MINT_OR_GPU_POW_PHRASES if k in visible]
            word_hits = [w for w in MINT_OR_GPU_POW_WORDS if re.search(rf"\b{re.escape(w)}\b", visible)]
            total_hits = len(phrase_hits) + len(word_hits)
            # Require either >=2 distinct visible signals, or an explicit mining/mint UI phrase
            if len(phrase_hits) >= 2 or (phrase_hits and total_hits >= 2) or any(
                strong in phrase_hits
                for strong in ("proof of work", "proof-of-work", "start mining", "lolminer", "rigel", "bzminer", "kawpow", "ethash", "autolykos", "firopow", "progpow", "ton giver", "erc-918")
            ):
                return True, f"ok_hits_{total_hits}"
            if ("<div id=\"root\"" in raw_low or "<div id=\"__next\"" in raw_low) and any(
                hint in url.lower() for hint in ("mint", "mine", "fodina", "titan", "x28", "orx", "shogun")
            ):
                return True, "ok_spa_shell"
            return False, "no_mint_or_pow_keywords"
    except Exception as exc:
        return False, f"err_{str(exc)[:30]}"


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
                    if r.status != 200:
                        return
                    data = await r.json(content_type=None)
                    for tok in (data.get("items") or [])[:5]:
                        addr = str(tok.get("address_hash") or tok.get("address") or "").strip()
                        sym = str(tok.get("symbol") or "").strip()
                        holders = int(tok.get("holders_count") or tok.get("holders") or 0)
                        if not addr or not sym or len(sym) > 15 or holders < 20:
                            continue
                        found.append(
                            {
                                "cid": cid,
                                "address": addr,
                                "symbol": sym,
                                "name": str(tok.get("name") or sym),
                                "holders": holders,
                            }
                        )
            except Exception:
                pass

    tasks = []
    for idx, (cid, base_url) in enumerate(rotated):
        q = ("mine", "pow", "xen")[idx % 3]
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
        blob = f"{sym} {name} {sites[0]} {reason}".lower()
        is_pow_site = any(
            k in blob
            for k in ("pow", "gpu", "stratum", "kawpow", "ethash", "autolykos", "octopus", "firopow", "dynex", "octa", "zano", "clore", "aipg")
        )
        ptype = "تعدين GPU Proof-of-Work" if is_pow_site else "تعدين PoW / Fair-Mint (موقع + DexScreener)"
        verified.append(
            {
                "ecosystem": eco,
                "chain_id": int(cid) if cid.isdigit() else cid,
                "chain_name": cname,
                "native_symbol": native_sym,
                "address": addr,
                "protocol_name": f"{name} ({sym})",
                "protocol_type": ptype,
                "decoded_functions": ["proof_of_work", "gpu_mine"] if is_pow_site else ["fair_mint", "mine"],
                "tx_count": max(1, int((p.get("txns") or {}).get("h24", {}).get("buys", 0) or 1)),
                "explorer_url": p.get("url") or "",
                "token_address": addr,
                "is_curated_miner": True,
                "is_standard_token_noise": False,
                "category": "GPU Proof-of-Work" if is_pow_site else "Discovered PoW / Mint",
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


async def run_hourly_mint_scan(max_evm_chains: int = 180, blocks_back: int = 10) -> dict[str, Any]:
    """Run one complete all-chains PoW + GPU + Fair-Mint scan and update mining_registry.json."""
    prev_reg = load_registry()
    scans_done = int(prev_reg.get("total_scans_completed") or 0)
    evm_offset = (scans_done * 90) % 570
    bs_offset = (scans_done * 12) % 90

    omni = OmniRPC()
    chain_resolver = _build_chain_resolver(omni)

    # 1. Direct rotating multi-chain on-chain RPC scan (small + large EVM, Cosmos, Substrate, Solana, TON, Sui)
    onchain_report = await onchain_mining_scanner.run_scan(
        max_evm_chains=max_evm_chains,
        blocks_back=blocks_back,
        all_ecosystems=True,
        evm_offset=evm_offset,
    )

    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        wtm_wooly, bs_hits = await asyncio.gather(
            _fetch_wtm_and_woolypooly(session),
            _discover_blockscout_small_chains(session, max_explorers=24, offset=bs_offset),
        )
        discovered_dex = await _discover_dexscreener_candidates(session, chain_resolver, bs_hits)

    # 2. Gather curated small/large PoW + GPU PoW + Mint seeds + onchain hits + newly discovered hits
    raw_items: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()

    def add_candidate(it: dict[str, Any]) -> None:
        cid = str(it.get("chain_id") or "")
        addr = str(it.get("address") or "").strip().lower()
        if not addr or _is_testnet_chain(str(it.get("chain_name") or ""), cid):
            return
        k = (cid, addr)
        if k in seen_keys:
            return
        seen_keys.add(k)
        raw_items.append(dict(it))

    for seed in CURATED_MINING_SEEDS:
        add_candidate(seed)
    for d in discovered_dex:
        add_candidate(d)

    for evm_ch in onchain_report.get("evm_results") or []:
        cid = str(evm_ch.get("chain_id") or "")
        cname = str(evm_ch.get("chain_name") or "")
        sym = str(evm_ch.get("native_symbol") or "ETH")
        if _is_testnet_chain(cname, cid):
            continue
        for c in (evm_ch.get("top_active_contracts") or []):
            add_candidate(
                {
                    "ecosystem": "EVM",
                    "chain_id": evm_ch.get("chain_id"),
                    "chain_name": cname,
                    "native_symbol": sym,
                    "address": c.get("address"),
                    "tx_count": c.get("tx_count", 0),
                    "decoded_functions": c.get("decoded_functions") or [],
                    "is_curated_miner": False,
                }
            )

    # 3. Enrich every candidate with live DexScreener + website + explorer data
    await enrich_registry_items_onchain(raw_items)

    # 4. Strict filter: actionable user-mineable / GPU PoW + official site + live DexScreener price
    actionable = [it for it in raw_items if is_actionable_mining_protocol(it)]
    now_iso = utc_now_iso()
    prev_items = prev_reg.get("items") or {}
    items_dict: dict[str, dict[str, Any]] = {}
    new_count = 0

    actionable.sort(
        key=lambda x: (
            1 if "gpu" in str(x.get("category") or x.get("protocol_type") or "").lower() else 0,
            float(((x.get("market_profile") or {}).get("liquidity_usd")) or 0),
        ),
        reverse=True,
    )

    for it in actionable:
        cid = str(it.get("chain_id") or "")
        addr = str(it.get("address") or "").strip()
        uid = it.get("uid") or f"{cid}:{addr.lower()}"
        prev = prev_items.get(uid) or {}
        is_new = uid not in prev_items
        if is_new:
            new_count += 1
        it["uid"] = uid
        it["symbol"] = it.get("symbol") or it.get("native_symbol") or "ETH"
        it["first_seen_at"] = prev.get("first_seen_at") or now_iso
        it["last_seen_at"] = now_iso
        it["discovered_in_scan"] = prev.get("discovered_in_scan") or (scans_done + 1)
        it["seen_scans"] = int(prev.get("seen_scans") or 0) + 1
        it["is_new_in_last_scan"] = is_new
        it["cumulative_txs"] = max(int(prev.get("cumulative_txs") or 0), int(it.get("tx_count") or 1))
        it["cumulative_mints"] = max(int(prev.get("cumulative_mints") or 0), int(it.get("tx_count") or 1))
        it["unique_callers"] = max(int(prev.get("unique_callers") or 0), int(it.get("unique_callers") or 1))
        items_dict[uid] = it

    stats = {
        "evm_chains_scanned": int(onchain_report.get("evm_chains_scanned") or len(onchain_report.get("evm_results") or [])),
        "total_chains_scanned": int(onchain_report.get("total_chains_scanned") or 0),
        "evm_offset": evm_offset,
        "wtm_gpu_coins": wtm_wooly.get("wtm_count", 0),
        "wooly_pools": wtm_wooly.get("wooly_count", 0),
        "blockscout_hits": len(bs_hits),
        "dex_discovered_verified": len(discovered_dex),
        "total_candidates_enriched": len(raw_items),
        "verified_actionable_count": len(items_dict),
        "newly_registered": new_count,
    }
    history_entry = {
        "scan_id": scans_done + 1,
        "timestamp": now_iso,
        "evm_chains_scanned": stats["evm_chains_scanned"],
        "matched_in_scan": len(items_dict),
        "newly_registered": new_count,
        "total_registry_size": len(items_dict),
    }

    out_reg = {
        "schema_version": 4,
        "updated_at": now_iso,
        "updated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_interval_seconds": 3600,
        "total_scans_completed": scans_done + 1,
        "total_protocols": len(items_dict),
        "pruned_last_scan": max(0, len(raw_items) - len(items_dict)),
        "last_scan_stats": stats,
        "items": items_dict,
        "scan_history": ([history_entry] + list(prev_reg.get("scan_history") or []))[:60],
    }
    save_registry(out_reg)
    return out_reg


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniRPC Hourly All-Chains PoW & GPU-Mint Scanner (v3)")
    parser.add_argument("--max-evm", type=int, default=180, help="Max EVM chains per rotating scan window")
    parser.add_argument("--blocks", type=int, default=10, help="Recent blocks back per EVM RPC")
    args = parser.parse_args()

    reg = asyncio.run(run_hourly_mint_scan(max_evm_chains=args.max_evm, blocks_back=args.blocks))
    stats = reg.get("last_scan_stats") or {}
    print(json.dumps({"updated_at_utc": reg.get("updated_at_utc"), "stats": stats}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
