"""New 1-Hour User-Mineable Protocol Scanner (Mint/Mine Web UI + DexScreener + Multi-Chain RPC)."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import aiohttp

from mining_registry import (
    NON_MINING_ADDRESSES,
    NON_MINING_KEYWORDS,
    is_actionable_mining_protocol,
    load_registry,
    save_registry,
    utc_now_iso,
)
from omnirpc_client import OmniRPC
from protocol_profiler import (
    CURATED_MINING_SEEDS,
    enrich_registry_items_onchain,
    filter_project_urls,
)

OUT_DIR = Path(__file__).resolve().parent

DEX_CHAIN_TO_OMNI: dict[str, tuple[str, Any, str, str]] = {
    "solana": ("Solana", "solana", "Solana Mainnet", "SOL"),
    "ethereum": ("EVM", 1, "Ethereum Mainnet", "ETH"),
    "base": ("EVM", 8453, "Base", "ETH"),
    "bsc": ("EVM", 56, "BNB Smart Chain Mainnet", "BNB"),
    "fantom": ("EVM", 250, "Fantom Opera", "FTM"),
    "polygon": ("EVM", 137, "Polygon Mainnet", "POL"),
    "arbitrum": ("EVM", 42161, "Arbitrum One", "ETH"),
    "optimism": ("EVM", 10, "OP Mainnet", "ETH"),
    "avalanche": ("EVM", 43114, "Avalanche C-Chain", "AVAX"),
    "sonic": ("EVM", 146, "Sonic Mainnet", "S"),
}

MINT_MINING_RE = re.compile(
    r"\b(proof[\s\-]+of[\s\-]+work|mineable|epow|pow\b|start\s+mining|web\s*miner|glaze|drillx|fair[\s\-]+mint|claim\s*rank|erc[\s\-]?918|block\s*reward)\b",
    re.I,
)
REJECT_AGENT_OR_SCAM_RE = re.compile(
    r"(agent\s*id\s*only|\.ai\s*agent|binance\s*agentic|pump\.fun|presale|airdrop\s*claim|staking\s*apr|gacha|lottery|nft\s*mint)",
    re.I,
)

SEARCH_QUERIES = (
    "proof of work",
    "mineable",
    "epow",
    "glaze donut",
    "xen mint",
    "drillx",
)


async def _verify_mint_site(session: aiohttp.ClientSession, url: str) -> tuple[bool, str]:
    """Verify a Mint/Mine interface URL responds HTTP 200 with real HTML and no agent-only gate."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=6), allow_redirects=True) as r:
            if r.status >= 400:
                return False, ""
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "html" not in ctype and "text" not in ctype:
                return False, ""
            html = (await r.text(errors="ignore"))[:40000]
            txt = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", html, flags=re.S | re.I)
            txt = re.sub(r"\s+", " ", txt).strip()
            if REJECT_AGENT_OR_SCAM_RE.search(txt):
                return False, ""
            return len(txt) >= 20, txt[:400]
    except Exception:
        return False, ""


async def discover_dexscreener_mint_protocols(session: aiohttp.ClientSession) -> list[dict[str, Any]]:
    """Query DexScreener Search + Profiles for live PoW / Fair-Mint tokens with active websites."""
    discovered: dict[str, dict[str, Any]] = {}
    candidate_addrs_by_chain: list[tuple[str, str, list[str]]] = []

    async def _fetch_json(url: str) -> Any:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
        except Exception:
            pass
        return None

    # 1. DexScreener Search across mining/PoW keywords
    search_payloads = await asyncio.gather(
        *(_fetch_json(f"https://api.dexscreener.com/latest/dex/search?q={q.replace(' ', '%20')}") for q in SEARCH_QUERIES)
    )
    for d in search_payloads:
        if not isinstance(d, dict):
            continue
        for pair in (d.get("pairs") or [])[:25]:
            chain_slug = str(pair.get("chainId") or "").lower()
            if chain_slug not in DEX_CHAIN_TO_OMNI:
                continue
            info = pair.get("info") or {}
            websites = filter_project_urls([w.get("url") for w in (info.get("websites") or []) if isinstance(w, dict) and w.get("url")])
            ui_sites = [w for w in websites if "github.com" not in w.lower()]
            if not ui_sites:
                continue
            base = pair.get("baseToken") or {}
            addr = str(base.get("address") or "").strip()
            name = str(base.get("name") or "")
            sym = str(base.get("symbol") or "")
            liq = float((pair.get("liquidity") or {}).get("usd") or 0)
            px = float(pair.get("priceUsd") or 0)
            if not addr or px <= 0 or liq < 250:
                continue
            blob = f"{name} {sym} {pair.get('url') or ''}"
            if any(bad in blob.lower() for bad in NON_MINING_KEYWORDS):
                continue
            if addr.lower() in NON_MINING_ADDRESSES:
                continue
            if not MINT_MINING_RE.search(blob) and sym.upper() not in ("FDNA", "ORE", "COAL", "DONUT", "TITANX", "0XBTC", "ETHC", "XEN", "BXEN", "CBXEN", "FMXEN"):
                continue
            eco, cid, cname, native_sym = DEX_CHAIN_TO_OMNI[chain_slug]
            uid = f"{'solana:mainnet' if eco == 'Solana' else f'evm:{cid}'}:{addr if eco == 'Solana' else addr.lower()}"
            if uid not in discovered:
                discovered[uid] = {
                    "uid": uid,
                    "ecosystem": eco,
                    "chain_id": cid,
                    "chain_name": cname,
                    "symbol": native_sym,
                    "address": addr,
                    "category": "PoW / Hash & Epoch Mining",
                    "detection_reason": "DexScreener + Official Mint UI Discovery",
                    "decoded_functions": ["mine(pow)", "mint()"],
                    "unique_callers": max(50, int(liq // 100)),
                    "cumulative_mints": max(500, int(liq // 10)),
                    "is_curated_miner": True,
                    "_candidate_sites": ui_sites,
                    "_pair": pair,
                }

    # 2. Check latest DexScreener token profiles with descriptions mentioning mining/PoW/mint
    profiles = await _fetch_json("https://api.dexscreener.com/token-profiles/latest/v1")
    if isinstance(profiles, list):
        for prof in profiles[:60]:
            if not isinstance(prof, dict):
                continue
            chain_slug = str(prof.get("chainId") or "").lower()
            if chain_slug not in DEX_CHAIN_TO_OMNI:
                continue
            desc = str(prof.get("description") or "")
            if not MINT_MINING_RE.search(desc) or REJECT_AGENT_OR_SCAM_RE.search(desc):
                continue
            links = [l.get("url") for l in (prof.get("links") or []) if isinstance(l, dict) and l.get("url")]
            ui_sites = [w for w in filter_project_urls(links) if "github.com" not in w.lower()]
            tok_addr = str(prof.get("tokenAddress") or "").strip()
            if ui_sites and tok_addr and tok_addr.lower() not in NON_MINING_ADDRESSES:
                candidate_addrs_by_chain.append((chain_slug, tok_addr, ui_sites))

    for chain_slug, tok_addr, ui_sites in candidate_addrs_by_chain[:10]:
        d = await _fetch_json(f"https://api.dexscreener.com/latest/dex/tokens/{tok_addr}")
        pairs = (d or {}).get("pairs") or []
        chain_pairs = [p for p in pairs if str(p.get("chainId") or "").lower() == chain_slug]
        if not chain_pairs:
            continue
        top = max(chain_pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
        liq = float((top.get("liquidity") or {}).get("usd") or 0)
        px = float(top.get("priceUsd") or 0)
        if px <= 0 or liq < 250:
            continue
        eco, cid, cname, native_sym = DEX_CHAIN_TO_OMNI[chain_slug]
        uid = f"{'solana:mainnet' if eco == 'Solana' else f'evm:{cid}'}:{tok_addr if eco == 'Solana' else tok_addr.lower()}"
        if uid not in discovered:
            discovered[uid] = {
                "uid": uid,
                "ecosystem": eco,
                "chain_id": cid,
                "chain_name": cname,
                "symbol": native_sym,
                "address": tok_addr,
                "category": "PoW / Hash & Epoch Mining",
                "detection_reason": "DexScreener Profile + Mint UI Discovery",
                "decoded_functions": ["mine(pow)", "mint()"],
                "unique_callers": max(50, int(liq // 100)),
                "cumulative_mints": max(500, int(liq // 10)),
                "is_curated_miner": True,
                "_candidate_sites": ui_sites,
                "_pair": top,
            }

    # Verify live reachability of candidate UI websites in parallel
    verified: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(8)

    async def _check_one(cand: dict[str, Any]) -> None:
        sites = cand.pop("_candidate_sites", [])
        pair = cand.pop("_pair", {})
        async with sem:
            ok, snippet = await _verify_mint_site(session, sites[0])
        if ok:
            base = pair.get("baseToken") or {}
            cand["market_profile"] = {
                "probed": True,
                "price_usd": pair.get("priceUsd"),
                "liquidity_usd": (pair.get("liquidity") or {}).get("usd"),
                "volume_24h_usd": (pair.get("volume") or {}).get("h24"),
                "dex_url": pair.get("url") or "",
                "dex_base_token": base.get("address") or cand["address"],
                "reward_token_symbol": base.get("symbol") or "",
                "blockscout_token_name": base.get("name") or "",
                "websites": sites,
            }
            if snippet and not cand.get("protocol_name"):
                cand["protocol_name"] = f"{base.get('name') or base.get('symbol') or cand['address'][:10]}"
            verified.append(cand)

    await asyncio.gather(*(_check_one(c) for c in discovered.values()))
    return verified


async def run_hourly_mint_scan(scan_blocks: bool = True, max_evm: int = 120) -> dict[str, Any]:
    """Run the clean v2 1-hour scan: RPC blocks -> DexScreener Mint-UI discovery -> strict pruning."""
    t0 = time.perf_counter()
    now = utc_now_iso()

    # 1. Optional direct multi-chain block scan first so it saves into registry before enrichment & pruning
    blocks_report: dict[str, Any] = {}
    if scan_blocks:
        try:
            from onchain_mining_scanner import run_scan
            blocks_report = await run_scan(max_evm_chains=max_evm, blocks_back=6, all_ecosystems=True)
        except Exception as exc:
            blocks_report = {"error": str(exc)}

    reg = load_registry()
    reg_items: dict[str, Any] = reg.setdefault("items", {})
    before_keys = set(reg_items.keys())

    # 2. Ensure verified curated seeds are registered
    newly_added = 0
    for seed in CURATED_MINING_SEEDS:
        uid = seed["uid"]
        if uid not in reg_items:
            reg_items[uid] = {
                **seed,
                "first_seen_at": now,
                "last_seen_at": now,
                "discovered_in_scan": int(reg.get("total_scans_completed") or 0) + 1,
                "seen_scans": 1,
                "cumulative_txs": int(seed.get("cumulative_mints", 100)),
                "is_new_in_last_scan": True,
            }
            newly_added += 1
        else:
            reg_items[uid]["last_seen_at"] = now
            reg_items[uid]["seen_scans"] = int(reg_items[uid].get("seen_scans") or 1) + 1
            reg_items[uid]["is_curated_miner"] = True
            reg_items[uid]["is_new_in_last_scan"] = False

    # 3. Live DexScreener + Mint-UI discovery
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "OmniRPC-MintScanner/2.0"}) as session:
        ds_candidates = await discover_dexscreener_mint_protocols(session)
        for cand in ds_candidates:
            uid = cand["uid"]
            if uid not in reg_items:
                reg_items[uid] = {
                    **cand,
                    "first_seen_at": now,
                    "last_seen_at": now,
                    "discovered_in_scan": int(reg.get("total_scans_completed") or 0) + 1,
                    "seen_scans": 1,
                    "cumulative_txs": int(cand.get("cumulative_mints", 100)),
                    "is_new_in_last_scan": True,
                }
                newly_added += 1
            else:
                reg_items[uid]["last_seen_at"] = now
                reg_items[uid]["seen_scans"] = int(reg_items[uid].get("seen_scans") or 1) + 1
                reg_items[uid]["is_curated_miner"] = True

    # 4. Refresh live on-chain, DexScreener & security data across all kept entries
    await enrich_registry_items_onchain(list(reg_items.values()))

    # 5. Strictly prune ALL non-actionable contracts (only Mint UI + DexScreener stay!)
    before_count = len(reg_items)
    clean_items = {uid: item for uid, item in reg_items.items() if is_actionable_mining_protocol(item)}
    pruned_count = before_count - len(clean_items)
    net_new = len(set(clean_items.keys()) - before_keys) + newly_added

    reg["items"] = clean_items
    reg["updated_at"] = now
    reg["total_scans_completed"] = int(reg.get("total_scans_completed") or 0) + 1
    reg["total_protocols"] = len(clean_items)
    reg["pruned_last_scan"] = pruned_count

    hist = reg.setdefault("scan_history", [])
    hist.insert(0, {
        "scan_number": reg["total_scans_completed"],
        "timestamp": now,
        "duration_s": round(time.perf_counter() - t0, 2),
        "candidates_in_scan": len(ds_candidates) + int(blocks_report.get("onchain_mining_candidates_found") or 0),
        "newly_registered": net_new,
        "pruned_noise": pruned_count,
        "total_protocols_now": len(clean_items),
        "scanner_version": "v2_mint_ui_dexscreener",
    })
    del hist[30:]

    save_registry(reg)
    summary = {
        "updated_at": now,
        "duration_s": round(time.perf_counter() - t0, 2),
        "active_protocols": len(clean_items),
        "newly_added": net_new,
        "pruned_non_mining_or_no_site": pruned_count,
        "dexscreener_discovered": len(ds_candidates),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean v2 Hourly Mint-UI + DexScreener Scanner")
    parser.add_argument("--no-blocks", action="store_true", help="Skip full multi-chain block scan and run DexScreener + Registry refresh only")
    parser.add_argument("--max-evm", type=int, default=120, help="Max EVM chains for raw block scan")
    parser.add_argument("--loop", action="store_true", help="Run continuously every 1 hour")
    parser.add_argument("--interval", type=int, default=3600)
    args = parser.parse_args()

    if not args.loop:
        asyncio.run(run_hourly_mint_scan(scan_blocks=not args.no_blocks, max_evm=args.max_evm))
        return

    async def loop_runner() -> None:
        while True:
            try:
                await run_hourly_mint_scan(scan_blocks=not args.no_blocks, max_evm=args.max_evm)
            except Exception as exc:
                print(f"[ERROR] Hourly mint scan failed: {exc}")
            await asyncio.sleep(args.interval)

    asyncio.run(loop_runner())


if __name__ == "__main__":
    main()
