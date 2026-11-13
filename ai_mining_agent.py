"""
OmniRPC Autonomous IA Mining & Arbitrage Agent.

Cognitive 1-hour loop:
  1. OBSERVE  : Load persistent mining_registry.json (ALL previous protocols) + agent_memory.json.
  2. PLAN     : Select rotating window across 598 EVM + 131 Cosmos + 73 Substrate chains,
                small-chain Blockscout v2 explorers, WhatToMine/WoolyPooly, and DexScreener queries.
  3. ACT      : Run multi-chain RPC block scanner + DEX/Blockscout/WhatToMine discovery tools.
  4. REASON   : Verify Mint-UI / GPU PoW authenticity (semantic DOM analysis + optional Gemini AI),
                strictly filtering out memes, ETFs, testnets, gambling, and AI-agent-only schemes.
  5. MEMORIZE : NON-DESTRUCTIVE ACCUMULATION — Keep ALL valid old protocols forever, refresh live
                market prices, append newly discovered protocols, update first_seen/last_seen/seen_scans.
  6. REPORT   : Persist agent_memory.json with reasoning brief and hourly discovery history.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any

import aiohttp

from mining_registry import is_actionable_mining_protocol, load_registry, save_registry, utc_now_iso
from omnirpc_client import OmniRPC
import onchain_mining_scanner
from protocol_profiler import CURATED_MINING_SEEDS, enrich_registry_items_onchain

ROOT = Path(__file__).resolve().parent
AGENT_MEMORY_PATH = ROOT / "agent_memory.json"

# Extra adaptive search rotations added every hour beyond base queries
ADAPTIVE_QUERY_POOL = [
    ["proof of work", "mineable", "epow", "glaze", "drillx", "xen", "0xbtc", "nonce", "miner"],
    ["hashrate", "fodina", "titanx", "orx", "gram ton", "mrdn", "pmint", "pulsechain mint", "octaspace"],
    ["firo", "aipg", "dynex", "zano", "rserg", "clore", "conflux", "mine token", "fair mint"],
    ["pow token", "solo mine", "erc918", "mineable token", "giver", "kaspa pow", "kawpow", "autolykos"],
    ["epoch mine", "proof of useful work", "gpu mine", "fair launch pow", "titan", "pulsechain pow", "ton pow"],
]

DEFAULT_USER_DIRECTIVES: list[dict[str, Any]] = [
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "عدم تصفير mining_registry.json أبداً؛ الحفاظ على كل البروتوكولات القديمة (first_seen_at, seen_scans) وإضافة البروتوكولات الجديدة فقط كل ساعة.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "التركيز على بروتوكولات GPU PoW القابلة للتعدين ببطاقات NVIDIA وبروتوكولات Fair-Mint ذات واجهة Web3 رسمية حقيقية + سعر وسيولة موثقين على DexScreener.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "تغطية الشبكات الصغيرة والمغمورة (PulseChain, Conflux, TON, Cardano, Base, Polygon, Arbitrum, Solana, Cosmos, Substrate) بالإضافة للشبكات الكبيرة.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "الرفض الصارم لشبكات التجربة (testnets: robinhood, arc, sepolia)، ألعاب النقرات (idle clickers)، مخططات AI-agent-only (amber, jagent)، صناديق ETF، مواقع القمار، والميم كوينز بدون عقود حقيقية.",
        "active": True,
    },
]

DEFAULT_PRIORITY_CHAINS: list[str] = [
    "PulseChain",
    "Conflux eSpace",
    "TON",
    "Cardano",
    "Base",
    "Polygon",
    "Arbitrum",
    "Solana",
    "Cosmos",
    "Substrate",
    "BNB Smart Chain",
    "Ethereum",
]

DEFAULT_WATCHLIST_QUERIES: list[str] = [
    "tari wxtm",
    "quai network",
    "neoxa",
    "karlsen",
    "xelis",
    "pulsechain pow",
    "conflux mine",
    "fair mint pow",
]

DEFAULT_REJECTED_PATTERNS: list[str] = [
    "neox.so",
    "robinhood",
    "arc",
    "sepolia",
    "amber",
    "jagent",
    "ethereumpow.org",
    "tap to earn",
    "idle clicker",
    "mint.club",
    "pump.fun",
]


def _dedupe_str_list(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v or "").strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _ensure_long_term_memory(mem: dict[str, Any]) -> dict[str, Any]:
    """Backfill persistent long-term memory fields without erasing existing user data."""
    mem.setdefault("agent_name", "OmniRPC Autonomous Mining Agent")
    mem.setdefault("version", "1.1")
    mem.setdefault("total_cycles", 0)
    mem.setdefault("cursor_evm_offset", 0)
    mem.setdefault("cursor_bs_offset", 0)
    mem.setdefault("cursor_query_batch", 0)
    mem.setdefault("last_cycle_at", None)
    mem.setdefault("known_protocols_count", 0)
    mem.setdefault("newly_added_last_cycle", 0)
    mem.setdefault("ai_llm_enabled", bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")))
    mem.setdefault("last_agent_brief_ar", "جاهز لبدء أول دورة بحث وتجميع تلقائي للبروتوكولات.")
    mem.setdefault("cycle_logs", [])

    existing_directives = mem.get("user_directives")
    if not isinstance(existing_directives, list) or not existing_directives:
        mem["user_directives"] = [dict(d) for d in DEFAULT_USER_DIRECTIVES]
    else:
        seen_dir = {
            (d.get("text", "") if isinstance(d, dict) else str(d)).strip().lower()
            for d in existing_directives
        }
        for d in DEFAULT_USER_DIRECTIVES:
            if d["text"].strip().lower() not in seen_dir:
                existing_directives.append(dict(d))

    if not isinstance(mem.get("conversation_notes"), list):
        mem["conversation_notes"] = []

    existing_chains = mem.get("priority_chains")
    if not isinstance(existing_chains, list) or not existing_chains:
        mem["priority_chains"] = list(DEFAULT_PRIORITY_CHAINS)
    else:
        mem["priority_chains"] = _dedupe_str_list(existing_chains)

    existing_watch = mem.get("watchlist_queries")
    if not isinstance(existing_watch, list) or not existing_watch:
        mem["watchlist_queries"] = list(DEFAULT_WATCHLIST_QUERIES)
    else:
        mem["watchlist_queries"] = _dedupe_str_list(existing_watch)

    existing_rej = mem.get("rejected_patterns")
    if not isinstance(existing_rej, list) or not existing_rej:
        mem["rejected_patterns"] = list(DEFAULT_REJECTED_PATTERNS)
    else:
        mem["rejected_patterns"] = _dedupe_str_list(existing_rej)

    return mem


def load_agent_memory(path: Path = AGENT_MEMORY_PATH) -> dict[str, Any]:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return _ensure_long_term_memory(data)
        except Exception:
            pass
    return _ensure_long_term_memory({})


def save_agent_memory(mem: dict[str, Any], path: Path = AGENT_MEMORY_PATH) -> None:
    _ensure_long_term_memory(mem)
    path.write_text(json.dumps(mem, indent=2, ensure_ascii=False), encoding="utf-8")


def record_user_directive(
    text: str,
    category: str = "directive",
    path: Path = AGENT_MEMORY_PATH,
) -> dict[str, Any]:
    """Persist a user directive, conversation note, priority chain, watchlist query, or rejected pattern."""
    clean = str(text or "").strip()
    if not clean:
        raise ValueError("Directive text cannot be empty.")
    mem = load_agent_memory(path)
    cat = str(category or "directive").strip().lower()
    now_iso = utc_now_iso()

    if cat in ("note", "conversation", "conversation_note"):
        notes = list(mem.get("conversation_notes") or [])
        if not notes or str((notes[-1] or {}).get("summary") or "").strip() != clean:
            notes.append({"timestamp": now_iso, "summary": clean, "applied": True})
        mem["conversation_notes"] = notes[-100:]
    elif cat in ("priority_chain", "chain"):
        mem["priority_chains"] = _dedupe_str_list(list(mem.get("priority_chains") or []) + [clean])
    elif cat in ("watchlist", "watchlist_query", "query"):
        mem["watchlist_queries"] = _dedupe_str_list(list(mem.get("watchlist_queries") or []) + [clean])
    elif cat in ("reject", "rejected", "rejected_pattern"):
        mem["rejected_patterns"] = _dedupe_str_list(list(mem.get("rejected_patterns") or []) + [clean])
    else:
        directives = list(mem.get("user_directives") or [])
        existing_texts = {
            (d.get("text", "") if isinstance(d, dict) else str(d)).strip().lower()
            for d in directives
        }
        if clean.lower() not in existing_texts:
            directives.append({"timestamp": now_iso, "category": cat, "text": clean, "active": True})
        mem["user_directives"] = directives

    save_agent_memory(mem, path=path)
    return mem


def _matches_rejected_patterns(item: dict[str, Any], rejected_patterns: list[str]) -> str | None:
    """Return the matching rejected pattern if a candidate matches long-term memory exclusions."""
    if not rejected_patterns:
        return None
    mkt = item.get("market_profile") or {}
    chain_l = str(item.get("chain_name") or "").lower()
    cid_l = str(item.get("chain_id") or "").lower()
    pname_l = str(item.get("protocol_name") or "").lower()
    addr_l = str(item.get("address") or "").lower()
    urls = [str(u).lower() for u in (mkt.get("websites") or [])]
    dex_url = str(mkt.get("dex_url") or "").lower()
    blob = " ".join([chain_l, cid_l, pname_l, addr_l, dex_url] + urls)

    for pat in rejected_patterns:
        p = str(pat or "").strip().lower()
        if not p:
            continue
        if len(p) <= 4 and "." not in p and " " not in p:
            # Short token like 'arc': require exact chain/id match or whole-word match
            if cid_l == p or chain_l == p or re.search(rf"\b{re.escape(p)}\b", f"{chain_l} {pname_l}"):
                return pat
        else:
            if p in blob:
                return pat
    return None


async def _gemini_verify_candidates(
    session: aiohttp.ClientSession,
    candidates: list[dict[str, Any]],
) -> dict[str, str]:
    """Optional Gemini 2.5 Flash semantic verification & Darija note when GEMINI_API_KEY is configured."""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key or not candidates:
        return {}
    brief_rows = [
        {
            "uid": f"{c.get('chain_id')}:{str(c.get('address') or '').lower()}",
            "name": c.get("protocol_name"),
            "chain": c.get("chain_name"),
            "site": ((c.get("market_profile") or {}).get("websites") or [""])[0],
            "note": c.get("verification_note", ""),
        }
        for c in candidates[:12]
    ]
    prompt = (
        "You are a Web3 PoW & Fair-Mint Mining Auditor. For each item JSON below, return a compact JSON object "
        "mapping uid -> short Arabic/Darija note (max 8 words) describing why user can mine/mint it or 'REJECT' "
        "if it is a memecoin/ETF/gambling site.\n"
        f"{json.dumps(brief_rows, ensure_ascii=False)}"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    try:
        async with session.post(
            url,
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"},
            },
            timeout=aiohttp.ClientTimeout(total=12),
        ) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                txt = (
                    ((data.get("candidates") or [{}])[0].get("content") or {})
                    .get("parts", [{}])[0]
                    .get("text", "{}")
                )
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    return {str(k): str(v) for k, v in parsed.items()}
    except Exception:
        pass
    return {}


async def _refresh_existing_market_prices(
    session: aiohttp.ClientSession,
    existing_items: dict[str, dict[str, Any]],
    batch_limit: int = 45,
) -> int:
    """Refresh live DexScreener prices & liquidity for accumulated protocols without dropping any."""
    updated = 0
    sem = asyncio.Semaphore(8)
    targets = list(existing_items.values())[:batch_limit]

    async def refresh_one(it: dict[str, Any]) -> None:
        nonlocal updated
        mkt = it.get("market_profile") or {}
        tok = (mkt.get("resolved_token_address") or it.get("token_address") or it.get("address") or "").strip()
        cid_l = str(it.get("chain_id") or "").lower()
        dex_slug = ""
        dex_url = str(mkt.get("dex_url") or "")
        if "dexscreener.com/" in dex_url:
            parts = dex_url.split("dexscreener.com/", 1)[-1].split("/")
            if parts and parts[0]:
                dex_slug = parts[0].lower()
        if not tok:
            return
        async with sem:
            try:
                async with session.get(
                    f"https://api.dexscreener.com/latest/dex/tokens/{tok}",
                    timeout=aiohttp.ClientTimeout(total=7),
                ) as r:
                    if r.status != 200:
                        return
                    d = await r.json(content_type=None)
                    pairs = [
                        p for p in (d.get("pairs") or [])
                        if str(p.get("chainId") or "").lower() not in ("robinhood", "arc")
                    ]
                    if not pairs:
                        return
                    if dex_slug:
                        same = [p for p in pairs if str(p.get("chainId") or "").lower() == dex_slug]
                        if same:
                            pairs = same
                    elif cid_l == "369":
                        same = [p for p in pairs if str(p.get("chainId") or "").lower() == "pulsechain"]
                        if same:
                            pairs = same
                    top = max(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                    px = top.get("priceUsd")
                    liq = (top.get("liquidity") or {}).get("usd")
                    if px and float(px) > 0:
                        mkt["price_usd"] = px
                        mkt["liquidity_usd"] = liq
                        mkt["volume_24h_usd"] = (top.get("volume") or {}).get("h24")
                        mkt["dex_url"] = top.get("url") or dex_url
                        it["market_profile"] = mkt
                        updated += 1
            except Exception:
                pass

    await asyncio.gather(*(refresh_one(it) for it in targets))
    return updated


async def run_agent_cycle(
    max_evm_chains: int = 180,
    blocks_back: int = 10,
    no_blocks: bool = False,
) -> dict[str, Any]:
    """Execute one full autonomous AI Agent discovery & cumulative registration cycle."""
    from hourly_mint_scanner import (
        SEARCH_QUERIES,
        _build_chain_resolver,
        _discover_blockscout_small_chains,
        _discover_dexscreener_candidates,
        _fetch_wtm_and_woolypooly,
        _is_testnet_chain,
    )

    t0 = time.perf_counter()

    # 1. OBSERVE: Load existing accumulated protocols + AI Agent persistent long-term memory
    prev_reg = load_registry()
    prev_items: dict[str, dict[str, Any]] = dict(prev_reg.get("items") or {})
    mem = load_agent_memory()
    cycle_num = int(mem.get("total_cycles") or prev_reg.get("total_scans_completed") or 0) + 1

    # 2. PLAN: Read long-term memory (priority_chains, watchlist_queries, rejected_patterns) + rotating windows
    priority_chains = _dedupe_str_list(mem.get("priority_chains") or [])
    watchlist_queries = _dedupe_str_list(mem.get("watchlist_queries") or [])
    rejected_patterns = _dedupe_str_list(mem.get("rejected_patterns") or [])

    omni = OmniRPC()
    evm_pool_size = max(1, len(omni.pool.get("evm") or []))
    evm_offset = int(mem.get("cursor_evm_offset") or 0) % evm_pool_size
    bs_offset = int(mem.get("cursor_bs_offset") or 0) % 90
    q_idx = int(mem.get("cursor_query_batch") or 0) % len(ADAPTIVE_QUERY_POOL)
    cycle_queries = list(dict.fromkeys(SEARCH_QUERIES + ADAPTIVE_QUERY_POOL[q_idx] + watchlist_queries))
    chain_resolver = _build_chain_resolver(omni)

    # 3. ACT: Execute RPC block scan + WhatToMine/WoolyPooly + Blockscout + DexScreener discovery
    if no_blocks:
        onchain_report: dict[str, Any] = {"evm_chains_scanned": 0, "total_chains_scanned": 0, "evm_results": []}
    else:
        onchain_report = await onchain_mining_scanner.run_scan(
            max_evm_chains=max_evm_chains,
            blocks_back=blocks_back,
            all_ecosystems=True,
            evm_offset=evm_offset,
        )

    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        wtm_wooly, bs_hits, refreshed_old = await asyncio.gather(
            _fetch_wtm_and_woolypooly(session),
            _discover_blockscout_small_chains(session, max_explorers=28, offset=bs_offset),
            _refresh_existing_market_prices(session, prev_items),
        )
        # Temporarily expand module SEARCH_QUERIES during discovery (including watchlist_queries)
        import hourly_mint_scanner as _hms
        orig_queries = list(_hms.SEARCH_QUERIES)
        _hms.SEARCH_QUERIES = cycle_queries
        try:
            discovered_dex = await _discover_dexscreener_candidates(session, chain_resolver, bs_hits)
        finally:
            _hms.SEARCH_QUERIES = orig_queries

        ai_notes = await _gemini_verify_candidates(session, discovered_dex)

    # Collect curated + newly discovered + live on-chain candidates
    raw_candidates: list[dict[str, Any]] = []
    seen_cand: set[tuple[str, str]] = set()
    priority_chains_l = [c.lower() for c in priority_chains]

    def push_cand(it: dict[str, Any], source_label: str) -> None:
        cid = str(it.get("chain_id") or "")
        cname = str(it.get("chain_name") or "")
        addr = str(it.get("address") or "").strip().lower()
        if not addr or _is_testnet_chain(cname, cid):
            return
        if _matches_rejected_patterns(it, rejected_patterns):
            return
        k = (cid, addr)
        if k in seen_cand:
            return
        seen_cand.add(k)
        rec = dict(it)
        rec.setdefault("discovery_source", source_label)
        if any(pc in cname.lower() for pc in priority_chains_l):
            rec["priority_chain_match"] = True
        raw_candidates.append(rec)

    for seed in CURATED_MINING_SEEDS:
        push_cand(seed, "curated_verified_seed")
    for d in discovered_dex:
        uid_d = f"{d.get('chain_id')}:{str(d.get('address') or '').lower()}"
        if ai_notes.get(uid_d) == "REJECT":
            continue
        if uid_d in ai_notes:
            d["agent_reasoning"] = ai_notes[uid_d]
        push_cand(d, "autonomous_dex_blockscout")

    for evm_ch in onchain_report.get("evm_results") or []:
        cid = str(evm_ch.get("chain_id") or "")
        cname = str(evm_ch.get("chain_name") or "")
        sym = str(evm_ch.get("native_symbol") or "ETH")
        if _is_testnet_chain(cname, cid):
            continue
        for c in (evm_ch.get("top_active_contracts") or []):
            push_cand(
                {
                    "ecosystem": "EVM",
                    "chain_id": evm_ch.get("chain_id"),
                    "chain_name": cname,
                    "native_symbol": sym,
                    "address": c.get("address"),
                    "tx_count": c.get("tx_count", 0),
                    "decoded_functions": c.get("decoded_functions") or [],
                    "is_curated_miner": False,
                },
                "onchain_rpc_scan",
            )

    # 4. REASON & ENRICH
    await enrich_registry_items_onchain(raw_candidates)
    verified_this_cycle = [
        it for it in raw_candidates
        if is_actionable_mining_protocol(it) and not _matches_rejected_patterns(it, rejected_patterns)
    ]

    # 5. MEMORIZE (NON-DESTRUCTIVE CUMULATIVE MERGE: Keep ALL valid old protocols + add new ones!)
    now_iso = utc_now_iso()
    merged_items: dict[str, dict[str, Any]] = {}

    # Preserve ALL valid previously stored protocols first (never reset to 0!)
    pruned_old = 0
    for uid, old_rec in prev_items.items():
        if is_actionable_mining_protocol(old_rec):
            kept = dict(old_rec)
            kept["is_new_in_last_scan"] = False
            merged_items[uid] = kept
        else:
            pruned_old += 1

    new_added_names: list[str] = []
    updated_count = 0

    for it in verified_this_cycle:
        cid = str(it.get("chain_id") or "")
        addr = str(it.get("address") or "").strip()
        uid = it.get("uid") or f"{cid}:{addr.lower()}"
        prev = merged_items.get(uid)
        is_brand_new = prev is None
        if is_brand_new:
            new_added_names.append(str(it.get("protocol_name") or uid))
            prev_base: dict[str, Any] = {}
        else:
            prev_base = prev
            updated_count += 1

        it["uid"] = uid
        it["symbol"] = it.get("symbol") or it.get("native_symbol") or prev_base.get("symbol") or "ETH"
        it["discovery_source"] = it.get("discovery_source") or prev_base.get("discovery_source") or "ai_agent_scan"
        it["first_seen_at"] = prev_base.get("first_seen_at") or now_iso
        it["last_seen_at"] = now_iso
        it["discovered_in_scan"] = prev_base.get("discovered_in_scan") or cycle_num
        it["seen_scans"] = int(prev_base.get("seen_scans") or 0) + 1
        it["is_new_in_last_scan"] = is_brand_new
        it["cumulative_txs"] = max(int(prev_base.get("cumulative_txs") or 0), int(it.get("tx_count") or 1))
        it["cumulative_mints"] = max(int(prev_base.get("cumulative_mints") or 0), int(it.get("tx_count") or 1))
        it["unique_callers"] = max(int(prev_base.get("unique_callers") or 0), int(it.get("unique_callers") or 1))
        if not it.get("agent_reasoning") and prev_base.get("agent_reasoning"):
            it["agent_reasoning"] = prev_base["agent_reasoning"]
        elif not it.get("agent_reasoning"):
            kind_tag = "تعدين GPU PoW" if "gpu" in str(it.get("protocol_type") or "").lower() else "تعدين / Mint عبر الموقع الرسمي"
            it["agent_reasoning"] = f"{kind_tag} • موثّق على {it.get('chain_name')}"

        merged_items[uid] = it

    duration_s = round(time.perf_counter() - t0, 1)
    evm_scanned = int(onchain_report.get("evm_chains_scanned") or 0)
    total_chains = int(onchain_report.get("total_chains_scanned") or 0)

    stats = {
        "evm_chains_scanned": evm_scanned,
        "total_chains_scanned": total_chains,
        "evm_offset": evm_offset,
        "bs_offset": bs_offset,
        "wtm_gpu_coins": wtm_wooly.get("wtm_count", 0),
        "wooly_pools": wtm_wooly.get("wooly_count", 0),
        "blockscout_hits": len(bs_hits),
        "dex_discovered_verified": len(discovered_dex),
        "refreshed_existing_prices": refreshed_old,
        "watchlist_queries_used": len(watchlist_queries),
        "priority_chains_count": len(priority_chains),
        "rejected_patterns_count": len(rejected_patterns),
        "verified_this_cycle": len(verified_this_cycle),
        "newly_registered": len(new_added_names),
        "total_accumulated_protocols": len(merged_items),
        "duration_s": duration_s,
    }

    history_entry = {
        "scan_id": cycle_num,
        "timestamp": now_iso,
        "duration_s": duration_s,
        "evm_chains_scanned": evm_scanned,
        "total_chains_scanned": total_chains,
        "matched_in_scan": len(verified_this_cycle),
        "newly_registered": len(new_added_names),
        "new_names": new_added_names[:10],
        "total_registry_size": len(merged_items),
    }

    out_reg = {
        "schema_version": 5,
        "agent_managed": True,
        "updated_at": now_iso,
        "updated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_interval_seconds": 3600,
        "total_scans_completed": cycle_num,
        "total_protocols": len(merged_items),
        "pruned_last_scan": pruned_old + max(0, len(raw_candidates) - len(verified_this_cycle)),
        "last_scan_stats": stats,
        "items": merged_items,
        "scan_history": ([history_entry] + list(prev_reg.get("scan_history") or []))[:60],
    }
    save_registry(out_reg)

    # 6. REPORT & UPDATE AGENT LONG-TERM MEMORY (preserve all directives, notes, chains, watchlist, rejections)
    if new_added_names:
        brief = (
            f"الدورة #{cycle_num}: فحص الإيجنت {total_chains} شبكة، زاد +{len(new_added_names)} بروتوكولات جديدة "
            f"({', '.join(new_added_names[:3])}) فوق القديم، المجموع المخزن دابا {len(merged_items)} بروتوكول."
        )
    else:
        brief = (
            f"الدورة #{cycle_num}: فحص الإيجنت {total_chains} شبكة وحدّث الأسعار، وبقى محافظ على كل البروتوكولات القديمة "
            f"({len(merged_items)} بروتوكول جاهز للتعدين)."
        )

    mem["agent_name"] = "OmniRPC Autonomous Mining Agent"
    mem["version"] = "1.1"
    mem["total_cycles"] = cycle_num
    mem["cursor_evm_offset"] = (evm_offset + 90) % evm_pool_size
    mem["cursor_bs_offset"] = (bs_offset + 14) % 90
    mem["cursor_query_batch"] = (q_idx + 1) % len(ADAPTIVE_QUERY_POOL)
    mem["last_cycle_at"] = now_iso
    mem["known_protocols_count"] = len(merged_items)
    mem["newly_added_last_cycle"] = len(new_added_names)
    mem["ai_llm_enabled"] = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    mem["last_agent_brief_ar"] = brief
    mem["cycle_logs"] = ([history_entry] + list(mem.get("cycle_logs") or []))[:40]
    mem["priority_chains"] = priority_chains
    mem["watchlist_queries"] = watchlist_queries
    mem["rejected_patterns"] = rejected_patterns
    save_agent_memory(mem)

    return {"registry": out_reg, "agent_memory": mem}


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniRPC Autonomous 1h IA Mining Discovery Agent")
    parser.add_argument("--max-evm", type=int, default=180)
    parser.add_argument("--blocks", type=int, default=10)
    parser.add_argument("--no-blocks", action="store_true")
    parser.add_argument("--loop", action="store_true", help="Run continuously every 3600s")
    parser.add_argument("--interval", type=int, default=3600)
    parser.add_argument("--remember", type=str, default="", help="Persist a new directive/note/chain/query/rejection to agent_memory.json")
    parser.add_argument(
        "--category",
        type=str,
        default="directive",
        choices=["directive", "note", "conversation_note", "priority_chain", "watchlist_query", "rejected_pattern"],
        help="Category for --remember",
    )
    args = parser.parse_args()

    if args.remember.strip():
        mem = record_user_directive(args.remember.strip(), category=args.category)
        print(
            json.dumps(
                {
                    "status": "remembered",
                    "category": args.category,
                    "user_directives_count": len(mem.get("user_directives") or []),
                    "conversation_notes_count": len(mem.get("conversation_notes") or []),
                    "priority_chains_count": len(mem.get("priority_chains") or []),
                    "watchlist_queries_count": len(mem.get("watchlist_queries") or []),
                    "rejected_patterns_count": len(mem.get("rejected_patterns") or []),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    if not args.loop:
        res = asyncio.run(run_agent_cycle(max_evm_chains=args.max_evm, blocks_back=args.blocks, no_blocks=args.no_blocks))
        reg = res["registry"]
        print(json.dumps({"updated_at": reg["updated_at"], "brief": res["agent_memory"]["last_agent_brief_ar"], "stats": reg["last_scan_stats"]}, indent=2, ensure_ascii=False))
        return

    async def loop_forever() -> None:
        while True:
            try:
                res = await run_agent_cycle(max_evm_chains=args.max_evm, blocks_back=args.blocks, no_blocks=args.no_blocks)
                print(res["agent_memory"]["last_agent_brief_ar"], flush=True)
            except Exception as exc:
                print(f"[AGENT ERROR] {exc}", flush=True)
            await asyncio.sleep(args.interval)

    asyncio.run(loop_forever())


if __name__ == "__main__":
    main()
