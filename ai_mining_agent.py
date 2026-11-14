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
from wallet_simulator import (
    DEFAULT_SANDBOX_EVM_WALLET,
    DEFAULT_SANDBOX_SOL_WALLET,
    inspect_evm_contract_onchain,
    simulate_sandbox_wallet_mint,
)

ROOT = Path(__file__).resolve().parent
AGENT_MEMORY_PATH = ROOT / "agent_memory.json"

# Extra adaptive search rotations added every hour beyond base queries (ONLY Web3 Connect-Wallet Mint & On-Chain PoW)
ADAPTIVE_QUERY_POOL = [
    ["claimrank", "startmint", "titanx", "glaze", "drillx", "xen mint", "pmint", "fair mint", "mint to earn"],
    ["orx minter", "mrdn", "pulsechain mint", "base mine", "shogun", "x28", "titanfarms", "burnandmint"],
    ["dragonx", "volt mint", "hyper mint", "pow token", "epow", "web3 miner", "mine token", "enterauction"],
    ["ore supply", "coal solana", "claim mint", "batchmint", "challengeNumber", "nonce mint", "epoch mine"],
]

DEFAULT_USER_DIRECTIVES: list[dict[str, Any]] = [
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "عدم تصفير mining_registry.json أبداً؛ الحفاظ على كل البروتوكولات الصالحة القديمة (first_seen_at, seen_scans) وإضافة الجديد كل ساعة مع حذف المواقع الطايحة والعملات الممنوعة.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T22:20:00Z",
        "category": "directive",
        "text": "التركيز 100% فقط على بروتوكولات Web3 (Connect Wallet -> Mint / Mine -> بيع التوكن فـ DEX وربح) وفحص عقودها On-Chain وتجريبها بالمحفظة التجريبية (Sandbox Wallet) — مع حظر تام لعملات L1/HiveOS بحال Dynex و Firo و Zano و Ergo و ETC.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "تغطية الشبكات الصغيرة والمغمورة والـ L2s (PulseChain, Base, Polygon, Arbitrum, BSC, Solana, TON, Ethereum) بحثاً عن عقود PoW و Mint حقيقية شغالة on-chain.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:40:00Z",
        "category": "directive",
        "text": "الرفض الصارم لشبكات التجربة (testnets: robinhood, arc, sepolia)، ألعاب النقرات (idle clickers)، عملات L1 PoW التقليدية، مواقع L1/CLI، والمواقع الطايحة DNS.",
        "active": True,
    },
    {
        "timestamp": "2026-11-13T21:52:00Z",
        "category": "directive",
        "text": "فين ما تلقى شي بروتوكول Connect Wallet -> Mint جديد مجرّب وناجح، صيفطو لينا هنا فوراً عبر notifications_queue.",
        "active": True,
    },
]

DEFAULT_PRIORITY_CHAINS: list[str] = [
    "PulseChain",
    "Base",
    "TON",
    "Solana",
    "Polygon",
    "Arbitrum",
    "BNB Smart Chain",
    "Ethereum",
    "Avalanche",
]

DEFAULT_WATCHLIST_QUERIES: list[str] = [
    "claimrank",
    "startmint",
    "glaze",
    "pmint",
    "titanx",
    "orx",
    "shogun",
    "mrdn",
    "ore",
    "coal",
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
    "dynexcoin.org",
    "firo.org",
    "zano.org",
    "ergoplatform.org",
    "confluxnetwork.org",
    "octa.space",
    "ethereumclassic.org",
    "clore.ai",
    "runonflux.io",
    "aipowergrid.io",
    "tari.com",
    "qu.ai",
    "alephium.org",
    "0xbitcoin.org",
    "gramcoin.org",
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
    mem.setdefault("version", "2.0")
    mem.setdefault("sandbox_wallet", DEFAULT_SANDBOX_EVM_WALLET)
    mem.setdefault("sandbox_sol_wallet", DEFAULT_SANDBOX_SOL_WALLET)
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

    if not isinstance(mem.get("notifications_queue"), list):
        mem["notifications_queue"] = []

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
        mem["rejected_patterns"] = _dedupe_str_list(list(existing_rej) + list(DEFAULT_REJECTED_PATTERNS))

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


def _build_discovery_alert(item: dict[str, Any], cycle_num: int, discovered_at: str) -> dict[str, Any]:
    """Create a structured notification alert payload for a newly discovered protocol."""
    mkt = item.get("market_profile") or {}
    ptype_l = str(item.get("protocol_type") or "").lower()
    cat_l = str(item.get("category") or "").lower()
    kind = "gpu_pow" if ("gpu" in ptype_l or "gpu" in cat_l) else "mint_tx"
    websites = [w for w in (mkt.get("websites") or []) if isinstance(w, str) and w.startswith(("http://", "https://"))]
    uid = str(item.get("uid") or f"{item.get('chain_id')}:{str(item.get('address') or '').strip().lower()}")
    return {
        "id": f"alert-{cycle_num}-{uid}",
        "discovered_at": discovered_at,
        "cycle_id": cycle_num,
        "uid": uid,
        "protocol_name": str(item.get("protocol_name") or uid),
        "token_symbol": str(mkt.get("token_symbol") or item.get("symbol") or ""),
        "chain_name": str(item.get("chain_name") or ""),
        "kind": kind,
        "price_usd": mkt.get("price_usd"),
        "liquidity_usd": mkt.get("liquidity_usd"),
        "website": websites[0] if websites else "",
        "dex_url": str(mkt.get("dex_url") or ""),
        "explorer_url": str(item.get("explorer_url") or ""),
        "reported_to_chat": False,
    }


def get_unreported_alerts(path: Path = AGENT_MEMORY_PATH) -> list[dict[str, Any]]:
    """Return all queued discovery alerts that have not yet been reported to chat."""
    mem = load_agent_memory(path)
    return [
        a for a in (mem.get("notifications_queue") or [])
        if isinstance(a, dict) and not a.get("reported_to_chat")
    ]


def acknowledge_alerts(alert_ids: list[str] | None = None, path: Path = AGENT_MEMORY_PATH) -> int:
    """Mark unreported alerts (or specific alert IDs) as reported_to_chat=True."""
    mem = load_agent_memory(path)
    queue = list(mem.get("notifications_queue") or [])
    target_set = {str(aid) for aid in (alert_ids or []) if str(aid).strip()}
    now_iso = utc_now_iso()
    acked = 0
    for alert in queue:
        if not isinstance(alert, dict) or alert.get("reported_to_chat"):
            continue
        if not target_set or str(alert.get("id") or "") in target_set:
            alert["reported_to_chat"] = True
            alert["reported_at"] = now_iso
            acked += 1
    if acked:
        mem["notifications_queue"] = queue
        save_agent_memory(mem, path=path)
    return acked


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

    sandbox_wallet = str(mem.get("sandbox_wallet") or DEFAULT_SANDBOX_EVM_WALLET)
    omni = OmniRPC()
    evm_pool_size = max(1, len(omni.pool.get("evm") or []))
    evm_offset = int(mem.get("cursor_evm_offset") or 0) % evm_pool_size
    bs_offset = int(mem.get("cursor_bs_offset") or 0) % 90
    q_idx = int(mem.get("cursor_query_batch") or 0) % len(ADAPTIVE_QUERY_POOL)
    # Purge old L1 watchlist queries from memory pool while preserving custom user mint queries
    _l1_watch_block = {"tari wxtm", "quai network", "neoxa", "karlsen", "xelis", "conflux mine", "pulsechain pow"}
    watchlist_queries = [q for q in watchlist_queries if q.lower() not in _l1_watch_block] or list(DEFAULT_WATCHLIST_QUERIES)
    cycle_queries = list(dict.fromkeys(SEARCH_QUERIES + ADAPTIVE_QUERY_POOL[q_idx] + watchlist_queries))
    chain_resolver = _build_chain_resolver(omni)

    # 3. ACT: Execute On-Chain RPC block/tx scan + Blockscout Verified Contracts + DexScreener Mint dApps
    if no_blocks:
        onchain_report: dict[str, Any] = {"evm_chains_scanned": 0, "total_chains_scanned": 0, "evm_results": []}
    else:
        onchain_report = await onchain_mining_scanner.run_scan(
            max_evm_chains=max_evm_chains,
            blocks_back=blocks_back,
            all_ecosystems=True,
            evm_offset=evm_offset,
        )

    connector = aiohttp.TCPConnector(limit=32, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        bs_hits, refreshed_old = await asyncio.gather(
            _discover_blockscout_small_chains(session, max_explorers=28, offset=bs_offset),
            _refresh_existing_market_prices(session, prev_items),
        )
        import hourly_mint_scanner as _hms
        orig_queries = list(_hms.SEARCH_QUERIES)
        _hms.SEARCH_QUERIES = cycle_queries
        try:
            discovered_dex = await _discover_dexscreener_candidates(session, chain_resolver, bs_hits)
        finally:
            _hms.SEARCH_QUERIES = orig_queries

        ai_notes = await _gemini_verify_candidates(session, discovered_dex)

        # Deep On-Chain PoW/Mint Bytecode Inspection on active contracts seen directly in EVM blocks
        onchain_pow_promoted = 0
        oc_sem = asyncio.Semaphore(10)
        raw_evm_contracts: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for evm_ch in onchain_report.get("evm_results") or []:
            cid = str(evm_ch.get("chain_id") or "")
            cname = str(evm_ch.get("chain_name") or "")
            if _is_testnet_chain(cname, cid):
                continue
            for c in (evm_ch.get("top_active_contracts") or [])[:5]:
                if int(c.get("unique_callers") or 0) >= 2:
                    raw_evm_contracts.append((evm_ch, c))

        async def _probe_evm_pow(evm_ch: dict[str, Any], c: dict[str, Any]) -> None:
            nonlocal onchain_pow_promoted
            async with oc_sem:
                oc = await inspect_evm_contract_onchain(
                    session, omni, evm_ch.get("chain_id"), str(c.get("address") or ""), decoded_functions=c.get("decoded_functions") or []
                )
            if oc.get("is_onchain_pow_or_mint") and not oc.get("paused"):
                extra_fns = (oc.get("pow_functions_found") or []) + (oc.get("mint_functions_found") or [])
                c["decoded_functions"] = list(dict.fromkeys((c.get("decoded_functions") or []) + extra_fns))
                c["onchain_pow_verified"] = True
                onchain_pow_promoted += 1

        if raw_evm_contracts:
            await asyncio.gather(*(_probe_evm_pow(ch, ct) for ch, ct in raw_evm_contracts[:40]), return_exceptions=True)

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
                    "onchain_pow_verified": bool(c.get("onchain_pow_verified")),
                    "is_curated_miner": False,
                },
                "onchain_rpc_scan",
            )

    # 4. REASON, ENRICH & SANDBOX WALLET TRIAL ("Agent enters site + connects wallet + tests mint")
    await enrich_registry_items_onchain(raw_candidates)

    # Fetch native USD gas prices once for fee valuation
    native_usd_map: dict[str, float] = {}
    try:
        from arbitrage_engine import _fetch_live_market_inputs
        mkt_in = await _fetch_live_market_inputs()
        native_usd_map = dict(mkt_in.get("native_prices") or {})
    except Exception:
        pass

    def _ready_for_sandbox(it: dict[str, Any]) -> bool:
        mkt = it.get("market_profile") or {}
        sites = [w for w in (mkt.get("websites") or []) if isinstance(w, str) and w.startswith(("http://", "https://")) and "github.com" not in w.lower()]
        try:
            px = float(mkt.get("price_usd") or 0)
        except Exception:
            px = 0.0
        return bool(sites and px > 0 and not _matches_rejected_patterns(it, rejected_patterns))

    trial_targets: list[dict[str, Any]] = [it for it in raw_candidates if _ready_for_sandbox(it)]
    cand_uids = {str(it.get("uid") or f"{it.get('chain_id')}:{str(it.get('address') or '').lower()}") for it in trial_targets}
    old_reverify: list[dict[str, Any]] = []
    for uid, old_rec in prev_items.items():
        if uid not in cand_uids and _ready_for_sandbox(old_rec):
            old_reverify.append(old_rec)

    all_to_test = trial_targets + old_reverify
    sb_sem = asyncio.Semaphore(8)
    sandbox_by_uid: dict[str, dict[str, Any]] = {}
    connector2 = aiohttp.TCPConnector(limit=32, ssl=False)
    async with aiohttp.ClientSession(connector=connector2) as sb_session:
        async def _run_trial(it: dict[str, Any]) -> None:
            mkt = it.get("market_profile") or {}
            eco = str(it.get("ecosystem") or "EVM")
            uid_t = str(it.get("uid") or f"{it.get('chain_id')}:{str(it.get('address') or '').lower()}")
            test_item = {
                "chain_type": "TON" if eco == "TON" else ("SOLANA" if eco == "Solana" else "EVM"),
                "evm_chain_id": it.get("chain_id") if eco == "EVM" else None,
                "contract": it.get("address"),
                "websites": mkt.get("websites") or [],
                "decoded_functions": it.get("decoded_functions") or [],
            }
            async with sb_sem:
                trial = await simulate_sandbox_wallet_mint(
                    sb_session, omni, test_item, sandbox_wallet=sandbox_wallet, native_usd_map=native_usd_map
                )
            it["sandbox_test"] = trial
            sandbox_by_uid[uid_t] = trial
            if trial.get("tested_fn") and trial["tested_fn"] not in (it.get("decoded_functions") or []):
                it["decoded_functions"] = list(dict.fromkeys([trial["tested_fn"]] + list(it.get("decoded_functions") or [])))

        if all_to_test:
            await asyncio.gather(*(_run_trial(it) for it in all_to_test), return_exceptions=True)

    verified_this_cycle = [
        it for it in raw_candidates
        if is_actionable_mining_protocol(it) and not _matches_rejected_patterns(it, rejected_patterns)
    ]

    # 5. MEMORIZE (NON-DESTRUCTIVE CUMULATIVE MERGE: Keep ALL valid old Web3 Mint protocols + add new ones!)
    now_iso = utc_now_iso()
    merged_items: dict[str, dict[str, Any]] = {}

    def _tok_dedup_key(rec: dict[str, Any]) -> tuple[str, str]:
        eco = str(rec.get("ecosystem") or "").lower()
        chain_bucket = eco if eco in ("solana", "ton", "sui", "aptos") else str(rec.get("chain_id") or "").lower()
        tok = str((rec.get("market_profile") or {}).get("resolved_token_address") or rec.get("token_address") or rec.get("address") or "").lower()
        return (chain_bucket, tok) if tok else ("", "")

    # Preserve ALL valid previously stored protocols first (applying fresh sandbox trials & pruning L1/dead/memes)
    pruned_old = 0
    seen_tok_keys: set[tuple[str, str]] = set()
    ordered_prev = sorted(prev_items.items(), key=lambda kv: (0 if kv[1].get("is_curated_miner") else 1, kv[0]))
    for uid, old_rec in ordered_prev:
        kept = dict(old_rec)
        if uid in sandbox_by_uid:
            kept["sandbox_test"] = sandbox_by_uid[uid]
        tkey = _tok_dedup_key(kept)
        if tkey[1] and tkey in seen_tok_keys:
            pruned_old += 1
            continue
        if is_actionable_mining_protocol(kept) and not _matches_rejected_patterns(kept, rejected_patterns):
            kept["is_new_in_last_scan"] = False
            merged_items[uid] = kept
            if tkey[1]:
                seen_tok_keys.add(tkey)
        else:
            pruned_old += 1

    new_added_names: list[str] = []
    new_alerts: list[dict[str, Any]] = []
    updated_count = 0

    for it in verified_this_cycle:
        cid = str(it.get("chain_id") or "")
        addr = str(it.get("address") or "").strip()
        uid = it.get("uid") or f"{cid}:{addr.lower()}"
        _tok_key = _tok_dedup_key(it)
        _tok_new = _tok_key[1]
        prev = merged_items.get(uid)
        if prev is None and _tok_new and _tok_key in seen_tok_keys:
            continue
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
            sb = it.get("sandbox_test") or {}
            verdict = sb.get("trial_verdict_ar") or "Connect Wallet -> Mint موثّق"
            it["agent_reasoning"] = f"{verdict} • {it.get('chain_name')}"

        merged_items[uid] = it
        if _tok_new:
            seen_tok_keys.add(_tok_key)
        if is_brand_new:
            alert = _build_discovery_alert(it, cycle_num, now_iso)
            new_alerts.append(alert)
            print(
                f"[NEW_DISCOVERY_ALERT] {alert['protocol_name']} ({alert['token_symbol']}) "
                f"on {alert['chain_name']} | kind={alert['kind']} | price=${alert['price_usd']} "
                f"| liq=${alert['liquidity_usd']} | site={alert['website']} | dex={alert['dex_url']}",
                flush=True,
            )

    duration_s = round(time.perf_counter() - t0, 1)
    evm_scanned = int(onchain_report.get("evm_chains_scanned") or 0)
    total_chains = int(onchain_report.get("total_chains_scanned") or 0)
    sim_open_count = sum(
        1 for it in merged_items.values()
        if (it.get("sandbox_test") or {}).get("trial_status") in ("SIMULATED_OPEN", "POW_OR_MINT_ACTIVE")
    )

    stats = {
        "evm_chains_scanned": evm_scanned,
        "total_chains_scanned": total_chains,
        "evm_offset": evm_offset,
        "bs_offset": bs_offset,
        "onchain_pow_promoted": onchain_pow_promoted,
        "sandbox_trials_run": len(all_to_test),
        "sandbox_trials_passed": len(merged_items),
        "sandbox_simulated_open": sim_open_count,
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
        "schema_version": 6,
        "agent_managed": True,
        "sandbox_wallet": sandbox_wallet,
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
            f"الدورة #{cycle_num}: دخل الإيجنت l-on-chain ({total_chains} شبكة)، جرّب {len(all_to_test)} داب بالمحفظة التجريبية "
            f"{sandbox_wallet[:8]}..، زاد +{len(new_added_names)} بروتوكول Connect Wallet -> Mint ({', '.join(new_added_names[:3])}) "
            f"والمجموع الصافي دابا {len(merged_items)} بروتوكول."
        )
    else:
        brief = (
            f"الدورة #{cycle_num}: دخل الإيجنت l-on-chain ({total_chains} شبكة)، جرّب {len(all_to_test)} داب بالمحفظة التجريبية "
            f"{sandbox_wallet[:8]}..، وصفّى اللستة غير لبروتوكولات Connect Wallet -> Mint الصالحة ({len(merged_items)} بروتوكول، "
            f"{sim_open_count} مجرّب On-Chain)."
        )

    mem["agent_name"] = "OmniRPC Autonomous Mining Agent"
    mem["version"] = "2.0"
    mem["sandbox_wallet"] = sandbox_wallet
    mem["sandbox_trials_last_cycle"] = {
        "tested": len(all_to_test),
        "passed": len(merged_items),
        "simulated_open": sim_open_count,
        "onchain_pow_promoted": onchain_pow_promoted,
    }
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
    existing_queue = [
        a for a in (mem.get("notifications_queue") or [])
        if isinstance(a, dict) and str(a.get("uid") or "") in merged_items
    ]
    if new_alerts:
        seen_uids = {str(a.get("uid") or "") for a in existing_queue}
        for alert in new_alerts:
            if alert["uid"] not in seen_uids:
                existing_queue.append(alert)
                seen_uids.add(alert["uid"])
    mem["notifications_queue"] = existing_queue[-50:]
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
    parser.add_argument("--show-alerts", action="store_true", help="Print unreported discovery alerts from notifications_queue")
    parser.add_argument("--ack-alerts", action="store_true", help="Mark all unreported alerts as reported_to_chat=True")
    args = parser.parse_args()

    if args.show_alerts:
        mem = load_agent_memory()
        unreported = get_unreported_alerts()
        print(
            json.dumps(
                {
                    "unreported_count": len(unreported),
                    "total_alerts": len(mem.get("notifications_queue") or []),
                    "alerts": unreported,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    if args.ack_alerts:
        acked = acknowledge_alerts()
        print(json.dumps({"status": "acknowledged", "acknowledged_count": acked}, indent=2, ensure_ascii=False))
        return

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
