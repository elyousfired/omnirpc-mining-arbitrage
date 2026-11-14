"""
Gamified Grid/Square Mining Games Scanner & Registry ("نظام المربعات بحال ORE").

Keeps gamified betting/auction/crafting mining games strictly SEPARATE from real
Proof-of-Work tokens, while teaching the AI Agent to hunt specifically for
ORE-style 5x5 grid betting games, King-of-the-Hill auctions, and crafting grids.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

from wallet_simulator import verify_gamified_grid_ui

BASE_DIR = Path(__file__).resolve().parent
GAMES_REGISTRY_JSON = BASE_DIR / "games_registry.json"

GAMIFIED_SEARCH_QUERIES = [
    "ore",
    "motherlode",
    "minebean",
    "beanpot",
    "binarium",
    "godl",
    "5x5",
    "25 blocks",
    "25 squares",
    "grid mining",
    "glaze",
    "minechain",
]

TESTNET_GAME_SLUGS = {"robinhood", "arc", "sepolia", "goerli", "holesky", "amoy", "devnet", "mumbai", "fuji"}

CURATED_GAMIFIED_MINING_GAMES: list[dict[str, Any]] = [
    {
        "uid": "game:solana:orev3",
        "name": "ORE Protocol V3/V4 (5x5 Grid Betting)",
        "symbol": "ORE",
        "chain_name": "Solana Mainnet",
        "chain_id": "solana",
        "contract": "oreV3EG1i9BEgiAJ8b177Z2S2rMarzak4NMv1kULvWv",
        "token_address": "oreoU2P8bN6jkk3jbaiVxYnG1dCXcYxwhwyK9jSybcp",
        "site_url": "https://ore.supply",
        "game_type": "GRID_5X5_BETTING",
        "game_type_ar": "نظام المربعات 5x5 (رهان SOL بحال ORE)",
        "grid_layout": "5x5 (25 مربع)",
        "round_duration_sec": 60,
        "entry_currency": "SOL",
        "house_cut_pct": 10.5,
        "mechanic_ar": "كتحط SOL فـ مربع أو كثر من شبكة 5x5 كل دقيقة؛ كيتختار مربع واحد عشوائياً، والرابحين كياخدو الجائزة + توكن ORE + جاكبوت Motherlode.",
        "risk_note_ar": "لعبة احتمالات/رهان (ماشي تعدين GPU).",
    },
    {
        "uid": "game:base:minebean",
        "name": "MineBean (Base 5x5 Grid Mining)",
        "symbol": "BEAN",
        "chain_name": "Base",
        "chain_id": "base",
        "contract": "0x5c72992b83E74c4D5200A8E8920fB946214a5A5D",
        "token_address": "0x5c72992b83E74c4D5200A8E8920fB946214a5A5D",
        "site_url": "https://www.minebean.com/",
        "game_type": "GRID_5X5_BETTING",
        "game_type_ar": "نظام المربعات 5x5 على Base (شبيه ORE)",
        "grid_layout": "5x5 (25 مربع)",
        "round_duration_sec": 60,
        "entry_currency": "ETH (Base)",
        "house_cut_pct": 10.0,
        "mechanic_ar": "نسخة نظام المربعات 5x5 على شبكة Base: كتدخل بـ ETH فـ مربعات الشبكة وكل جولة كيربح مربع وكيوزع BEAN + جاكبوت Beanpot.",
        "risk_note_ar": "لعبة مربعات على Base L2 — راقب السيولة ورسوم الغاز.",
    },
    {
        "uid": "game:bsc:binarium",
        "name": "Binarium ($BNR — BSC Grid Mining)",
        "symbol": "BNR",
        "chain_name": "BNB Smart Chain",
        "chain_id": "bsc",
        "contract": "0xc3Fc2156e53Ab760574EAd452627e6B8CD675B32",
        "token_address": "0xc3Fc2156e53Ab760574EAd452627e6B8CD675B32",
        "site_url": "https://binarium.supply",
        "game_type": "GRID_5X5_BETTING",
        "game_type_ar": "نظام المربعات على BSC (شبيه ORE)",
        "grid_layout": "Grid Squares (60s)",
        "round_duration_sec": 60,
        "entry_currency": "BNB (BSC)",
        "house_cut_pct": 10.0,
        "mechanic_ar": "نظام المربعات بحال ORE على شبكة BSC: كتدخل بـ BNB فـ مربعات الشبكة كل 60 ثانية، والرابحين كيقسمو 90% من الـ BNB + توكن BNR + جاكبوت Motherlode.",
        "risk_note_ar": "لعبة مربعات ورهان بـ BNB على شبكة BSC.",
    },
    {
        "uid": "game:solana:godl",
        "name": "GODL Supply (Solana 5x5 Grid Mining)",
        "symbol": "GODL",
        "chain_name": "Solana Mainnet",
        "chain_id": "solana",
        "contract": "GodL6KZ9uuUoQwELggtVzQkKmU1LfqmDokPibPeDKkhF",
        "token_address": "GodL6KZ9uuUoQwELggtVzQkKmU1LfqmDokPibPeDKkhF",
        "site_url": "https://godl.supply",
        "game_type": "GRID_5X5_BETTING",
        "game_type_ar": "نظام المربعات 5x5 على Solana (شبيه ORE)",
        "grid_layout": "5x5 (25 مربع)",
        "round_duration_sec": 60,
        "entry_currency": "SOL",
        "house_cut_pct": 10.0,
        "mechanic_ar": "نسخة 5x5 بحال ORE على Solana: كتختار مربعات فـ الشبكة وتدخل بـ SOL كل جولة، والرابح كياخد توزيع SOL + توكن GODL + جاكبوت Motherlode.",
        "risk_note_ar": "لعبة مربعات ورهان بـ SOL على Solana.",
    },
    {
        "uid": "game:base:donut_glaze",
        "name": "Donut Protocol / Glaze Corp",
        "symbol": "DONUT",
        "chain_name": "Base",
        "chain_id": "base",
        "contract": "0xae4a37d554c6d6f3e398546d8566b25052e0169c",
        "token_address": "0xae4a37d554c6d6f3e398546d8566b25052e0169c",
        "site_url": "https://glaze.click/",
        "game_type": "KOTH_AUCTION",
        "game_type_ar": "مزاد التاج (King of the Hill)",
        "grid_layout": "Dutch Auction 1h",
        "round_duration_sec": 3600,
        "entry_currency": "ETH (Base)",
        "house_cut_pct": 20.0,
        "mechanic_ar": "مزاد تنازلي (King of the Hill): كتخلص ETH باش تاخد التاج وتبدا تربح DONUT كل ثانية حتى يجي واحد آخر يشري التاج عليك.",
        "risk_note_ar": "لعبة تنافسية (ماشي تعدين GPU).",
    },
    {
        "uid": "game:solana:coal_minechain",
        "name": "COAL / Minechain (Crafting Grid + DrillX)",
        "symbol": "COAL",
        "chain_name": "Solana Mainnet",
        "chain_id": "solana",
        "contract": "E3yUqBNTZxV8ELvW99oRLC7z4ddbJqqR4NphwrMug9zu",
        "token_address": "E3yUqBNTZxV8ELvW99oRLC7z4ddbJqqR4NphwrMug9zu",
        "site_url": "https://minechain.gg",
        "game_type": "IDLE_CRAFTING_MINER",
        "game_type_ar": "شبكة موارد وكرافتينغ + DrillX",
        "grid_layout": "Resource Grid + Tools",
        "round_duration_sec": 60,
        "entry_currency": "SOL / COAL",
        "house_cut_pct": 5.0,
        "mechanic_ar": "كيجمع بين تعدين DrillX وميكانيك لعبة جمع الموارد (ORE, WOOD, INGOT) وصناعة أدوات.",
        "risk_note_ar": "نظام هجين (فيه PoW بـ coal-cli ولكن الواجهة ديالو لعبة crafting).",
    },
]


def load_games_registry() -> dict[str, Any]:
    if not GAMES_REGISTRY_JSON.exists():
        return {"updated_at": None, "total_games": 0, "items": []}
    try:
        return json.loads(GAMES_REGISTRY_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {"updated_at": None, "total_games": 0, "items": []}


async def _fetch_dex_stats(session: aiohttp.ClientSession, token_addr: str) -> dict[str, Any]:
    try:
        async with session.get(
            f"https://api.dexscreener.com/latest/dex/tokens/{token_addr}",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            if r.status != 200:
                return {}
            data = await r.json(content_type=None)
            pairs = [p for p in (data.get("pairs") or []) if isinstance(p, dict)]
            if not pairs:
                return {}
            best = max(pairs, key=lambda x: float(((x.get("liquidity") or {}).get("usd")) or 0))
            return {
                "price_usd": float(best.get("priceUsd") or 0.0),
                "liquidity_usd": float(((best.get("liquidity") or {}).get("usd")) or 0.0),
                "volume_24h_usd": float(((best.get("volume") or {}).get("h24")) or 0.0),
                "dex_url": best.get("url") or "",
                "dex_id": best.get("dexId") or "",
            }
    except Exception:
        return {}


async def _discover_new_grid_games(session: aiohttp.ClientSession, known_tokens: set[str]) -> list[dict[str, Any]]:
    """Search DexScreener for ORE-style grid/square/tile mining games across all chains."""
    candidates: list[dict[str, Any]] = []
    seen_tok: set[str] = set(known_tokens)

    async def _search_q(q: str) -> list[dict[str, Any]]:
        try:
            async with session.get(
                f"https://api.dexscreener.com/latest/dex/search?q={q}",
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status == 200:
                    d = await r.json(content_type=None)
                    return d.get("pairs") or []
        except Exception:
            pass
        return []

    batches = await asyncio.gather(*[_search_q(q) for q in GAMIFIED_SEARCH_QUERIES], return_exceptions=True)
    to_verify: list[tuple[dict[str, Any], str]] = []
    for res in batches:
        if not isinstance(res, list):
            continue
        for p in res[:15]:
            if not isinstance(p, dict):
                continue
            cid = str(p.get("chainId") or "").lower()
            if not cid or cid in TESTNET_GAME_SLUGS:
                continue
            liq = float(((p.get("liquidity") or {}).get("usd")) or 0.0)
            if liq < 300:
                continue
            base = p.get("baseToken") or {}
            taddr = str(base.get("address") or "").strip()
            if not taddr or taddr.lower() in seen_tok:
                continue
            websites = [w.get("url") for w in ((p.get("info") or {}).get("websites") or []) if isinstance(w, dict) and w.get("url")]
            if not websites:
                continue
            site_low = str(websites[0]).lower()
            if any(lp in site_low for lp in ("stonkfun.xyz", "pump.fun", "four.meme", "clanker.world", "moonshot", "raydium.io", "uniswap.org", "jup.ag", "gmgn.ai", "zora.co", "bonk.fun", "believe.app")):
                continue
            seen_tok.add(taddr.lower())
            to_verify.append((p, websites[0]))

    sem = asyncio.Semaphore(6)

    async def _verify_one(p: dict[str, Any], site: str) -> dict[str, Any] | None:
        async with sem:
            ui = await verify_gamified_grid_ui(session, site)
        if not ui.get("is_gamified_mining"):
            return None
        base = p.get("baseToken") or {}
        taddr = str(base.get("address") or "")
        chain_id = str(p.get("chainId") or "unknown")
        return {
            "uid": f"game:{chain_id}:{taddr.lower()}",
            "name": str(base.get("name") or base.get("symbol") or "Grid Game"),
            "symbol": str(base.get("symbol") or "GAME"),
            "chain_name": chain_id.title(),
            "chain_id": chain_id,
            "contract": taddr,
            "token_address": taddr,
            "site_url": site,
            "game_type": ui.get("game_type") or "GRID_5X5_BETTING",
            "game_type_ar": ui.get("game_type_ar") or "لعبة تعدين بالمربعات",
            "grid_layout": "Web3 Grid / Tiles",
            "round_duration_sec": 60,
            "entry_currency": chain_id.upper(),
            "house_cut_pct": 10.0,
            "mechanic_ar": f"لعبة Web3 مكتشفة أوتوماتيكياً ({', '.join(ui.get('matched_game_signals') or [])}).",
            "risk_note_ar": "لعبة تعدين تفاعلية (Connect Wallet + شبكة مربعات/مزاد) — ماشي تعدين GPU.",
            "price_usd": float(p.get("priceUsd") or 0.0),
            "liquidity_usd": float(((p.get("liquidity") or {}).get("usd")) or 0.0),
            "volume_24h_usd": float(((p.get("volume") or {}).get("h24")) or 0.0),
            "dex_url": p.get("url") or "",
            "site_live": True,
            "has_connect_wallet": bool(ui.get("has_connect_wallet")),
            "matched_game_signals": ui.get("matched_game_signals") or [],
        }

    verified = await asyncio.gather(*[_verify_one(p, site) for p, site in to_verify[:40]], return_exceptions=True)
    for item in verified:
        if isinstance(item, dict):
            candidates.append(item)
    return candidates


async def refresh_games_registry(session: aiohttp.ClientSession | None = None) -> dict[str, Any]:
    """Refresh curated + newly discovered ORE-style grid/KOTH mining games and persist games_registry.json."""
    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession()
    try:
        # Rebuild fresh from curated + strictly verified discoveries so stale meme-coin false positives never linger
        by_uid: dict[str, dict[str, Any]] = {}
        known_toks: set[str] = set()

        async def _check_curated(g: dict[str, Any]) -> dict[str, Any]:
            rec = dict(g)
            ui_res, dex_res = await asyncio.gather(
                verify_gamified_grid_ui(session, rec["site_url"]),
                _fetch_dex_stats(session, rec["token_address"]),
                return_exceptions=True,
            )
            if isinstance(ui_res, dict):
                rec["site_live"] = bool(ui_res.get("site_live"))
                rec["has_connect_wallet"] = bool(ui_res.get("has_connect_wallet"))
                rec["matched_game_signals"] = ui_res.get("matched_game_signals") or []
            if isinstance(dex_res, dict) and dex_res:
                rec.update(dex_res)
            return rec

        curated_updated = await asyncio.gather(*[_check_curated(g) for g in CURATED_GAMIFIED_MINING_GAMES])
        for rec in curated_updated:
            by_uid[rec["uid"]] = rec
            if rec.get("token_address"):
                known_toks.add(rec["token_address"].lower())

        new_games = await _discover_new_grid_games(session, known_toks)
        for g in new_games:
            by_uid[g["uid"]] = g

        items = sorted(by_uid.values(), key=lambda x: float(x.get("liquidity_usd") or 0.0), reverse=True)
        out = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_games": len(items),
            "grid_5x5_count": sum(1 for x in items if x.get("game_type") == "GRID_5X5_BETTING"),
            "items": items,
        }
        GAMES_REGISTRY_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        return out
    finally:
        if own_session:
            await session.close()


if __name__ == "__main__":
    res = asyncio.run(refresh_games_registry())
    print(json.dumps({"total_games": res["total_games"], "names": [x["name"] for x in res["items"]]}, ensure_ascii=False))
