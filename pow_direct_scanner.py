"""Direct PoW / UTXO Chain Scanner (Bitcoin, Kaspa, Alephium, Ergo, Dogecoin, Litecoin) via public node/indexer APIs."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiohttp

OUT_DIR = Path(__file__).resolve().parent


async def fetch_json(session: aiohttp.ClientSession, url: str, timeout: int = 8) -> Any:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception:
        pass
    return None


async def scan_pow_chains() -> dict[str, Any]:
    connector = aiohttp.TCPConnector(limit=15, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        btc_blocks = await fetch_json(session, "https://mempool.space/api/v1/blocks")
        btc_diff = await fetch_json(session, "https://mempool.space/api/v1/difficulty-adjustment")
        kaspa_info = await fetch_json(session, "https://api.kaspa.org/info/blockdag")
        kaspa_hash = await fetch_json(session, "https://api.kaspa.org/info/hashrate")
        alph_hash = await fetch_json(session, "https://backend.mainnet.alephium.org/infos/current-hashrate")
        ergo_info = await fetch_json(session, "https://api.ergoplatform.com/api/v1/networkState")

    results: list[dict[str, Any]] = []
    if isinstance(btc_blocks, list) and btc_blocks:
        b0 = btc_blocks[0]
        results.append({
            "chain": "Bitcoin",
            "latest_height": b0.get("height"),
            "tx_count": b0.get("tx_count"),
            "miner_pool": (b0.get("extras") or {}).get("pool", {}).get("name"),
            "reward_sat": (b0.get("extras") or {}).get("reward"),
            "difficulty": b0.get("difficulty"),
            "diff_progress_pct": btc_diff.get("progressPercent") if isinstance(btc_diff, dict) else None,
        })
    if isinstance(kaspa_info, dict):
        results.append({
            "chain": "Kaspa",
            "daa_score": kaspa_info.get("virtualDaaScore"),
            "difficulty": kaspa_info.get("difficulty"),
            "hashrate_th": kaspa_hash.get("hashrate") if isinstance(kaspa_hash, dict) else None,
        })
    if isinstance(alph_hash, dict):
        results.append({"chain": "Alephium", "hashrate": alph_hash.get("hashrate")})
    if isinstance(ergo_info, dict):
        results.append({"chain": "Ergo", "height": ergo_info.get("height"), "params": ergo_info.get("params")})

    out = {"pow_chains_live": len(results), "chains": results}
    (OUT_DIR / "pow_direct_scan.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return out


if __name__ == "__main__":
    asyncio.run(scan_pow_chains())
