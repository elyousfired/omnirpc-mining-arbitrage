"""Direct Non-EVM On-Chain Scanner for Cosmos/IBC and Substrate/Polkadot chains."""

from __future__ import annotations

import asyncio
import base64
import json
from collections import Counter
from pathlib import Path
from typing import Any

import aiohttp
import websockets

from omnirpc_client import OmniRPC

OUT_DIR = Path(__file__).resolve().parent


async def scan_cosmos_chain(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    chain: dict[str, Any],
) -> dict[str, Any]:
    slug = chain["slug"]
    rest = chain["best_rest"]
    async with sem:
        try:
            url = f"{rest}/cosmos/base/tendermint/v1beta1/blocks/latest"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status != 200:
                    return {"slug": slug, "ok": False}
                data = await r.json(content_type=None)
                blk = data.get("block", {})
                header = blk.get("header", {})
                txs = blk.get("data", {}).get("txs") or []
                height = int(header.get("height", 0))

                # Also inspect recent txs if any exist in latest block
                decoded_msgs: list[str] = []
                if txs:
                    tx_url = f"{rest}/cosmos/tx/v1beta1/txs?events=tx.height%3D{height}&pagination.limit=20"
                    try:
                        async with session.get(tx_url, timeout=aiohttp.ClientTimeout(total=6)) as tr:
                            if tr.status == 200:
                                td = await tr.json(content_type=None)
                                for tx in td.get("txs") or []:
                                    for msg in tx.get("body", {}).get("messages", []):
                                        t = msg.get("@type", "")
                                        if t:
                                            decoded_msgs.append(t.split(".")[-1])
                                        if "MsgExecuteContract" in t:
                                            raw_msg = msg.get("msg")
                                            if isinstance(raw_msg, dict):
                                                decoded_msgs.append("wasm:" + ",".join(raw_msg.keys()))
                    except Exception:
                        pass

                return {
                    "slug": slug,
                    "name": chain["name"],
                    "chain_id": header.get("chain_id"),
                    "ok": True,
                    "height": height,
                    "txs_in_latest_block": len(txs),
                    "msg_types": dict(Counter(decoded_msgs)),
                }
        except Exception:
            return {"slug": slug, "ok": False}


async def scan_substrate_chain(sem: asyncio.Semaphore, chain: dict[str, Any]) -> dict[str, Any]:
    slug = chain["slug"]
    url = chain["best_rpc"]
    async with sem:
        try:
            async with websockets.connect(url, open_timeout=6, close_timeout=2) as ws:
                await ws.send(json.dumps({"id": 1, "jsonrpc": "2.0", "method": "chain_getBlock", "params": []}))
                raw = await asyncio.wait_for(ws.recv(), timeout=6)
                res = json.loads(raw).get("result") or {}
                blk = res.get("block", {})
                header = blk.get("header", {})
                extrinsics = blk.get("extrinsics") or []
                num_hex = header.get("number", "0x0")
                return {
                    "slug": slug,
                    "name": chain["name"],
                    "ok": True,
                    "height": int(num_hex, 16) if isinstance(num_hex, str) else 0,
                    "extrinsics_count": len(extrinsics),
                }
        except Exception:
            return {"slug": slug, "ok": False}


async def run_non_evm_scan(max_cosmos: int = 40, max_substrate: int = 30) -> dict[str, Any]:
    omni = OmniRPC()
    cosmos_list = omni.pool.get("cosmos", [])[:max_cosmos]
    sub_list = omni.pool.get("substrate", [])[:max_substrate]

    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        c_sem = asyncio.Semaphore(15)
        cosmos_res = await asyncio.gather(*(scan_cosmos_chain(c_sem, session, c) for c in cosmos_list))

    s_sem = asyncio.Semaphore(8)
    sub_res = await asyncio.gather(*(scan_substrate_chain(s_sem, c) for c in sub_list))

    ok_cosmos = [x for x in cosmos_res if x.get("ok")]
    ok_sub = [x for x in sub_res if x.get("ok")]

    out = {
        "cosmos_scanned": len(cosmos_list),
        "cosmos_ok": len(ok_cosmos),
        "cosmos_with_txs": [x for x in ok_cosmos if x.get("txs_in_latest_block", 0) > 0],
        "substrate_scanned": len(sub_list),
        "substrate_ok": len(ok_sub),
        "substrate_sample": ok_sub[:15],
    }
    (OUT_DIR / "non_evm_onchain_scan.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return out


if __name__ == "__main__":
    asyncio.run(run_non_evm_scan())
