"""OmniRPC CLI: Inspect live chains, read raw blocks/txs/contracts, or scan for mining activity."""

from __future__ import annotations

import argparse
import asyncio
import json

import aiohttp

from omnirpc_client import OmniRPC


async def cmd_block(chain: str, block_num: str) -> None:
    omni = OmniRPC()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        blk_param = block_num if block_num in ("latest", "finalized") else hex(int(block_num))
        blk = await omni.evm_call(session, chain, "eth_getBlockByNumber", [blk_param, True])
        if not isinstance(blk, dict):
            print(json.dumps({"error": "Block not found", "raw": blk}, indent=2))
            return
        txs = blk.get("transactions") or []
        summary = {
            "chain": omni.resolve_evm(chain)["name"],
            "block_number": int(blk["number"], 16),
            "timestamp": int(blk["timestamp"], 16),
            "miner": blk.get("miner"),
            "tx_count": len(txs),
            "gas_used": int(blk.get("gasUsed", "0x0"), 16),
            "sample_txs": [
                {
                    "hash": t.get("hash"),
                    "from": t.get("from"),
                    "to": t.get("to"),
                    "value_native": round(int(t.get("value", "0x0"), 16) / 1e18, 6),
                    "selector": (t.get("input") or "0x")[:10],
                }
                for t in txs[:15]
                if isinstance(t, dict)
            ],
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))


async def cmd_list(eco: str, limit: int) -> None:
    omni = OmniRPC()
    key = eco.lower()
    items = omni.pool.get(key, [])
    print(json.dumps({"ecosystem": key, "total_live": len(items), "items": items[:limit]}, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniRPC Direct Multi-Chain CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List live chains in RPC pool")
    p_list.add_argument("--eco", choices=["evm", "cosmos", "substrate", "non_evm_majors"], default="evm")
    p_list.add_argument("--limit", type=int, default=30)

    p_blk = sub.add_parser("block", help="Read a raw EVM block & transactions directly via RPC")
    p_blk.add_argument("chain", help="Chain ID or name (e.g. 8453, 4663, monad, robinhood)")
    p_blk.add_argument("--number", default="latest")

    args = parser.parse_args()
    if args.cmd == "list":
        asyncio.run(cmd_list(args.eco, args.limit))
    elif args.cmd == "block":
        asyncio.run(cmd_block(args.chain, args.number))


if __name__ == "__main__":
    main()
