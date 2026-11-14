"""Direct Multi-Chain On-Chain Scanner: discovers mining, PoW, and repetitive mint contracts directly via RPC."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import time

import aiohttp

from mining_registry import (
    MINING_TOKENS,
    POW_STRICT_TOKENS,
    classify_evm_candidate,
    load_registry,
    merge_scan_into_registry,
    save_registry,
    tokenize_signature,
)
from omnirpc_client import OmniRPC
from protocol_profiler import enrich_registry_items_onchain

OUT_DIR = Path(__file__).resolve().parent

ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ERC918_MINT_TOPIC = "0xcf6fbb9dcea7d07263ab4f5c3a92f53af33dffc421d9d121e1c74b307e68189d"
ZERO_TOPIC = "0x0000000000000000000000000000000000000000000000000000000000000000"


async def lookup_selectors(session: aiohttp.ClientSession, selectors: list[str]) -> dict[str, list[str]]:
    """Decode raw 4-byte EVM function selectors via Sourcify 4byte DB (primary) with OpenChain fallback."""
    clean = sorted({s for s in selectors if s and s.startswith("0x") and len(s) == 10})
    decoded: dict[str, list[str]] = {}
    bases = (
        "https://api.4byte.sourcify.dev/signature-database/v1/lookup?function=",
        "https://api.openchain.xyz/signature-database/v1/lookup?function=",
    )
    for i in range(0, len(clean), 40):
        chunk = clean[i : i + 40]
        joined = ",".join(chunk)
        for base in bases:
            try:
                async with session.get(base + joined, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status != 200:
                        continue
                    data = await r.json(content_type=None)
                    fn_map = (data.get("result") or {}).get("function") or {}
                    for sel, entries in fn_map.items():
                        if entries and sel not in decoded:
                            decoded[sel] = [e["name"] for e in entries[:3] if isinstance(e, dict) and e.get("name")]
                    if all(sel in decoded for sel in chunk):
                        break
            except Exception:
                continue
    return decoded


async def scan_evm_chain(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    omni: OmniRPC,
    chain: dict[str, Any],
    blocks_back: int = 12,
) -> dict[str, Any]:
    """Scan the latest N raw blocks and Mint logs directly on an EVM chain."""
    cid = chain["chain_id"]
    name = chain["name"]
    async with sem:
        try:
            latest_hex = await omni.evm_call(session, cid, "eth_blockNumber", [], timeout=6)
            latest = int(latest_hex, 16)
            start_blk = max(0, latest - blocks_back + 1)

            calls = [("eth_getBlockByNumber", [hex(b), True]) for b in range(start_blk, latest + 1)]
            blocks_res = await omni.evm_batch(session, cid, calls, timeout=10)
            blocks = [b for b in blocks_res if isinstance(b, dict)]

            # Also query ERC-918 Mint(address,uint256,uint256,bytes32) & Transfer(0x0 -> any) logs
            mint_contracts: Counter[str] = Counter()
            try:
                from wallet_simulator import _raw_evm_rpc
                pow_logs = await _raw_evm_rpc(
                    session,
                    omni,
                    cid,
                    "eth_getLogs",
                    [{
                        "fromBlock": hex(max(0, latest - max(blocks_back, 60))),
                        "toBlock": hex(latest),
                        "topics": [ERC918_MINT_TOPIC],
                    }],
                    timeout=7,
                )
                if isinstance(pow_logs, list):
                    for lg in pow_logs:
                        addr = (lg.get("address") or "").lower()
                        if addr:
                            mint_contracts[addr] += 5
            except Exception:
                pass
            try:
                logs = await omni.evm_call(
                    session,
                    cid,
                    "eth_getLogs",
                    [{
                        "fromBlock": hex(start_blk),
                        "toBlock": hex(latest),
                        "topics": [ERC20_TRANSFER_TOPIC, ZERO_TOPIC],
                    }],
                    timeout=8,
                )
                if isinstance(logs, list):
                    for lg in logs:
                        addr = (lg.get("address") or "").lower()
                        if addr:
                            mint_contracts[addr] += 1
            except Exception:
                pass

            contract_stats: dict[str, dict[str, Any]] = {}
            total_txs = 0
            for blk in blocks:
                txs = blk.get("transactions") or []
                total_txs += len(txs)
                for tx in txs:
                    if not isinstance(tx, dict):
                        continue
                    to_addr = (tx.get("to") or "").lower()
                    from_addr = (tx.get("from") or "").lower()
                    inp = tx.get("input") or "0x"
                    if not to_addr or inp == "0x" or len(inp) < 10:
                        continue
                    sel = inp[:10].lower()
                    val_wei = int(tx.get("value", "0x0"), 16)
                    st = contract_stats.setdefault(
                        to_addr,
                        {
                            "address": to_addr,
                            "tx_count": 0,
                            "callers": set(),
                            "selectors": Counter(),
                            "total_value_wei": 0,
                            "blocks_hit": set(),
                        },
                    )
                    st["tx_count"] += 1
                    st["callers"].add(from_addr)
                    st["selectors"][sel] += 1
                    st["total_value_wei"] += val_wei
                    st["blocks_hit"].add(blk.get("number"))

            candidates = []
            for addr, st in contract_stats.items():
                if st["tx_count"] >= 2 or addr in mint_contracts:
                    candidates.append({
                        "chain_id": cid,
                        "chain_name": name,
                        "symbol": chain.get("symbol", ""),
                        "address": addr,
                        "tx_count": st["tx_count"],
                        "unique_callers": len(st["callers"]),
                        "blocks_active": len(st["blocks_hit"]),
                        "total_value_native": round(st["total_value_wei"] / 1e18, 6),
                        "mint_events_in_window": mint_contracts.get(addr, 0),
                        "top_selectors": [s for s, _ in st["selectors"].most_common(5)],
                    })

            candidates.sort(
                key=lambda x: (x["mint_events_in_window"] > 0, x["unique_callers"], x["tx_count"]),
                reverse=True,
            )
            return {
                "chain_id": cid,
                "name": name,
                "ok": True,
                "latest_block": latest,
                "blocks_scanned": len(blocks),
                "total_txs": total_txs,
                "mint_tokens_active": len(mint_contracts),
                "candidates": candidates[:12],
            }
        except Exception as exc:
            return {"chain_id": cid, "name": name, "ok": False, "err": str(exc)[:80], "candidates": []}


SOL_LOG_PATTERNS = (
    "instruction: mintto", "instruction: mine", "instruction: drill", "instruction: deploy",
    "instruction: checkpoint", "instruction: automate", "instruction: pow", "instruction: hash",
    "instruction: bury", "instruction: claimmint",
)


async def scan_solana_recent(session: aiohttp.ClientSession, omni: OmniRPC, slot_count: int = 8) -> dict[str, Any]:
    """Scan recent Solana confirmed blocks directly via Helius/Rotator RPC for minting & mining programs."""
    try:
        slot_res = await omni.solana_call(session, "getSlot", [{"commitment": "confirmed"}])
        slot = slot_res["result"]
        blocks_res = await omni.solana_call(session, "getBlocks", [slot - 30, slot, {"commitment": "confirmed"}])
        recent_slots = (blocks_res.get("result") or [])[-slot_count:]

        prog_counts: Counter[str] = Counter()
        prog_signers: dict[str, set[str]] = defaultdict(set)
        mint_programs: Counter[str] = Counter()
        prog_signals: dict[str, set[str]] = defaultdict(set)
        tx_total = 0

        skip_progs = {
            "ComputeBudget111111111111111111111111111111",
            "11111111111111111111111111111111",
            "Vote111111111111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        }

        for s in recent_slots:
            blk_res = await omni.solana_call(
                session,
                "getBlock",
                [s, {"encoding": "json", "transactionDetails": "full", "rewards": False, "maxSupportedTransactionVersion": 1}],
                timeout=15,
            )
            txs = (blk_res.get("result") or {}).get("transactions") or []
            for tx_item in txs:
                tx_total += 1
                msg = tx_item.get("transaction", {}).get("message", {})
                keys = msg.get("accountKeys") or []
                if not keys:
                    continue
                signer = keys[0] if isinstance(keys[0], str) else keys[0].get("pubkey", "")
                raw_logs = (tx_item.get("meta") or {}).get("logMessages") or []
                logs_lower = " ".join(raw_logs).lower()
                matched_kw = [pat.split(": ", 1)[1] for pat in SOL_LOG_PATTERNS if pat in logs_lower]
                for ix in msg.get("instructions") or []:
                    idx = ix.get("programIdIndex")
                    if idx is not None and idx < len(keys):
                        prog = keys[idx] if isinstance(keys[idx], str) else keys[idx].get("pubkey", "")
                        if prog and prog not in skip_progs:
                            prog_counts[prog] += 1
                            prog_signers[prog].add(signer)
                            if matched_kw:
                                mint_programs[prog] += 1
                                prog_signals[prog].update(matched_kw)

        top_progs = [
            {
                "program_id": p,
                "calls": cnt,
                "unique_signers": len(prog_signers[p]),
                "mint_or_mine_logs": mint_programs.get(p, 0),
                "matched_signals": sorted(prog_signals.get(p, set())),
            }
            for p, cnt in prog_counts.most_common(35)
            if len(prog_signers[p]) >= 2 or mint_programs.get(p, 0) > 0
        ]
        return {
            "ok": True,
            "slots_scanned": len(recent_slots),
            "txs_scanned": tx_total,
            "top_active_programs": top_progs,
        }
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:100]}


async def scan_sui_recent(session: aiohttp.ClientSession, omni: OmniRPC) -> dict[str, Any]:
    """Scan recent Sui Move transactions directly via Sui GraphQL."""
    sui = omni.majors_by_name.get("sui")
    if not sui:
        return {"ok": False, "err": "Sui not in live pool"}
    query = """
    {
      transactions(last: 80) {
        nodes {
          digest
          sender { address }
          kind {
            __typename
            ... on ProgrammableTransaction {
              commands(first: 10) {
                nodes {
                  __typename
                  ... on MoveCallCommand {
                    function {
                      module { package { address } name }
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        async with session.post(
            sui["best_rpc"], json={"query": query}, timeout=aiohttp.ClientTimeout(total=12)
        ) as r:
            data = await r.json(content_type=None)
            nodes = (data.get("data") or {}).get("transactions", {}).get("nodes", [])
            calls: Counter[str] = Counter()
            senders: dict[str, set[str]] = defaultdict(set)
            for n in nodes:
                sender = (n.get("sender") or {}).get("address", "")
                cmds = (n.get("kind") or {}).get("commands", {}).get("nodes", [])
                for c in cmds:
                    fn = c.get("function") or {}
                    if fn:
                        mod = fn.get("module") or {}
                        pkg = (mod.get("package") or {}).get("address", "")
                        tgt = f"{pkg}::{mod.get('name')}::{fn.get('name')}"
                        calls[tgt] += 1
                        if sender:
                            senders[tgt].add(sender)
            return {
                "ok": True,
                "txs_scanned": len(nodes),
                "top_move_calls": [
                    {"target": k, "count": v, "unique_senders": len(senders[k])}
                    for k, v in calls.most_common(25)
                ],
            }
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:100]}


async def scan_aptos_recent(session: aiohttp.ClientSession, omni: OmniRPC) -> dict[str, Any]:
    """Scan latest Aptos mainnet transactions for mining/mint/claim Move entry functions."""
    apt = omni.majors_by_name.get("aptos")
    base = (apt or {}).get("best_rpc") or "https://fullnode.mainnet.aptoslabs.com/v1"
    try:
        async with session.get(f"{base.rstrip('/')}/transactions?limit=80", timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return {"ok": False, "err": f"HTTP {r.status}"}
            txs = await r.json(content_type=None)
            if not isinstance(txs, list):
                return {"ok": False, "err": "Invalid Aptos response"}
            calls: Counter[str] = Counter()
            senders: dict[str, set[str]] = defaultdict(set)
            for tx in txs:
                payload = tx.get("payload") or {}
                if payload.get("type") == "entry_function_payload":
                    fn = str(payload.get("function") or "")
                    sender = str(tx.get("sender") or "")
                    if fn:
                        calls[fn] += 1
                        if sender:
                            senders[fn].add(sender)
            return {
                "ok": True,
                "txs_scanned": len(txs),
                "top_move_calls": [
                    {"target": k, "count": v, "unique_senders": len(senders[k])}
                    for k, v in calls.most_common(25)
                ],
            }
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:100]}


async def scan_near_recent(session: aiohttp.ClientSession, omni: OmniRPC) -> dict[str, Any]:
    """Scan latest finalized Near Protocol block chunks for mining/mint FunctionCall methods."""
    near = omni.majors_by_name.get("near")
    url = (near or {}).get("best_rpc") or "https://rpc.mainnet.near.org"
    try:
        blk_res = await omni.json_rpc_post(url, session, "block", {"finality": "final"}, timeout=10)
        chunks = (blk_res.get("result") or {}).get("chunks") or []
        chunk_hashes = [c.get("chunk_hash") for c in chunks[:6] if c.get("chunk_hash")]
        chunk_res_list = await asyncio.gather(*(
            omni.json_rpc_post(url, session, "chunk", {"chunk_id": ch}, timeout=10)
            for ch in chunk_hashes
        ), return_exceptions=True)

        calls: Counter[tuple[str, str]] = Counter()
        signers: dict[tuple[str, str], set[str]] = defaultdict(set)
        tx_total = 0
        for cres in chunk_res_list:
            if not isinstance(cres, dict):
                continue
            txs = (cres.get("result") or {}).get("transactions") or []
            for tx in txs:
                tx_total += 1
                receiver = str(tx.get("receiver_id") or "")
                signer = str(tx.get("signer_id") or "")
                for act in tx.get("actions") or []:
                    if isinstance(act, dict) and "FunctionCall" in act:
                        method = str((act["FunctionCall"] or {}).get("method_name") or "")
                        if receiver and method:
                            key = (receiver, method)
                            calls[key] += 1
                            if signer:
                                signers[key].add(signer)
        return {
            "ok": True,
            "chunks_scanned": len(chunk_hashes),
            "txs_scanned": tx_total,
            "top_contract_calls": [
                {"receiver": rcv, "method": mth, "count": cnt, "unique_signers": len(signers[(rcv, mth)])}
                for (rcv, mth), cnt in calls.most_common(25)
            ],
        }
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:100]}


async def scan_ton_recent(session: aiohttp.ClientSession) -> dict[str, Any]:
    """Scan latest TON workchain shards via TonAPI for PoW givers, jetton mints, and mining calls."""
    try:
        async with session.get("https://tonapi.io/v2/blockchain/masterchain-head", timeout=aiohttp.ClientTimeout(total=8)) as r:
            if r.status != 200:
                return {"ok": False, "err": f"TonAPI HTTP {r.status}"}
            mc = await r.json(content_type=None)
        seq = mc.get("seqno")
        async with session.get(f"https://tonapi.io/v2/blockchain/masterchain/{seq}/shards", timeout=aiohttp.ClientTimeout(total=8)) as r:
            shards_data = await r.json(content_type=None)
        shards = (shards_data.get("shards") or [])[:2]

        op_counts: Counter[tuple[str, str]] = Counter()
        callers: dict[tuple[str, str], set[str]] = defaultdict(set)
        pow_hints: dict[tuple[str, str], bool] = {}
        tx_total = 0

        for sh in shards:
            bid = sh.get("last_known_block_id")
            if not bid:
                continue
            async with session.get(f"https://tonapi.io/v2/blockchain/blocks/{bid}/transactions", timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status != 200:
                    continue
                txs = (await r.json(content_type=None)).get("transactions") or []
                for tx in txs:
                    tx_total += 1
                    acc = tx.get("account") or {}
                    addr = str(acc.get("address") or "")
                    acc_name = str(acc.get("name") or "")
                    in_msg = tx.get("in_msg") or {}
                    op = str(in_msg.get("decoded_op_name") or "")
                    src = str((in_msg.get("source") or {}).get("address") or "")
                    if op in ("jetton_transfer", "jetton_internal_transfer", "jetton_notify", "excesses", "bounce"):
                        continue
                    hint_blob = f"{acc_name} {op}".lower()
                    is_pow = bool(re.search(r"\b(pow|giver|mine|miner|mining)\b", hint_blob))
                    _, toks = tokenize_signature(op)
                    if addr and ((toks & MINING_TOKENS) or is_pow):
                        key = (addr, op or acc_name or "ton_mine")
                        op_counts[key] += 1
                        if src:
                            callers[key].add(src)
                        if is_pow:
                            pow_hints[key] = True

        return {
            "ok": True,
            "masterchain_seqno": seq,
            "txs_scanned": tx_total,
            "candidates": [
                {
                    "address": addr,
                    "op_name": op,
                    "count": cnt,
                    "unique_callers": len(callers[(addr, op)]),
                    "is_pow_hint": pow_hints.get((addr, op), False),
                }
                for (addr, op), cnt in op_counts.most_common(20)
            ],
        }
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:100]}


async def scan_cosmos_all(sem: asyncio.Semaphore, session: aiohttp.ClientSession, cosmos_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Scan all live Cosmos/IBC chains (known + obscure) for CosmWasm/module mint & mine activity."""
    async def probe_one(chain: dict[str, Any]) -> dict[str, Any]:
        slug = chain["slug"]
        rest = chain["best_rest"]
        async with sem:
            try:
                async with session.get(f"{rest}/cosmos/base/tendermint/v1beta1/blocks/latest", timeout=aiohttp.ClientTimeout(total=6)) as r:
                    if r.status != 200:
                        return {"ok": False}
                    data = await r.json(content_type=None)
                blk = data.get("block", {})
                hdr = blk.get("header", {})
                txs = (blk.get("data") or {}).get("txs") or []
                height = int(header_h) if (header_h := hdr.get("height")) else 0
                cands: list[dict[str, Any]] = []
                if txs and height:
                    tx_url = f"{rest}/cosmos/tx/v1beta1/txs?events=tx.height%3D{height}&pagination.limit=25"
                    try:
                        async with session.get(tx_url, timeout=aiohttp.ClientTimeout(total=6)) as tr:
                            if tr.status == 200:
                                td = await tr.json(content_type=None)
                                contract_hits: dict[str, dict[str, Any]] = {}
                                for tx in td.get("txs") or []:
                                    for msg in (tx.get("body") or {}).get("messages") or []:
                                        mtype = str(msg.get("@type") or "")
                                        if "MsgExecuteContract" in mtype:
                                            contract = str(msg.get("contract") or "")
                                            sender = str(msg.get("sender") or "")
                                            raw_msg = msg.get("msg")
                                            keys = list(raw_msg.keys()) if isinstance(raw_msg, dict) else []
                                            matched = [k for k in keys if (tokenize_signature(k)[1] & MINING_TOKENS)]
                                            if contract and matched:
                                                st = contract_hits.setdefault(contract, {"actions": set(), "callers": set(), "tx_count": 0})
                                                st["actions"].update(matched)
                                                if sender:
                                                    st["callers"].add(sender)
                                                st["tx_count"] += 1
                                for caddr, st in contract_hits.items():
                                    acts = sorted(st["actions"])
                                    is_pow = any((tokenize_signature(a)[1] & POW_STRICT_TOKENS) for a in acts)
                                    cands.append({
                                        "slug": slug,
                                        "chain_id": hdr.get("chain_id") or slug,
                                        "chain_name": chain.get("name") or slug,
                                        "symbol": chain.get("symbol", ""),
                                        "address": caddr,
                                        "actions": acts,
                                        "tx_count": st["tx_count"],
                                        "unique_callers": len(st["callers"]),
                                        "category": "PoW / Hash & Epoch Mining" if is_pow else "Cosmos Mint/Mine",
                                        "detection_reason": f"CosmWasm: {', '.join(acts[:4])}",
                                    })
                    except Exception:
                        pass
                return {"ok": True, "txs": len(txs), "candidates": cands}
            except Exception:
                return {"ok": False}

    res = await asyncio.gather(*(probe_one(c) for c in cosmos_list))
    all_cands = []
    for r in res:
        all_cands.extend(r.get("candidates") or [])
    return {
        "cosmos_scanned": len(cosmos_list),
        "cosmos_ok": sum(1 for r in res if r.get("ok")),
        "cosmos_txs": sum(r.get("txs", 0) for r in res if r.get("ok")),
        "candidates": all_cands,
    }


async def scan_substrate_all(sub_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Probe all live Substrate/Polkadot chains (known + obscure) for active blocks and extrinsic counts."""
    import websockets

    sem = asyncio.Semaphore(12)

    async def probe_sub(chain: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            try:
                async with websockets.connect(chain["best_rpc"], open_timeout=5, close_timeout=2) as ws:
                    await ws.send(json.dumps({"id": 1, "jsonrpc": "2.0", "method": "chain_getBlock", "params": []}))
                    raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    blk = (json.loads(raw).get("result") or {}).get("block") or {}
                    exts = blk.get("extrinsics") or []
                    return {"ok": True, "extrinsics": len(exts)}
            except Exception:
                return {"ok": False}

    res = await asyncio.gather(*(probe_sub(c) for c in sub_list))
    return {
        "substrate_scanned": len(sub_list),
        "substrate_ok": sum(1 for r in res if r.get("ok")),
        "substrate_extrinsics": sum(r.get("extrinsics", 0) for r in res if r.get("ok")),
    }


async def scan_pow_l1_summary(session: aiohttp.ClientSession) -> dict[str, Any]:
    """Read live PoW L1 chains (Bitcoin, Kaspa, Alephium, Ergo)."""
    async def get_j(url: str) -> Any:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
        except Exception:
            pass
        return None

    btc, kas, alph, ergo = await asyncio.gather(
        get_j("https://mempool.space/api/v1/blocks"),
        get_j("https://api.kaspa.org/info/blockdag"),
        get_j("https://backend.mainnet.alephium.org/infos/current-hashrate"),
        get_j("https://api.ergoplatform.com/api/v1/networkState"),
    )
    chains = []
    if isinstance(btc, list) and btc:
        chains.append({"chain": "Bitcoin", "height": btc[0].get("height"), "txs": btc[0].get("tx_count")})
    if isinstance(kas, dict):
        chains.append({"chain": "Kaspa", "daa_score": kas.get("virtualDaaScore")})
    if isinstance(alph, dict):
        chains.append({"chain": "Alephium", "hashrate": alph.get("hashrate")})
    if isinstance(ergo, dict):
        chains.append({"chain": "Ergo", "height": ergo.get("height")})
    return {"pow_l1_ok": len(chains), "chains": chains}


async def run_scan(max_evm_chains: int = 650, blocks_back: int = 10, all_ecosystems: bool = True, evm_offset: int = 0) -> dict[str, Any]:
    t0 = time.perf_counter()
    omni = OmniRPC()
    evm_chains = [
        c for c in omni.pool.get("evm", [])
        if c.get("chain_id") != 46630 and not any(
            bad in str(c.get("name") or "").lower()
            for bad in ("testnet", "sepolia", "goerli", "holesky", "amoy", "devnet", "robinhood")
        )
    ]
    cosmos_chains = omni.pool.get("cosmos", []) if all_ecosystems else []
    sub_chains = omni.pool.get("substrate", []) if all_ecosystems else []

    # Prioritize diverse active chains + small/obscure PoW & alt EVM chains (excluding testnets)
    priority_ids = {
        1, 8453, 42161, 10, 56, 137, 43114, 143, 999, 2741, 57073, 130, 146,
        80094, 534352, 59144, 5000, 167000, 1088, 1890, 252, 360, 19, 14, 25,
        369, 1030, 61, 2000, 10001, 1284, 100, 42220, 1116, 30, 800001,
    }
    prioritized = [c for c in evm_chains if c["chain_id"] in priority_ids]
    others = [c for c in evm_chains if c["chain_id"] not in priority_ids]
    if others and evm_offset:
        off = evm_offset % len(others)
        others = others[off:] + others[:off]
    selected_evm = (prioritized + others)[:max_evm_chains]

    connector = aiohttp.TCPConnector(limit=55, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(22)
        c_sem = asyncio.Semaphore(20)
        evm_task = asyncio.gather(*(scan_evm_chain(sem, session, omni, c, blocks_back) for c in selected_evm))
        sol_task = scan_solana_recent(session, omni)
        sui_task = scan_sui_recent(session, omni)
        apt_task = scan_aptos_recent(session, omni) if all_ecosystems else asyncio.sleep(0, result={})
        near_task = scan_near_recent(session, omni) if all_ecosystems else asyncio.sleep(0, result={})
        ton_task = scan_ton_recent(session) if all_ecosystems else asyncio.sleep(0, result={})
        cosmos_task = scan_cosmos_all(c_sem, session, cosmos_chains) if cosmos_chains else asyncio.sleep(0, result={})
        sub_task = scan_substrate_all(sub_chains) if sub_chains else asyncio.sleep(0, result={})
        pow_task = scan_pow_l1_summary(session) if all_ecosystems else asyncio.sleep(0, result={})

        (
            evm_results,
            sol_res,
            sui_res,
            apt_res,
            near_res,
            ton_res,
            cosmos_res,
            sub_res,
            pow_res,
        ) = await asyncio.gather(
            evm_task, sol_task, sui_task, apt_task, near_task, ton_task, cosmos_task, sub_task, pow_task
        )

        # Decode all unique 4-byte selectors across discovered EVM contracts
        all_selectors: list[str] = []
        for ch in evm_results:
            for cand in ch.get("candidates", []):
                all_selectors.extend(cand["top_selectors"])
        sig_map = await lookup_selectors(session, all_selectors)

    mining_suspects: list[dict[str, Any]] = []
    all_active_contracts: list[dict[str, Any]] = []

    for ch in evm_results:
        for cand in ch.get("candidates", []):
            decoded_fns = []
            for sel in cand["top_selectors"]:
                names = sig_map.get(sel) or [sel]
                decoded_fns.extend(names)
            cand["decoded_functions"] = decoded_fns

            is_match, category, reason = classify_evm_candidate(
                decoded_fns,
                int(cand.get("mint_events_in_window", 0)),
                int(cand.get("unique_callers", 0)),
            )
            if is_match:
                cand["category"] = category
                cand["detection_reason"] = reason
                mining_suspects.append(cand)
            all_active_contracts.append(cand)

    mining_suspects.sort(
        key=lambda x: (x["mint_events_in_window"], x["unique_callers"], x["tx_count"]),
        reverse=True,
    )

    total_chains_scanned = (
        len(selected_evm)
        + (cosmos_res.get("cosmos_scanned", 0) if isinstance(cosmos_res, dict) else 0)
        + (sub_res.get("substrate_scanned", 0) if isinstance(sub_res, dict) else 0)
        + (5 if all_ecosystems else 2)
        + (pow_res.get("pow_l1_ok", 0) if isinstance(pow_res, dict) else 0)
    )
    total_raw_blocks = (
        sum(c.get("blocks_scanned", 0) for c in evm_results)
        + (sol_res.get("slots_scanned", 0) if isinstance(sol_res, dict) else 0)
        + (cosmos_res.get("cosmos_ok", 0) if isinstance(cosmos_res, dict) else 0)
        + (sub_res.get("substrate_ok", 0) if isinstance(sub_res, dict) else 0)
    )
    total_raw_txs = (
        sum(c.get("total_txs", 0) for c in evm_results)
        + (sol_res.get("txs_scanned", 0) if isinstance(sol_res, dict) else 0)
        + (sui_res.get("txs_scanned", 0) if isinstance(sui_res, dict) else 0)
        + (apt_res.get("txs_scanned", 0) if isinstance(apt_res, dict) else 0)
        + (near_res.get("txs_scanned", 0) if isinstance(near_res, dict) else 0)
        + (ton_res.get("txs_scanned", 0) if isinstance(ton_res, dict) else 0)
        + (cosmos_res.get("cosmos_txs", 0) if isinstance(cosmos_res, dict) else 0)
    )

    report = {
        "total_chains_scanned": total_chains_scanned,
        "evm_chains_scanned": len(selected_evm),
        "evm_chains_ok": sum(1 for c in evm_results if c.get("ok")),
        "evm_chains_with_txs": sum(1 for c in evm_results if c.get("total_txs", 0) > 0),
        "total_raw_blocks_scanned": total_raw_blocks,
        "total_raw_txs_scanned": total_raw_txs,
        "onchain_mining_candidates_found": len(mining_suspects),
        "onchain_mining_candidates": mining_suspects,
        "solana_direct_scan": sol_res,
        "sui_direct_scan": sui_res,
        "aptos_direct_scan": apt_res,
        "near_direct_scan": near_res,
        "ton_direct_scan": ton_res,
        "cosmos_candidates": (cosmos_res.get("candidates", []) if isinstance(cosmos_res, dict) else []),
        "cosmos_summary": {k: v for k, v in cosmos_res.items() if k != "candidates"} if isinstance(cosmos_res, dict) else {},
        "substrate_summary": sub_res if isinstance(sub_res, dict) else {},
        "pow_l1_summary": pow_res if isinstance(pow_res, dict) else {},
        "per_chain_activity_summary": [
            {
                "chain_id": c["chain_id"],
                "name": c["name"],
                "block": c.get("latest_block"),
                "txs": c.get("total_txs", 0),
                "mint_tokens": c.get("mint_tokens_active", 0),
            }
            for c in evm_results
            if c.get("ok") and c.get("total_txs", 0) > 0
        ],
    }

    (OUT_DIR / "onchain_mining_scan_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    reg_summary = merge_scan_into_registry(report, duration_s=(time.perf_counter() - t0))
    reg = load_registry()
    await enrich_registry_items_onchain(list(reg["items"].values()))
    save_registry(reg)
    report["registry_update"] = reg_summary
    with (OUT_DIR / "onchain_mining_candidates.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "chain_id", "chain_name", "symbol", "address", "tx_count",
                "unique_callers", "blocks_active", "total_value_native",
                "mint_events_in_window", "decoded_functions", "detection_reason",
            ],
        )
        w.writeheader()
        for r in mining_suspects:
            row = dict(r)
            row["decoded_functions"] = ", ".join(r["decoded_functions"][:6])
            w.writerow({k: row.get(k, "") for k in w.fieldnames})

    print(
        json.dumps(
            {
                "total_chains_scanned": report["total_chains_scanned"],
                "evm_chains_scanned": report["evm_chains_scanned"],
                "evm_chains_with_txs": report["evm_chains_with_txs"],
                "cosmos_ok": report["cosmos_summary"].get("cosmos_ok", 0),
                "substrate_ok": report["substrate_summary"].get("substrate_ok", 0),
                "total_raw_blocks_scanned": report["total_raw_blocks_scanned"],
                "total_raw_txs_scanned": report["total_raw_txs_scanned"],
                "onchain_mining_candidates_found": report["onchain_mining_candidates_found"],
                "registry_update": reg_summary,
                "solana_top_programs": (sol_res.get("top_active_programs", []) if isinstance(sol_res, dict) else [])[:10],
                "sui_top_move_calls": (sui_res.get("top_move_calls", []) if isinstance(sui_res, dict) else [])[:8],
                "ton_candidates": (ton_res.get("candidates", []) if isinstance(ton_res, dict) else [])[:8],
                "aptos_top_calls": (apt_res.get("top_move_calls", []) if isinstance(apt_res, dict) else [])[:8],
                "near_top_calls": (near_res.get("top_contract_calls", []) if isinstance(near_res, dict) else [])[:8],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Direct On-Chain Multi-Blockchain Mining Scanner.")
    parser.add_argument("--max-evm", type=int, default=650)
    parser.add_argument("--blocks", type=int, default=10)
    parser.add_argument("--all-ecosystems", action="store_true", default=True)
    parser.add_argument("--evm-only", action="store_true", help="Skip Cosmos/Substrate/TON/Aptos/Near")
    parser.add_argument("--loop", action="store_true", help="Run continuously on interval")
    parser.add_argument("--interval", type=int, default=3600, help="Loop interval in seconds (default 3600 = 1h)")
    args = parser.parse_args()
    use_all = not args.evm_only

    if not args.loop:
        asyncio.run(run_scan(max_evm_chains=args.max_evm, blocks_back=args.blocks, all_ecosystems=use_all))
        return

    async def loop_runner() -> None:
        while True:
            try:
                await run_scan(max_evm_chains=args.max_evm, blocks_back=args.blocks, all_ecosystems=use_all)
            except Exception as exc:
                print(f"[ERROR] Scan failed: {exc}")
            print(f"[SLEEP] Waiting {args.interval}s (1h cycle) before next multi-chain block scan...")
            await asyncio.sleep(args.interval)

    asyncio.run(loop_runner())


if __name__ == "__main__":
    main()
