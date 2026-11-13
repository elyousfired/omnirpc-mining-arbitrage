"""OmniRPC Local Multi-Chain HTTP Gateway & Live PC Dashboard."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web

from arbitrage_engine import compute_arbitrage_snapshot
from mining_registry import REGISTRY_CSV, REGISTRY_JSON, load_registry
from omnirpc_client import OmniRPC, POOL_PATH
from protocol_profiler import check_all_apis_health

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_HTML = BASE_DIR / "dashboard" / "index.html"
MINING_HTML = BASE_DIR / "dashboard" / "mining.html"
ARBITRAGE_HTML = BASE_DIR / "dashboard" / "arbitrage.html"
AUTO_SCAN_INTERVAL = 3600  # 1 hour
MINING_REPORT_PATH = BASE_DIR / "onchain_mining_scan_report.json"
MINING_CSV_PATH = BASE_DIR / "onchain_mining_candidates.csv"
NON_EVM_REPORT_PATH = BASE_DIR / "non_evm_onchain_scan.json"
POW_REPORT_PATH = BASE_DIR / "pow_direct_scan.json"

SCAN_COMMANDS: dict[str, list[str]] = {
    "evm_fast": [sys.executable, str(BASE_DIR / "onchain_mining_scanner.py"), "--max-evm", "60", "--blocks", "8", "--evm-only"],
    "evm_full": [sys.executable, str(BASE_DIR / "onchain_mining_scanner.py"), "--max-evm", "650", "--blocks", "10"],
    "all_chains": [sys.executable, str(BASE_DIR / "onchain_mining_scanner.py"), "--max-evm", "650", "--blocks", "10"],
    "non_evm": [sys.executable, str(BASE_DIR / "non_evm_onchain_scanner.py")],
    "pow": [sys.executable, str(BASE_DIR / "pow_direct_scanner.py")],
    "pool": [sys.executable, str(BASE_DIR / "rpc_pool_builder.py")],
}


def _read_json(path: Path, default: Any = None) -> Any:
    """Safely load a JSON file from disk if it exists."""
    if not path.exists():
        return {} if default is None else default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {} if default is None else default


async def _fetch_live_evm_block(
    omni: OmniRPC, session: aiohttp.ClientSession, key: str
) -> dict[str, Any]:
    """Fetch latest EVM block header and sample transactions directly via OmniRPC."""
    hex_num = await omni.evm_call(session, key, "eth_blockNumber", [])
    height = int(hex_num, 16)
    blk = await omni.evm_call(session, key, "eth_getBlockByNumber", [hex_num, True])
    txs = blk.get("transactions") or [] if isinstance(blk, dict) else []
    samples = []
    for tx in txs[:15]:
        if not isinstance(tx, dict):
            continue
        inp = tx.get("input") or "0x"
        val_wei = int(tx.get("value", "0x0"), 16) if isinstance(tx.get("value"), str) else 0
        samples.append({
            "hash": tx.get("hash", ""),
            "from": tx.get("from", ""),
            "to": tx.get("to") or "Contract Deploy",
            "value": f"{val_wei / 1e18:.6f}" if val_wei else "0",
            "selector": inp[:10] if len(inp) >= 10 else "native",
        })
    return {
        "height": height,
        "hash": blk.get("hash", "") if isinstance(blk, dict) else "",
        "tx_count": len(txs),
        "sample_txs": samples,
    }


async def _fetch_live_major_block(
    omni: OmniRPC, session: aiohttp.ClientSession, eco_key: str
) -> dict[str, Any]:
    """Fetch latest block/ledger snapshot from major Non-EVM L1s."""
    info = omni.majors_by_name.get(eco_key.lower())
    if not info:
        raise KeyError(f"Unknown major chain: {eco_key}")
    url = info["best_rpc"]

    if eco_key.lower() == "solana":
        slot_res = await omni.solana_call(session, "getSlot", [])
        slot = slot_res.get("result")
        blk_res = await omni.solana_call(
            session,
            "getBlock",
            [slot, {"encoding": "json", "maxSupportedTransactionVersion": 1, "transactionDetails": "signatures", "rewards": False}],
        )
        blk = blk_res.get("result") or {}
        sigs = blk.get("signatures") or []
        return {
            "height": slot,
            "hash": blk.get("blockhash", ""),
            "tx_count": len(sigs),
            "sample_txs": [{"hash": s, "from": "-", "to": "Solana Runtime", "value": "-", "selector": "sig"} for s in sigs[:12]],
        }

    if eco_key.lower() == "sui":
        query = "{ checkpoint { sequenceNumber digest } transactions(last: 12) { nodes { digest } } }"
        async with session.post(url, json={"query": query}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            data = (await r.json(content_type=None)).get("data", {})
        cp = data.get("checkpoint") or {}
        nodes = (data.get("transactions") or {}).get("nodes") or []
        return {
            "height": cp.get("sequenceNumber"),
            "hash": cp.get("digest", ""),
            "tx_count": len(nodes),
            "sample_txs": [{"hash": n.get("digest", ""), "from": "-", "to": "Move VM", "value": "-", "selector": "tx"} for n in nodes],
        }

    if eco_key.lower() == "aptos":
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            led = await r.json(content_type=None)
        return {
            "height": int(led.get("block_height", 0)),
            "tx_count": int(led.get("ledger_version", 0)),
            "raw_summary": led,
        }

    if eco_key.lower() == "near":
        res = await omni.json_rpc_post(url, session, "status", [])
        sync = (res.get("result") or {}).get("sync_info") or {}
        return {
            "height": sync.get("latest_block_height"),
            "hash": sync.get("latest_block_hash", ""),
            "tx_count": 0,
            "raw_summary": sync,
        }

    # TON
    async with session.get(f"{url.rstrip('/')}/getMasterchainInfo", timeout=aiohttp.ClientTimeout(total=10)) as r:
        data = await r.json(content_type=None)
    last = (data.get("result") or {}).get("last") or {}
    return {
        "height": last.get("seqno"),
        "hash": last.get("root_hash", ""),
        "tx_count": 0,
        "raw_summary": data,
    }


def create_app(pool_path: Path = POOL_PATH) -> web.Application:
    """Build the aiohttp application combining OmniRPC proxy routes and Dashboard UI."""
    app = web.Application()
    app["pool_path"] = pool_path
    app["omni"] = OmniRPC(pool_path)
    app["scan_state"] = {
        "running": False,
        "preset": None,
        "started_at": 0.0,
        "last_line": "",
        "just_finished": False,
        "returncode": None,
    }
    app["auto_scan"] = {
        "enabled": True,
        "interval_sec": AUTO_SCAN_INTERVAL,
        "next_run_at": time.time() + 15,
        "last_run_at": None,
        "last_new_count": 0,
    }

    async def _run_scan_bg(preset: str, cmd: list[str]) -> None:
        st = app["scan_state"]
        st.update({"running": True, "preset": preset, "started_at": time.time(), "last_line": "Starting process...", "just_finished": False, "returncode": None})
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(BASE_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if line:
                    st["last_line"] = line[:160]
            rc = await proc.wait()
            st["returncode"] = rc
            if rc == 0 and preset == "pool":
                app["omni"] = OmniRPC(app["pool_path"])
            if rc == 0 and preset in ("evm_fast", "evm_full", "all_chains"):
                reg = load_registry(REGISTRY_JSON)
                hist = reg.get("scan_history") or []
                if hist:
                    app["auto_scan"]["last_run_at"] = hist[0].get("timestamp")
                    app["auto_scan"]["last_new_count"] = hist[0].get("newly_registered", 0)
        except Exception as exc:
            st["last_line"] = f"Error: {exc}"
            st["returncode"] = -1
        finally:
            st["running"] = False
            st["just_finished"] = True
            app["auto_scan"]["next_run_at"] = time.time() + AUTO_SCAN_INTERVAL

    async def _auto_mining_loop() -> None:
        """Background 1-hour autonomous multi-chain mining discovery & deduplicated registration loop."""
        try:
            while True:
                await asyncio.sleep(1.0)
                auto = app["auto_scan"]
                if not auto["enabled"] or app["scan_state"]["running"]:
                    continue
                if time.time() >= auto["next_run_at"]:
                    await _run_scan_bg("all_chains", SCAN_COMMANDS["all_chains"])
        except asyncio.CancelledError:
            return

    async def on_startup(application: web.Application) -> None:
        connector = aiohttp.TCPConnector(limit=100, ssl=False)
        application["http"] = aiohttp.ClientSession(connector=connector)
        application["auto_miner_task"] = asyncio.create_task(_auto_mining_loop())

    async def on_cleanup(application: web.Application) -> None:
        task = application.get("auto_miner_task")
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await application["http"].close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    def get_omni() -> OmniRPC:
        return app["omni"]

    async def handle_dashboard(_request: web.Request) -> web.Response:
        if not DASHBOARD_HTML.exists():
            return web.Response(text="Dashboard UI file missing.", status=404)
        return web.Response(text=DASHBOARD_HTML.read_text(encoding="utf-8"), content_type="text/html", charset="utf-8")

    async def handle_mining_page(_request: web.Request) -> web.Response:
        if not MINING_HTML.exists():
            return web.Response(text="Mining Hunter UI file missing.", status=404)
        return web.Response(text=MINING_HTML.read_text(encoding="utf-8"), content_type="text/html", charset="utf-8")

    async def handle_arbitrage_page(_request: web.Request) -> web.Response:
        if not ARBITRAGE_HTML.exists():
            return web.Response(text="Arbitrage UI file missing.", status=404)
        return web.Response(text=ARBITRAGE_HTML.read_text(encoding="utf-8"), content_type="text/html", charset="utf-8")

    async def handle_api_arbitrage(request: web.Request) -> web.Response:
        q = request.rel_url.query
        gpu = q.get("gpu", "rtx4090")
        mode = q.get("mode", "cloud")
        cloud_rate = float(q["cloud_rate"]) if q.get("cloud_rate") else None
        kwh_cost = float(q.get("kwh_cost", "0.14"))
        tx_per_hr = max(1, int(q.get("tx_per_hr", "20")))
        data = await compute_arbitrage_snapshot(
            gpu_id=gpu,
            mode=mode,
            cloud_rate=cloud_rate,
            kwh_cost=kwh_cost,
            tx_per_hr=tx_per_hr,
        )
        return web.json_response(data)

    async def handle_api_registry(_request: web.Request) -> web.Response:
        reg = load_registry(REGISTRY_JSON)
        auto = app["auto_scan"]
        st = app["scan_state"]
        hist = reg.get("scan_history") or []
        last_run = auto["last_run_at"] or (hist[0].get("timestamp") if hist else None)
        last_new = auto["last_new_count"] if auto["last_run_at"] else (hist[0].get("newly_registered", 0) if hist else 0)
        return web.json_response({
            "registry": reg,
            "auto_scan": {
                "enabled": auto["enabled"],
                "interval_sec": auto["interval_sec"],
                "running_now": st["running"],
                "last_line": st["last_line"],
                "last_run_at": last_run,
                "last_new_count": last_new,
                "seconds_until_next_scan": max(0, int(auto["next_run_at"] - time.time())) if auto["enabled"] else 0,
            },
        })

    async def handle_api_registry_scan_now(_request: web.Request) -> web.Response:
        if app["scan_state"]["running"]:
            return web.json_response({"status": "already_running"}, status=409)
        asyncio.create_task(_run_scan_bg("all_chains", SCAN_COMMANDS["all_chains"]))
        return web.json_response({"status": "started", "preset": "all_chains"})

    async def handle_api_registry_toggle(_request: web.Request) -> web.Response:
        auto = app["auto_scan"]
        auto["enabled"] = not auto["enabled"]
        if auto["enabled"]:
            auto["next_run_at"] = time.time() + auto["interval_sec"]
        return web.json_response({"enabled": auto["enabled"]})

    async def handle_api_registry_csv(_request: web.Request) -> web.Response:
        if not REGISTRY_CSV.exists():
            return web.Response(text="Registry CSV not created yet", status=404)
        return web.Response(
            text=REGISTRY_CSV.read_text(encoding="utf-8"),
            content_type="text/csv",
            charset="utf-8",
            headers={"Content-Disposition": 'attachment; filename="mining_registry.csv"'},
        )

    async def handle_api_overview(_request: web.Request) -> web.Response:
        omni = get_omni()
        mining = _read_json(MINING_REPORT_PATH)
        return web.json_response({
            "pool_generated_at": omni.pool.get("generated_at"),
            "pool_counts": omni.pool.get("counts", {}),
            "mining_summary": {
                "evm_chains_scanned": mining.get("evm_chains_scanned", 0),
                "evm_chains_ok": mining.get("evm_chains_ok", 0),
                "evm_chains_with_txs": mining.get("evm_chains_with_txs", 0),
                "total_raw_blocks_scanned": mining.get("total_raw_blocks_scanned", 0),
                "total_raw_txs_scanned": mining.get("total_raw_txs_scanned", 0),
                "onchain_mining_candidates_found": mining.get("onchain_mining_candidates_found", 0),
            },
        })

    async def handle_api_pool(_request: web.Request) -> web.Response:
        return web.json_response(get_omni().pool)

    async def handle_api_mining(_request: web.Request) -> web.Response:
        mining = _read_json(MINING_REPORT_PATH)
        non_evm = _read_json(NON_EVM_REPORT_PATH)
        pow_data = _read_json(POW_REPORT_PATH)
        return web.json_response({
            "evm_candidates": mining.get("onchain_mining_candidates", []),
            "per_chain_activity_summary": mining.get("per_chain_activity_summary", []),
            "solana": mining.get("solana_direct_scan"),
            "sui": mining.get("sui_direct_scan"),
            "non_evm": non_evm,
            "pow": pow_data,
        })

    async def handle_api_live_block(request: web.Request) -> web.Response:
        omni = get_omni()
        session: aiohttp.ClientSession = request.app["http"]
        payload = await request.json()
        eco = str(payload.get("ecosystem", "")).strip()
        key = str(payload.get("key", "")).strip()
        t0 = time.perf_counter()
        try:
            if eco == "EVM":
                res = await _fetch_live_evm_block(omni, session, key)
            elif eco == "Cosmos":
                data = await omni.cosmos_get(session, key, "/cosmos/base/tendermint/v1beta1/blocks/latest")
                blk = data.get("block") or {}
                hdr = blk.get("header") or {}
                txs = (blk.get("data") or {}).get("txs") or []
                res = {
                    "height": hdr.get("height"),
                    "hash": ((data.get("block_id") or {}).get("hash")) or "",
                    "tx_count": len(txs),
                    "raw_summary": {"chain_id": hdr.get("chain_id"), "time": hdr.get("time"), "txs_count": len(txs)},
                }
            elif eco == "Substrate":
                blk = await omni.substrate_call(key, "chain_getBlock", [])
                inner = (blk or {}).get("block") or {}
                hdr = inner.get("header") or {}
                exts = inner.get("extrinsics") or []
                h_raw = hdr.get("number", "0x0")
                res = {
                    "height": int(h_raw, 16) if isinstance(h_raw, str) and h_raw.startswith("0x") else h_raw,
                    "hash": hdr.get("parentHash", ""),
                    "tx_count": len(exts),
                    "raw_summary": {"extrinsics_count": len(exts), "stateRoot": hdr.get("stateRoot")},
                }
            elif eco == "Majors":
                res = await _fetch_live_major_block(omni, session, key)
            else:
                return web.json_response({"error": f"Unsupported ecosystem: {eco}"}, status=400)
            res["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            return web.json_response(res)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)

    async def handle_api_scan_run(request: web.Request) -> web.Response:
        st = app["scan_state"]
        if st["running"]:
            return web.json_response({"status": "already_running", "preset": st["preset"]}, status=409)
        body = await request.json()
        preset = str(body.get("preset", "evm_fast"))
        cmd = SCAN_COMMANDS.get(preset)
        if not cmd:
            return web.json_response({"error": f"Unknown preset: {preset}"}, status=400)
        asyncio.create_task(_run_scan_bg(preset, cmd))
        return web.json_response({"status": "started", "preset": preset})

    async def handle_api_scan_status(_request: web.Request) -> web.Response:
        st = app["scan_state"]
        elapsed = round(time.time() - st["started_at"], 1) if st["started_at"] else 0.0
        resp = {
            "running": st["running"],
            "preset": st["preset"],
            "elapsed_s": elapsed,
            "last_line": st["last_line"],
            "just_finished": st["just_finished"],
            "returncode": st["returncode"],
        }
        if not st["running"] and st["just_finished"]:
            st["just_finished"] = False
        return web.json_response(resp)

    async def handle_download_csv(_request: web.Request) -> web.Response:
        if not MINING_CSV_PATH.exists():
            return web.Response(text="CSV not found", status=404)
        return web.Response(
            text=MINING_CSV_PATH.read_text(encoding="utf-8"),
            content_type="text/csv",
            charset="utf-8",
            headers={"Content-Disposition": 'attachment; filename="onchain_mining_candidates.csv"'},
        )

    # Standard OmniRPC proxy endpoints
    async def handle_chains(_request: web.Request) -> web.Response:
        omni = get_omni()
        return web.json_response({
            "counts": omni.pool.get("counts", {}),
            "evm": [{"chain_id": c["chain_id"], "name": c["name"], "symbol": c["symbol"], "block": c["block_height"], "ms": c["latency_ms"]} for c in omni.pool.get("evm", [])],
            "cosmos": [{"slug": c["slug"], "chain_id": c["cosmos_chain_id"], "name": c["name"], "block": c["block_height"]} for c in omni.pool.get("cosmos", [])],
            "substrate": [{"slug": c["slug"], "name": c["name"], "block": c["block_height"]} for c in omni.pool.get("substrate", [])],
            "non_evm_majors": omni.pool.get("non_evm_majors", []),
        })

    async def handle_evm_rpc(request: web.Request) -> web.Response:
        omni = get_omni()
        chain_key = request.match_info["chain"]
        body = await request.json()
        session: aiohttp.ClientSession = request.app["http"]
        try:
            if isinstance(body, list):
                calls = [(item["method"], item.get("params", [])) for item in body]
                results = await omni.evm_batch(session, chain_key, calls)
                return web.json_response([
                    {"jsonrpc": "2.0", "id": body[i].get("id", i), "result": None if isinstance(r, Exception) else r}
                    for i, r in enumerate(results)
                ])
            result = await omni.evm_call(session, chain_key, body["method"], body.get("params", []))
            return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": result})
        except Exception as exc:
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"message": str(exc)}}, status=502)

    async def handle_cosmos_rest(request: web.Request) -> web.Response:
        omni = get_omni()
        slug = request.match_info["slug"]
        subpath = request.match_info.get("path", "")
        session: aiohttp.ClientSession = request.app["http"]
        try:
            data = await omni.cosmos_get(session, slug, subpath)
            return web.json_response(data)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)

    async def handle_substrate_rpc(request: web.Request) -> web.Response:
        omni = get_omni()
        slug = request.match_info["slug"]
        body = await request.json()
        try:
            res = await omni.substrate_call(slug, body["method"], body.get("params", []))
            return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": res})
        except Exception as exc:
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"message": str(exc)}}, status=502)

    async def handle_major_proxy(request: web.Request) -> web.Response:
        omni = get_omni()
        eco = request.match_info["eco"].lower()
        info = omni.majors_by_name.get(eco)
        if not info:
            return web.json_response({"error": f"Unknown ecosystem {eco}"}, status=404)
        session: aiohttp.ClientSession = request.app["http"]
        body = await request.json()
        try:
            async with session.post(info["best_rpc"], json=body, timeout=aiohttp.ClientTimeout(total=12)) as r:
                data = await r.json(content_type=None)
                return web.json_response(data)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)

    async def handle_api_providers_health(_request: web.Request) -> web.Response:
        return web.json_response(await check_all_apis_health(get_omni()))

    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/mining", handle_mining_page)
    app.router.add_get("/arbitrage", handle_arbitrage_page)
    app.router.add_get("/api/arbitrage", handle_api_arbitrage)
    app.router.add_get("/api/registry", handle_api_registry)
    app.router.add_get("/api/providers/health", handle_api_providers_health)
    app.router.add_post("/api/registry/scan-now", handle_api_registry_scan_now)
    app.router.add_post("/api/registry/toggle", handle_api_registry_toggle)
    app.router.add_get("/api/registry/csv", handle_api_registry_csv)
    app.router.add_get("/api/overview", handle_api_overview)
    app.router.add_get("/api/pool", handle_api_pool)
    app.router.add_get("/api/mining", handle_api_mining)
    app.router.add_post("/api/live-block", handle_api_live_block)
    app.router.add_post("/api/scan/run", handle_api_scan_run)
    app.router.add_get("/api/scan/status", handle_api_scan_status)
    app.router.add_get("/api/download/csv", handle_download_csv)

    app.router.add_get("/chains", handle_chains)
    app.router.add_post("/evm/{chain}", handle_evm_rpc)
    app.router.add_get("/cosmos/{slug}/{path:.*}", handle_cosmos_rest)
    app.router.add_post("/substrate/{slug}", handle_substrate_rpc)
    app.router.add_post("/major/{eco}", handle_major_proxy)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Start local OmniRPC Multi-Chain Gateway & Dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    web.run_app(create_app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
