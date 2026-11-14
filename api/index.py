"""Vercel Serverless Function Entrypoint for OmniRPC Scanner & Arbitrage Dashboard."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import aiohttp

from arbitrage_engine import compute_arbitrage_snapshot, load_latest_registry_and_memory
from mining_registry import REGISTRY_CSV, REGISTRY_JSON, load_registry
from omnirpc_client import OmniRPC, POOL_PATH
from omnirpc_server import (
    ARBITRAGE_HTML,
    AUTO_SCAN_INTERVAL,
    DASHBOARD_HTML,
    MINING_HTML,
    MINING_REPORT_PATH,
    NON_EVM_REPORT_PATH,
    POW_REPORT_PATH,
    _fetch_live_evm_block,
    _fetch_live_major_block,
    _read_json,
)
from protocol_profiler import check_all_apis_health

_OMNI_CACHE: OmniRPC | None = None


def _get_omni() -> OmniRPC:
    global _OMNI_CACHE
    if _OMNI_CACHE is None:
        _OMNI_CACHE = OmniRPC(POOL_PATH)
    return _OMNI_CACHE


async def _with_session(coro_fn):
    connector = aiohttp.TCPConnector(limit=60, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await coro_fn(session)


class handler(BaseHTTPRequestHandler):
    """Vercel @vercel/python HTTP request handler."""

    def _send_json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_text(self, text: str, content_type: str = "text/html", status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        raw = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Any:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(raw) if raw.strip() else {}

    def _resolve_route(self) -> tuple[str, dict[str, str]]:
        parsed = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        path = qs.pop("__path", None) or parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return path, qs

    def do_GET(self) -> None:  # noqa: N802
        path, qs = self._resolve_route()

        try:
            if path in ("/", "/index.html", "/dashboard/index.html", "/arbitrage", "/arbitrage.html", "/dashboard/arbitrage.html"):
                return self._send_text(ARBITRAGE_HTML.read_text(encoding="utf-8"))
            if path in ("/games", "/games.html", "/dashboard/games.html"):
                games_html = BASE_DIR / "dashboard" / "games.html"
                if not games_html.exists():
                    return self._send_text("Games UI missing", content_type="text/plain", status=404)
                return self._send_text(games_html.read_text(encoding="utf-8"))
            if path == "/api/games":
                from game_scanner import load_games_registry
                return self._send_json(load_games_registry())
            if path in ("/mining", "/mining.html", "/dashboard/mining.html"):
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return

            if path == "/api/arbitrage":
                gpu = qs.get("gpu", "rtx4090")
                mode = qs.get("mode", "cloud")
                cloud_rate = float(qs["cloud_rate"]) if qs.get("cloud_rate") else None
                kwh_cost = float(qs.get("kwh_cost", "0.14"))
                tx_per_hr = max(1, int(qs.get("tx_per_hr", "20")))
                data = asyncio.run(
                    compute_arbitrage_snapshot(
                        gpu_id=gpu,
                        mode=mode,
                        cloud_rate=cloud_rate,
                        kwh_cost=kwh_cost,
                        tx_per_hr=tx_per_hr,
                    )
                )
                return self._send_json(data)

            if path == "/api/agent":
                reg, mem = asyncio.run(_with_session(load_latest_registry_and_memory))
                return self._send_json({
                    "mode": "cloud_github_agent",
                    "agent_memory": mem,
                    "total_accumulated": len(reg.get("items") or {}),
                    "auto_scan": {
                        "enabled": True,
                        "interval_sec": AUTO_SCAN_INTERVAL,
                        "running_now": False,
                        "last_line": mem.get("last_agent_brief_ar") or "الإيجنت التلقائي خدام كل ساعة عبر GitHub Actions.",
                        "seconds_until_next_scan": AUTO_SCAN_INTERVAL,
                    },
                })

            if path == "/api/registry":
                reg, mem = asyncio.run(_with_session(load_latest_registry_and_memory))
                hist = reg.get("scan_history") or []
                last_run = hist[0].get("timestamp") if hist else None
                last_new = hist[0].get("newly_registered", 0) if hist else 0
                return self._send_json({
                    "registry": reg,
                    "agent_memory": mem,
                    "auto_scan": {
                        "enabled": True,
                        "interval_sec": AUTO_SCAN_INTERVAL,
                        "running_now": False,
                        "last_line": "GitHub Actions Scheduled Auto-Scan (every 1h)",
                        "last_run_at": last_run,
                        "last_new_count": last_new,
                        "seconds_until_next_scan": AUTO_SCAN_INTERVAL,
                    },
                })

            if path == "/api/registry/csv":
                if not REGISTRY_CSV.exists():
                    return self._send_text("Registry CSV not found", content_type="text/plain", status=404)
                return self._send_text(
                    REGISTRY_CSV.read_text(encoding="utf-8"),
                    content_type="text/csv",
                    extra_headers={"Content-Disposition": 'attachment; filename="mining_registry.csv"'},
                )

            if path == "/api/providers/health":
                data = asyncio.run(check_all_apis_health(_get_omni()))
                return self._send_json(data)

            if path == "/api/overview":
                omni = _get_omni()
                mining = _read_json(MINING_REPORT_PATH)
                return self._send_json({
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

            if path == "/api/pool":
                return self._send_json(_get_omni().pool)

            if path == "/api/mining":
                mining = _read_json(MINING_REPORT_PATH)
                non_evm = _read_json(NON_EVM_REPORT_PATH)
                pow_data = _read_json(POW_REPORT_PATH)
                return self._send_json({
                    "evm_candidates": mining.get("onchain_mining_candidates", []),
                    "per_chain_activity_summary": mining.get("per_chain_activity_summary", []),
                    "solana": mining.get("solana_direct_scan"),
                    "sui": mining.get("sui_direct_scan"),
                    "non_evm": non_evm,
                    "pow": pow_data,
                })

            if path == "/api/scan/status":
                return self._send_json({
                    "running": False,
                    "preset": None,
                    "elapsed_s": 0.0,
                    "last_line": "السيرفر سحابي (Vercel): الفحص التلقائي كل ساعة كيخدم عبر GitHub Actions.",
                    "just_finished": False,
                    "returncode": 0,
                })

            if path == "/api/chains":
                omni = _get_omni()
                return self._send_json({
                    "counts": omni.pool.get("counts", {}),
                    "evm": [{"chain_id": c["chain_id"], "name": c["name"], "symbol": c["symbol"], "block": c["block_height"], "ms": c["latency_ms"]} for c in omni.pool.get("evm", [])],
                    "cosmos": [{"slug": c["slug"], "chain_id": c["cosmos_chain_id"], "name": c["name"], "block": c["block_height"]} for c in omni.pool.get("cosmos", [])],
                    "substrate": [{"slug": c["slug"], "name": c["name"], "block": c["block_height"]} for c in omni.pool.get("substrate", [])],
                    "non_evm_majors": omni.pool.get("non_evm_majors", []),
                })

            if path.startswith("/cosmos/"):
                rest = path[len("/cosmos/"):]
                parts = rest.split("/", 1)
                slug = unquote(parts[0])
                subpath = "/" + parts[1] if len(parts) > 1 else ""
                omni = _get_omni()
                data = asyncio.run(_with_session(lambda s: omni.cosmos_get(s, slug, subpath)))
                return self._send_json(data)

            return self._send_json({"error": f"Route not found: {path}"}, status=404)
        except Exception as exc:
            return self._send_json({"error": str(exc)}, status=500)

    def do_POST(self) -> None:  # noqa: N802
        path, _qs = self._resolve_route()
        try:
            omni = _get_omni()
            body = self._read_json_body()

            if path == "/api/live-block":
                eco = str(body.get("ecosystem", "")).strip()
                key = str(body.get("key", "")).strip()
                t0 = time.perf_counter()

                async def _run(session: aiohttp.ClientSession):
                    if eco == "EVM":
                        return await _fetch_live_evm_block(omni, session, key)
                    if eco == "Cosmos":
                        data = await omni.cosmos_get(session, key, "/cosmos/base/tendermint/v1beta1/blocks/latest")
                        blk = data.get("block") or {}
                        hdr = blk.get("header") or {}
                        txs = (blk.get("data") or {}).get("txs") or []
                        return {
                            "height": hdr.get("height"),
                            "hash": ((data.get("block_id") or {}).get("hash")) or "",
                            "tx_count": len(txs),
                            "raw_summary": {"chain_id": hdr.get("chain_id"), "time": hdr.get("time"), "txs_count": len(txs)},
                        }
                    if eco == "Substrate":
                        blk = await omni.substrate_call(key, "chain_getBlock", [])
                        inner = (blk or {}).get("block") or {}
                        hdr = inner.get("header") or {}
                        exts = inner.get("extrinsics") or []
                        h_raw = hdr.get("number", "0x0")
                        return {
                            "height": int(h_raw, 16) if isinstance(h_raw, str) and h_raw.startswith("0x") else h_raw,
                            "hash": hdr.get("parentHash", ""),
                            "tx_count": len(exts),
                            "raw_summary": {"extrinsics_count": len(exts), "stateRoot": hdr.get("stateRoot")},
                        }
                    if eco == "Majors":
                        return await _fetch_live_major_block(omni, session, key)
                    raise ValueError(f"Unsupported ecosystem: {eco}")

                res = asyncio.run(_with_session(_run))
                res["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                return self._send_json(res)

            if path in ("/api/scan/run", "/api/registry/scan-now", "/api/registry/toggle"):
                return self._send_json({
                    "status": "cloud_scheduled",
                    "enabled": True,
                    "message": "على Vercel، المسح الشامل كيتدار تلقائياً كل ساعة عبر GitHub Actions (أو شغّلو محلياً على جهازك).",
                })

            if path.startswith("/evm/"):
                chain_key = unquote(path[len("/evm/"):].strip("/"))
                async def _evm(session: aiohttp.ClientSession):
                    if isinstance(body, list):
                        calls = [(item["method"], item.get("params", [])) for item in body]
                        results = await omni.evm_batch(session, chain_key, calls)
                        return [
                            {"jsonrpc": "2.0", "id": body[i].get("id", i), "result": None if isinstance(r, Exception) else r}
                            for i, r in enumerate(results)
                        ]
                    result = await omni.evm_call(session, chain_key, body["method"], body.get("params", []))
                    return {"jsonrpc": "2.0", "id": body.get("id", 1), "result": result}

                return self._send_json(asyncio.run(_with_session(_evm)))

            if path.startswith("/substrate/"):
                slug = unquote(path[len("/substrate/"):].strip("/"))
                res = asyncio.run(omni.substrate_call(slug, body["method"], body.get("params", [])))
                return self._send_json({"jsonrpc": "2.0", "id": body.get("id", 1), "result": res})

            if path.startswith("/major/"):
                eco = unquote(path[len("/major/"):].strip("/")).lower()
                info = omni.majors_by_name.get(eco)
                if not info:
                    return self._send_json({"error": f"Unknown ecosystem {eco}"}, status=404)

                async def _major(session: aiohttp.ClientSession):
                    async with session.post(info["best_rpc"], json=body, timeout=aiohttp.ClientTimeout(total=12)) as r:
                        return await r.json(content_type=None)

                return self._send_json(asyncio.run(_with_session(_major)))

            return self._send_json({"error": f"Route not found: {path}"}, status=404)
        except Exception as exc:
            return self._send_json({"error": str(exc)}, status=502)
