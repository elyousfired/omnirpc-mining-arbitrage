"""OmniRPC v2: Health-Aware Ranked Multi-Chain RPC Rotator & Circuit Breaker (EVM, Helius/Solana, Cosmos Directory, Substrate, Sui, Aptos)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import aiohttp
import websockets

POOL_PATH = Path(__file__).resolve().parent / "live_rpc_pool.json"
MCP_CONFIG_PATH = Path.home() / ".gemini" / "config" / "mcp_config.json"

CORE_EVM_FALLBACKS: dict[int, list[str]] = {
    1: [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://1rpc.io/eth",
        "https://rpc.ankr.com/eth",
        "https://eth.drpc.org",
    ],
    8453: [
        "https://mainnet.base.org",
        "https://base-rpc.publicnode.com",
        "https://base.llamarpc.com",
        "https://1rpc.io/base",
        "https://base.drpc.org",
    ],
    42161: [
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum-one-rpc.publicnode.com",
        "https://1rpc.io/arb",
        "https://arbitrum.drpc.org",
    ],
    56: [
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed1.defibit.io",
        "https://bsc-rpc.publicnode.com",
        "https://1rpc.io/bnb",
        "https://bsc.drpc.org",
    ],
    10: [
        "https://mainnet.optimism.io",
        "https://optimism-rpc.publicnode.com",
        "https://1rpc.io/op",
        "https://optimism.drpc.org",
    ],
    137: [
        "https://polygon-rpc.com",
        "https://polygon-bor-rpc.publicnode.com",
        "https://1rpc.io/matic",
        "https://polygon.drpc.org",
    ],
}


def mask_url(url: str) -> str:
    """Strip any embedded API keys before logging or surfacing endpoint URLs."""
    return re.sub(r"(api-key=)[^&]+", r"\1***", url)


def _load_helius_rpc() -> str | None:
    """Load locally configured Helius Solana RPC URL from env or mcp_config.json without exposing keys."""
    env_rpc = os.environ.get("RPC_URL", "")
    env_key = os.environ.get("HELIUS_API_KEY", "")
    if env_rpc and "helius" in env_rpc.lower():
        return env_rpc
    if env_key:
        return f"https://mainnet.helius-rpc.com/?api-key={env_key}"
    if MCP_CONFIG_PATH.exists():
        try:
            cfg = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            sol_env = (cfg.get("mcpServers") or {}).get("solana-agent-kit", {}).get("env") or {}
            rpc = sol_env.get("RPC_URL") or ""
            key = sol_env.get("HELIUS_API_KEY") or ""
            if rpc and "helius" in rpc.lower():
                return rpc
            if key:
                return f"https://mainnet.helius-rpc.com/?api-key={key}"
        except Exception:
            pass
    return None


class OmniRPC:
    """Health-aware multi-chain RPC router with latency ranking, 429 cooldowns, and multi-provider fallback."""

    def __init__(self, pool_path: Path = POOL_PATH) -> None:
        if not pool_path.exists():
            raise FileNotFoundError(f"Pool not found: {pool_path}. Run rpc_pool_builder.py first.")
        self.pool = json.loads(pool_path.read_text(encoding="utf-8"))
        self.evm_by_id: dict[int, dict[str, Any]] = {c["chain_id"]: c for c in self.pool.get("evm", [])}
        self.evm_by_name: dict[str, dict[str, Any]] = {c["name"].lower(): c for c in self.pool.get("evm", [])}
        self.cosmos_by_slug: dict[str, dict[str, Any]] = {c["slug"].lower(): c for c in self.pool.get("cosmos", [])}
        self.substrate_by_slug: dict[str, dict[str, Any]] = {c["slug"].lower(): c for c in self.pool.get("substrate", [])}
        self.majors_by_name: dict[str, dict[str, Any]] = {c["name"].lower(): c for c in self.pool.get("non_evm_majors", [])}

        # Endpoint telemetry & circuit breaker state: url -> {ok, fail, ewma_ms, cooldown_until}
        self._ep_stats: dict[str, dict[str, Any]] = {}
        self.helius_rpc: str | None = _load_helius_rpc()
        self.solana_rpcs: list[str] = []
        if self.helius_rpc:
            self.solana_rpcs.append(self.helius_rpc)
        self.solana_rpcs.extend([
            "https://api.mainnet-beta.solana.com",
            "https://solana-rpc.publicnode.com",
        ])
        self.solana_rpcs = list(dict.fromkeys(self.solana_rpcs))

    def _ranked_urls(self, candidates: list[str]) -> list[str]:
        now = time.time()
        unique = list(dict.fromkeys(u for u in candidates if u))
        active = [u for u in unique if self._ep_stats.get(u, {}).get("cooldown_until", 0.0) <= now]
        cooling = [u for u in unique if u not in active]
        active.sort(key=lambda u: self._ep_stats.get(u, {}).get("ewma_ms", 250.0))
        return active + cooling

    def _record_ok(self, url: str, elapsed_ms: float) -> None:
        st = self._ep_stats.setdefault(url, {"ok": 0, "fail": 0, "ewma_ms": elapsed_ms, "cooldown_until": 0.0})
        st["ok"] += 1
        st["ewma_ms"] = round(0.7 * st["ewma_ms"] + 0.3 * elapsed_ms, 1)
        st["cooldown_until"] = 0.0

    def _record_fail(self, url: str, status: int | None = None) -> None:
        st = self._ep_stats.setdefault(url, {"ok": 0, "fail": 0, "ewma_ms": 1500.0, "cooldown_until": 0.0})
        st["fail"] += 1
        base = 45.0 if status in (429, 403) else 20.0
        st["cooldown_until"] = time.time() + min(300.0, base * (2 ** min(st["fail"] - 1, 3)))

    def rotator_stats(self) -> dict[str, Any]:
        now = time.time()
        cooling = [mask_url(u) for u, s in self._ep_stats.items() if s.get("cooldown_until", 0.0) > now]
        return {
            "helius_configured": bool(self.helius_rpc),
            "tracked_endpoints": len(self._ep_stats),
            "endpoints_in_cooldown": len(cooling),
            "total_success_calls": sum(s["ok"] for s in self._ep_stats.values()),
            "total_failed_calls": sum(s["fail"] for s in self._ep_stats.values()),
        }

    def resolve_evm(self, chain: int | str) -> dict[str, Any]:
        if isinstance(chain, int) and chain in self.evm_by_id:
            return self.evm_by_id[chain]
        key = str(chain).lower().strip()
        if key.isdigit() and int(key) in self.evm_by_id:
            return self.evm_by_id[int(key)]
        if key in self.evm_by_name:
            return self.evm_by_name[key]
        for cname, obj in self.evm_by_name.items():
            if key in cname:
                return obj
        raise KeyError(f"EVM chain '{chain}' not found in live pool")

    def _evm_candidates(self, info: dict[str, Any]) -> list[str]:
        cid = int(info["chain_id"])
        pool_urls = list(info.get("working_rpcs") or [info["best_rpc"]])
        extra = CORE_EVM_FALLBACKS.get(cid, [])
        return self._ranked_urls(pool_urls + extra)

    async def evm_call(
        self,
        session: aiohttp.ClientSession,
        chain: int | str,
        method: str,
        params: list[Any],
        timeout: int = 8,
    ) -> Any:
        """Execute an EVM JSON-RPC call using latency-ranked failover rotation."""
        info = self.resolve_evm(chain)
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        last_err: Exception | None = None
        for url in self._evm_candidates(info):
            t0 = time.perf_counter()
            try:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status != 200:
                        self._record_fail(url, r.status)
                        continue
                    data = await r.json(content_type=None)
                    if isinstance(data, dict) and "result" in data:
                        self._record_ok(url, (time.perf_counter() - t0) * 1000)
                        return data["result"]
                    if isinstance(data, dict) and "error" in data:
                        self._record_fail(url)
                        last_err = RuntimeError(str(data["error"]))
            except Exception as exc:
                self._record_fail(url)
                last_err = exc
        raise RuntimeError(f"All RPCs failed for {info['name']} ({method}): {last_err}")

    async def evm_batch(
        self,
        session: aiohttp.ClientSession,
        chain: int | str,
        calls: list[tuple[str, list[Any]]],
        timeout: int = 10,
    ) -> list[Any]:
        """Execute a JSON-RPC batch request on an EVM chain with ranked rotation & sequential fallback."""
        info = self.resolve_evm(chain)
        payload = [{"jsonrpc": "2.0", "id": idx, "method": m, "params": p} for idx, (m, p) in enumerate(calls)]
        for url in self._evm_candidates(info):
            t0 = time.perf_counter()
            try:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status != 200:
                        self._record_fail(url, r.status)
                        continue
                    data = await r.json(content_type=None)
                    if isinstance(data, list):
                        self._record_ok(url, (time.perf_counter() - t0) * 1000)
                        by_id = {item["id"]: item.get("result") for item in data if isinstance(item, dict) and "id" in item}
                        return [by_id.get(i) for i in range(len(calls))]
            except Exception:
                self._record_fail(url)
                continue
        return await asyncio.gather(
            *(self.evm_call(session, chain, m, p, timeout=timeout) for m, p in calls),
            return_exceptions=True,
        )

    async def solana_call(
        self,
        session: aiohttp.ClientSession,
        method: str,
        params: Any,
        timeout: int = 12,
    ) -> dict[str, Any]:
        """Execute a Solana JSON-RPC or Helius DAS call with automatic Helius -> PublicNode -> mainnet-beta rotation."""
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        last_err: Any = None
        for url in self._ranked_urls(self.solana_rpcs):
            t0 = time.perf_counter()
            try:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status != 200:
                        self._record_fail(url, r.status)
                        last_err = f"HTTP {r.status}"
                        continue
                    data = await r.json(content_type=None)
                    if isinstance(data, dict) and "result" in data:
                        self._record_ok(url, (time.perf_counter() - t0) * 1000)
                        return data
                    self._record_fail(url)
                    last_err = data.get("error") if isinstance(data, dict) else data
            except Exception as exc:
                self._record_fail(url)
                last_err = str(exc)
        return {"error": last_err}

    async def cosmos_get(self, session: aiohttp.ClientSession, slug: str, path: str, timeout: int = 8) -> Any:
        info = self.cosmos_by_slug.get(slug.lower())
        if not info:
            raise KeyError(f"Cosmos chain '{slug}' not found in live pool")
        bases = list(info.get("working_rest") or [info["best_rest"]]) + [f"https://rest.cosmos.directory/{slug.lower()}"]
        last_err: Exception | None = None
        for base in self._ranked_urls(bases):
            url = f"{base.rstrip('/')}/{path.lstrip('/')}"
            t0 = time.perf_counter()
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        self._record_ok(base, (time.perf_counter() - t0) * 1000)
                        return data
                    self._record_fail(base, r.status)
            except Exception as exc:
                self._record_fail(base)
                last_err = exc
        raise RuntimeError(f"All Cosmos REST nodes failed for {slug}: {last_err}")

    async def substrate_call(self, slug: str, method: str, params: list[Any], timeout: int = 8) -> Any:
        info = self.substrate_by_slug.get(slug.lower())
        if not info:
            raise KeyError(f"Substrate chain '{slug}' not found in live pool")
        urls = list(info.get("working_rpcs") or [info["best_rpc"]])
        last_err: Exception | None = None
        for url in self._ranked_urls(urls):
            t0 = time.perf_counter()
            try:
                async with websockets.connect(url, open_timeout=timeout, close_timeout=2) as ws:
                    await ws.send(json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}))
                    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    self._record_ok(url, (time.perf_counter() - t0) * 1000)
                    return json.loads(raw).get("result")
            except Exception as exc:
                self._record_fail(url)
                last_err = exc
        raise RuntimeError(f"All Substrate WSS nodes failed for {slug}: {last_err}")

    async def json_rpc_post(self, url: str, session: aiohttp.ClientSession, method: str, params: Any, timeout: int = 8) -> Any:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            return await r.json(content_type=None)
