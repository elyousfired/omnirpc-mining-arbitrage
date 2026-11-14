"""Live Mining Arbitrage & Cloud NVIDIA GPU Profitability Engine for OmniRPC."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import aiohttp

from mining_registry import is_actionable_mining_protocol, load_registry
from omnirpc_client import OmniRPC
from protocol_profiler import _load_blockscout_map, _load_chainid_explorers, resolve_explorer_link

BASE_DIR = Path(__file__).resolve().parent

GPU_PROFILES: dict[str, dict[str, Any]] = {
    "rtx3060ti": {
        "id": "rtx3060ti",
        "label": "NVIDIA RTX 3060 Ti (8GB)",
        "watts": 150,
        "default_cloud_hr": 0.14,
        "algos": {
            "KawPow": ("MH/s", 28.5),
            "Autolykos": ("MH/s", 130.0),
            "Etchash": ("MH/s", 60.0),
            "ProgPow": ("MH/s", 26.0),
            "Octopus": ("MH/s", 52.0),
            "ZelHash": ("Sol/s", 55.0),
            "Cuckaroo29": ("G/s", 6.2),
            "FishHash": ("MH/s", 24.0),
            "KarlsenHash": ("GH/s", 0.55),
            "QPoW": ("MH/s", 1.0),
        },
    },
    "rtx4070": {
        "id": "rtx4070",
        "label": "NVIDIA RTX 4070 (12GB)",
        "watts": 170,
        "default_cloud_hr": 0.22,
        "algos": {
            "KawPow": ("MH/s", 34.0),
            "Autolykos": ("MH/s", 155.0),
            "Etchash": ("MH/s", 65.0),
            "ProgPow": ("MH/s", 32.0),
            "Octopus": ("MH/s", 66.0),
            "ZelHash": ("Sol/s", 75.0),
            "Cuckaroo29": ("G/s", 8.0),
            "FishHash": ("MH/s", 32.0),
            "KarlsenHash": ("GH/s", 0.85),
            "QPoW": ("MH/s", 1.3),
            "Ethash": ("MH/s", 62.0),
            "FiroPow": ("MH/s", 32.0),
            "ProgPowZ": ("MH/s", 33.0),
            "DynexSolve": ("H/s", 6500.0),
            "Blake3": ("GH/s", 1.8),
        },
    },
    "rtx4090": {
        "id": "rtx4090",
        "label": "NVIDIA RTX 4090 (24GB)",
        "watts": 350,
        "default_cloud_hr": 0.42,
        "algos": {
            "KawPow": ("MH/s", 72.0),
            "Autolykos": ("MH/s", 295.0),
            "Etchash": ("MH/s", 128.0),
            "ProgPow": ("MH/s", 68.0),
            "Octopus": ("MH/s", 135.0),
            "ZelHash": ("Sol/s", 145.0),
            "Cuckaroo29": ("G/s", 16.5),
            "FishHash": ("MH/s", 68.0),
            "KarlsenHash": ("GH/s", 2.15),
            "QPoW": ("MH/s", 2.8),
            "Ethash": ("MH/s", 128.0),
            "FiroPow": ("MH/s", 70.0),
            "ProgPowZ": ("MH/s", 72.0),
            "DynexSolve": ("H/s", 13200.0),
            "Blake3": ("GH/s", 3.6),
        },
    },
    "rtx5090": {
        "id": "rtx5090",
        "label": "NVIDIA RTX 5090 (32GB)",
        "watts": 450,
        "default_cloud_hr": 0.85,
        "algos": {
            "KawPow": ("MH/s", 105.0),
            "Autolykos": ("MH/s", 430.0),
            "Etchash": ("MH/s", 185.0),
            "ProgPow": ("MH/s", 98.0),
            "Octopus": ("MH/s", 195.0),
            "ZelHash": ("Sol/s", 210.0),
            "Cuckaroo29": ("G/s", 24.0),
            "FishHash": ("MH/s", 96.0),
            "KarlsenHash": ("GH/s", 3.1),
            "QPoW": ("MH/s", 4.0),
            "Ethash": ("MH/s", 185.0),
            "FiroPow": ("MH/s", 98.0),
            "ProgPowZ": ("MH/s", 102.0),
            "DynexSolve": ("H/s", 19000.0),
            "Blake3": ("GH/s", 5.2),
        },
    },
    "rig6x3060ti": {
        "id": "rig6x3060ti",
        "label": "Rig 6x RTX 3060 Ti (48GB)",
        "watts": 950,
        "default_cloud_hr": 0.80,
        "algos": {
            "KawPow": ("MH/s", 171.0),
            "Autolykos": ("MH/s", 780.0),
            "Etchash": ("MH/s", 360.0),
            "ProgPow": ("MH/s", 156.0),
            "Octopus": ("MH/s", 312.0),
            "ZelHash": ("Sol/s", 330.0),
            "Cuckaroo29": ("G/s", 37.2),
            "FishHash": ("MH/s", 144.0),
            "KarlsenHash": ("GH/s", 3.3),
            "QPoW": ("MH/s", 6.0),
            "Ethash": ("MH/s", 360.0),
            "FiroPow": ("MH/s", 155.0),
            "ProgPowZ": ("MH/s", 160.0),
            "DynexSolve": ("H/s", 28000.0),
            "Blake3": ("GH/s", 7.5),
        },
    },
}

# WhatToMine coins.json default reference hashrates (used as fallback when coin-specific endpoint is skipped)
WTM_DEFAULT_HR: dict[str, float] = {
    "KawPow": 88.9,
    "Autolykos": 390.0,
    "Etchash": 90.0,
    "ProgPow": 60.0,
    "Octopus": 140.0,
    "ZelHash": 130.0,
    "Cuckaroo29": 12.0,
    "FishHash": 70.0,
    "KarlsenHash": 1.6,
}

NATIVE_SYMBOL_TO_BINANCE: dict[str, str] = {
    "BTC": "BTCUSDT",
    "ETH": "ETHUSDT",
    "BNB": "BNBUSDT",
    "POL": "POLUSDT",
    "MATIC": "POLUSDT",
    "AVAX": "AVAXUSDT",
    "SOL": "SOLUSDT",
    "TON": "TONUSDT",
    "SUI": "SUIUSDT",
    "APT": "APTUSDT",
    "NEAR": "NEARUSDT",
    "ATOM": "ATOMUSDT",
    "FTM": "FTMUSDT",
    "S": "SUSDT",
    "MNT": "MNTUSDT",
    "CRO": "CROUSDT",
    "BERA": "BERAUSDT",
    "SEI": "SEIUSDT",
    "ADA": "ADAUSDT",
    "TRX": "TRXUSDT",
    "CFX": "CFXUSDT",
    "ETC": "ETCUSDT",
    "XRP": "XRPUSDT",
    "GLMR": "GLMRUSDT",
    "CELO": "CELOUSDT",
}

_MARKET_CACHE: dict[str, Any] = {"ts": 0.0, "prices": {}, "wtm": {}, "gas_gwei": {}}
_WTM_COIN_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


async def _fetch_live_market_inputs(session: aiohttp.ClientSession, omni: OmniRPC, active_chain_ids: list[str]) -> dict[str, Any]:
    """Fetch live Binance spot prices, WhatToMine coins, and live EVM gas prices (cached 90s)."""
    now = time.time()
    if now - _MARKET_CACHE["ts"] < 90 and _MARKET_CACHE["prices"] and _MARKET_CACHE["wtm"]:
        return _MARKET_CACHE

    prices: dict[str, float] = {}
    wtm_coins: dict[str, Any] = {}
    gas_gwei: dict[str, float] = dict(_MARKET_CACHE.get("gas_gwei") or {})

    async def load_binance() -> None:
        for endpoint in (
            "https://data-api.binance.vision/api/v3/ticker/price",
            "https://api.binance.com/api/v3/ticker/price",
        ):
            try:
                async with session.get(endpoint, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status == 200:
                        rows = await r.json(content_type=None)
                        sym_map = {x["symbol"]: float(x["price"]) for x in rows if isinstance(x, dict) and "symbol" in x}
                        for nat, bsym in NATIVE_SYMBOL_TO_BINANCE.items():
                            if bsym in sym_map:
                                prices[nat] = sym_map[bsym]
                        if prices:
                            return
            except Exception:
                pass
        # Fallback to CryptoCompare (US-cloud safe) if Binance endpoints fail
        try:
            fsyms = ",".join(dict.fromkeys(NATIVE_SYMBOL_TO_BINANCE.keys()))
            cc_url = f"https://min-api.cryptocompare.com/data/pricemulti?fsyms={fsyms}&tsyms=USD"
            async with session.get(cc_url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    if isinstance(data, dict):
                        for nat in NATIVE_SYMBOL_TO_BINANCE:
                            usd = (data.get(nat) or {}).get("USD")
                            if usd:
                                prices[nat] = float(usd)
        except Exception:
            pass

    async def load_wtm() -> None:
        try:
            async with session.get(
                "https://whattomine.com/coins.json",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    coins_obj = data.get("coins") if isinstance(data, dict) else {}
                    if isinstance(coins_obj, dict):
                        for cname, meta in coins_obj.items():
                            if not isinstance(meta, dict) or meta.get("lagging"):
                                continue
                            entry = {"name": cname, **meta}
                            wtm_coins[cname.lower()] = entry
                            tag = str(meta.get("tag") or "").upper()
                            if tag and tag not in wtm_coins:
                                wtm_coins[tag] = entry
        except Exception:
            pass
        try:
            async with session.get(
                "https://api.woolypooly.com/api/stats",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=aiohttp.ClientTimeout(total=7),
            ) as rw:
                if rw.status == 200:
                    wp = await rw.json(content_type=None)
                    if isinstance(wp, dict) and isinstance(wp.get("alph-1"), dict):
                        ap = wp["alph-1"]
                        alph_entry = {
                            "name": "Alephium",
                            "tag": "ALPH",
                            "algorithm": "Blake3",
                            "nethash": ap.get("netHashrate"),
                            "block_time": ap.get("blockTime"),
                            "block_reward": ap.get("blockReward"),
                        }
                        wtm_coins.setdefault("alephium", alph_entry)
                        wtm_coins.setdefault("ALPH", alph_entry)
        except Exception:
            pass

    async def probe_gas(cid: str) -> None:
        try:
            if not cid.isdigit():
                return
            hex_gp = await omni.evm_call(session, int(cid), "eth_gasPrice", [], timeout=4)
            if isinstance(hex_gp, str) and hex_gp.startswith("0x"):
                gas_gwei[cid] = int(hex_gp, 16) / 1e9
        except Exception:
            pass

    top_cids = list(dict.fromkeys(active_chain_ids))[:22]
    await asyncio.gather(load_binance(), *(probe_gas(c) for c in top_cids))

    if prices:
        _MARKET_CACHE["prices"] = prices
    _MARKET_CACHE["wtm"] = wtm_coins
    _MARKET_CACHE["gas_gwei"] = gas_gwei
    _MARKET_CACHE["ts"] = now
    return _MARKET_CACHE


async def _fetch_wtm_exact_coin(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    coin_id: int,
    hr: float,
) -> dict[str, Any] | None:
    """Query WhatToMine single-coin calculator for exact live GPU hashrate revenue."""
    ckey = f"{coin_id}:{hr:.2f}"
    cached = _WTM_COIN_CACHE.get(ckey)
    if cached and (time.time() - cached[0] < 180):
        return cached[1]
    async with sem:
        try:
            url = f"https://whattomine.com/coins/{coin_id}.json?hr={hr}&p=0&fee=1&cost=0"
            async with session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=aiohttp.ClientTimeout(total=7)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    _WTM_COIN_CACHE[ckey] = (time.time(), data)
                    return data
        except Exception:
            pass
    return None


def _to_float(val: Any, default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        return float(str(val).replace(",", "").strip())
    except (ValueError, TypeError):
        return default


def _estimate_tx_gas_usd(item: dict[str, Any], prices: dict[str, float], gas_gwei: dict[str, float]) -> float:
    """Estimate live USD transaction cost for one mining/minting call on the target chain."""
    eco = (item.get("ecosystem") or "EVM").lower()
    if eco == "solana":
        sol_px = prices.get("SOL", 150.0)
        return round(0.000015 * sol_px, 6)
    if eco == "ton":
        ton_px = prices.get("TON", 5.0)
        return round(0.012 * ton_px, 6)
    if eco == "sui":
        sui_px = prices.get("SUI", 2.0)
        return round(0.003 * sui_px, 6)
    if eco == "aptos":
        apt_px = prices.get("APT", 8.0)
        return round(0.0008 * apt_px, 6)
    if eco == "near":
        near_px = prices.get("NEAR", 4.0)
        return round(0.001 * near_px, 6)
    if eco == "cardano":
        return round(0.17 * prices.get("ADA", 0.5), 5)
    if eco == "tron":
        return round(1.0 * prices.get("TRX", 0.25), 5)
    if eco == "xrpl":
        return round(0.0001 * prices.get("XRP", 1.5), 6)
    if eco == "cosmos":
        return 0.005

    cid = str(item.get("chain_id") or "")
    sym = (item.get("symbol") or "ETH").upper()
    if cid == "369" or sym == "PLS":
        nat_px = 0.00004
    else:
        nat_px = prices.get(sym, prices.get("ETH", 2500.0) if sym == "ETH" else 0.2)
    gwei = gas_gwei.get(cid)
    if gwei is None:
        gwei = 15.0 if cid == "1" else 0.05
    # Use Sandbox-measured gas units from eth_estimateGas when available, else typical 120,000 gas
    sb = item.get("sandbox_test") or {}
    gas_units = int(sb.get("est_gas_units") or 0) or 120_000
    eth_used = (gas_units * gwei) / 1e9
    return round(eth_used * nat_px, 6)


def _extract_token_symbol(item: dict[str, Any]) -> str:
    prof = item.get("onchain_profile") or {}
    mkt = item.get("market_profile") or {}
    sym = (mkt.get("reward_token_symbol") or prof.get("symbol") or mkt.get("blockscout_symbol") or "").strip()
    if sym:
        return sym
    pname = str(item.get("protocol_name") or "")
    if "(" in pname and ")" in pname:
        inner = pname.rsplit("(", 1)[-1].rstrip(")").strip()
        if 1 <= len(inner) <= 14 and " " not in inner:
            return inner
    return item.get("symbol") or "TOKEN"


def _compute_verification(item: dict[str, Any]) -> tuple[str, str, bool]:
    """Verify contract existence (bytecode/program), source verification, and activity before surfacing."""
    eco = item.get("ecosystem") or "EVM"
    prof = item.get("onchain_profile") or {}
    mkt = item.get("market_profile") or {}
    bc_bytes = int(prof.get("bytecode_bytes") or 0)
    is_src_verified = bool(mkt.get("is_verified") or mkt.get("sourcify_verified"))
    has_non_evm_proof = bool(mkt.get("verified_contract_name")) or (
        bool(item.get("is_curated_miner")) and bool(mkt.get("dex_url"))
    )
    has_onchain_code = bc_bytes > 0 if eco == "EVM" else (int(item.get("unique_callers") or 0) >= 2 or has_non_evm_proof)

    if is_src_verified and has_onchain_code:
        return ("verified", "✅ موثّق ومؤكد", True)
    if has_onchain_code:
        return ("onchain_confirmed", "☑️ كود مؤكد على السلسلة", True)
    return ("unverified", "⚠️ غير موثّق مصدرياً", False)


_GITHUB_REG_CACHE: dict[str, Any] = {"ts": 0.0, "reg": None, "mem": None}
_RAW_BASE = "https://raw.githubusercontent.com/elyousfired/omnirpc-mining-arbitrage/main"
_AGENT_MEM_PATH = Path(__file__).resolve().parent / "agent_memory.json"


def _load_local_agent_memory() -> dict[str, Any]:
    if _AGENT_MEM_PATH.exists():
        try:
            d = json.loads(_AGENT_MEM_PATH.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    return {}


async def load_latest_registry_and_memory(session: aiohttp.ClientSession) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load accumulated mining_registry + agent_memory, merging local & latest GitHub hourly state."""
    local_reg = load_registry()
    local_mem = _load_local_agent_memory()

    now = time.time()
    remote_reg = _GITHUB_REG_CACHE.get("reg")
    remote_mem = _GITHUB_REG_CACHE.get("mem")
    if now - float(_GITHUB_REG_CACHE.get("ts") or 0) > 45:
        async def _get_json(url: str) -> dict[str, Any] | None:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as r:
                    if r.status == 200:
                        d = await r.json(content_type=None)
                        return d if isinstance(d, dict) else None
            except Exception:
                return None
            return None

        r_reg, r_mem = await asyncio.gather(
            _get_json(f"{_RAW_BASE}/mining_registry.json"),
            _get_json(f"{_RAW_BASE}/agent_memory.json"),
        )
        if r_reg is not None:
            remote_reg = r_reg
            _GITHUB_REG_CACHE["reg"] = r_reg
        if r_mem is not None:
            remote_mem = r_mem
            _GITHUB_REG_CACHE["mem"] = r_mem
        _GITHUB_REG_CACHE["ts"] = now

    # If local registry is already at or ahead of GitHub remote, avoid resurrecting pruned entries;
    # only union-merge when remote GitHub Actions actually finished a newer hourly cycle.
    use_remote = (
        isinstance(remote_reg, dict)
        and (
            int(remote_reg.get("total_scans_completed") or 0) > int(local_reg.get("total_scans_completed") or 0)
            or str(remote_reg.get("updated_at") or "") > str(local_reg.get("updated_at") or "")
        )
    )
    merged_items: dict[str, dict[str, Any]] = {}
    sources = (local_reg, remote_reg) if use_remote else (local_reg,)
    for src in sources:
        if not isinstance(src, dict):
            continue
        for uid, it in (src.get("items") or {}).items():
            if not isinstance(it, dict):
                continue
            prev = merged_items.get(uid)
            if prev is None or str(it.get("last_seen_at") or "") > str(prev.get("last_seen_at") or ""):
                merged_items[uid] = it
    primary_reg = dict(remote_reg if use_remote else local_reg)
    primary_reg["items"] = merged_items
    primary_reg["total_protocols"] = len(merged_items)

    use_remote_mem = (
        isinstance(remote_mem, dict)
        and int(remote_mem.get("total_cycles") or 0) >= int(local_mem.get("total_cycles") or 0)
        and str(remote_mem.get("last_cycle_at") or "") >= str(local_mem.get("last_cycle_at") or "")
    )
    primary_mem = dict(remote_mem if use_remote_mem else local_mem)
    return primary_reg, primary_mem


async def compute_arbitrage_snapshot(
    gpu_id: str = "rtx4090",
    mode: str = "cloud",
    cloud_rate: float | None = None,
    kwh_cost: float = 0.14,
    tx_per_hr: int = 20,
) -> dict[str, Any]:
    """Compute live GPU PoW Coin Arbitrage and On-Chain Mining Protocol Arbitrage."""
    gpu = GPU_PROFILES.get(gpu_id) or GPU_PROFILES["rtx4090"]
    effective_cloud_hr = float(cloud_rate) if cloud_rate is not None else float(gpu["default_cloud_hr"])
    watts = float(gpu["watts"])
    machine_cost_hr = effective_cloud_hr if mode == "cloud" else round((watts / 1000.0) * kwh_cost, 4)
    machine_cost_day = round(machine_cost_hr * 24.0, 4)

    omni = OmniRPC()
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        reg, agent_mem = await load_latest_registry_and_memory(session)
        all_reg_items = list((reg.get("items") or {}).values())
        raw_items = [x for x in all_reg_items if is_actionable_mining_protocol(x)]
        excluded_non_mining_count = max(len(all_reg_items) - len(raw_items), int(reg.get("pruned_last_scan") or 0))
        last_scan_at = reg.get("updated_at")
        active_cids = [str(x.get("chain_id")) for x in raw_items if x.get("ecosystem") == "EVM"]

        mkt_cache = await _fetch_live_market_inputs(session, omni, active_cids)
        chainid_map, bs_map = await asyncio.gather(
            _load_chainid_explorers(session),
            _load_blockscout_map(session),
        )
        prices = mkt_cache["prices"]
        wtm_map = mkt_cache.get("wtm") or {}
        btc_usd = prices.get("BTC", 80000.0)

    def _unit_mult(u: str) -> float:
        ul = u.lower()
        if ul.startswith("gh"):
            return 1e9
        if ul.startswith("mh"):
            return 1e6
        if ul.startswith("kh"):
            return 1e3
        return 1.0

    gpu_coins: list[dict[str, Any]] = []

    # Evaluate On-Chain Mining & GPU PoW Protocols (from 1h scanner registry)
    onchain_rows: list[dict[str, Any]] = []
    gas_gwei = mkt_cache.get("gas_gwei") or {}

    for item in raw_items:
        eco = item.get("ecosystem") or "EVM"
        cid = str(item.get("chain_id") or "")
        cname = item.get("chain_name") or eco
        addr = item.get("address") or ""
        mkt = item.get("market_profile") or {}
        sec = item.get("security_profile") or {}
        prof = item.get("onchain_profile") or {}
        ptype = str(item.get("protocol_type") or item.get("category") or "")
        fns_blob = " ".join(item.get("decoded_functions") or []).lower()
        token_sym = _extract_token_symbol(item)
        wtm_name = str(item.get("wtm_name") or "").strip()
        gpu_algo_pref = str(item.get("gpu_algo") or "").strip()

        wtm_entry = None
        if wtm_name and wtm_name.lower() in wtm_map:
            wtm_entry = wtm_map[wtm_name.lower()]
        elif token_sym.upper() in wtm_map and ("gpu" in ptype.lower() or "pow" in ptype.lower() or gpu_algo_pref):
            wtm_entry = wtm_map[token_sym.upper()]

        matched_algo = gpu_algo_pref or (str(wtm_entry.get("algorithm") or "") if wtm_entry else "")
        is_gpu_pow = bool(
            matched_algo
            or wtm_entry
            or "gpu proof-of-work" in ptype.lower()
            or "gpu proof-of-work" in str(item.get("category") or "").lower()
        )
        is_cuda_pow = is_gpu_pow or (
            "pow" in ptype.lower()
            or "epoch" in ptype.lower()
            or any(
                k in fns_blob
                for k in ("mine(", "log: mine", "drill", "nonce", "pow", "difficulty", "sealepoch", "submitepoch", "provepossession", "glaze", "giver", "mine_ore", "claim_coal", "bitz", "proof_of_work")
            )
        )

        # Look up exact GPU hashrate & compute WhatToMine live daily PoW yield
        algo_spec = gpu["algos"].get(matched_algo)
        if not algo_spec and matched_algo:
            for k_alg, v_alg in gpu["algos"].items():
                if k_alg.lower() == matched_algo.lower():
                    algo_spec = v_alg
                    matched_algo = k_alg
                    break

        px = _to_float(mkt.get("price_usd"))
        liq = _to_float(mkt.get("liquidity_usd"))
        vol24 = _to_float(mkt.get("volume_24h_usd"))
        sb = item.get("sandbox_test") or {}
        gas_tx = _estimate_tx_gas_usd(item, prices, gas_gwei)
        mint_fee_usd = _to_float(sb.get("mint_fee_usd"))
        tx_fee_total = round(gas_tx + mint_fee_usd, 6)
        gas_hr = tx_fee_total * tx_per_hr

        est_coins_day = None
        gross_day_usd = None
        net_day_usd = None
        breakeven_coin_px = None
        gpu_hashrate_label = ""
        is_gpu_pow = False

        if sb.get("onchain_pow_state") or sb.get("pow_functions"):
            mining_mode = "On-Chain PoW + Web3 Mint"
        elif sb.get("trial_status") == "SIMULATED_OPEN":
            mining_mode = "Web3 Mint (Simulated Open)"
        elif eco == "Solana" or eco == "TON":
            mining_mode = f"{eco} Web3 Mint/Mine UI"
        else:
            mining_mode = "Connect Wallet -> Mint UI"

        # Pure Web3 Mint / Mine cost: on-chain gas + contract mint fee (+ minimal node overhead)
        effective_machine_hr = 0.02 if mode == "cloud" else 0.01
        total_cost_hr = effective_machine_hr + gas_hr
        total_cost_tx = (effective_machine_hr / tx_per_hr if tx_per_hr > 0 else effective_machine_hr) + tx_fee_total

        breakeven_usd_hr = round(total_cost_hr, 4)
        breakeven_usd_tx = round(total_cost_tx, 5)
        breakeven_tokens_hr = round(total_cost_hr / px, 4) if px > 0 else None
        breakeven_tokens_tx = round(total_cost_tx / px, 4) if px > 0 else None

        ver_level, ver_label, is_code_ok = _compute_verification(item)
        websites = [w for w in (mkt.get("websites") or []) if isinstance(w, str) and w.startswith(("http://", "https://"))]
        socials = [s for s in (mkt.get("socials") or []) if isinstance(s, str) and s.startswith(("http://", "https://"))]
        resolved_tok_addr = (mkt.get("resolved_token_address") or item.get("token_address") or mkt.get("dex_base_token") or addr)

        risk = sec.get("risk_level") or "unknown"
        sec_verdict = sec.get("verdict") or "غير مفحوص"
        if risk == "high" and item.get("is_curated_miner") and sec_verdict == "خطر RugCheck":
            # PoW/Mint Solana tokens keep Mint Authority enabled on their mining program PDA by design
            risk = "medium"
            sec_verdict = "PoW Mintable (عادي للتعدين)"
        score = 0
        if sb.get("is_actionable_web3_mint"):
            score += 20
        if sb.get("trial_status") in ("SIMULATED_OPEN", "POW_OR_MINT_ACTIVE"):
            score += 10
        if sb.get("onchain_pow_state") or sb.get("pow_functions"):
            score += 8
        if ver_level == "verified":
            score += 14
        elif ver_level == "onchain_confirmed":
            score += 6
        if liq >= 50000:
            score += 24
        elif liq >= 5000:
            score += 16
        elif px > 0:
            score += 8
        if websites:
            score += 5
        if gas_tx < 0.02:
            score += 12
        elif gas_tx < 0.25:
            score += 6
        callers = int(item.get("unique_callers") or 0)
        if callers >= 5:
            score += 8
        elif callers >= 2:
            score += 4
        if risk == "low":
            score += 10
        elif risk == "high":
            score -= 60

        score = max(0, min(100, score))

        if risk == "high":
            verdict = "🔴 خطر / Honeypot"
        elif score >= 60 and liq >= 5000:
            verdict = "🟢 Connect Wallet -> Mint قوية"
        elif px > 0 and liq >= 1000:
            verdict = "🟡 Connect Wallet -> Mint شغالة"
        else:
            verdict = "⚪ سيولة ضعيفة"

        exp_name, exp_url = resolve_explorer_link(eco, cid, cname, addr, chainid_map, bs_map)

        onchain_rows.append({
            "uid": item.get("uid"),
            "kind": "mint_tx",
            "protocol_name": item.get("protocol_name") or addr[:14],
            "token_symbol": token_sym,
            "address": addr,
            "token_address": resolved_tok_addr,
            "token_differs_from_protocol": resolved_tok_addr.lower() != addr.lower(),
            "ecosystem": eco,
            "chain_name": cname,
            "chain_id": cid,
            "protocol_type": ptype,
            "standard": prof.get("standard") or eco,
            "mining_mode": mining_mode,
            "is_cuda_pow": bool(sb.get("onchain_pow_state") or sb.get("pow_functions")),
            "is_gpu_pow": False,
            "gpu_algo": "",
            "gpu_hashrate": "",
            "est_coins_day": None,
            "gross_day_usd": None,
            "net_day_usd": None,
            "breakeven_coin_price_usd": None,
            "verification_level": ver_level,
            "verification_label": ver_label,
            "is_code_confirmed": is_code_ok,
            "websites": websites,
            "socials": socials,
            "price_usd": px if px > 0 else None,
            "liquidity_usd": round(liq, 2) if liq > 0 else 0.0,
            "volume_24h_usd": round(vol24, 2) if vol24 > 0 else 0.0,
            "gas_cost_tx_usd": gas_tx,
            "mint_fee_usd": round(mint_fee_usd, 4),
            "total_cost_tx_usd": round(total_cost_tx, 5),
            "total_cost_hr_usd": round(total_cost_hr, 4),
            "breakeven_usd_hr": breakeven_usd_hr,
            "breakeven_usd_tx": breakeven_usd_tx,
            "breakeven_tokens_hr": breakeven_tokens_hr,
            "breakeven_tokens_tx": breakeven_tokens_tx,
            "unique_callers": callers,
            "cumulative_mints": int(item.get("cumulative_mints") or 0),
            "security_verdict": sec_verdict,
            "risk_level": risk,
            "arbitrage_score": score,
            "verdict": verdict,
            "explorer_name": exp_name,
            "explorer_url": exp_url,
            "dex_url": mkt.get("dex_url") or "",
            "is_new": bool(item.get("is_new_in_last_scan")),
            "first_seen_at": item.get("first_seen_at"),
            "seen_scans": int(item.get("seen_scans") or 1),
            "discovery_source": item.get("discovery_source") or "verified_registry",
            "agent_reasoning": item.get("agent_reasoning") or "",
            "decoded_functions": (item.get("decoded_functions") or [])[:4],
            "sandbox_wallet": sb.get("sandbox_wallet") or agent_mem.get("sandbox_wallet") or "",
            "trial_status": sb.get("trial_status") or "UNVERIFIED",
            "trial_verdict_ar": sb.get("trial_verdict_ar") or "",
            "tested_fn": sb.get("tested_fn") or "",
            "est_gas_units": int(sb.get("est_gas_units") or 0),
            "has_connect_wallet": bool(sb.get("has_connect_wallet")),
            "has_mint_ui": bool(sb.get("has_mint_ui")),
            "onchain_pow_state": sb.get("onchain_pow_state") or {},
            "site_live": bool(sb.get("site_live")),
        })

    onchain_rows.sort(
        key=lambda r: (
            r["price_usd"] is not None,
            r["net_day_usd"] if r["net_day_usd"] is not None else -9999.0,
            r["arbitrage_score"],
            r["liquidity_usd"],
        ),
        reverse=True,
    )

    strong_onchain_count = sum(1 for r in onchain_rows if r["arbitrage_score"] >= 60)
    simulated_open_count = sum(1 for r in onchain_rows if r.get("trial_status") in ("SIMULATED_OPEN", "POW_OR_MINT_ACTIVE"))

    return {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "btc_usd": round(btc_usd, 2),
        "native_prices_usd": {k: round(v, 4) for k, v in prices.items()},
        "machine": {
            "gpu_id": gpu["id"],
            "label": gpu["label"],
            "watts": gpu["watts"],
            "mode": mode,
            "cloud_rate_hr": effective_cloud_hr,
            "kwh_cost": kwh_cost,
            "tx_per_hr": tx_per_hr,
            "machine_cost_hr_usd": round(machine_cost_hr, 4),
            "machine_cost_day_usd": round(machine_cost_day, 4),
        },
        "gpu_profiles": [
            {"id": k, "label": v["label"], "watts": v["watts"], "default_cloud_hr": v["default_cloud_hr"]}
            for k, v in GPU_PROFILES.items()
        ],
        "agent": {
            "name": agent_mem.get("agent_name") or "OmniRPC Autonomous Mining Agent",
            "sandbox_wallet": agent_mem.get("sandbox_wallet") or reg.get("sandbox_wallet") or "",
            "sandbox_trials_last_cycle": agent_mem.get("sandbox_trials_last_cycle") or {},
            "total_cycles": int(agent_mem.get("total_cycles") or reg.get("total_scans_completed") or 0),
            "last_cycle_at": agent_mem.get("last_cycle_at") or last_scan_at,
            "newly_added_last_cycle": int(agent_mem.get("newly_added_last_cycle") or (reg.get("last_scan_stats") or {}).get("newly_registered") or 0),
            "known_protocols_count": len(onchain_rows),
            "last_brief_ar": agent_mem.get("last_agent_brief_ar") or "",
            "ai_llm_enabled": bool(agent_mem.get("ai_llm_enabled")),
            "cycle_logs": (agent_mem.get("cycle_logs") or reg.get("scan_history") or [])[:5],
        },
        "summary": {
            "total_onchain_protocols": len(onchain_rows),
            "excluded_non_mining_count": excluded_non_mining_count,
            "cuda_pow_protocols": sum(1 for r in onchain_rows if r["is_cuda_pow"]),
            "simulated_open_protocols": simulated_open_count,
            "strong_onchain_opportunities": strong_onchain_count,
            "last_scan_at": last_scan_at,
        },
        "onchain_protocols": onchain_rows,
    }
