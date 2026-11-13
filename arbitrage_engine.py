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
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    if isinstance(data.get("coins"), dict):
                        wtm_coins.update(data["coins"])
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
    await asyncio.gather(load_binance(), load_wtm(), *(probe_gas(c) for c in top_cids))

    if prices:
        _MARKET_CACHE["prices"] = prices
    if wtm_coins:
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
    if eco == "cosmos":
        return 0.005

    cid = str(item.get("chain_id") or "")
    sym = (item.get("symbol") or "ETH").upper()
    nat_px = prices.get(sym, prices.get("ETH", 2500.0) if sym == "ETH" else 0.5)
    gwei = gas_gwei.get(cid)
    if gwei is None:
        gwei = 15.0 if cid == "1" else 0.05
    # Typical on-chain mine/mint tx uses ~120,000 gas
    eth_used = (120_000 * gwei) / 1e9
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
    has_onchain_code = bc_bytes > 0 if eco == "EVM" else (int(item.get("unique_callers") or 0) >= 2 or bool(mkt.get("verified_contract_name")))

    if is_src_verified and has_onchain_code:
        return ("verified", "✅ موثّق ومؤكد", True)
    if has_onchain_code:
        return ("onchain_confirmed", "☑️ كود مؤكد على السلسلة", True)
    return ("unverified", "⚠️ غير موثّق مصدرياً", False)


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

    reg = load_registry()
    all_reg_items = list((reg.get("items") or {}).values())
    raw_items = [x for x in all_reg_items if is_actionable_mining_protocol(x)]
    excluded_non_mining_count = len(all_reg_items) - len(raw_items)
    active_cids = [str(x.get("chain_id")) for x in raw_items if x.get("ecosystem") == "EVM"]

    omni = OmniRPC()
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        mkt_cache = await _fetch_live_market_inputs(session, omni, active_cids)
        chainid_map, bs_map = await asyncio.gather(
            _load_chainid_explorers(session),
            _load_blockscout_map(session),
        )
        prices = mkt_cache["prices"]
        btc_usd = prices.get("BTC", 80000.0)
        wtm_coins = mkt_cache["wtm"]

        # Query exact WhatToMine live calculator for matching GPU algorithms
        exact_tasks = []
        matched_coin_meta: list[tuple[str, dict[str, Any], str, float]] = []
        for cname, cdata in wtm_coins.items():
            algo = str(cdata.get("algorithm") or "")
            if algo in gpu["algos"] and cdata.get("id"):
                unit, hr = gpu["algos"][algo]
                matched_coin_meta.append((cname, cdata, unit, hr))
        # Limit live exact sub-requests to top 14 by btc_revenue so dashboard loads in <1.5s
        matched_coin_meta.sort(key=lambda t: float(t[1].get("btc_revenue") or 0), reverse=True)
        top_matched = matched_coin_meta[:14]
        sem = asyncio.Semaphore(6)
        exact_res = await asyncio.gather(*(
            _fetch_wtm_exact_coin(sem, session, int(cdata["id"]), hr)
            for _, cdata, _, hr in top_matched
        ))

    gpu_coins: list[dict[str, Any]] = []
    for (cname, cdata, unit, hr), exact in zip(top_matched, exact_res):
        algo = str(cdata.get("algorithm") or "")
        tag = str(cdata.get("tag") or cname)
        est_coins_day = 0.0
        gross_day_usd = 0.0

        if exact and exact.get("btc_revenue"):
            est_coins_day = _to_float(exact.get("estimated_rewards"))
            gross_day_usd = _to_float(exact.get("btc_revenue")) * btc_usd
        else:
            ref_hr = WTM_DEFAULT_HR.get(algo)
            if ref_hr and ref_hr > 0:
                ratio = hr / ref_hr
                est_coins_day = _to_float(cdata.get("estimated_rewards")) * ratio
                gross_day_usd = _to_float(cdata.get("btc_revenue")) * btc_usd * ratio

        gross_hr_usd = gross_day_usd / 24.0
        net_day_usd = gross_day_usd - machine_cost_day
        net_hr_usd = gross_hr_usd - machine_cost_hr
        roi_pct = ((gross_day_usd / machine_cost_day) - 1.0) * 100.0 if machine_cost_day > 0 else 0.0

        ex_btc = float(cdata.get("exchange_rate") or 0)
        coin_usd = ex_btc * btc_usd if ex_btc > 0 else 0.0
        mcap_str = str(cdata.get("market_cap") or "—")

        if net_day_usd > 0.05:
            verdict = "🟢 مربح (أربيتراج إيجابي)"
        elif net_day_usd > -0.25:
            verdict = "🟡 قريب من التعادل"
        else:
            verdict = "🔴 خاسر (الكلفة > العائد)"

        gpu_coins.append({
            "coin_name": cname,
            "symbol": tag,
            "algorithm": algo,
            "gpu_hashrate": f"{hr} {unit}",
            "coin_price_usd": round(coin_usd, 6),
            "market_cap": mcap_str,
            "est_coins_day": round(est_coins_day, 4),
            "gross_day_usd": round(gross_day_usd, 4),
            "gross_hr_usd": round(gross_hr_usd, 4),
            "machine_cost_day_usd": round(machine_cost_day, 4),
            "machine_cost_hr_usd": round(machine_cost_hr, 4),
            "net_day_usd": round(net_day_usd, 4),
            "net_hr_usd": round(net_hr_usd, 4),
            "roi_pct": round(roi_pct, 1),
            "verdict": verdict,
            "lagging": bool(cdata.get("lagging")),
        })

    gpu_coins.sort(key=lambda x: x["net_day_usd"], reverse=True)

    # Evaluate On-Chain Mining Protocols (from 1h scanner registry)
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

        is_cuda_pow = (
            "pow" in ptype.lower()
            or "epoch" in ptype.lower()
            or any(
                k in fns_blob
                for k in ("mine(", "log: mine", "drill", "nonce", "pow", "difficulty", "sealepoch", "submitepoch", "provepossession", "glaze", "giver", "mine_ore", "claim_coal", "bitz")
            )
        )
        if eco == "Solana" or "eclipse" in cname.lower():
            mining_mode = "CLI / GPU Miner (PoW)" if is_cuda_pow else "SVM Mint / Miner"
        elif any(k in ptype.lower() for k in ("node", "storage", "depin")) or any(k in fns_blob for k in ("provepossession", "submitepoch", "sealepoch")):
            mining_mode = "Node / Epoch Miner"
        elif is_cuda_pow:
            mining_mode = "NVIDIA CUDA / EVM PoW"
        else:
            mining_mode = "RPC Bot / Fair Mint"

        px = _to_float(mkt.get("price_usd"))
        liq = _to_float(mkt.get("liquidity_usd"))
        vol24 = _to_float(mkt.get("volume_24h_usd"))
        gas_tx = _estimate_tx_gas_usd(item, prices, gas_gwei)
        gas_hr = gas_tx * tx_per_hr
        # For CUDA PoW, include GPU rental/electricity cost; for RPC Bot/Mint, mostly gas + tiny VPS/PC cost
        effective_machine_hr = machine_cost_hr if is_cuda_pow else (0.02 if mode == "cloud" else 0.01)
        total_cost_hr = effective_machine_hr + gas_hr

        breakeven_usd_hr = round(total_cost_hr, 4)
        breakeven_usd_tx = round(total_cost_hr / tx_per_hr, 5) if tx_per_hr > 0 else round(total_cost_hr, 5)
        breakeven_tokens_hr = round(total_cost_hr / px, 4) if px > 0 else None
        breakeven_tokens_tx = round((total_cost_hr / tx_per_hr) / px, 4) if (px > 0 and tx_per_hr > 0) else None

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
        if is_cuda_pow:
            score += 25
        if ver_level == "verified":
            score += 15
        elif ver_level == "onchain_confirmed":
            score += 6
        if liq >= 50000:
            score += 28
        elif liq >= 5000:
            score += 18
        elif px > 0:
            score += 10
        if websites:
            score += 5
        if gas_tx < 0.02:
            score += 12
        elif gas_tx < 0.25:
            score += 6
        callers = int(item.get("unique_callers") or 0)
        if callers >= 5:
            score += 10
        elif callers >= 2:
            score += 5
        if risk == "low":
            score += 10
        elif risk == "high":
            score -= 60

        score = max(0, min(100, score))

        if risk == "high":
            verdict = "🔴 خطر / Honeypot"
        elif score >= 60 and liq >= 5000:
            verdict = "🟢 فرصة أربيتراج قوية"
        elif px > 0 and liq >= 1000:
            verdict = "🟡 قابل للمراقبة (مسعّر)"
        elif is_cuda_pow and px == 0:
            verdict = "🟡 PoW مبكر (قبل الإدراج)"
        else:
            verdict = "⚪ غير مسعّر / بلا سيولة"

        exp_name, exp_url = resolve_explorer_link(eco, cid, cname, addr, chainid_map, bs_map)
        token_sym = _extract_token_symbol(item)

        onchain_rows.append({
            "uid": item.get("uid"),
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
            "is_cuda_pow": is_cuda_pow,
            "verification_level": ver_level,
            "verification_label": ver_label,
            "is_code_confirmed": is_code_ok,
            "websites": websites,
            "socials": socials,
            "price_usd": px if px > 0 else None,
            "liquidity_usd": round(liq, 2) if liq > 0 else 0.0,
            "volume_24h_usd": round(vol24, 2) if vol24 > 0 else 0.0,
            "gas_cost_tx_usd": gas_tx,
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
            "decoded_functions": (item.get("decoded_functions") or [])[:4],
        })

    onchain_rows.sort(
        key=lambda r: (r["price_usd"] is not None, r["arbitrage_score"], r["is_cuda_pow"], r["liquidity_usd"], r["unique_callers"]),
        reverse=True,
    )

    profitable_l1_count = sum(1 for c in gpu_coins if c["net_day_usd"] > 0)
    strong_onchain_count = sum(1 for r in onchain_rows if r["arbitrage_score"] >= 60)

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
        "summary": {
            "total_onchain_protocols": len(onchain_rows),
            "excluded_non_mining_count": excluded_non_mining_count,
            "cuda_pow_protocols": sum(1 for r in onchain_rows if r["is_cuda_pow"]),
            "strong_onchain_opportunities": strong_onchain_count,
            "total_gpu_l1_coins": len(gpu_coins),
            "profitable_gpu_l1_coins": profitable_l1_count,
            "best_gpu_l1_coin": gpu_coins[0] if gpu_coins else None,
        },
        "onchain_protocols": onchain_rows,
        "gpu_l1_coins": gpu_coins,
    }
