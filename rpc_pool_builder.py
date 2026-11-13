"""Async multi-ecosystem RPC health scanner and live RPC pool builder."""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any

import aiohttp
import websockets

REGISTRY_DIR = Path(r"C:\Users\red1e\.gemini\antigravity\scratch\all-blockchains-registry")
SOURCES_DIR = REGISTRY_DIR / "sources"
OUT_DIR = Path(__file__).resolve().parent

EXTRA_RPCS_URL = "https://raw.githubusercontent.com/DefiLlama/chainlist/main/constants/extraRpcs.js"

TESTNET_KEYWORDS = (
    "testnet", "sepolia", "goerli", "holesky", "hoodi", "devnet", "ropsten",
    "rinkeby", "kovan", "mumbai", "amoy", "fuji", "chapel", "alfajores",
    "baklava", "chiado", "shasta", "nile", "faucet", "sandbox", "staging",
    "localnet", "paseo", "westend", "rococo",
)

PREFERRED_PROVIDERS = ("publicnode", "llamarpc", "drpc", "1rpc", "ankr", "alchemy", "quicknode", "blastapi", "tenderly")


def is_testnet(name: str, status: str = "", title: str = "") -> bool:
    if status.lower() == "deprecated":
        return True
    hay = f"{name} {title}".lower()
    return any(k in hay for k in TESTNET_KEYWORDS)


def clean_http_rpcs(rpcs: list[Any]) -> list[str]:
    out: list[str] = []
    for r in rpcs or []:
        if not isinstance(r, str):
            continue
        r = r.strip()
        if r.startswith(("https://", "http://")) and "${" not in r and "{" not in r:
            if r not in out:
                out.append(r)
    return out


def sort_rpcs_by_reliability(rpcs: list[str]) -> list[str]:
    def score(u: str) -> tuple[int, str]:
        low = u.lower()
        for idx, prov in enumerate(PREFERRED_PROVIDERS):
            if prov in low:
                return (idx, u)
        return (len(PREFERRED_PROVIDERS), u)
    return sorted(rpcs, key=score)


def fetch_chainlist_extra_rpcs() -> dict[int, list[str]]:
    """Parse DefiLlama/chainlist extraRpcs.js into {chainId: [http_rpc_urls]}."""
    cache_path = OUT_DIR / "chainlist_extra_rpcs.json"
    try:
        req = urllib.request.Request(EXTRA_RPCS_URL, headers={"User-Agent": "Mozilla/5.0"})
        txt = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", errors="replace")
        idx = txt.find("export const extraRpcs")
        if idx == -1:
            raise ValueError("extraRpcs marker not found")
        body = txt[idx:]
        parsed: dict[int, list[str]] = {}
        current_cid: int | None = None
        for line in body.splitlines():
            m_cid = re.match(r"^\s*(\d+)\s*:\s*\{", line)
            if m_cid:
                current_cid = int(m_cid.group(1))
                parsed.setdefault(current_cid, [])
                continue
            if current_cid is not None:
                for url_m in re.findall(r'["\'](https?://[^"\']+)["\']', line):
                    if "${" not in url_m and "{" not in url_m and "tos" not in url_m.lower() and "privacy" not in url_m.lower():
                        if url_m not in parsed[current_cid]:
                            parsed[current_cid].append(url_m)
        cache_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        return parsed
    except Exception as exc:
        print(f"[WARN] extraRpcs fetch failed: {exc}")
        if cache_path.exists():
            raw = json.loads(cache_path.read_text(encoding="utf-8"))
            return {int(k): v for k, v in raw.items()}
        return {}


async def probe_evm_rpc(session: aiohttp.ClientSession, url: str) -> tuple[bool, int | None, float]:
    t0 = time.perf_counter()
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}
    try:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=3)) as resp:
            if resp.status != 200:
                return False, None, 0.0
            data = await resp.json(content_type=None)
            res = data.get("result") if isinstance(data, dict) else None
            if isinstance(res, str) and res.startswith("0x"):
                ms = round((time.perf_counter() - t0) * 1000, 1)
                return True, int(res, 16), ms
    except Exception:
        pass
    return False, None, 0.0


async def check_evm_chain(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    chain: dict[str, Any],
) -> dict[str, Any] | None:
    candidates = sort_rpcs_by_reliability(chain["rpcs"])[:4]
    if not candidates:
        return None
    async with sem:
        probes = await asyncio.gather(*(probe_evm_rpc(session, url) for url in candidates))
        working = [
            {"url": url, "latency_ms": ms, "block": block_num}
            for url, (ok, block_num, ms) in zip(candidates, probes)
            if ok and block_num is not None
        ]
        if not working:
            return None
        working.sort(key=lambda x: x["latency_ms"])
        best = working[0]
        return {
            "chain_id": chain["chain_id"],
            "name": chain["name"],
            "symbol": chain["symbol"],
            "ecosystem": "EVM",
            "best_rpc": best["url"],
            "working_rpcs": [w["url"] for w in working],
            "latency_ms": best["latency_ms"],
            "block_height": best["block"],
        }


async def check_cosmos_chain(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    chain: dict[str, Any],
) -> dict[str, Any] | None:
    slug = chain.get("slug")
    if not slug:
        return None
    rest_url = f"https://rest.cosmos.directory/{slug}/cosmos/base/tendermint/v1beta1/blocks/latest"
    rpc_url = f"https://rpc.cosmos.directory/{slug}"
    async with sem:
        t0 = time.perf_counter()
        try:
            async with session.get(rest_url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                header = data.get("block", {}).get("header", {})
                height = int(header["height"])
                ms = round((time.perf_counter() - t0) * 1000, 1)
                return {
                    "slug": slug,
                    "cosmos_chain_id": header.get("chain_id") or chain.get("chain_id_str"),
                    "name": chain.get("name") or slug,
                    "symbol": chain.get("symbol") or "",
                    "ecosystem": "Cosmos/IBC",
                    "best_rest": f"https://rest.cosmos.directory/{slug}",
                    "best_rpc": rpc_url,
                    "latency_ms": ms,
                    "block_height": height,
                }
        except Exception:
            return None


async def check_substrate_chain(
    sem: asyncio.Semaphore,
    chain: dict[str, Any],
) -> dict[str, Any] | None:
    wss_urls = [u for u in chain.get("wss_urls", []) if u.startswith("wss://")][:2]
    if not wss_urls:
        return None
    async with sem:
        for url in wss_urls:
            t0 = time.perf_counter()
            try:
                async with websockets.connect(url, open_timeout=6, close_timeout=2) as ws:
                    await ws.send(json.dumps({"id": 1, "jsonrpc": "2.0", "method": "chain_getHeader", "params": []}))
                    raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    data = json.loads(raw)
                    res = data.get("result") or {}
                    num_hex = res.get("number")
                    if isinstance(num_hex, str) and num_hex.startswith("0x"):
                        ms = round((time.perf_counter() - t0) * 1000, 1)
                        return {
                            "slug": chain["slug"],
                            "name": chain["name"],
                            "symbol": chain.get("symbol", ""),
                            "ecosystem": "Substrate / Polkadot",
                            "best_rpc": url,
                            "latency_ms": ms,
                            "block_height": int(num_hex, 16),
                        }
            except Exception:
                continue
        return None


async def check_non_evm_majors(session: aiohttp.ClientSession) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    # Solana
    try:
        t0 = time.perf_counter()
        async with session.post(
            "https://api.mainnet-beta.solana.com",
            json={"jsonrpc": "2.0", "id": 1, "method": "getSlot"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            d = await r.json(content_type=None)
            if isinstance(d.get("result"), int):
                results.append({
                    "name": "Solana",
                    "symbol": "SOL",
                    "ecosystem": "Solana",
                    "protocol": "json-rpc",
                    "best_rpc": "https://api.mainnet-beta.solana.com",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "block_height": d["result"],
                })
    except Exception:
        pass

    # Sui (GraphQL)
    try:
        t0 = time.perf_counter()
        async with session.post(
            "https://graphql.mainnet.sui.io/graphql",
            json={"query": "{ checkpoint { sequenceNumber } }"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            d = await r.json(content_type=None)
            seq = d.get("data", {}).get("checkpoint", {}).get("sequenceNumber")
            if seq is not None:
                results.append({
                    "name": "Sui",
                    "symbol": "SUI",
                    "ecosystem": "Sui/Move",
                    "protocol": "graphql",
                    "best_rpc": "https://graphql.mainnet.sui.io/graphql",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "block_height": int(seq),
                })
    except Exception:
        pass

    # Aptos
    try:
        t0 = time.perf_counter()
        async with session.get(
            "https://fullnode.mainnet.aptoslabs.com/v1",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            d = await r.json(content_type=None)
            if d.get("block_height"):
                results.append({
                    "name": "Aptos",
                    "symbol": "APT",
                    "ecosystem": "Aptos/Move",
                    "protocol": "rest",
                    "best_rpc": "https://fullnode.mainnet.aptoslabs.com/v1",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "block_height": int(d["block_height"]),
                })
    except Exception:
        pass

    # Near
    try:
        t0 = time.perf_counter()
        async with session.post(
            "https://rpc.mainnet.near.org",
            json={"jsonrpc": "2.0", "id": 1, "method": "status", "params": []},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            d = await r.json(content_type=None)
            h = d.get("result", {}).get("sync_info", {}).get("latest_block_height")
            if h:
                results.append({
                    "name": "Near",
                    "symbol": "NEAR",
                    "ecosystem": "Near",
                    "protocol": "json-rpc",
                    "best_rpc": "https://rpc.mainnet.near.org",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "block_height": int(h),
                })
    except Exception:
        pass

    # TON
    try:
        t0 = time.perf_counter()
        async with session.get(
            "https://toncenter.com/api/v2/getMasterchainInfo",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            d = await r.json(content_type=None)
            seq = d.get("result", {}).get("last", {}).get("seqno")
            if seq:
                results.append({
                    "name": "TON",
                    "symbol": "TON",
                    "ecosystem": "TON",
                    "protocol": "rest",
                    "best_rpc": "https://toncenter.com/api/v2",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "block_height": int(seq),
                })
    except Exception:
        pass

    return results


async def run_all() -> dict[str, Any]:
    evm_raw = json.loads((SOURCES_DIR / "evm_chains_github.json").read_text(encoding="utf-8"))
    superchain_raw = json.loads((SOURCES_DIR / "superchain_registry_github.json").read_text(encoding="utf-8"))
    subwallet_raw = json.loads((SOURCES_DIR / "subwallet_chains_github.json").read_text(encoding="utf-8"))
    cosmos_raw = json.loads((SOURCES_DIR / "cosmos_chains_github.json").read_text(encoding="utf-8"))
    extra_rpcs = fetch_chainlist_extra_rpcs()

    evm_map: dict[int, dict[str, Any]] = {}
    for x in evm_raw:
        cid = x.get("chainId")
        name = x.get("name") or f"Chain {cid}"
        if cid is None or is_testnet(name, x.get("status", ""), x.get("title", "")):
            continue
        rpcs = clean_http_rpcs(x.get("rpc") or [])
        native = x.get("nativeCurrency") or {}
        evm_map[cid] = {"chain_id": cid, "name": name, "symbol": native.get("symbol", ""), "rpcs": rpcs}

    for cid, extra_urls in extra_rpcs.items():
        if cid in evm_map:
            for u in extra_urls:
                if u not in evm_map[cid]["rpcs"]:
                    evm_map[cid]["rpcs"].append(u)

    for x in superchain_raw:
        cid = x.get("chainId")
        name = x.get("name") or ""
        if cid is None or "sepolia" in str(x.get("identifier", "")).lower() or is_testnet(name):
            continue
        rpcs = clean_http_rpcs(x.get("rpc") or [])
        if cid in evm_map:
            for r in rpcs:
                if r not in evm_map[cid]["rpcs"]:
                    evm_map[cid]["rpcs"].append(r)
        else:
            evm_map[cid] = {"chain_id": cid, "name": name, "symbol": "ETH", "rpcs": rpcs}

    substrate_candidates: list[dict[str, Any]] = []
    if isinstance(subwallet_raw, dict):
        for slug, item in subwallet_raw.items():
            if not isinstance(item, dict) or item.get("isTestnet"):
                continue
            name = item.get("name") or slug
            if is_testnet(name):
                continue
            providers = item.get("providers") or {}
            urls = list(providers.values()) if isinstance(providers, dict) else []
            evm_info = item.get("evmInfo") or {}
            sub_info = item.get("substrateInfo") or {}
            cid = evm_info.get("evmChainId") if isinstance(evm_info, dict) else None
            if cid is not None:
                http_urls = clean_http_rpcs(urls)
                if cid in evm_map:
                    for r in http_urls:
                        if r not in evm_map[cid]["rpcs"]:
                            evm_map[cid]["rpcs"].append(r)
                elif http_urls:
                    evm_map[cid] = {"chain_id": cid, "name": name, "symbol": evm_info.get("symbol", ""), "rpcs": http_urls}
            if sub_info:
                wss_urls = [u for u in urls if isinstance(u, str) and u.startswith("wss://")]
                if wss_urls:
                    substrate_candidates.append({
                        "slug": slug,
                        "name": name,
                        "symbol": sub_info.get("symbol", "") if isinstance(sub_info, dict) else "",
                        "wss_urls": wss_urls,
                    })

    evm_candidates = [v for v in evm_map.values() if v["rpcs"]]

    # Sequential phases with controlled concurrency to avoid socket saturation
    connector = aiohttp.TCPConnector(limit=80, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        majors_res = await check_non_evm_majors(session)
        evm_sem = asyncio.Semaphore(20)
        evm_res = await asyncio.gather(*(check_evm_chain(evm_sem, session, c) for c in evm_candidates))
        cosmos_sem = asyncio.Semaphore(25)
        cosmos_res = await asyncio.gather(*(check_cosmos_chain(cosmos_sem, session, c) for c in cosmos_raw))

    sub_sem = asyncio.Semaphore(10)
    sub_res = await asyncio.gather(*(check_substrate_chain(sub_sem, c) for c in substrate_candidates))

    live_evm = sorted([x for x in evm_res if x], key=lambda x: x["latency_ms"])
    live_cosmos = sorted([x for x in cosmos_res if x], key=lambda x: x["latency_ms"])
    live_sub = sorted([x for x in sub_res if x], key=lambda x: x["latency_ms"])

    pool = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": {
            "evm_candidates_tested": len(evm_candidates),
            "evm_live": len(live_evm),
            "cosmos_candidates_tested": len(cosmos_raw),
            "cosmos_live": len(live_cosmos),
            "substrate_candidates_tested": len(substrate_candidates),
            "substrate_live": len(live_sub),
            "non_evm_majors_live": len(majors_res),
            "total_live_chains": len(live_evm) + len(live_cosmos) + len(live_sub) + len(majors_res),
        },
        "evm": live_evm,
        "cosmos": live_cosmos,
        "substrate": live_sub,
        "non_evm_majors": majors_res,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "live_rpc_pool.json").write_text(
        json.dumps(pool, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {
        "counts": pool["counts"],
        "non_evm_majors": majors_res,
        "sample_substrate": [{"name": x["name"], "ms": x["latency_ms"], "blk": x["block_height"]} for x in live_sub[:10]],
        "fastest_10_evm": [{"name": x["name"], "id": x["chain_id"], "ms": x["latency_ms"], "blk": x["block_height"]} for x in live_evm[:10]],
    }


if __name__ == "__main__":
    summary = asyncio.run(run_all())
    print(json.dumps(summary, indent=2, ensure_ascii=False))
