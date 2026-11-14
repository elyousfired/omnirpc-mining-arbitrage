"""
Web3 Mint / On-Chain PoW Site & Sandbox Wallet Simulator.

Performs three real verification layers without risking real funds:
  1. Site + JS-Bundle Entry Check (`verify_web3_mint_ui`):
     Loads live HTML and up to 6 JS bundles to confirm HTTP 200, real Web3 wallet
     connectors (wagmi/rainbowkit/web3modal/metamask/phantom/tonconnect/privy/etc.)
     and active Mint/Mine UI actions, while rejecting DOWN sites & L1 HiveOS/CLI coins.
  2. Deep On-Chain PoW & Mint Forensics (`inspect_evm_contract_onchain`):
     Scans EVM bytecode (`PUSH4` selectors), Sourcify/4byte functions, and live `eth_call`
     state (`paused()`, `challengeNumber()`, `difficulty()`, `miningTarget()`, `epochCount()`,
     mint fees) to verify genuine on-chain Proof-of-Work or Connect-Wallet Mint mechanics.
  3. Persistent Sandbox Test Wallet Trial (`simulate_sandbox_wallet_mint`):
     Uses a deterministic read-only Sandbox Wallet (`0x5e71a9E84B2F90C11d43a68C9B77F1A02cD4109E`)
     to dry-run `eth_estimateGas` / `eth_call` against mint/mine functions and return exact
     gas estimates, mint fees, and clear Darija trial verdicts.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

DEFAULT_SANDBOX_EVM_WALLET = "0x5e71a9E84B2F90C11d43a68C9B77F1A02cD4109E"
DEFAULT_SANDBOX_SOL_WALLET = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"

# --- Pure-Python Keccak-256 (original Ethereum Keccak padding 0x01, zero external deps) ---
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_M64 = 0xFFFFFFFFFFFFFFFF


def _rol64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _M64 if n else (x & _M64)


def keccak256(data: bytes) -> bytes:
    """Compute Ethereum Keccak-256 digest (rate=136 bytes, padding 0x01)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        for rc in _RC:
            c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = _rol64(state[x][y], _ROT[x][y])
            for x in range(5):
                for y in range(5):
                    state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
            state[0][0] ^= rc

    out = bytearray()
    for i in range(4):
        out.extend(state[i % 5][i // 5].to_bytes(8, "little"))
    return bytes(out)


def keccak_selector(sig: str) -> str:
    """Return 0x-prefixed 4-byte EVM function selector for a canonical signature."""
    return "0x" + keccak256(sig.encode("utf-8"))[:4].hex()


# Precomputed verified selector dictionaries
POW_VIEW_SIGNATURES = [
    "challengeNumber()",
    "getChallengeNumber()",
    "difficulty()",
    "getMiningDifficulty()",
    "miningTarget()",
    "getMiningTarget()",
    "epochCount()",
    "tokensMinted()",
    "rewardEra()",
    "lastRewardEthBlockNumber()",
    "getMintReward()",
]

MINT_FEE_VIEW_SIGNATURES = [
    "mintPrice()",
    "cost()",
    "fee()",
    "mintFee()",
    "getMintFee()",
    "getCurrentBatchCost()",
    "price()",
    "protocolFee()",
    "getProtocolFee()",
]

PAUSE_VIEW_SIGNATURES = ["paused()", "isPaused()", "mintPaused()"]

# Candidate write functions ordered from most specific (Web3 PoW / Fair-Mint) to generic
WRITE_TRIAL_SIGNATURES: list[tuple[str, str]] = [
    ("mine(uint256,bytes32)", "pow_mine"),
    ("mine(uint256)", "pow_mine"),
    ("mint(uint256,bytes32)", "pow_mint"),
    ("proofOfWork(uint256)", "pow_mine"),
    ("claimRank(uint256)", "xen_claim_rank"),
    ("startMint(uint256,uint256)", "titanx_start_mint"),
    ("batchMint(uint256,uint256)", "batch_mint"),
    ("claimMintReward()", "claim_mint"),
    ("claimMint(uint256)", "claim_mint"),
    ("enterAuction(uint256)", "auction_mint"),
    ("glaze(address,address,uint256,uint256,uint256,string)", "glaze_mine"),
    ("transform(uint256)", "transform_mint"),
    ("burnAndMint(uint256)", "burn_mint"),
    ("mint(uint256)", "mint_qty"),
    ("mint()", "mint_zero"),
    ("claim()", "claim_zero"),
]

POW_SELECTOR_MAP = {keccak_selector(s): s for s in POW_VIEW_SIGNATURES}
FEE_SELECTOR_MAP = {keccak_selector(s): s for s in MINT_FEE_VIEW_SIGNATURES}
PAUSE_SELECTOR_MAP = {keccak_selector(s): s for s in PAUSE_VIEW_SIGNATURES}
WRITE_SELECTOR_MAP = {keccak_selector(s): (s, kind) for s, kind in WRITE_TRIAL_SIGNATURES}

# Signals searched across HTML + fetched JS bundles
WALLET_CONNECT_SIGNALS = (
    "connect wallet",
    "connectwallet",
    "connect your wallet",
    "rainbowkit",
    "wagmi",
    "web3modal",
    "reown",
    "appkit",
    "metamask",
    "walletconnect",
    "privy",
    "tonconnect",
    "phantom",
    "solflare",
    "@solana/wallet-adapter",
    "wallet-adapter",
    "useaccount",
    "eth_requestaccounts",
    "connect_wallet",
    "coinbase wallet",
    "farcaster",
    "miniapp",
    "usewritecontract",
    "usesendtransaction",
    "sendtransaction",
    "ethers",
    "viem",
    "web3-react",
)

MINT_MINE_UI_SIGNALS = (
    "claimrank",
    "claim rank",
    "startmint",
    "start mint",
    "claimmint",
    "claim mint",
    "batchmint",
    "burnandmint",
    "burn & mint",
    "glaze",
    "drillx",
    "start mining",
    "mine now",
    "enter auction",
    "mint now",
    "mint token",
    "start miner",
    "claim reward",
    "hashrate",
    "challengenumber",
    "difficulty",
    "proof of work",
    "proof-of-work",
    "minter",
    "attachminter",
    "mintx28",
    "mintreward",
    "checkpoint",
)

CLI_L1_ONLY_SIGNALS = (
    "stratum+tcp",
    "hiveos",
    "lolminer",
    "rigel",
    "bzminer",
    "gminer",
    "srbminer",
    "xmrig",
    "teamredminer",
    "t-rex miner",
    "onezerominer",
    "download miner",
    "mining pool",
)

BAD_HTTP_HOSTS = (
    "github.com",
    "twitter.com",
    "x.com",
    "t.me",
    "discord.gg",
    "discord.com",
    "medium.com",
    "coingecko.com",
    "coinmarketcap.com",
    "dexscreener.com",
    "etherscan.io",
    "bscscan.com",
    "basescan.org",
    "arbiscan.io",
    "polygonscan.com",
    "solscan.io",
    "blockscout.com",
    "flap.sh",
    "four.meme",
    "pump.fun",
    "moonshot.cc",
    "sunpump.meme",
    "pinksale.finance",
    "gempad.app",
    "raydium.io",
    "uniswap.org",
    "pancakeswap.finance",
    "jup.ag",
    "dexview.com",
)

HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/javascript,*/*;q=0.8",
}


def extract_push4_selectors(bytecode_hex: str) -> set[str]:
    """Scan EVM runtime bytecode for PUSH4 (0x63) 4-byte function selectors."""
    code = (bytecode_hex or "").lower().removeprefix("0x")
    if len(code) < 10:
        return set()
    try:
        raw = bytes.fromhex(code)
    except ValueError:
        return set()
    sels: set[str] = set()
    i = 0
    n = len(raw)
    while i < n:
        op = raw[i]
        if op == 0x63 and i + 5 <= n:
            sels.add("0x" + raw[i + 1 : i + 5].hex())
            i += 5
        elif 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
        else:
            i += 1
    return sels


def _encode_arg(ptype: str, wallet: str) -> str:
    p = ptype.strip().lower()
    if p == "address":
        return wallet.lower().removeprefix("0x").rjust(64, "0")
    if p.startswith("uint") or p.startswith("int"):
        return hex(1)[2:].rjust(64, "0")
    if p == "bool":
        return "0" * 64
    if p.startswith("bytes") and p != "bytes":
        return "0" * 63 + "1"
    return "0" * 64


def encode_trial_calldata(signature: str, wallet: str) -> str | None:
    """Build 0x-prefixed ABI calldata for fixed-size common mint/mine functions."""
    m = re.match(r"^\s*([a-zA-Z0-9_]+)\(([^)]*)\)\s*$", signature or "")
    if not m:
        return None
    params_raw = m.group(2).strip()
    sel = keccak_selector(f"{m.group(1)}({','.join(x.strip() for x in params_raw.split(',')) if params_raw else ''})")
    if not params_raw:
        return sel
    params = [x.strip() for x in params_raw.split(",") if x.strip()]
    # Support fixed-size types directly; dynamic string/bytes only as trailing arg
    body = ""
    dyn_tail = ""
    head_words = len(params)
    for idx, p in enumerate(params):
        pl = p.lower()
        if pl in ("string", "bytes") or "[]" in pl:
            if "[]" in pl:
                return None
            # Offset in bytes = head_words * 32 + len(dyn_tail)//2
            offset = head_words * 32 + (len(dyn_tail) // 2)
            body += hex(offset)[2:].rjust(64, "0")
            # empty string/bytes => length 0
            dyn_tail += "0" * 64
        elif "(" in pl or ")" in pl:
            return None
        else:
            body += _encode_arg(pl, wallet)
    return sel + body + dyn_tail


def _is_good_dapp_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host or "." not in host:
        return False
    return not any(host == b or host.endswith("." + b) for b in BAD_HTTP_HOSTS)


async def _fetch_text_limited(session: aiohttp.ClientSession, url: str, max_bytes: int = 320_000, timeout: int = 7) -> tuple[int, str, str]:
    try:
        async with session.get(url, headers=HTTP_HEADERS, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as r:
            raw = await r.content.read(max_bytes)
            txt = raw.decode("utf-8", errors="ignore")
            return r.status, txt, str(r.url)
    except Exception as exc:
        return 0, str(exc)[:120], url


async def verify_web3_mint_ui(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    """
    Enter the live website + fetch its JS SPA bundles to verify real Web3 Connect Wallet + Mint/Mine UI.
    Also follows an obvious `app.` / `minter` subdomain CTA if landing HTML links to it.
    """
    out: dict[str, Any] = {
        "url": url,
        "final_url": url,
        "site_live": False,
        "http_status": 0,
        "js_bundles_checked": 0,
        "has_connect_wallet": False,
        "wallet_signals": [],
        "has_mint_ui": False,
        "mint_signals": [],
        "is_l1_cli_miner": False,
        "is_web3_mint_dapp": False,
        "ui_summary": "",
        "error": "",
    }
    if not url or not _is_good_dapp_url(url):
        out["error"] = "invalid_or_social_url"
        out["ui_summary"] = "رابط غير صالح لواجهة dApp"
        return out

    status, html, final_url = await _fetch_text_limited(session, url, max_bytes=280_000, timeout=8)
    out["http_status"] = status
    out["final_url"] = final_url
    if status < 200 or status >= 400 or len(html) < 120:
        out["error"] = f"http_{status}" if status else html
        out["ui_summary"] = f"الموقع طايح أو ما كيحلش ({out['error'][:45]})"
        return out

    out["site_live"] = True
    combined_lower = html.lower()

    # Check if landing page points to an app.* / minter URL
    app_links = re.findall(r'href=["\'](https?://(?:app|mint|mine|dapp)\.[^"\']+|[^"\']*minter[^"\']*)["\']', html, re.I)
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)

    js_urls: list[str] = []
    seen_js: set[str] = set()
    base_host = (urlparse(final_url).hostname or "").lower()
    for src in script_srcs:
        if any(skip in src.lower() for skip in ("gtag", "analytics", "cloudflareinsights", "twitter", "intercom")):
            continue
        full_js = urljoin(final_url, src)
        h = (urlparse(full_js).hostname or "").lower()
        if h and (h == base_host or h.endswith("." + base_host) or "assets" in full_js or "static" in full_js or "chunk" in full_js or "_next" in full_js):
            if full_js not in seen_js:
                seen_js.add(full_js)
                js_urls.append(full_js)
                if len(js_urls) >= 14:
                    break

    # If landing page had 0 wallet signals so far and linked an app subdomain, also fetch that app page
    extra_app_url = ""
    if app_links:
        cand = urljoin(final_url, app_links[0])
        if _is_good_dapp_url(cand) and cand != final_url:
            extra_app_url = cand

    fetch_tasks = [_fetch_text_limited(session, j, max_bytes=950_000, timeout=8) for j in js_urls]
    if extra_app_url:
        fetch_tasks.append(_fetch_text_limited(session, extra_app_url, max_bytes=220_000, timeout=7))

    if fetch_tasks:
        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        checked = 0
        for idx, res in enumerate(results):
            if isinstance(res, tuple) and 200 <= res[0] < 400 and res[1]:
                combined_lower += "\n" + res[1].lower()
                if idx < len(js_urls):
                    checked += 1
        out["js_bundles_checked"] = checked

    w_hits = [sig for sig in WALLET_CONNECT_SIGNALS if sig in combined_lower]
    m_hits = [sig for sig in MINT_MINE_UI_SIGNALS if sig in combined_lower]
    cli_hits = [sig for sig in CLI_L1_ONLY_SIGNALS if sig in combined_lower]

    out["wallet_signals"] = w_hits[:6]
    out["mint_signals"] = m_hits[:8]
    out["has_connect_wallet"] = len(w_hits) >= 1
    out["has_mint_ui"] = len(m_hits) >= 1
    out["is_l1_cli_miner"] = len(cli_hits) >= 2 and not out["has_connect_wallet"]

    # Strict Web3 Connect-Wallet + Mint/Mine dApp requirement (eliminates CSS/CSP & non-mint meme sites)
    out["is_web3_mint_dapp"] = bool(
        out["site_live"]
        and not out["is_l1_cli_miner"]
        and out["has_connect_wallet"]
        and out["has_mint_ui"]
    )

    if out["is_l1_cli_miner"]:
        out["ui_summary"] = f"صفحة تعدين L1/CLI تقليدي ({', '.join(cli_hits[:3])}) — ماشي Connect Wallet Mint"
    elif out["is_web3_mint_dapp"]:
        out["ui_summary"] = f"واجهة Web3 شغالة ({len(js_urls)} JS bundles) — Wallet: {', '.join(w_hits[:3]) or 'web3'} | Mint: {', '.join(m_hits[:3]) or 'mint'}"
    elif out["site_live"]:
        out["ui_summary"] = f"موقع مفتوح بلا واجهة Connect Wallet + Mint واضحة (JS={len(js_urls)})"

    return out


async def inspect_evm_contract_onchain(
    session: aiohttp.ClientSession,
    omni: Any,
    chain_id: int | str,
    address: str,
    decoded_functions: list[str] | None = None,
    bytecode_hex: str | None = None,
) -> dict[str, Any]:
    """
    Go directly ON-CHAIN via OmniRPC to verify bytecode selectors, PoW state getters,
    paused() state, and mint fees directly from the deployed smart contract.
    """
    info: dict[str, Any] = {
        "contract_exists": False,
        "code_bytes": 0,
        "paused": False,
        "pow_functions_found": [],
        "mint_functions_found": [],
        "onchain_pow_state": {},
        "mint_fee_wei": 0,
        "mint_fee_native": 0.0,
        "fee_method": "",
        "is_onchain_pow_or_mint": False,
    }
    if not address or not address.startswith("0x") or len(address) != 42:
        return info

    code = bytecode_hex
    if not isinstance(code, str) or len(code) <= 4:
        try:
            code = await omni.evm_call(session, chain_id, "eth_getCode", [address, "latest"], timeout=6)
        except Exception:
            code = ""
    if not isinstance(code, str) or len(code) <= 4:
        code, _err = await _raw_evm_rpc(session, omni, chain_id, "eth_getCode", [address, "latest"], timeout=6)
    if not isinstance(code, str) or len(code) <= 4:
        return info

    info["contract_exists"] = True
    info["code_bytes"] = (len(code) - 2) // 2
    selectors = extract_push4_selectors(code)

    dec_list = [str(f).strip() for f in (decoded_functions or []) if f]
    pow_found: list[str] = [sig for sel, sig in POW_SELECTOR_MAP.items() if sel in selectors]
    mint_found: list[str] = []

    for sel, (sig, _kind) in WRITE_SELECTOR_MAP.items():
        if sel in selectors:
            mint_found.append(sig)
    for fn in dec_list:
        fl = fn.lower()
        if any(k in fl for k in ("challenge", "difficulty", "miningtarget", "epochcount", "mine(")):
            if fn not in pow_found:
                pow_found.append(fn)
        if any(k in fl for k in ("claimrank", "startmint", "claimmint", "batchmint", "glaze", "transform", "burnandmint", "enterauction", "mintx28", "mintreward", "mint(", "mine(")):
            if fn not in mint_found:
                mint_found.append(fn)

    info["pow_functions_found"] = pow_found[:10]
    info["mint_functions_found"] = mint_found[:12]

    # Check paused() if present OR single quick check
    pause_calls = [(sel, sig) for sel, sig in PAUSE_SELECTOR_MAP.items() if sel in selectors]
    if not pause_calls:
        pause_calls = [(keccak_selector("paused()"), "paused()")]
    for sel, _sig in pause_calls[:1]:
        res, _ = await _raw_evm_rpc(session, omni, chain_id, "eth_call", [{"to": address, "data": sel}, "latest"], timeout=4)
        if isinstance(res, str) and len(res) >= 66 and int(res[-64:], 16) == 1:
            info["paused"] = True
            break

    # Probe PoW on-chain state getters present in bytecode concurrently
    pow_probes = [(sel, sig) for sel, sig in POW_SELECTOR_MAP.items() if sel in selectors]
    if pow_probes:
        pow_res = await asyncio.gather(
            *[_raw_evm_rpc(session, omni, chain_id, "eth_call", [{"to": address, "data": sel}, "latest"], timeout=4) for sel, _ in pow_probes[:6]],
            return_exceptions=True,
        )
        for (_sel, sig), rp in zip(pow_probes[:6], pow_res):
            if isinstance(rp, tuple) and isinstance(rp[0], str) and rp[0].startswith("0x") and len(rp[0]) >= 66:
                val = int(rp[0][2:66], 16)
                if val > 0:
                    key = sig.replace("()", "")
                    info["onchain_pow_state"][key] = hex(val) if "challenge" in key.lower() or "target" in key.lower() else val

    # Probe mint fee getters present in bytecode
    fee_probes = [(sel, sig) for sel, sig in FEE_SELECTOR_MAP.items() if sel in selectors]
    for sel, sig in fee_probes[:3]:
        res, _ = await _raw_evm_rpc(session, omni, chain_id, "eth_call", [{"to": address, "data": sel}, "latest"], timeout=4)
        if isinstance(res, str) and res.startswith("0x") and len(res) >= 66:
            val = int(res[2:66], 16)
            if 0 < val < 10**22:
                info["mint_fee_wei"] = val
                info["mint_fee_native"] = val / 1e18
                info["fee_method"] = sig
                break

    info["is_onchain_pow_or_mint"] = bool(
        info["onchain_pow_state"]
        or info["pow_functions_found"]
        or info["mint_functions_found"]
    )
    return info


async def _raw_evm_rpc(
    session: aiohttp.ClientSession,
    omni: Any,
    chain_id: int | str,
    method: str,
    params: list[Any],
    timeout: int = 5,
) -> tuple[Any, str]:
    """Call EVM JSON-RPC with fast failover and preserve revert error (`error.message`) for simulation analysis."""
    try:
        info = omni.resolve_evm(chain_id)
        urls = omni._evm_candidates(info)[:12]
    except Exception:
        return None, "chain_not_in_pool"

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_err = ""
    for url in urls:
        try:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status != 200:
                    continue
                data = await r.json(content_type=None)
                if "result" in data and data["result"] is not None:
                    # Prefer non-empty bytecode if eth_getCode returned 0x from a lagging node
                    if method == "eth_getCode" and data["result"] == "0x" and url != urls[-1]:
                        last_err = "empty_code"
                        continue
                    return data["result"], ""
                if isinstance(data.get("error"), dict):
                    msg = str(data["error"].get("message") or data["error"])
                    d_err = data["error"].get("data")
                    full_err = f"{msg} {d_err or ''}".strip()[:160]
                    err_low = full_err.lower()
                    if any(
                        p in err_low
                        for p in (
                            "usage limit",
                            "rate limit",
                            "quota",
                            "too many",
                            "exceeded",
                            "api key",
                            "unauthorized",
                            "internal error",
                            "missing trie",
                            "header not found",
                            "method not found",
                            "not supported",
                            "block not found",
                            "specify an address",
                            "smaller block range",
                            "query returned more than",
                        )
                    ) and url != urls[-1]:
                        last_err = full_err
                        continue
                    return None, full_err
        except Exception as exc:
            last_err = str(exc)[:80]
    if last_err == "empty_code":
        return "0x", ""
    return None, last_err or "rpc_failed"


async def simulate_sandbox_wallet_mint(
    session: aiohttp.ClientSession,
    omni: Any,
    item: dict[str, Any],
    sandbox_wallet: str = DEFAULT_SANDBOX_EVM_WALLET,
    native_usd_map: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Full Agent Entry & Sandbox Wallet Trial for ONE protocol:
      1. Visit live website + JS bundles -> verify `Connect Wallet` + `Mint/Mine` UI.
      2. Inspect contract ON-CHAIN -> check bytecode PoW/Mint selectors, paused(), mint fee.
      3. Run dry-run transaction (`eth_estimateGas` / `eth_call`) from `sandbox_wallet`.
    """
    site = ""
    for w in (item.get("websites") or []):
        if w and _is_good_dapp_url(w):
            site = w
            break
    if not site and _is_good_dapp_url(item.get("official_site") or ""):
        site = item["official_site"]

    ui = await verify_web3_mint_ui(session, site) if site else {
        "url": "", "final_url": "", "site_live": False, "http_status": 0,
        "js_bundles_checked": 0, "has_connect_wallet": False, "wallet_signals": [],
        "has_mint_ui": False, "mint_signals": [], "is_l1_cli_miner": False,
        "is_web3_mint_dapp": False, "ui_summary": "ما عندوش موقع dApp رسمي", "error": "no_site",
    }

    chain_type = str(item.get("chain_type") or "EVM").upper()
    cid = item.get("evm_chain_id")
    addr = (item.get("contract") or "").strip()
    decoded_fns = item.get("decoded_functions") or []

    trial: dict[str, Any] = {
        "tested": True,
        "sandbox_wallet": sandbox_wallet if chain_type == "EVM" else DEFAULT_SANDBOX_SOL_WALLET,
        "site_url": site,
        "site_live": bool(ui.get("site_live")),
        "http_status": ui.get("http_status", 0),
        "js_bundles_checked": ui.get("js_bundles_checked", 0),
        "has_connect_wallet": bool(ui.get("has_connect_wallet")),
        "wallet_signals": ui.get("wallet_signals") or [],
        "has_mint_ui": bool(ui.get("has_mint_ui")),
        "mint_signals": ui.get("mint_signals") or [],
        "is_l1_cli_miner": bool(ui.get("is_l1_cli_miner")),
        "ui_summary": ui.get("ui_summary") or "",
        "onchain_verified": False,
        "onchain_pow_state": {},
        "pow_functions": [],
        "mint_functions": [],
        "paused": False,
        "tested_fn": "",
        "est_gas_units": 0,
        "mint_fee_native": 0.0,
        "mint_fee_usd": 0.0,
        "trial_status": "UNVERIFIED",
        "trial_error": "",
        "trial_verdict_ar": "",
        "is_actionable_web3_mint": False,
    }

    # --- EVM Full On-Chain PoW Inspection + Sandbox Wallet eth_estimateGas / eth_call ---
    if chain_type == "EVM" and cid is not None and addr.startswith("0x") and len(addr) == 42:
        oc = await inspect_evm_contract_onchain(session, omni, cid, addr, decoded_functions=decoded_fns)
        trial["onchain_verified"] = bool(oc.get("contract_exists"))
        trial["onchain_pow_state"] = oc.get("onchain_pow_state") or {}
        trial["pow_functions"] = oc.get("pow_functions_found") or []
        trial["mint_functions"] = oc.get("mint_functions_found") or []
        trial["paused"] = bool(oc.get("paused"))
        trial["mint_fee_native"] = round(float(oc.get("mint_fee_native") or 0.0), 6)

        nat_price = 0.0
        if native_usd_map:
            nat_price = float(native_usd_map.get(str(cid)) or 0.0)
        if trial["mint_fee_native"] > 0 and nat_price > 0:
            trial["mint_fee_usd"] = round(trial["mint_fee_native"] * nat_price, 4)

        if not oc.get("contract_exists"):
            trial["trial_status"] = "NO_CONTRACT"
            trial["trial_verdict_ar"] = "العقد ما كاينش على الشبكة"
            return trial

        if oc.get("paused"):
            trial["trial_status"] = "PAUSED_OR_CLOSED"
            trial["trial_verdict_ar"] = "العقد متوقف (paused=true) حالياً"
            return trial

        # Build prioritized trial functions: discovered on-chain mint/mine first, then decoded functions
        candidates_sigs: list[str] = []
        for sig in (oc.get("mint_functions_found") or []) + (oc.get("pow_functions_found") or []) + list(decoded_fns):
            if "(" in sig and not any(bad in sig.lower() for bad in ("transfer", "approve", "renounce", "owner", "withdraw", "pause", "set")):
                if sig not in candidates_sigs:
                    candidates_sigs.append(sig)

        best_revert = ""
        for sig in candidates_sigs[:8]:
            calldata = encode_trial_calldata(sig, sandbox_wallet)
            if not calldata:
                continue
            tx_obj: dict[str, Any] = {"from": sandbox_wallet, "to": addr, "data": calldata}
            if oc.get("mint_fee_wei", 0) > 0:
                tx_obj["value"] = hex(int(oc["mint_fee_wei"]))

            gas_hex, g_err = await _raw_evm_rpc(session, omni, cid, "eth_estimateGas", [tx_obj], timeout=6)
            if isinstance(gas_hex, str) and gas_hex.startswith("0x"):
                trial["tested_fn"] = sig
                trial["est_gas_units"] = int(gas_hex, 16)
                trial["trial_status"] = "SIMULATED_OPEN"
                break

            err_low = (g_err or "").lower()
            if any(k in err_low for k in ("paused", "ended", "finished", "closed", "onlyowner", "not owner", "disabled")):
                best_revert = g_err
                trial["tested_fn"] = sig
                trial["trial_status"] = "PAUSED_OR_CLOSED"
                trial["trial_error"] = g_err
                break
            if any(k in err_low for k in ("insufficient funds", "allowance", "balance", "invalid nonce", "digest", "target", "difficulty", "invalid proof", "msg.value", "fee", "term", ": stf")):
                # Contract IS active and validates user balance/PoW solution! Estimate fallback gas via eth_call/default
                trial["tested_fn"] = sig
                trial["trial_status"] = "POW_OR_MINT_ACTIVE"
                trial["trial_error"] = g_err
                break
            if not best_revert:
                best_revert = g_err

        # If paused check passed & contract has PoW/Mint selectors verified on-chain even without gas success
        if trial["trial_status"] == "UNVERIFIED":
            if oc.get("is_onchain_pow_or_mint"):
                trial["tested_fn"] = (oc.get("mint_functions_found") or oc.get("pow_functions_found") or ["onchain_mint"])[0]
                trial["trial_status"] = "ONCHAIN_VERIFIED"
                trial["trial_error"] = best_revert
            elif best_revert:
                trial["trial_error"] = best_revert

    # --- Solana / TON / Non-EVM Live Program & Web3 Mint UI Trial ---
    elif chain_type in ("SOLANA", "TON", "SUI", "APTOS"):
        if chain_type == "SOLANA" and addr and len(addr) >= 32:
            try:
                acc = await omni.solana_call(session, "getAccountInfo", [addr, {"encoding": "jsonParsed"}], timeout=8)
                val = ((acc or {}).get("result") or {}).get("value")
                if isinstance(val, dict):
                    trial["onchain_verified"] = True
                    is_exec = bool(val.get("executable"))
                    parsed_info = (((val.get("data") or {}).get("parsed") or {}).get("info") or {})
                    mint_auth = parsed_info.get("mintAuthority")
                    # Pump.fun / fixed-supply memecoins have mintAuthority=None & executable=False
                    if is_exec or mint_auth:
                        trial["pow_functions"] = ["solana_program_live" if is_exec else f"solana_active_mint({str(mint_auth)[:6]})"]
                    else:
                        trial["pow_functions"] = []
            except Exception:
                pass
        elif chain_type == "TON" and addr:
            try:
                async with session.get(f"https://tonapi.io/v2/accounts/{addr}", timeout=aiohttp.ClientTimeout(total=6)) as tr:
                    if tr.status == 200:
                        td = await tr.json(content_type=None)
                        if td.get("status") == "active":
                            trial["onchain_verified"] = True
                            trial["pow_functions"] = ["ton_contract_active"]
            except Exception:
                pass
        if ui.get("is_web3_mint_dapp") or (chain_type == "TON" and ui.get("has_connect_wallet") and trial["onchain_verified"]):
            if chain_type == "SOLANA" and trial["onchain_verified"] and not trial["pow_functions"]:
                # Pure fixed-supply memecoin on Solana (no executable program & no mintAuthority)
                trial["trial_status"] = "MEME_FIXED_SUPPLY"
            else:
                trial["tested_fn"] = "Connect Wallet + Web3 Mint UI"
                trial["trial_status"] = "WEB3_DAPP_LIVE"

    # Final actionability verdict: strictly requires live Web3 Mint/Mine site + on-chain active contract/program
    good_status = trial["trial_status"] in ("SIMULATED_OPEN", "POW_OR_MINT_ACTIVE", "ONCHAIN_VERIFIED", "WEB3_DAPP_LIVE")
    ton_ok = chain_type == "TON" and ui.get("has_connect_wallet") and trial["onchain_verified"]
    ui_ok = bool(ui.get("site_live") and not ui.get("is_l1_cli_miner") and (ui.get("is_web3_mint_dapp") or ton_ok))
    trial["is_actionable_web3_mint"] = bool(good_status and ui_ok and not trial["paused"])

    # Strict mechanics classification: separate REAL PoW from Gamified Grid/KOTH Games & Time-Locks
    has_real_evm_pow = bool(trial["pow_functions"] or trial["onchain_pow_state"])
    is_drillx_or_ton_pow = bool(
        chain_type == "SOLANA" and any("solana_program_live" in str(x) for x in (trial.get("pow_functions") or []))
    ) or bool(chain_type == "TON" and trial["onchain_verified"])
    trial["is_real_pow_onchain"] = bool((has_real_evm_pow or is_drillx_or_ton_pow) and not trial["paused"])

    if not ui.get("site_live"):
        trial["trial_verdict_ar"] = f"مرفوض — الموقع ما خدامش ({ui.get('error', 'down')})"
    elif ui.get("is_l1_cli_miner"):
        trial["trial_verdict_ar"] = "مرفوض — عملة L1/HiveOS تقليدية بدون Connect Wallet"
    elif trial["paused"]:
        trial["trial_verdict_ar"] = "مرفوض — المينت متوقف فـ العقد (Paused)"
    elif trial["is_actionable_web3_mint"]:
        if trial["trial_status"] == "SIMULATED_OPEN" and trial["est_gas_units"] > 0:
            trial["trial_verdict_ar"] = (
                f"ناجح — المحفظة {sandbox_wallet[:8]}.. جربات {trial['tested_fn']} "
                f"(Gas: {trial['est_gas_units']:,})"
            )
        elif trial["trial_status"] == "POW_OR_MINT_ACTIVE":
            trial["trial_verdict_ar"] = (
                f"نشط on-chain — العقد قبل نداء {trial['tested_fn']} وطلب رصيد/PoW من المحفظة"
            )
        else:
            trial["trial_verdict_ar"] = f"موثّق Live — Connect Wallet + Mint UI خدامة ({trial['tested_fn']})"
    else:
        trial["trial_verdict_ar"] = trial["ui_summary"] or "ما استوفاش شروط Connect Wallet -> Mint"

    return trial


STRICT_5X5_LAYOUT_SIGNALS = (
    "5x5",
    "25 squares",
    "25 blocks",
    "25 tiles",
    "winning tile",
    "winning square",
    "winning block",
    "motherlode",
    "beanpot",
    "ore.supply",
    "minebean",
    "binarium",
)

GRID_ACTION_SIGNALS = (
    "deploy",
    "claim",
    "round",
    "tile",
    "square",
    "block",
    "unrefined",
)

KOTH_AUCTION_SIGNALS = (
    "king glazer",
    "king of the hill",
    "glaze",
    "outbid",
    "dutch auction",
    "steal the crown",
    "glaze.click",
)


async def verify_gamified_grid_ui(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    """
    Enter a Gamified Mining site + JS bundles and detect true ORE-style 5x5 Grid/Square games
    ("نظام المربعات") or King-of-the-Hill (KOTH) auction games (like DONUT).
    Requires strict 5x5 / 25-tile / motherlode / beanpot evidence to reject generic CSS "grid" meme pages.
    """
    res: dict[str, Any] = {
        "url": url,
        "site_live": False,
        "http_status": 0,
        "has_connect_wallet": False,
        "game_type": "",
        "game_type_ar": "",
        "matched_game_signals": [],
        "is_gamified_mining": False,
        "error": "",
    }
    if not _is_good_dapp_url(url):
        res["error"] = "invalid_url"
        return res

    status, html, final_url = await _fetch_text_limited(session, url, max_bytes=400_000, timeout=8)
    res["http_status"] = status
    if status < 200 or status >= 400 or not html:
        res["error"] = (html if status == 0 else "") or f"http_{status}"
        return res
    res["site_live"] = True

    corpus = html.lower()
    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    # Prioritize app / Next.js / Vite chunks and skip third-party analytics
    raw_js = [
        urljoin(final_url, s)
        for s in script_urls
        if not s.startswith("data:") and not any(x in s.lower() for x in ("googletagmanager", "google-analytics", "plausible", "clarity.ms", "cloudflareinsights"))
    ]
    prioritized_js = sorted(
        raw_js,
        key=lambda u: (0 if any(k in u.lower() for k in ("_next/static/chunks", "assets/", "app", "main", "index", "page")) else 1),
    )[:8]
    if prioritized_js:
        chunks = await asyncio.gather(*[_fetch_text_limited(session, u, max_bytes=500_000, timeout=6) for u in prioritized_js], return_exceptions=True)
        for ch in chunks:
            if isinstance(ch, tuple) and len(ch) >= 2 and ch[0] == 200 and ch[1]:
                corpus += "\n" + ch[1].lower()

    res["has_connect_wallet"] = any(sig in corpus for sig in WALLET_CONNECT_SIGNALS)
    layout_hits = [s for s in STRICT_5X5_LAYOUT_SIGNALS if s in corpus]
    action_hits = [s for s in GRID_ACTION_SIGNALS if s in corpus]
    koth_hits = [s for s in KOTH_AUCTION_SIGNALS if s in corpus]

    has_web3_stack = res["has_connect_wallet"] or any(w in corpus for w in ("wagmi", "viem", "@solana/web3", "ethers", "rainbowkit", "privy", "wallet"))

    if layout_hits and len(action_hits) >= 2 and has_web3_stack:
        res["game_type"] = "GRID_5X5_BETTING"
        res["game_type_ar"] = "نظام المربعات 5x5 (Grid Betting بحال ORE)"
        res["matched_game_signals"] = (layout_hits + action_hits)[:8]
        res["is_gamified_mining"] = True
    elif (len(koth_hits) >= 2 or "king glazer" in koth_hits) and has_web3_stack:
        res["game_type"] = "KOTH_AUCTION"
        res["game_type_ar"] = "مزاد التاج (King of the Hill بحال DONUT)"
        res["matched_game_signals"] = koth_hits[:8]
        res["is_gamified_mining"] = True
    elif ("minechain" in corpus or ("crafting" in corpus and "drillx" in corpus)) and has_web3_stack:
        res["game_type"] = "IDLE_CRAFTING_MINER"
        res["game_type_ar"] = "تعدين مع كرافتينغ وGrid (بحال Minechain)"
        res["matched_game_signals"] = (layout_hits + ["crafting", "drillx"])[:8]
        res["is_gamified_mining"] = True

    return res
