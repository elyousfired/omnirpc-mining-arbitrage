"""Architecture v2 Deep Protocol Intelligence Pipeline:
1. Direct On-Chain OmniRPC (eth_call name/symbol/ERC721/1155/decimals + eth_getCode bytecode hints)
2. Sourcify v2 (verified match & metadata)
3. Blockscout v2 (646 EVM chains verified contract name & holders)
4. GoPlus Security API (honeypot, mintable, buy/sell tax, risk verdict)
5. Solana ProgramWatch + RugCheck + Helius DAS + Jupiter Price v3
6. DexScreener + GeckoTerminal (USD price, liquidity, volume, pools, website/socials)
7. Unified Provider Health Monitor (all 14 free/Helius APIs)
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import aiohttp

from omnirpc_client import OmniRPC

SEL_NAME = "0x06fdde03"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"
SEL_TOTAL_SUPPLY = "0x18160ddd"
SEL_SUPPORTS_721 = "0x01ffc9a780ac58cd00000000000000000000000000000000000000000000000000000000"
SEL_SUPPORTS_1155 = "0x01ffc9a7d9b67a2600000000000000000000000000000000000000000000000000000000"
SEL_TOKEN = "0xfc0c546a"
SEL_REWARD_TOKEN = "0xf7c618c1"
SEL_REWARDS_TOKEN = "0xd1af0c7d"
SEL_ASSET = "0x38d52e0f"
SEL_UNDERLYING = "0x6f307dc3"
SEL_BASE_URI = "0x6c0360eb"
SEL_CONTRACT_URI = "0xe8a3d485"

NOISE_URL_DOMAINS = (
    "eips.ethereum.org", "github.com/openzeppelin", "openzeppelin.com", "spdx.org",
    "soliditylang.org", "docs.soliditylang.org", "ethereum.org/en/", "consensys.net",
    "hardhat.org", "book.getfoundry.sh", "getfoundry.sh", "npmjs.com", "chain.link",
    "github.com/transmissions11", "github.com/vectorized", "solady", "solmate",
    "w3.org", "json-schema.org", "wikipedia.org",
)


def decode_abi_address(raw_hex: Any) -> str:
    """Decode a 20-byte EVM address returned by eth_call."""
    if not isinstance(raw_hex, str) or not raw_hex.startswith("0x") or len(raw_hex) < 66:
        return ""
    cand = "0x" + raw_hex[-40:].lower()
    if cand == "0x0000000000000000000000000000000000000000":
        return ""
    return cand


def filter_project_urls(urls: list[str]) -> list[str]:
    """Filter out compiler/boilerplate library URLs so only real project websites remain."""
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = (u or "").strip().rstrip(".,;)\"'`")
        if not u.startswith(("http://", "https://")):
            continue
        low = u.lower()
        if any(bad in low for bad in NOISE_URL_DOMAINS):
            continue
        if low not in seen:
            seen.add(low)
            out.append(u)
            if len(out) >= 3:
                break
    return out

BLOCKSCOUT_CACHE_PATH = Path(__file__).resolve().parent / "blockscout_explorers_cache.json"
CHAINID_EXPLORERS_CACHE_PATH = Path(__file__).resolve().parent / "chainid_explorers_cache.json"

KNOWN_EVM_EXPLORERS: dict[str, tuple[str, str, str]] = {
    # chain_id -> (display_name, base_url, address_path_fmt)
    "1": ("Etherscan", "https://etherscan.io", "/address/{addr}"),
    "56": ("BscScan", "https://bscscan.com", "/address/{addr}"),
    "137": ("Polygonscan", "https://polygonscan.com", "/address/{addr}"),
    "8453": ("Basescan", "https://basescan.org", "/address/{addr}"),
    "42161": ("Arbiscan", "https://arbiscan.io", "/address/{addr}"),
    "10": ("Optimism Explorer", "https://optimistic.etherscan.io", "/address/{addr}"),
    "42220": ("CeloScan", "https://celoscan.io", "/address/{addr}"),
    "43114": ("SnowScan", "https://snowscan.xyz", "/address/{addr}"),
    "250": ("FtmScan", "https://ftmscan.com", "/address/{addr}"),
    "100": ("GnosisScan", "https://gnosisscan.io", "/address/{addr}"),
    "314": ("Filecoin Blockscout", "https://filecoin.blockscout.com", "/address/{addr}"),
    "100009": ("VeChain Explorer", "https://explore.vechain.org", "/accounts/{addr}"),
    "39797": ("Energi Explorer", "https://explorer.energi.network", "/address/{addr}"),
    "660279": ("Xai Explorer", "https://explorer.xai-chain.net", "/address/{addr}"),
    "80094": ("BeraScan", "https://berascan.com", "/address/{addr}"),
    "146": ("SonicScan", "https://sonicscan.org", "/address/{addr}"),
    "204": ("opBNBScan", "https://opbnbscan.com", "/address/{addr}"),
    "143": ("MonadVision", "https://monadvision.com", "/address/{addr}"),
}

GAMING_CHAINS = {
    "xai", "henesys", "immutable", "skale", "miracle", "ronin", "beam", "treasure", "mythos",
}

STABLE_OR_WRAPPED_NAMES = {
    "usd coin", "usdc", "tether usd", "usdt", "wrapped ether", "weth",
    "wrapped bnb", "wbnb", "wrapped matic", "wpol", "wrapped avax", "wavax",
    "wrapped bera", "wbera", "bridged usdc", "dai stablecoin",
}


def decode_abi_string(raw_hex: Any) -> str:
    """Decode either ABI dynamic string or fixed bytes32 string from eth_call hex."""
    if not isinstance(raw_hex, str) or not raw_hex.startswith("0x") or len(raw_hex) <= 2:
        return ""
    try:
        raw = bytes.fromhex(raw_hex[2:])
    except ValueError:
        return ""
    if len(raw) >= 64:
        offset = int.from_bytes(raw[:32], "big")
        if offset == 32:
            slen = int.from_bytes(raw[32:64], "big")
            if 0 < slen <= 128 and len(raw) >= 64 + slen:
                return raw[64 : 64 + slen].decode("utf-8", errors="ignore").strip("\x00 \t\n\r")
    if len(raw) == 32:
        return raw.decode("utf-8", errors="ignore").strip("\x00 \t\n\r")
    return ""


def decode_abi_uint(raw_hex: Any) -> int | None:
    if not isinstance(raw_hex, str) or not raw_hex.startswith("0x") or len(raw_hex) < 66:
        return None
    try:
        return int(raw_hex[-64:], 16)
    except ValueError:
        return None


def decode_abi_bool(raw_hex: Any) -> bool:
    return decode_abi_uint(raw_hex) == 1


def extract_bytecode_hints(code_hex: Any) -> dict[str, Any]:
    """Extract bytecode size and readable ASCII clues directly from deployed EVM bytecode."""
    if not isinstance(code_hex, str) or not code_hex.startswith("0x") or len(code_hex) <= 4:
        return {"bytecode_bytes": 0, "hints": []}
    raw = bytes.fromhex(code_hex[2:])
    text = raw.decode("latin-1", errors="ignore")
    words = re.findall(r"[A-Za-z][A-Za-z0-9_:/.-]{3,36}", text)
    keywords = (
        "game", "crate", "loot", "box", "quest", "player", "hero", "battle", "hatch",
        "mine", "miner", "mining", "pow", "epoch", "difficulty", "nonce", "challenge",
        "stake", "stak", "reward", "yield", "vault", "pool", "farm", "xen", "claim",
        "airdrop", "nft", "erc721", "erc1155", "uniswap", "position", "https://", "ipfs://",
    )
    found: list[str] = []
    seen: set[str] = set()
    for w in words:
        wl = w.lower()
        if any(k in wl for k in keywords) and wl not in seen:
            seen.add(wl)
            found.append(w)
            if len(found) >= 8:
                break
    return {"bytecode_bytes": len(raw), "hints": found}


def classify_protocol_type(
    chain_name: str,
    address: str,
    decoded_functions: list[str],
    onchain_info: dict[str, Any],
    market_info: dict[str, Any] | None = None,
) -> tuple[str, str, bool]:
    """Determine exact protocol type using on-chain RPC + Sourcify + Blockscout + DexScreener signals."""
    fn_blob = " ".join(decoded_functions).lower()
    mkt = market_info or {}
    pname = (onchain_info.get("name") or mkt.get("blockscout_token_name") or mkt.get("verified_contract_name") or "").strip()
    psym = (onchain_info.get("symbol") or mkt.get("blockscout_symbol") or "").strip()
    pname_l = f"{pname} {mkt.get('verified_contract_name') or ''}".lower()
    hints_blob = " ".join(onchain_info.get("bytecode_hints") or []).lower()
    chain_l = chain_name.lower()
    is_nft = bool(onchain_info.get("is_erc721") or onchain_info.get("is_erc1155"))

    if (
        pname_l.strip() in STABLE_OR_WRAPPED_NAMES
        or any(st in pname_l for st in ("usd coin", "tether usd", "wrapped "))
        or ("ownertransfer" in fn_blob and "withdraw(" in fn_blob)
    ):
        return (
            "توكن عادي / مستقر (Standard Token)",
            f"{pname} ({psym})" if pname and psym else (pname or psym or "Standard ERC-20 / Wrapped"),
            True,
        )
    if (
        "uniswap v3 positions" in pname_l
        or "uniswap v4 positions" in pname_l
        or "positions nft" in pname_l
        or address.lower() == "0xc36442b4a4522e871399cd717abdd847ab11fe88"
    ):
        return (
            "سيولة DeFi LP (DEX Position NFT)",
            f"{pname} ({psym})" if pname and psym else (pname or "DEX LP Positions NFT"),
            True,
        )

    game_words = (
        "unboxcrate", "openbox", "crate", "loot", "quest", "battle", "hatch",
        "hero", "craft", "pet", "spin", "wager", "bet", "play", "gacha", "game", "arena",
    )
    if (
        any(w in fn_blob for w in game_words)
        or any(w in pname_l for w in ("gacha", "crate", "loot", "game", "quest", "arena", "battle", "rpg", "hero"))
        or any(w in hints_blob for w in ("game", "crate", "loot", "quest", "hero", "player", "gacha"))
        or (any(g in chain_l for g in GAMING_CHAINS) and ("mint(" in fn_blob or "claim" in fn_blob))
    ):
        return (
            "لعبة ويب 3 / GameFi",
            f"{pname} ({psym})" if pname and psym else (pname or f"Game Contract on {chain_name}"),
            False,
        )

    if any(w in fn_blob for w in ("provepossession", "addpieces", "sealepoch", "submitepoch", "glaze")):
        return (
            "تعدين شبكة / إثبات تخزين (PoW / Epoch)",
            pname or f"Network Epoch / Storage Miner ({chain_name})",
            False,
        )

    if (
        any(w in fn_blob for w in ("claimmintreward", "mine(", "difficulty", "nonce", "pow"))
        or ("miner" in pname_l and not is_nft)
        or ("mint()" in fn_blob and "burn(" in fn_blob)
    ):
        return (
            "تعدين توكن PoW / Fair-Mint",
            f"{pname} ({psym})" if pname and psym else (pname or f"On-Chain Token Miner ({chain_name})"),
            False,
        )

    if any(w in fn_blob for w in ("claimreward", "claiminterest", "unstake", "submit(address)", "harvest")):
        return (
            "ستيكينغ وعوائد DeFi (Yield / Staking)",
            f"{pname} ({psym})" if pname and psym else (pname or f"Staking / Yield Protocol ({chain_name})"),
            False,
        )

    if is_nft or any(w in fn_blob for w in ("safemint", "mintfree", ",string)")):
        return (
            "سكّ NFT / مقتنيات رقمية",
            f"{pname} ({psym})" if pname and psym else (pname or f"NFT Mint Contract ({chain_name})"),
            False,
        )

    if any(w in fn_blob for w in ("claimtokens", "claim()", "claim(", "resolveclaim", "stamp()")):
        return (
            "مطالبة ومكافآت (Claim / Airdrop)",
            f"{pname} ({psym})" if pname and psym else (pname or f"Claim / Airdrop Contract ({chain_name})"),
            False,
        )

    return (
        "سكّ توكن / بروتوكول Mint",
        f"{pname} ({psym})" if pname and psym else (pname or f"Mint Protocol ({chain_name})"),
        False,
    )


async def probe_evm_contract_onchain(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    omni: OmniRPC,
    chain_id: int | str,
    address: str,
) -> dict[str, Any]:
    """Query contract name, symbol, decimals, totalSupply, ERC-721/1155, and bytecode directly on-chain."""
    async with sem:
        calls = [
            ("eth_call", [{"to": address, "data": SEL_NAME}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_SYMBOL}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_DECIMALS}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_TOTAL_SUPPLY}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_SUPPORTS_721}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_SUPPORTS_1155}, "latest"]),
            ("eth_getCode", [address, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_TOKEN}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_REWARD_TOKEN}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_REWARDS_TOKEN}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_ASSET}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_UNDERLYING}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_BASE_URI}, "latest"]),
            ("eth_call", [{"to": address, "data": SEL_CONTRACT_URI}, "latest"]),
        ]
        try:
            res = await omni.evm_batch(session, chain_id, calls, timeout=10)
            name = decode_abi_string(res[0]) if len(res) > 0 else ""
            symbol = decode_abi_string(res[1]) if len(res) > 1 else ""
            decimals = decode_abi_uint(res[2]) if len(res) > 2 else None
            supply = decode_abi_uint(res[3]) if len(res) > 3 else None
            is_721 = decode_abi_bool(res[4]) if len(res) > 4 else False
            is_1155 = decode_abi_bool(res[5]) if len(res) > 5 else False
            bc = extract_bytecode_hints(res[6] if len(res) > 6 else "")
            reward_token = ""
            for idx in (7, 8, 9, 10, 11):
                if len(res) > idx:
                    cand = decode_abi_address(res[idx])
                    if cand and cand.lower() != address.lower():
                        reward_token = cand
                        break
            onchain_uri = ""
            for idx in (12, 13):
                if len(res) > idx:
                    u = decode_abi_string(res[idx])
                    if u.startswith(("http://", "https://")):
                        onchain_uri = u
                        break
            standards = []
            if is_721:
                standards.append("ERC-721")
            if is_1155:
                standards.append("ERC-1155")
            if not standards and decimals is not None and decimals <= 36:
                standards.append(f"ERC-20 ({decimals}d)")
            if not standards and bc["bytecode_bytes"] > 0:
                standards.append("Custom Contract")
            return {
                "probed": True,
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply_raw": str(supply) if supply is not None else None,
                "is_erc721": is_721,
                "is_erc1155": is_1155,
                "standard": ", ".join(standards) or "Unknown",
                "bytecode_bytes": bc["bytecode_bytes"],
                "bytecode_hints": bc["hints"],
                "onchain_reward_token": reward_token,
                "onchain_uri": onchain_uri,
            }
        except Exception as exc:
            return {"probed": False, "error": str(exc)[:80]}


async def _load_blockscout_map(session: aiohttp.ClientSession) -> dict[str, str]:
    """Load chain_id -> Blockscout explorer base URL from cache or Blockscout directory."""
    if BLOCKSCOUT_CACHE_PATH.exists():
        try:
            cached = json.loads(BLOCKSCOUT_CACHE_PATH.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and cached:
                return cached
        except Exception:
            pass
    bs_map: dict[str, str] = {}
    try:
        async with session.get("https://chains.blockscout.com/api/chains", timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                if isinstance(data, dict):
                    for cid, info in data.items():
                        for exp in info.get("explorers") or []:
                            url = (exp.get("url") or "").rstrip("/")
                            if url and exp.get("hostedBy") == "blockscout":
                                bs_map[str(cid)] = url
                                break
        if bs_map:
            BLOCKSCOUT_CACHE_PATH.write_text(json.dumps(bs_map, indent=2), encoding="utf-8")
    except Exception:
        pass
    return bs_map


async def _load_chainid_explorers(session: aiohttp.ClientSession) -> dict[str, str]:
    """Load chain_id -> official primary explorer base URL from chainid.network (2,300+ EVM chains)."""
    if CHAINID_EXPLORERS_CACHE_PATH.exists():
        try:
            cached = json.loads(CHAINID_EXPLORERS_CACHE_PATH.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and cached:
                return cached
        except Exception:
            pass
    cid_map: dict[str, str] = {}
    try:
        async with session.get("https://chainid.network/chains.json", timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                if isinstance(data, list):
                    for c in data:
                        exps = c.get("explorers") or []
                        if isinstance(exps, list) and exps:
                            url = (exps[0].get("url") or "").rstrip("/")
                            if url:
                                cid_map[str(c["chainId"])] = url
        if cid_map:
            CHAINID_EXPLORERS_CACHE_PATH.write_text(json.dumps(cid_map, indent=2), encoding="utf-8")
    except Exception:
        pass
    return cid_map


def resolve_explorer_link(
    ecosystem: str,
    chain_id: str,
    chain_name: str,
    address: str,
    chainid_map: dict[str, str],
    bs_map: dict[str, str],
) -> tuple[str, str]:
    """Resolve exact (explorer_name, protocol_explorer_url) on the protocol's native blockchain."""
    eco = (ecosystem or "EVM").lower()
    cid = str(chain_id or "")
    addr = (address or "").strip()

    if eco == "solana":
        return ("Solscan", f"https://solscan.io/account/{addr}" if addr else "https://solscan.io")
    if eco == "sui":
        pkg = addr.split("::")[0] if "::" in addr else addr
        return ("SuiScan", f"https://suiscan.xyz/mainnet/object/{pkg}" if pkg.startswith("0x") else "https://suiscan.xyz/mainnet")
    if eco == "aptos":
        acc = addr.split("::")[0] if "::" in addr else addr
        return ("Aptoscan", f"https://aptoscan.com/account/{acc}" if acc.startswith("0x") else "https://aptoscan.com")
    if eco == "near":
        return ("NearBlocks", f"https://nearblocks.io/address/{addr}" if addr else "https://nearblocks.io")
    if eco == "ton":
        return ("Tonviewer", f"https://tonviewer.com/{addr}" if addr else "https://tonviewer.com")
    if eco == "cosmos":
        slug = cid.split("-")[0] if cid else (chain_name or "cosmos").lower().replace(" ", "-")
        return ("Mintscan", f"https://www.mintscan.io/{slug}")
    if eco == "substrate":
        slug = (cid or chain_name or "polkadot").lower().replace(" ", "-")
        return ("Subscan", f"https://{slug}.subscan.io")

    # EVM chains
    if cid in KNOWN_EVM_EXPLORERS:
        name, base, fmt = KNOWN_EVM_EXPLORERS[cid]
        return (name, f"{base}{fmt.format(addr=addr)}" if addr else base)

    base = chainid_map.get(cid) or bs_map.get(cid) or ""
    if base:
        host = base.replace("https://", "").replace("http://", "").split("/")[0]
        label = host.removeprefix("www.")
        return (label, f"{base.rstrip('/')}/address/{addr}" if addr else base)

    # Last-resort universal EVM explorer lookup
    return ("Blockscan", f"https://blockscan.com/address/{addr}" if addr else "https://blockscan.com")


async def _probe_evm_open_apis(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    bs_map: dict[str, str],
    chain_id: str,
    address: str,
    onchain_prof: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Query Sourcify v2, Blockscout v2 (incl. reward token transfers & source URLs), DexScreener, GeckoTerminal, and GoPlus Security."""
    mkt: dict[str, Any] = {"probed": True}
    sec: dict[str, Any] = {"probed": True, "verdict": "غير مفحوص"}
    prof = onchain_prof or {}
    resolved_token_addr = (prof.get("onchain_reward_token") or "").lower()
    source_urls: list[str] = []
    if prof.get("onchain_uri"):
        source_urls.append(prof["onchain_uri"])

    async with sem:
        # 1. Sourcify v2 verification status
        try:
            async with session.get(
                f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}",
                timeout=aiohttp.ClientTimeout(total=6),
            ) as rs:
                if rs.status == 200:
                    ds = await rs.json(content_type=None)
                    if ds.get("match") in ("match", "exact_match", "partial"):
                        mkt["sourcify_verified"] = True
                        mkt["sourcify_match"] = ds.get("match")
        except Exception:
            pass

        # 2. Blockscout v2 verified contract, reward ERC-20 transfers, and official URLs
        bs_base = bs_map.get(str(chain_id))
        bs_token_type = ""
        if bs_base:
            try:
                async with session.get(
                    f"{bs_base}/api/v2/addresses/{address}",
                    timeout=aiohttp.ClientTimeout(total=7),
                ) as r:
                    if r.status == 200:
                        d = await r.json(content_type=None)
                        impls = d.get("implementations") or []
                        impl_name = impls[0].get("name") if impls and isinstance(impls[0], dict) else ""
                        tok = d.get("token") if isinstance(d.get("token"), dict) else {}
                        bs_token_type = str(tok.get("type") or "")
                        mkt["blockscout_url"] = f"{bs_base}/address/{address}"
                        mkt["verified_contract_name"] = impl_name or d.get("name") or ""
                        mkt["is_verified"] = bool(d.get("is_verified") or mkt.get("sourcify_verified"))
                        mkt["blockscout_token_name"] = tok.get("name") or ""
                        mkt["blockscout_symbol"] = tok.get("symbol") or ""
                        mkt["token_holders"] = tok.get("holders_count")
            except Exception:
                pass

            # If this contract is not itself an ERC-20 token, check ERC-20 transfers to discover its Reward Token address
            if not resolved_token_addr and bs_token_type != "ERC-20":
                try:
                    async with session.get(
                        f"{bs_base}/api/v2/addresses/{address}/token-transfers?type=ERC-20",
                        timeout=aiohttp.ClientTimeout(total=7),
                    ) as rt:
                        if rt.status == 200:
                            dt = await rt.json(content_type=None)
                            for tr in (dt.get("items") or [])[:10]:
                                tok_info = tr.get("token") or {}
                                t_addr = (tok_info.get("address_hash") or "").lower()
                                if t_addr and t_addr != address.lower():
                                    resolved_token_addr = t_addr
                                    mkt["reward_token_name"] = tok_info.get("name") or ""
                                    mkt["reward_token_symbol"] = tok_info.get("symbol") or ""
                                    break
                except Exception:
                    pass

            # Extract any project website URLs from verified smart-contract source code
            if mkt.get("is_verified"):
                try:
                    async with session.get(
                        f"{bs_base}/api/v2/smart-contracts/{address}",
                        timeout=aiohttp.ClientTimeout(total=7),
                    ) as rsc:
                        if rsc.status == 200:
                            dsc = await rsc.json(content_type=None)
                            src_blob = str(dsc.get("source_code") or "")[:30000]
                            found_urls = re.findall(r"https?://[^\s\"'<>\\)]+", src_blob)
                            source_urls.extend(found_urls)
                except Exception:
                    pass
        elif mkt.get("sourcify_verified"):
            mkt["is_verified"] = True

        target_token_addr = resolved_token_addr or address.lower()
        mkt["resolved_token_address"] = target_token_addr

        # 3. DexScreener multi-chain market & official website lookup (check contract first, then resolved reward token)
        dex_candidates = [address.lower()]
        if target_token_addr != address.lower():
            dex_candidates.append(target_token_addr)

        for cand_addr in dex_candidates:
            try:
                async with session.get(
                    f"https://api.dexscreener.com/latest/dex/tokens/{cand_addr}",
                    timeout=aiohttp.ClientTimeout(total=7),
                ) as r2:
                    if r2.status == 200:
                        d2 = await r2.json(content_type=None)
                        pairs = d2.get("pairs") or []
                        if pairs:
                            top = max(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                            info = top.get("info") or {}
                            mkt["dex_pairs_count"] = len(pairs)
                            mkt["dex_id"] = top.get("dexId") or ""
                            mkt["price_usd"] = top.get("priceUsd")
                            mkt["liquidity_usd"] = (top.get("liquidity") or {}).get("usd")
                            mkt["volume_24h_usd"] = (top.get("volume") or {}).get("h24")
                            mkt["dex_url"] = top.get("url") or ""
                            if isinstance(top.get("baseToken"), dict) and top["baseToken"].get("address"):
                                mkt["dex_base_token"] = top["baseToken"]["address"]
                                if cand_addr == target_token_addr:
                                    mkt["resolved_token_address"] = top["baseToken"]["address"].lower()
                            dex_sites = [w.get("url") for w in (info.get("websites") or []) if isinstance(w, dict) and w.get("url")]
                            mkt["websites"] = filter_project_urls(dex_sites + source_urls)
                            mkt["socials"] = [s.get("url") for s in (info.get("socials") or []) if isinstance(s, dict) and s.get("url")][:3]
                            break
            except Exception:
                pass

        if not mkt.get("websites") and source_urls:
            mkt["websites"] = filter_project_urls(source_urls)

        # 4. GeckoTerminal fallback pool lookup when DexScreener has no price
        if not mkt.get("price_usd"):
            try:
                async with session.get(
                    f"https://api.geckoterminal.com/api/v2/search/pools?query={target_token_addr}",
                    timeout=aiohttp.ClientTimeout(total=7),
                ) as rg:
                    if rg.status == 200:
                        dg = await rg.json(content_type=None)
                        gpools = dg.get("data") or []
                        if gpools:
                            attrs = gpools[0].get("attributes") or {}
                            mkt["price_usd"] = attrs.get("base_token_price_usd")
                            mkt["liquidity_usd"] = attrs.get("reserve_in_usd")
                            mkt["gecko_pool_name"] = attrs.get("name")
                            mkt["gecko_pools_count"] = len(gpools)
            except Exception:
                pass

        # 5. GoPlus Security API audit (audit the resolved token address!)
        try:
            async with session.get(
                f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={target_token_addr}",
                timeout=aiohttp.ClientTimeout(total=7),
            ) as rsec:
                if rsec.status == 200:
                    ds = await rsec.json(content_type=None)
                    res_map = ds.get("result") or {}
                    info = res_map.get(target_token_addr) or (next(iter(res_map.values())) if res_map else None)
                    if isinstance(info, dict) and info:
                        honeypot = info.get("is_honeypot") == "1"
                        cannot_sell = info.get("cannot_sell_all") == "1"
                        mintable = info.get("is_mintable") == "1"
                        open_src = info.get("is_open_source") == "1"
                        buy_tax = float(info.get("buy_tax") or 0) * 100
                        sell_tax = float(info.get("sell_tax") or 0) * 100
                        sec.update({
                            "is_honeypot": honeypot,
                            "cannot_sell_all": cannot_sell,
                            "is_mintable": mintable,
                            "is_open_source": open_src,
                            "is_proxy": info.get("is_proxy") == "1",
                            "buy_tax_pct": round(buy_tax, 2),
                            "sell_tax_pct": round(sell_tax, 2),
                            "holder_count": info.get("holder_count"),
                            "owner_address": info.get("owner_address") or "",
                        })
                        if honeypot or cannot_sell:
                            sec["verdict"] = "خطر / Honeypot!"
                            sec["risk_level"] = "high"
                        elif sell_tax >= 10 or buy_tax >= 10 or mintable:
                            sec["verdict"] = "تنبيه: Mintable أو ضريبة"
                            sec["risk_level"] = "medium"
                        elif open_src:
                            sec["verdict"] = "آمن / مفتوح المصدر"
                            sec["risk_level"] = "low"
                        else:
                            sec["verdict"] = "منخفض الخطورة (مغلق المصدر)"
                            sec["risk_level"] = "medium"
        except Exception:
            pass

    return mkt, sec


async def _probe_solana_open_apis(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    omni: OmniRPC,
    address: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Inspect Solana programs/tokens via ProgramWatch, RugCheck, Helius DAS, and Jupiter Price v3."""
    mkt: dict[str, Any] = {"probed": True}
    sec: dict[str, Any] = {"probed": True, "verdict": "غير مفحوص"}
    async with sem:
        # 1. ProgramWatch BPF metadata & name
        try:
            async with session.get(
                f"https://programwatch.dev/api/program/{address}",
                timeout=aiohttp.ClientTimeout(total=7),
            ) as rp:
                if rp.status == 200:
                    dp = await rp.json(content_type=None)
                    pdata = dp.get("data") or {}
                    if isinstance(pdata, dict) and pdata:
                        mkt["verified_contract_name"] = pdata.get("program_name") or ""
                        mkt["is_verified"] = bool(pdata.get("idl") or pdata.get("program_name"))
                        mkt["solana_mutable"] = pdata.get("mutable")
                        mkt["solana_invocations_24h"] = pdata.get("tx_count_24h")
        except Exception:
            pass

        # 2. RugCheck summary if token/mint
        try:
            async with session.get(
                f"https://api.rugcheck.xyz/v1/tokens/{address}/report/summary",
                timeout=aiohttp.ClientTimeout(total=6),
            ) as rr:
                if rr.status == 200:
                    dr = await rr.json(content_type=None)
                    if isinstance(dr, dict) and (dr.get("score") is not None or dr.get("risks")):
                        risks = [rk.get("name") for rk in (dr.get("risks") or []) if isinstance(rk, dict)]
                        score = dr.get("score", 0)
                        sec.update({"rugcheck_score": score, "risks": risks[:4]})
                        sec["verdict"] = "خطر RugCheck" if score and score > 2000 else "آمن / RugCheck OK"
                        sec["risk_level"] = "high" if score and score > 2000 else "low"
        except Exception:
            pass

        # 3. Jupiter Price v3 if token
        try:
            async with session.get(
                f"https://api.jup.ag/price/v3?ids={address}",
                timeout=aiohttp.ClientTimeout(total=6),
            ) as rj:
                if rj.status == 200:
                    dj = await rj.json(content_type=None)
                    pobj = (dj or {}).get(address) or (dj.get("data") or {}).get(address)
                    if isinstance(pobj, dict) and pobj.get("usdPrice"):
                        mkt["price_usd"] = str(pobj["usdPrice"])
        except Exception:
            pass

        # 4. Helius DAS getAsset check if configured
        if omni.helius_rpc:
            try:
                das = await omni.solana_call(session, "getAsset", {"id": address}, timeout=8)
                res = das.get("result")
                if isinstance(res, dict):
                    meta = ((res.get("content") or {}).get("metadata")) or {}
                    if meta.get("name"):
                        mkt["blockscout_token_name"] = meta["name"]
                        mkt["blockscout_symbol"] = meta.get("symbol", "")
            except Exception:
                pass
    return mkt, sec


async def enrich_registry_items_onchain(items: list[dict[str, Any]]) -> None:
    """Run Architecture v2 7-source inspection across all new or incomplete protocols."""
    to_probe_rpc = [
        item for item in items
        if item.get("ecosystem") == "EVM"
        and (not item.get("onchain_profile", {}).get("probed") or "onchain_reward_token" not in (item.get("onchain_profile") or {}))
    ]
    to_probe_ext = [
        item for item in items
        if item.get("ecosystem") == "EVM"
        and (
            not item.get("market_profile", {}).get("probed")
            or not item.get("security_profile", {}).get("probed")
            or "sourcify_verified" not in (item.get("market_profile") or {})
            or "resolved_token_address" not in (item.get("market_profile") or {})
        )
    ]
    to_probe_sol = [
        item for item in items
        if item.get("ecosystem") == "Solana"
        and (not item.get("market_profile", {}).get("probed") or not item.get("security_profile", {}).get("probed"))
    ]

    connector = aiohttp.TCPConnector(limit=35, ssl=False)
    headers = {"User-Agent": "OmniRPC-ArchV2/2.0"}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        bs_map, chainid_map = await asyncio.gather(
            _load_blockscout_map(session),
            _load_chainid_explorers(session),
        )

        if to_probe_rpc:
            rpc_omni = OmniRPC()
            sem = asyncio.Semaphore(14)
            rpc_results = await asyncio.gather(*(
                probe_evm_contract_onchain(sem, session, rpc_omni, item["chain_id"], item["address"])
                for item in to_probe_rpc
            ))
            for item, profile in zip(to_probe_rpc, rpc_results):
                item["onchain_profile"] = profile

        if to_probe_ext:
            ext_sem = asyncio.Semaphore(6)
            ext_results = await asyncio.gather(*(
                _probe_evm_open_apis(ext_sem, session, bs_map, item["chain_id"], item["address"], item.get("onchain_profile"))
                for item in to_probe_ext
            ))
            for item, (mkt, sec) in zip(to_probe_ext, ext_results):
                item["market_profile"] = mkt
                item["security_profile"] = sec

        if to_probe_sol:
            sol_omni = OmniRPC()
            sol_sem = asyncio.Semaphore(4)
            sol_results = await asyncio.gather(*(
                _probe_solana_open_apis(sol_sem, session, sol_omni, item["address"])
                for item in to_probe_sol
            ))
            for item, (mkt, sec) in zip(to_probe_sol, sol_results):
                item["market_profile"] = mkt
                item["security_profile"] = sec

    for item in items:
        eco = item.get("ecosystem", "EVM")
        mkt = item.get("market_profile") or {}
        exp_name, exp_url = resolve_explorer_link(
            eco,
            str(item.get("chain_id", "")),
            str(item.get("chain_name", "")),
            str(item.get("address", "")),
            chainid_map,
            bs_map,
        )
        item["explorer_name"] = exp_name
        item["explorer_url"] = exp_url
        item["token_address"] = mkt.get("resolved_token_address") or mkt.get("dex_base_token") or item.get("address", "")
        if eco == "EVM":
            prof = item.get("onchain_profile") or {}
            ptype, pname, is_noise = classify_protocol_type(
                item.get("chain_name", ""),
                item.get("address", ""),
                item.get("decoded_functions") or [],
                prof,
                mkt,
            )
            item["protocol_type"] = ptype
            item["protocol_name"] = pname
            item["is_standard_token_noise"] = is_noise
        elif eco == "Solana":
            pw_name = mkt.get("verified_contract_name") or mkt.get("blockscout_token_name") or ""
            item["protocol_type"] = "تعدين / سكّ Solana Program"
            item["protocol_name"] = pw_name or f"Solana Program {item.get('address', '')[:8]}..."
            item["is_standard_token_noise"] = False
        elif eco == "Sui":
            item["protocol_type"] = "حركة Sui Move (Mining/Mint)"
            item["protocol_name"] = item.get("address", "")
            item["is_standard_token_noise"] = False
        elif eco in ("Aptos", "Near", "TON", "Cosmos", "Substrate"):
            cat = item.get("category") or f"{eco} Mining/Mint"
            item["protocol_type"] = "تعدين توكن PoW / Fair-Mint" if "pow" in cat.lower() else f"بروتوكول {eco} (Mining/Mint)"
            item["protocol_name"] = item.get("protocol_name") or f"{eco}: {str(item.get('address', ''))[:24]}"
            item["is_standard_token_noise"] = False


async def check_all_apis_health(omni: OmniRPC) -> dict[str, Any]:
    """Run live latency & status health check across all Architecture v2 public & Helius endpoints."""
    connector = aiohttp.TCPConnector(limit=25, ssl=False)
    headers = {"User-Agent": "OmniRPC-ArchV2/2.0"}

    async def probe_get(session: aiohttp.ClientSession, name: str, cat: str, url: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as r:
                return {"name": name, "category": cat, "ok": r.status == 200, "status": r.status, "ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as exc:
            return {"name": name, "category": cat, "ok": False, "status": str(exc)[:40], "ms": round((time.perf_counter() - t0) * 1000, 1)}

    async def probe_evm(session: aiohttp.ClientSession, cid: int, name: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            res = await omni.evm_call(session, cid, "eth_blockNumber", [], timeout=6)
            return {"name": name, "category": "RPC Rotator", "ok": True, "status": f"blk {int(res, 16)}", "ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as exc:
            return {"name": name, "category": "RPC Rotator", "ok": False, "status": str(exc)[:40], "ms": round((time.perf_counter() - t0) * 1000, 1)}

    async def probe_sol(session: aiohttp.ClientSession) -> dict[str, Any]:
        t0 = time.perf_counter()
        res = await omni.solana_call(session, "getSlot", [], timeout=7)
        slot = res.get("result")
        tag = "Helius+Fallback" if omni.helius_rpc else "Public"
        return {"name": f"Solana ({tag})", "category": "RPC Rotator", "ok": bool(slot), "status": f"slot {slot}" if slot else "err", "ms": round((time.perf_counter() - t0) * 1000, 1)}

    async def probe_sui(session: aiohttp.ClientSession) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            async with session.post("https://graphql.mainnet.sui.io/graphql", json={"query": "{ checkpoint { sequenceNumber } }"}, timeout=aiohttp.ClientTimeout(total=7)) as r:
                d = await r.json(content_type=None)
                seq = ((d.get("data") or {}).get("checkpoint") or {}).get("sequenceNumber")
                return {"name": "Sui GraphQL", "category": "RPC Rotator", "ok": bool(seq), "status": f"cp {seq}", "ms": round((time.perf_counter() - t0) * 1000, 1)}
        except Exception as exc:
            return {"name": "Sui GraphQL", "category": "RPC Rotator", "ok": False, "status": str(exc)[:40], "ms": round((time.perf_counter() - t0) * 1000, 1)}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        checks = await asyncio.gather(
            probe_evm(session, 1, "Ethereum Rotator"),
            probe_evm(session, 8453, "Base Rotator"),
            probe_sol(session),
            probe_sui(session),
            probe_get(session, "Aptos REST", "L1 Node", "https://fullnode.mainnet.aptoslabs.com/v1"),
            probe_get(session, "Cosmos Directory", "Cosmos IBC", "https://rest.cosmos.directory/cosmoshub/cosmos/base/tendermint/v1beta1/blocks/latest"),
            probe_get(session, "4byte.sourcify.dev", "ABI Decoder", "https://api.4byte.sourcify.dev/signature-database/v1/lookup?function=0xa9059cbb"),
            probe_get(session, "Sourcify v2", "Contract Verify", "https://sourcify.dev/server/v2/contract/1/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            probe_get(session, "Blockscout v2 (646 Chains)", "Explorer API", "https://eth.blockscout.com/api/v2/addresses/0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            probe_get(session, "GoPlus Security", "Security Audit", "https://api.gopluslabs.io/api/v1/token_security/1?contract_addresses=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            probe_get(session, "RugCheck Solana", "Security Audit", "https://api.rugcheck.xyz/v1/tokens/JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN/report/summary"),
            probe_get(session, "ProgramWatch Solana", "Solana IDL", "https://programwatch.dev/api/program/6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"),
            probe_get(session, "DexScreener", "DEX Market", "https://api.dexscreener.com/latest/dex/tokens/0xef4b763385838fffc708000f884026b8c0434275"),
            probe_get(session, "GeckoTerminal (100+)", "DEX Pools", "https://api.geckoterminal.com/api/v2/networks"),
            probe_get(session, "Jupiter Price v3", "Solana Prices", "https://api.jup.ag/price/v3?ids=So11111111111111111111111111111111111111112"),
            probe_get(session, "Mempool.space", "Bitcoin PoW", "https://mempool.space/api/blocks/tip/height"),
        )
    return {
        "total_providers": len(checks),
        "online_providers": sum(1 for c in checks if c["ok"]),
        "rotator": omni.rotator_stats(),
        "providers": list(checks),
    }


async def enrich_saved_registry() -> None:
    """Load mining_registry.json, run full 7-source introspection, and persist enriched data."""
    import collections
    from mining_registry import load_registry, save_registry

    reg = load_registry()
    items = list((reg.get("items") or {}).values())
    await enrich_registry_items_onchain(items)
    save_registry(reg)
    types = collections.Counter(x.get("protocol_type") for x in items)
    sec_counts = collections.Counter((x.get("security_profile") or {}).get("verdict", "غير مفحوص") for x in items)
    real = [x for x in items if not x.get("is_standard_token_noise")]
    print(json.dumps({
        "total_protocols": len(items),
        "genuine_protocols": len(real),
        "type_breakdown": dict(types),
        "security_breakdown": dict(sec_counts),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(enrich_saved_registry())
