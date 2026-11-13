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
    "w3.org", "json-schema.org", "wikipedia.org", "eth.wiki", "github.com/ethereum/",
    "github.com/synthetixio", "github.com/uniswap", "github.com/aave", "github.com/lidofinance",
    "github.com/safe-global", "github.com/gnosis", "audit",
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
    """Filter out compiler/boilerplate/issue/code library URLs so only real project websites remain."""
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = (u or "").strip().rstrip(".,;)\"'`]")
        if not u.startswith(("http://", "https://")):
            continue
        low = u.lower()
        if any(bad in low for bad in NOISE_URL_DOMAINS):
            continue
        if any(p in low for p in ("/issues/", "/pull/", "/edit/", ".sol", "[`", "json-rpc")):
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
    "369": ("PulseScan", "https://otter.pulsechain.com", "/address/{addr}"),
    "1030": ("ConfluxScan", "https://evm.confluxscan.io", "/address/{addr}"),
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
    if eco == "cardano":
        return ("Cardanoscan", f"https://cardanoscan.io/token/{addr}" if addr else "https://cardanoscan.io")
    if eco == "tron":
        return ("Tronscan", f"https://tronscan.org/#/contract/{addr}" if addr else "https://tronscan.org")
    if eco == "xrpl":
        return ("XRPScan", "https://xrpscan.com")
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
                            ds_chain_map = {
                                1: "ethereum", 56: "bsc", 8453: "base", 250: "fantom",
                                137: "polygon", 42161: "arbitrum", 10: "optimism",
                                43114: "avalanche", 146: "sonic", 369: "pulsechain",
                                1030: "conflux", 80094: "berachain", 2741: "abstract",
                                999: "hyperevm", 534352: "scroll", 59144: "linea",
                                5000: "mantle", 130: "unichain", 57073: "ink",
                                1868: "soneium", 167000: "taiko", 81457: "blast",
                                34443: "mode", 1116: "core", 25: "cronos",
                                100: "gnosis", 42220: "celo", 61: "ethereumclassic",
                            }
                            want_ds_chain = ds_chain_map.get(int(chain_id)) if str(chain_id).isdigit() else None
                            chain_pairs = [p for p in pairs if p.get("chainId") == want_ds_chain] if want_ds_chain else []
                            pool_candidates = chain_pairs or pairs
                            top = max(pool_candidates, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                            info = top.get("info") or {}
                            mkt["dex_pairs_count"] = len(pool_candidates)
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

        # 4. GeckoTerminal fallback pool & token lookup when DexScreener has no price
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
        if not mkt.get("price_usd") and str(chain_id) == "56":
            try:
                async with session.get(
                    f"https://api.geckoterminal.com/api/v2/networks/bsc/tokens/{target_token_addr}",
                    timeout=aiohttp.ClientTimeout(total=7),
                ) as rgt:
                    if rgt.status == 200:
                        dgt = await rgt.json(content_type=None)
                        attrs = (dgt.get("data") or {}).get("attributes") or {}
                        if attrs.get("price_usd"):
                            mkt["price_usd"] = attrs["price_usd"]
                            mkt["liquidity_usd"] = attrs.get("total_reserve_in_usd")
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


# Canonical verified mining directory (verified contract, reward token, and official mining site)
VERIFIED_MINING_DIRECTORY: dict[str, dict[str, Any]] = {
    "0xe957ea0b072910f508dd2009f4acb7238c308e29": {
        "protocol_name": "Ethcoin (ETHC) — EVM PoW",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "ETHC",
        "token_address": "0xe957ea0b072910f508dd2009f4acb7238c308e29",
        "websites": ["https://ethcoin.org/"],
        "socials": ["https://x.com/ethcoinorg", "https://t.me/ethcoinorg"],
        "is_verified": True,
    },
    "0xae4a37d554c6d6f3e398546d8566b25052e0169c": {
        "protocol_name": "Donut Protocol / Glaze (DONUT) — Base",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "DONUT",
        "token_address": "0xae4a37d554c6d6f3e398546d8566b25052e0169c",
        "websites": ["https://glaze.click/"],
        "socials": [],
        "is_verified": True,
    },
    "0xf19308f923582a6f7c465e5ce7a9dc1bec6665b1": {
        "protocol_name": "TitanX (TITANX) — Ethereum Fair-Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "TITANX",
        "token_address": "0xF19308F923582A6f7c465e5CE7a9Dc1BEC6665B1",
        "websites": ["https://app.titanx.win/", "https://titanx.win/"],
        "socials": [],
        "is_verified": True,
    },
    "0xb6ed7644c69416d67b522e20bc294a9a9b405b31": {
        "protocol_name": "0xBitcoin (0xBTC) — ERC-918 PoW",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "0xBTC",
        "token_address": "0xB6eD7644C69416d67B522e20bC294A9a9B405B31",
        "websites": ["https://www.0xbitcoin.org/", "https://0xbtc.info/"],
        "socials": [],
        "is_verified": True,
    },
    "0x06450dee7fd2fb8e39061434babcfc05599a6fb8": {
        "protocol_name": "XEN Crypto (XEN) — Ethereum Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "XEN",
        "token_address": "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto", "https://t.me/XENCryptoTalk"],
        "is_verified": True,
    },
    "0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e": {
        "protocol_name": "XEN Crypto (bXEN) — BSC Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "bXEN",
        "token_address": "0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto"],
        "is_verified": True,
    },
    "0xffcbf84650ce02dafe96926b37a0ac5e34932fa5": {
        "protocol_name": "XEN Crypto (cbXEN) — Base Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "cbXEN",
        "token_address": "0xffcbF84650cE02DaFE96926B37a0ac5E34932fa5",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto"],
        "is_verified": True,
    },
    "0xef4b763385838fffc708000f884026b8c0434275": {
        "protocol_name": "XEN Crypto (fmXEN) — Fantom Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "fmXEN",
        "token_address": "0xef4b763385838fffc708000f884026b8c0434275",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto", "https://t.me/XENCryptoTalk"],
        "is_verified": True,
    },
    "v9tkmoduraibbjpuvidc4xsyc5y3kuvm8xxqnmwmine": {
        "protocol_name": "Fodina (FDNA) — Solana Web PoW",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "FDNA",
        "token_address": "V9TkMoDUrAiBBJPuVidc4xsYc5y3kUVM8XxQnMwmine",
        "websites": ["https://fodinamine.com/#start", "https://fodinamine.com/"],
        "socials": [],
        "is_verified": True,
    },
    "orev3eg1i9begiaj8b177z2s2rmarzak4nmv1kulvwv": {
        "protocol_name": "ORE Protocol V3 (Solana PoW / Grid)",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "ORE",
        "token_address": "oreoU2P8bN6jkk3jbaiVxYnG1dCXcYxwhwyK9jSybcp",
        "websites": ["https://ore.supply", "https://github.com/hardhatchad/ore"],
        "socials": ["https://x.com/OREsupply"],
        "is_verified": True,
    },
    "e3yuqbntzxv8elvw99orlc7z4ddbjqqr4nphwrmug9zu": {
        "protocol_name": "COAL Merged-Mining (Solana PoW)",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "COAL",
        "token_address": "E3yUqBNTZxV8ELvW99oRLC7z4ddbJqqR4NphwrMug9zu",
        "websites": ["https://minechain.gg", "https://github.com/coal-digital/coal"],
        "socials": ["https://x.com/coalonsolana"],
        "is_verified": True,
    },
    # Small & Alternative Chain User-Mineable PoW / Fair-Mint Protocols
    "369:0xff640cbd35a618df1348d861b5e47f7eab05b422": {
        "protocol_name": "pMINT (PulseChain Proof-of-Mint)",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "pMINT",
        "token_address": "0xFf640cBd35A618Df1348D861B5e47f7eaB05b422",
        "websites": ["https://pmint.win/"],
        "socials": [],
        "is_verified": True,
    },
    "369:0x06450dee7fd2fb8e39061434babcfc05599a6fb8": {
        "protocol_name": "XEN Crypto (pXEN) — PulseChain Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "XEN",
        "token_address": "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto"],
        "is_verified": True,
    },
    "369:0x037645963aece8c5beb947da5621362c9f7db5a6": {
        "protocol_name": "Mintables — PulseChain Mint dApp",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "MINTABLES",
        "token_address": "0x037645963Aece8C5Beb947dA5621362c9f7dB5a6",
        "websites": ["https://mintables.pages.dev/"],
        "socials": [],
        "is_verified": True,
    },
    "137:0x71b821aa52a49f32eed535fca6eb5aa130085978": {
        "protocol_name": "0xBitcoin (0xBTC) — Polygon PoW",
        "protocol_type": "تعدين توكن PoW / GPU Mining",
        "token_symbol": "0xBTC",
        "token_address": "0x71b821aa52a49f32eed535fca6eb5aa130085978",
        "websites": ["https://www.0xbitcoin.org/", "https://0xbtc.info/"],
        "socials": [],
        "is_verified": True,
    },
    "137:0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e": {
        "protocol_name": "XEN Crypto (mXEN) — Polygon Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "mXEN",
        "token_address": "0x2AB0e9e4eE70FFf1fB9D67031E44F6410170d00e",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto"],
        "is_verified": True,
    },
    "43114:0xc0c5aa69dbe4d6dddfbc89c0957686ec60f24389": {
        "protocol_name": "XEN Crypto (aXEN) — Avalanche Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "aXEN",
        "token_address": "0xC0C5AA69Dbe4d6DDdfBc89c0957686ec60F24389",
        "websites": ["https://xen.network/", "https://docs.xen.network"],
        "socials": ["https://x.com/xen_crypto"],
        "is_verified": True,
    },
    "ton:eqc47093ox5xhb0xuk2lcr2rhs8rj-vul61u4w2uh5ormg_o": {
        "protocol_name": "Gram (GRM) — TON GPU PoW Giver",
        "protocol_type": "تعدين توكن PoW / GPU Mining",
        "token_symbol": "GRM",
        "token_address": "EQC47093oX5Xhb0xuk2lCr2RhS8rj-vul61u4W2UH5ORmG_O",
        "websites": ["https://gramcoin.org/"],
        "socials": [],
        "is_verified": True,
    },
    "ton:eqcymlrxp1qyxzkek4ctinckb1ey5tkyajqppalnetio54vt": {
        "protocol_name": "Meridian (MRDN) — TON GPU PoW Giver",
        "protocol_type": "تعدين توكن PoW / GPU Mining",
        "token_symbol": "MRDN",
        "token_address": "EQCymLRXp1QYxZKek4CTInckB1ey5TkyAJQpPAlNetiO54Vt",
        "websites": ["https://meridian.wtf"],
        "socials": [],
        "is_verified": True,
    },
    "1:0xd536e7a9543cf9867a580b45cec7f748a1fe11ec": {
        "protocol_name": "Ouroboros (ORX Minter) — Ethereum",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "ORX",
        "token_address": "0xd536E7A9543Cf9867a580B45CEC7F748a1FE11eC",
        "websites": ["https://ouroboros.foundation/orx-minter"],
        "socials": [],
        "is_verified": True,
    },
    "1:0xfcd7ccee4071aa4ecfac1683b7cc0afecaf42a36": {
        "protocol_name": "Titan Blaze (BLAZE) — Ethereum Mint",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "BLAZE",
        "token_address": "0xfcd7cceE4071aA4ecFAC1683b7CC0aFeCAF42A36",
        "websites": ["https://app.titanblaze.win"],
        "socials": [],
        "is_verified": True,
    },
    "1:0x5c47902c8c80779cb99235e42c354e53f38c3b0d": {
        "protocol_name": "X28 (Transform & Mine) — Ethereum",
        "protocol_type": "تعدين توكن PoW / Fair-Mint",
        "token_symbol": "X28",
        "token_address": "0x5c47902c8C80779CB99235E42C354E53F38C3B0d",
        "websites": ["https://app.x28.win/"],
        "socials": [],
        "is_verified": True,
    },
    # GPU Proof-of-Work Chains with Live Verified DexScreener Tokens
    "1:0xfa704148d516b209d52c2d75f239274c8f8eaf1a": {
        "protocol_name": "OctaSpace (OCTA) — GPU Ethash PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "OCTA",
        "token_address": "0xfa704148d516b209d52c2d75f239274c8f8eaf1a",
        "websites": ["https://octa.space/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "OctaSpace",
        "gpu_algo": "Ethash",
    },
    "56:0xd5d0322b6bab6a762c79f8c81a0b674778e13aed": {
        "protocol_name": "Firo (FIRO) — GPU FiroPow PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "FIRO",
        "token_address": "0xd5d0322b6bab6a762c79f8c81a0b674778e13aed",
        "websites": ["https://firo.org/guide/how-to-mine-firo.html"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Firo",
        "gpu_algo": "FiroPow",
    },
    "cardano:04b95368393c821f180deee8229fbd941baaf9bd748ebcdbf7adbb147273455247": {
        "protocol_name": "Ergo (rsERG) — GPU Autolykos2 PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "ERG",
        "token_address": "04b95368393c821f180deee8229fbd941baaf9bd748ebcdbf7adbb147273455247",
        "websites": ["https://ergoplatform.org/en/get-erg/#Mining"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Ergo",
        "gpu_algo": "Autolykos",
    },
    "56:0xe0e8a04242f35b95dc64b07e0eae23a8e43a78e4": {
        "protocol_name": "Ergo (rsERG BSC) — GPU Autolykos2 PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "ERG",
        "token_address": "0xe0E8a04242f35b95DC64b07E0eAe23A8e43A78e4",
        "websites": ["https://ergoplatform.org/en/get-erg/#Mining"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Ergo",
        "gpu_algo": "Autolykos",
    },
    "1:0x9928a8600d14ac22c0be1e8d58909834d7ceaf13": {
        "protocol_name": "Dynex (0xDNX) — GPU DynexSolve PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "DNX",
        "token_address": "0x9928a8600d14ac22c0be1e8d58909834d7ceaf13",
        "websites": ["https://dynexcoin.org/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Dynexcoin",
        "gpu_algo": "DynexSolve",
    },
    "1:0xdb85f6685950e285b1e611037bebe5b34e2b7d78": {
        "protocol_name": "Zano (WZANO) — GPU ProgPowZ PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "ZANO",
        "token_address": "0xdb85f6685950E285b1E611037BEBe5B34e2B7d78",
        "websites": ["https://zano.org/downloads"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Zano",
        "gpu_algo": "ProgPowZ",
    },
    "1030:0x14b2d3bc65e74dae1030eafd8ac30c533c976a9b": {
        "protocol_name": "Conflux (CFX) — GPU Octopus PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "CFX",
        "token_address": "0x14b2D3bC65e74DAE1030EAFd8ac30c533c976A9b",
        "websites": ["https://confluxnetwork.org/en/mining"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Conflux",
        "gpu_algo": "Octopus",
    },
    "56:0x3d6545b08693dae087e957cb1180ee38b9e3c25e": {
        "protocol_name": "Ethereum Classic (ETC) — GPU Etchash PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "ETC",
        "token_address": "0x3d6545b08693dae087e957cb1180ee38b9e3c25e",
        "websites": ["https://ethereumclassic.org/mining"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "EthereumClassic",
        "gpu_algo": "Etchash",
    },
    "8453:0xa1c0decafe3e9bf06a5f29b7015cd373a9854608": {
        "protocol_name": "AI Power Grid (AIPG) — GPU KawPow PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "AIPG",
        "token_address": "0xa1c0decafe3e9bf06a5f29b7015cd373a9854608",
        "websites": ["https://aipowergrid.io/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "",
        "gpu_algo": "KawPow",
    },
    "1:0xe60201989b8628f43dc0605f585a72bcf1f1e977": {
        "protocol_name": "Clore.ai (CLORE) — GPU KawPow PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "CLORE",
        "token_address": "0xE60201989b8628F43dC0605f585a72Bcf1F1e977",
        "websites": ["https://clore.ai/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "",
        "gpu_algo": "KawPow",
    },
    "56:0xaff9084f2374585879e8b434c399e29e80cce635": {
        "protocol_name": "Flux (FLUX) — GPU ZelHash PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "FLUX",
        "token_address": "0xaff9084f2374585879e8b434c399e29e80cce635",
        "websites": ["https://runonflux.io/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "",
        "gpu_algo": "ZelHash",
    },
    "1:0x590f820444fa3638e022776752c5eef34e2f89a6": {
        "protocol_name": "Alephium (ALPH) — GPU Blake3 PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "ALPH",
        "token_address": "0x590f820444fa3638e022776752c5eef34e2f89a6",
        "websites": ["https://alephium.org/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "",
        "gpu_algo": "Blake3",
    },
    "1:0xfd36fa88bb3fea8d1264fc89d70723b6a2b56958": {
        "protocol_name": "Tari (wXTM) — GPU Cuckaroo29 PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "wXTM",
        "token_address": "0xfD36fA88bb3feA8D1264fc89d70723b6a2B56958",
        "websites": ["https://tari.com/", "https://tariswap.io/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Tari-Cuckaroo29",
        "gpu_algo": "Cuckaroo29",
    },
    "8453:0x5c97d726bf5130ae15408ce32bc764e458320d2f": {
        "protocol_name": "Quai Network (QUAI) — GPU KawPow PoW",
        "protocol_type": "تعدين GPU Proof-of-Work",
        "token_symbol": "QUAI",
        "token_address": "0x5c97D726bf5130AE15408cE32bc764e458320D2f",
        "websites": ["https://qu.ai/"],
        "socials": [],
        "is_verified": True,
        "wtm_name": "Quai-KawPow",
        "gpu_algo": "KawPow",
    },
}

CURATED_MINING_SEEDS: list[dict[str, Any]] = [
    {
        "uid": "solana:mainnet:V9TkMoDUrAiBBJPuVidc4xsYc5y3kUVM8XxQnMwmine",
        "ecosystem": "Solana",
        "chain_id": "solana",
        "chain_name": "Solana Mainnet",
        "symbol": "SOL",
        "address": "V9TkMoDUrAiBBJPuVidc4xsYc5y3kUVM8XxQnMwmine",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "User-Verified Solana Web PoW Miner (Fodina)",
        "decoded_functions": ["mine(pow)", "start_mining()"],
        "unique_callers": 320,
        "cumulative_mints": 18000,
        "is_curated_miner": True,
    },
    {
        "uid": "solana:mainnet:oreV3EG1i9BEgiAJ8b177Z2S2rMarzak4NMv1kULvWv",
        "ecosystem": "Solana",
        "chain_id": "solana",
        "chain_name": "Solana Mainnet",
        "symbol": "SOL",
        "address": "oreV3EG1i9BEgiAJ8b177Z2S2rMarzak4NMv1kULvWv",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Solana ORE V3 Mining Program + Token Mint",
        "decoded_functions": ["mine(drillx)", "automate()", "checkpoint()"],
        "unique_callers": 500,
        "cumulative_mints": 50000,
        "is_curated_miner": True,
    },
    {
        "uid": "solana:mainnet:E3yUqBNTZxV8ELvW99oRLC7z4ddbJqqR4NphwrMug9zu",
        "ecosystem": "Solana",
        "chain_id": "solana",
        "chain_name": "Solana Mainnet",
        "symbol": "SOL",
        "address": "E3yUqBNTZxV8ELvW99oRLC7z4ddbJqqR4NphwrMug9zu",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Solana COAL Merged-Mining Token Mint",
        "decoded_functions": ["mine(drillx)", "reprocess()"],
        "unique_callers": 120,
        "cumulative_mints": 12000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:8453:0xae4a37d554c6d6f3e398546d8566b25052e0169c",
        "ecosystem": "EVM",
        "chain_id": 8453,
        "chain_name": "Base",
        "symbol": "ETH",
        "address": "0xae4a37d554c6d6f3e398546d8566b25052e0169c",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Base Donut / Glaze Mining Web UI",
        "decoded_functions": ["glaze()", "mine()"],
        "unique_callers": 420,
        "cumulative_mints": 35000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0xf19308f923582a6f7c465e5ce7a9dc1bec6665b1",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0xF19308F923582A6f7c465e5CE7a9Dc1BEC6665B1",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified TitanX Fair-Mint Mining dApp (app.titanx.win)",
        "decoded_functions": ["startMint(uint256,uint256)", "claimMint(uint256)"],
        "unique_callers": 450,
        "cumulative_mints": 60000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0xb6ed7644c69416d67b522e20bc294a9a9b405b31",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0xb6ed7644c69416d67b522e20bc294a9a9b405b31",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified ERC-918 Mineable Token Standard (0xBitcoin)",
        "decoded_functions": ["mint(uint256,bytes32)", "getChallengeNumber()", "getMiningDifficulty()"],
        "unique_callers": 250,
        "cumulative_mints": 25000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0x06450dee7fd2fb8e39061434babcfc05599a6fb8",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0x06450dee7fd2fb8e39061434babcfc05599a6fb8",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified XEN Crypto Fair-Mint Contract (Ethereum)",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 400,
        "cumulative_mints": 40000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:56:0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e",
        "ecosystem": "EVM",
        "chain_id": 56,
        "chain_name": "BNB Smart Chain Mainnet",
        "symbol": "BNB",
        "address": "0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified XEN Crypto Fair-Mint Contract (BSC)",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 280,
        "cumulative_mints": 28000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:8453:0xffcbf84650ce02dafe96926b37a0ac5e34932fa5",
        "ecosystem": "EVM",
        "chain_id": 8453,
        "chain_name": "Base",
        "symbol": "ETH",
        "address": "0xffcbF84650cE02DaFE96926B37a0ac5E34932fa5",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified XEN Crypto Fair-Mint Contract (Base)",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 240,
        "cumulative_mints": 24000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:369:0xff640cbd35a618df1348d861b5e47f7eab05b422",
        "ecosystem": "EVM",
        "chain_id": 369,
        "chain_name": "PulseChain",
        "symbol": "PLS",
        "address": "0xFf640cBd35A618Df1348D861B5e47f7eaB05b422",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified PulseChain pMINT Proof-of-Mint Protocol",
        "decoded_functions": ["mine()", "mint()"],
        "unique_callers": 410,
        "cumulative_mints": 19500,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:369:0x06450dee7fd2fb8e39061434babcfc05599a6fb8",
        "ecosystem": "EVM",
        "chain_id": 369,
        "chain_name": "PulseChain",
        "symbol": "PLS",
        "address": "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified PulseChain XEN Fair-Mint Contract",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 310,
        "cumulative_mints": 21000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:369:0x037645963aece8c5beb947da5621362c9f7db5a6",
        "ecosystem": "EVM",
        "chain_id": 369,
        "chain_name": "PulseChain",
        "symbol": "PLS",
        "address": "0x037645963Aece8C5Beb947dA5621362c9f7dB5a6",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified PulseChain Mintables Wallet-Mint dApp",
        "decoded_functions": ["mint()"],
        "unique_callers": 140,
        "cumulative_mints": 8000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:137:0x71b821aa52a49f32eed535fca6eb5aa130085978",
        "ecosystem": "EVM",
        "chain_id": 137,
        "chain_name": "Polygon Mainnet",
        "symbol": "POL",
        "address": "0x71b821aa52a49f32eed535fca6eb5aa130085978",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Polygon 0xBitcoin ERC-918 GPU PoW Token",
        "decoded_functions": ["mint(uint256,bytes32)", "getChallengeNumber()"],
        "unique_callers": 180,
        "cumulative_mints": 14000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:137:0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e",
        "ecosystem": "EVM",
        "chain_id": 137,
        "chain_name": "Polygon Mainnet",
        "symbol": "POL",
        "address": "0x2AB0e9e4eE70FFf1fB9D67031E44F6410170d00e",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Polygon mXEN Fair-Mint Contract",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 290,
        "cumulative_mints": 26000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:43114:0xc0c5aa69dbe4d6dddfbc89c0957686ec60f24389",
        "ecosystem": "EVM",
        "chain_id": 43114,
        "chain_name": "Avalanche C-Chain",
        "symbol": "AVAX",
        "address": "0xC0C5AA69Dbe4d6DDdfBc89c0957686ec60F24389",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Avalanche aXEN Fair-Mint Contract",
        "decoded_functions": ["claimRank(uint256)", "claimMintReward()"],
        "unique_callers": 160,
        "cumulative_mints": 12000,
        "is_curated_miner": True,
    },
    {
        "uid": "ton:mainnet:EQC47093oX5Xhb0xuk2lCr2RhS8rj-vul61u4W2UH5ORmG_O",
        "ecosystem": "TON",
        "chain_id": "ton",
        "chain_name": "TON Mainnet",
        "symbol": "TON",
        "address": "EQC47093oX5Xhb0xuk2lCr2RhS8rj-vul61u4W2UH5ORmG_O",
        "category": "PoW / GPU Mining Giver",
        "detection_reason": "Verified TON GPU OpenCL/CUDA PoW Jetton (Gram)",
        "decoded_functions": ["pow_mine()", "gpu_hash()"],
        "unique_callers": 900,
        "cumulative_mints": 85000,
        "is_curated_miner": True,
    },
    {
        "uid": "ton:mainnet:EQCymLRXp1QYxZKek4CTInckB1ey5TkyAJQpPAlNetiO54Vt",
        "ecosystem": "TON",
        "chain_id": "ton",
        "chain_name": "TON Mainnet",
        "symbol": "TON",
        "address": "EQCymLRXp1QYxZKek4CTInckB1ey5TkyAJQpPAlNetiO54Vt",
        "category": "PoW / GPU Mining Giver",
        "detection_reason": "Verified TON GPU OpenCL/CUDA PoW Jetton (Meridian)",
        "decoded_functions": ["pow_mine()", "gpu_hash()"],
        "unique_callers": 620,
        "cumulative_mints": 42000,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0xd536e7a9543cf9867a580b45cec7f748a1fe11ec",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0xd536E7A9543Cf9867a580B45CEC7F748a1FE11eC",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Ouroboros ORX Minter (attachMinter + mint)",
        "decoded_functions": ["mint()", "attachMinter()"],
        "unique_callers": 190,
        "cumulative_mints": 9500,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0xfcd7ccee4071aa4ecfac1683b7cc0afecaf42a36",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0xfcd7cceE4071aA4ecFAC1683b7CC0aFeCAF42A36",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified Titan Blaze Miner UI (app.titanblaze.win)",
        "decoded_functions": ["mintReward()"],
        "unique_callers": 170,
        "cumulative_mints": 8400,
        "is_curated_miner": True,
    },
    {
        "uid": "evm:1:0x5c47902c8c80779cb99235e42c354e53f38c3b0d",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Ethereum Mainnet",
        "symbol": "ETH",
        "address": "0x5c47902c8C80779CB99235E42C354E53F38C3B0d",
        "category": "PoW / Hash & Epoch Mining",
        "detection_reason": "Verified X28 Miner UI (app.x28.win)",
        "decoded_functions": ["mintX28withTitanX()"],
        "unique_callers": 210,
        "cumulative_mints": 11000,
        "is_curated_miner": True,
    },
    # GPU Proof-of-Work Small & Major Chains (RTX 4090 / 4070 / 5090 + Verified DexScreener)
    {
        "uid": "evm:1:0xfa704148d516b209d52c2d75f239274c8f8eaf1a",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "OctaSpace (Ethash)",
        "symbol": "ETH",
        "address": "0xfa704148d516b209d52c2d75f239274c8f8eaf1a",
        "category": "GPU Proof-of-Work",
        "detection_reason": "Small L1 GPU Ethash PoW + Verified wOCTA on DexScreener",
        "decoded_functions": ["gpu_pow(Ethash)", "mine()"],
        "unique_callers": 350,
        "cumulative_mints": 25000,
        "is_curated_miner": True,
        "wtm_name": "OctaSpace",
        "gpu_algo": "Ethash",
    },
    {
        "uid": "evm:56:0xd5d0322b6bab6a762c79f8c81a0b674778e13aed",
        "ecosystem": "EVM",
        "chain_id": 56,
        "chain_name": "Firo (BSC Bridge)",
        "symbol": "BNB",
        "address": "0xd5d0322b6bab6a762c79f8c81a0b674778e13aed",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU FiroPow L1 + Verified FIRO on DexScreener",
        "decoded_functions": ["gpu_pow(FiroPow)", "mine()"],
        "unique_callers": 480,
        "cumulative_mints": 30000,
        "is_curated_miner": True,
        "wtm_name": "Firo",
        "gpu_algo": "FiroPow",
    },
    {
        "uid": "cardano:mainnet:04b95368393c821f180deee8229fbd941baaf9bd748ebcdbf7adbb147273455247",
        "ecosystem": "Cardano",
        "chain_id": "cardano",
        "chain_name": "Ergo / Cardano (rsERG)",
        "symbol": "ADA",
        "address": "04b95368393c821f180deee8229fbd941baaf9bd748ebcdbf7adbb147273455247",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU Autolykos2 L1 + Verified Rosen Bridge rsERG on DexScreener",
        "decoded_functions": ["gpu_pow(Autolykos)", "mine()"],
        "unique_callers": 640,
        "cumulative_mints": 45000,
        "is_curated_miner": True,
        "wtm_name": "Ergo",
        "gpu_algo": "Autolykos",
    },
    {
        "uid": "evm:1:0x9928a8600d14ac22c0be1e8d58909834d7ceaf13",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Dynex (ETH Bridge)",
        "symbol": "ETH",
        "address": "0x9928a8600d14ac22c0be1e8d58909834d7ceaf13",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU DynexSolve PoW L1 + Verified 0xDNX on DexScreener",
        "decoded_functions": ["gpu_pow(DynexSolve)", "mine()"],
        "unique_callers": 410,
        "cumulative_mints": 32000,
        "is_curated_miner": True,
        "wtm_name": "Dynexcoin",
        "gpu_algo": "DynexSolve",
    },
    {
        "uid": "evm:1:0xdb85f6685950e285b1e611037bebe5b34e2b7d78",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Zano (ETH Bridge)",
        "symbol": "ETH",
        "address": "0xdb85f6685950E285b1E611037BEBe5B34e2B7d78",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU ProgPowZ L1 + Verified WZANO on DexScreener",
        "decoded_functions": ["gpu_pow(ProgPowZ)", "mine()"],
        "unique_callers": 390,
        "cumulative_mints": 29000,
        "is_curated_miner": True,
        "wtm_name": "Zano",
        "gpu_algo": "ProgPowZ",
    },
    {
        "uid": "evm:1030:0x14b2d3bc65e74dae1030eafd8ac30c533c976a9b",
        "ecosystem": "EVM",
        "chain_id": 1030,
        "chain_name": "Conflux eSpace",
        "symbol": "CFX",
        "address": "0x14b2D3bC65e74DAE1030EAFd8ac30c533c976A9b",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU Octopus PoW L1 + Verified WCFX on DexScreener",
        "decoded_functions": ["gpu_pow(Octopus)", "mine()"],
        "unique_callers": 720,
        "cumulative_mints": 55000,
        "is_curated_miner": True,
        "wtm_name": "Conflux",
        "gpu_algo": "Octopus",
    },
    {
        "uid": "evm:56:0x3d6545b08693dae087e957cb1180ee38b9e3c25e",
        "ecosystem": "EVM",
        "chain_id": 56,
        "chain_name": "Ethereum Classic (BSC)",
        "symbol": "BNB",
        "address": "0x3d6545b08693dae087e957cb1180ee38b9e3c25e",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU Etchash L1 + Verified BSC ETC on DexScreener",
        "decoded_functions": ["gpu_pow(Etchash)", "mine()"],
        "unique_callers": 900,
        "cumulative_mints": 75000,
        "is_curated_miner": True,
        "wtm_name": "EthereumClassic",
        "gpu_algo": "Etchash",
    },
    {
        "uid": "evm:8453:0xa1c0decafe3e9bf06a5f29b7015cd373a9854608",
        "ecosystem": "EVM",
        "chain_id": 8453,
        "chain_name": "AI Power Grid (Base)",
        "symbol": "ETH",
        "address": "0xa1c0decafe3e9bf06a5f29b7015cd373a9854608",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU KawPow AI Inference PoW + Verified Base AIPG on DexScreener",
        "decoded_functions": ["gpu_pow(KawPow)", "mine()"],
        "unique_callers": 320,
        "cumulative_mints": 21000,
        "is_curated_miner": True,
        "gpu_algo": "KawPow",
    },
    {
        "uid": "evm:1:0xe60201989b8628f43dc0605f585a72bcf1f1e977",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Clore.ai (ETH)",
        "symbol": "ETH",
        "address": "0xE60201989b8628F43dC0605f585a72Bcf1F1e977",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU KawPow PoW + GPU Marketplace on DexScreener",
        "decoded_functions": ["gpu_pow(KawPow)", "mine()"],
        "unique_callers": 340,
        "cumulative_mints": 22000,
        "is_curated_miner": True,
        "gpu_algo": "KawPow",
    },
    {
        "uid": "evm:56:0xaff9084f2374585879e8b434c399e29e80cce635",
        "ecosystem": "EVM",
        "chain_id": 56,
        "chain_name": "Flux (BSC Bridge)",
        "symbol": "BNB",
        "address": "0xaff9084f2374585879e8b434c399e29e80cce635",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU ZelHash PoW L1 + Verified BSC FLUX on DexScreener",
        "decoded_functions": ["gpu_pow(ZelHash)", "mine()"],
        "unique_callers": 440,
        "cumulative_mints": 28000,
        "is_curated_miner": True,
        "gpu_algo": "ZelHash",
    },
    {
        "uid": "evm:1:0xfd36fa88bb3fea8d1264fc89d70723b6a2b56958",
        "ecosystem": "EVM",
        "chain_id": 1,
        "chain_name": "Tari (ETH Bridge)",
        "symbol": "ETH",
        "address": "0xfD36fA88bb3feA8D1264fc89d70723b6a2B56958",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU Cuckaroo29/SHA3x L1 + Verified wXTM on DexScreener",
        "decoded_functions": ["gpu_pow(Cuckaroo29)", "mine()"],
        "unique_callers": 380,
        "cumulative_mints": 26000,
        "is_curated_miner": True,
        "wtm_name": "Tari-Cuckaroo29",
        "gpu_algo": "Cuckaroo29",
    },
    {
        "uid": "evm:8453:0x5c97d726bf5130ae15408ce32bc764e458320d2f",
        "ecosystem": "EVM",
        "chain_id": 8453,
        "chain_name": "Quai Network (Base Bridge)",
        "symbol": "ETH",
        "address": "0x5c97D726bf5130AE15408cE32bc764e458320D2f",
        "category": "GPU Proof-of-Work",
        "detection_reason": "GPU KawPow L1 + Verified Symbiosis QUAI on DexScreener",
        "decoded_functions": ["gpu_pow(KawPow)", "mine()"],
        "unique_callers": 310,
        "cumulative_mints": 19000,
        "is_curated_miner": True,
        "wtm_name": "Quai-KawPow",
        "gpu_algo": "KawPow",
    },
]


def _apply_verified_directory(item: dict[str, Any]) -> None:
    """Enforce verified names, websites, symbols, and token addresses for known real mining protocols."""
    addr_l = str(item.get("address") or "").strip().lower()
    cid_l = str(item.get("chain_id") or "").strip().lower()
    meta = VERIFIED_MINING_DIRECTORY.get(f"{cid_l}:{addr_l}") or VERIFIED_MINING_DIRECTORY.get(addr_l)
    if not meta:
        return
    mkt = item.setdefault("market_profile", {"probed": True})
    prof = item.setdefault("onchain_profile", {"probed": True})
    item["protocol_name"] = meta["protocol_name"]
    item["protocol_type"] = meta["protocol_type"]
    item["is_standard_token_noise"] = False
    item["is_curated_miner"] = True
    item["token_address"] = meta["token_address"]
    if meta.get("wtm_name"):
        item["wtm_name"] = meta["wtm_name"]
    if meta.get("gpu_algo"):
        item["gpu_algo"] = meta["gpu_algo"]
    mkt["resolved_token_address"] = meta["token_address"]
    mkt["reward_token_symbol"] = meta["token_symbol"]
    mkt["websites"] = list(meta["websites"])
    if meta.get("socials"):
        mkt["socials"] = list(meta["socials"])
    if meta.get("is_verified"):
        mkt["is_verified"] = True
    if not prof.get("symbol"):
        prof["symbol"] = meta["token_symbol"]


async def enrich_registry_items_onchain(items: list[dict[str, Any]]) -> None:
    """Run Architecture v2 7-source inspection across all new or incomplete protocols."""
    for item in items:
        _apply_verified_directory(item)
        mkt = item.get("market_profile") or {}
        if mkt.get("websites"):
            mkt["websites"] = filter_project_urls(list(mkt["websites"]))

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
            or (item.get("is_curated_miner") and not item.get("market_profile", {}).get("price_usd"))
        )
    ]
    to_probe_sol = [
        item for item in items
        if item.get("ecosystem") == "Solana"
        and (
            not item.get("market_profile", {}).get("probed")
            or not item.get("security_profile", {}).get("probed")
            or (item.get("is_curated_miner") and not item.get("market_profile", {}).get("price_usd"))
        )
    ]
    to_probe_other_dex = [
        item for item in items
        if item.get("ecosystem") not in ("EVM", "Solana")
        and not item.get("market_profile", {}).get("price_usd")
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
                old_mkt = item.get("market_profile") or {}
                merged_sites = filter_project_urls(list(mkt.get("websites") or []) + list(old_mkt.get("websites") or []))
                if merged_sites:
                    mkt["websites"] = merged_sites
                for k in ("price_usd", "liquidity_usd", "volume_24h_usd", "dex_url", "dex_base_token", "reward_token_symbol", "blockscout_token_name"):
                    if not mkt.get(k) and old_mkt.get(k):
                        mkt[k] = old_mkt[k]
                item["market_profile"] = mkt
                item["security_profile"] = sec

        if to_probe_sol:
            sol_omni = OmniRPC()
            sol_sem = asyncio.Semaphore(4)
            sol_results = await asyncio.gather(*(
                _probe_solana_open_apis(sol_sem, session, sol_omni, (item.get("market_profile") or {}).get("resolved_token_address") or item.get("token_address") or item["address"])
                for item in to_probe_sol
            ))
            for item, (mkt, sec) in zip(to_probe_sol, sol_results):
                old_mkt = item.get("market_profile") or {}
                # Also enrich DexScreener price for Solana/SVM tokens
                tok = old_mkt.get("resolved_token_address") or item.get("token_address") or item["address"]
                try:
                    async with session.get(f"https://api.dexscreener.com/latest/dex/tokens/{tok}", timeout=aiohttp.ClientTimeout(total=7)) as rds:
                        if rds.status == 200:
                            dds = await rds.json(content_type=None)
                            pairs = dds.get("pairs") or []
                            if pairs:
                                top = max(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                                mkt["price_usd"] = top.get("priceUsd")
                                mkt["liquidity_usd"] = (top.get("liquidity") or {}).get("usd")
                                mkt["volume_24h_usd"] = (top.get("volume") or {}).get("h24")
                                mkt["dex_url"] = top.get("url") or ""
                except Exception:
                    pass
                merged_sites = filter_project_urls(list(mkt.get("websites") or []) + list(old_mkt.get("websites") or []))
                if merged_sites:
                    mkt["websites"] = merged_sites
                item["market_profile"] = mkt
                item["security_profile"] = sec

        if to_probe_other_dex:
            async def _probe_other(item: dict[str, Any]) -> None:
                mkt = item.setdefault("market_profile", {"probed": True})
                tok = mkt.get("resolved_token_address") or item.get("token_address") or item.get("address") or ""
                if not tok:
                    return
                try:
                    async with session.get(f"https://api.dexscreener.com/latest/dex/tokens/{tok}", timeout=aiohttp.ClientTimeout(total=7)) as rds:
                        if rds.status == 200:
                            dds = await rds.json(content_type=None)
                            pairs = [p for p in (dds.get("pairs") or []) if p.get("chainId") not in ("robinhood", "arc")]
                            if pairs:
                                cid_l = str(item.get("chain_id") or "").lower()
                                same_ch = [p for p in pairs if str(p.get("chainId") or "").lower() == cid_l]
                                pool_list = same_ch or pairs
                                top = max(pool_list, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                                mkt["price_usd"] = top.get("priceUsd")
                                mkt["liquidity_usd"] = (top.get("liquidity") or {}).get("usd")
                                mkt["volume_24h_usd"] = (top.get("volume") or {}).get("h24")
                                mkt["dex_url"] = top.get("url") or ""
                                base = top.get("baseToken") or {}
                                if base.get("symbol") and not mkt.get("reward_token_symbol"):
                                    mkt["reward_token_symbol"] = base.get("symbol")
                except Exception:
                    pass
            await asyncio.gather(*(_probe_other(it) for it in to_probe_other_dex))

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
        elif eco in ("Aptos", "Near", "TON", "Cosmos", "Substrate", "Cardano", "Tron", "XRPL"):
            cat = item.get("category") or f"{eco} Mining/Mint"
            cat_l = cat.lower()
            if "gpu proof-of-work" in cat_l:
                item["protocol_type"] = "تعدين GPU Proof-of-Work"
            elif "pow" in cat_l:
                item["protocol_type"] = "تعدين توكن PoW / Fair-Mint"
            else:
                item["protocol_type"] = f"بروتوكول {eco} (Mining/Mint)"
            item["protocol_name"] = item.get("protocol_name") or f"{eco}: {str(item.get('address', ''))[:24]}"
            item["is_standard_token_noise"] = False
        _apply_verified_directory(item)


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
    """Load mining_registry.json, seed verified mining contracts, run introspection, and persist."""
    import collections
    from mining_registry import is_actionable_mining_protocol, load_registry, save_registry, utc_now_iso

    reg = load_registry()
    reg_items = reg.setdefault("items", {})
    now = utc_now_iso()
    for seed in CURATED_MINING_SEEDS:
        uid = seed["uid"]
        if uid not in reg_items:
            reg_items[uid] = {
                **seed,
                "first_seen_at": now,
                "last_seen_at": now,
                "discovered_in_scan": int(reg.get("total_scans_completed") or 1),
                "seen_scans": 1,
                "cumulative_txs": int(seed.get("cumulative_mints", 100)),
                "is_new_in_last_scan": False,
            }
        else:
            reg_items[uid]["is_curated_miner"] = True

    items = list(reg_items.values())
    await enrich_registry_items_onchain(items)
    reg["total_protocols"] = len(reg_items)
    save_registry(reg)
    types = collections.Counter(x.get("protocol_type") for x in items)
    sec_counts = collections.Counter((x.get("security_profile") or {}).get("verdict", "غير مفحوص") for x in items)
    real = [x for x in items if not x.get("is_standard_token_noise")]
    actionable = [x for x in items if is_actionable_mining_protocol(x)]
    print(json.dumps({
        "total_protocols": len(items),
        "genuine_protocols": len(real),
        "actionable_mining_with_site": len(actionable),
        "type_breakdown": dict(types),
        "security_breakdown": dict(sec_counts),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(enrich_saved_registry())
