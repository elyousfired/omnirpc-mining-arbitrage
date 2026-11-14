"""Persistent deduplicated registry & clean ABI classifier for on-chain mining protocols."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUT_DIR = Path(__file__).resolve().parent
REGISTRY_JSON = OUT_DIR / "mining_registry.json"
REGISTRY_CSV = OUT_DIR / "mining_registry.csv"

# Exact function/camelCase token keywords indicating genuine mining, PoW, or fair-mint protocols
MINING_TOKENS = {
    "mine", "minebatch", "miner", "mining", "dig", "drill", "drillx", "glaze",
    "prove", "provepossession", "submitepoch", "claimmintreward",
    "claimmintrewardandshare", "nonce", "pow", "difficulty", "checkpoint",
    "automate", "giver", "commithash", "blockreward", "challenge", "l2_claim",
}

POW_STRICT_TOKENS = {
    "mine", "minebatch", "miner", "mining", "dig", "drill", "drillx", "glaze",
    "nonce", "pow", "difficulty", "prove", "provepossession", "submitepoch",
    "claimmintreward", "claimmintrewardandshare", "blockreward", "commithash",
    "automate", "giver", "challenge",
}

NON_MINING_ADDRESSES = {
    "0x00005ea00ac477b1030ce78506496e8c2de24bf5",  # SeaDrop NFT drop
    "0x0000000000000000000000000000000000001000",  # Validator system precompile
    "0x0000000000000000000000000000000000001003",  # ERC1967Proxy precompile
    "0x0000000000000000000000000000000000000300",  # Energi system contract
    "0xd100a01e00000000000000000000000000000000",  # SFC consensus sealEpoch precompile
    "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67",  # Gnosis Safe Proxy Factory (createProxyWithNonce)
    "0x55a0e8c9e14309c82ab011ed2ef3cfbc49f43522",  # Gnosis Safe Multisig
    "0x68e534a0122223a119980f6c394683bcd0215e71",  # BananaMiner ERC-721 farm (not PoW mining)
    "0x4008a353d3476884dc8cd8fbf314970c8409fb22",  # Amber (AI Agent .ai ID gated, protocol agents mine it & no DexScreener)
    "0x3643a907f875fa9b740e1c0747e91b5aa5222ab8",  # JAGENT Mint Pass (Agent .ai ID gated)
    "0xbadd0b92c1c71d02e7d520f64c0876538fa2557f",  # Filecoin PDPVerifier infra (no web mint / no DexScreener token)
    "0xa596e82b0e7d9f5c3e7841cf3f53f66b34d2c1d2",  # OptimAI Epoch Node (no DexScreener token)
    "0x3ae2dfc3b795267e284cbab7eff9a0cefdab401d",  # Apertum Virtual Miner (no DexScreener token)
    "6ef8rrecthr5dkzon8nwu78hrvfckubj14m5ubewf6p",  # Pump.fun bonding-curve launchpad
    "6vo3245eszab5wuqemw8mgdbfrudkbhhdhp5lcagutab", # Pump app launchpad router
    # Traditional L1 / HiveOS GPU Pool Coins (NO Web3 Connect-Wallet Mint UI)
    "0x14b2d3bc65e74dae1030eafd8ac30c533c976a9b",   # Conflux wrapped
    "0x3d6545b08693dae087e957cb1180ee38b9e3c25e",   # ETC bridged
    "0xdb85f6685950e285b1e611037bebe5b34e2b7d78",   # WZANO
    "04b95368393c821f180deee8229fbd941baaf9bd748ebcdbf7adbb147273455247",  # rsERG Cardano
    "0xe0e8a04242f35b95dc64b07e0eae23a8e43a78e4",   # rsERG BSC
    "0xe60201989b8628f43dc0605f585a72bcf1f1e977",   # CLORE
    "0x9928a8600d14ac22c0be1e8d58909834d7ceaf13",   # 0xDNX (Dynex)
    "0xd5d0322b6bab6a762c79f8c81a0b674778e13aed",   # FIRO
    "0xfa704148d516b209d52c2d75f239274c8f8eaf1a",   # OCTA
    "0xaff9084f2374585879e8b434c399e29e80cce635",   # FLUX
    "0xa1c0decafe3e9bf06a5f29b7015cd373a9854608",   # AIPG
    "0xfd36fa88bb3fea8d1264fc89d70723b6a2b56958",   # Tari wXTM
    "0x5c97d726bf5130ae15408ce32bc764e458320d2f",   # Quai wrapped
    "0x590f820444fa3638e022776752c5eef34e2f89a6",   # Alephium wrapped
    "0xb6ed7644c69416d67b522e20bc294a9a9b405b31",   # 0xBTC CLI miner (no Web3 Mint UI)
    "0x71b821aa52a49f32eed535fca6eb5aa130085978",   # 0xBTC Polygon CLI miner
}

NON_MINING_KEYWORDS = (
    "uniswap", "positions nft", "algebra positions", "pharaoh v3", "shadow v3",
    "slipstream v3", "nest positions", "liquid staked", "staked aave", "steth",
    "wrapped ", "usd coin", "usdc", "eure", "erc1967proxy", "pump.fun",
    "gacha", "game contract", "false punks", "ghoulstation", "courtyard",
    "ct3keys", "toy-story", "astroverse", "strands trade", "ubischeme",
    "claim / airdrop", "test strategy", "seadrop", "ethereum name service",
    "gnosis", "safe proxy", "bananaminer", "banana miner", "stkaave", "swbera",
    "copper miners", "copxon", "jetton", "mtonga", "ton cat", "ton inu",
    "the virus", "proof of karl", "bonk", "edenorex", "mint club", "mint token", "proof of bagwork",
    "dragon coin", "zendawg", "never give up", "antminer", "minted hub",
    "staking / yield", "سيولة defi", "سكّ nft", "توكن عادي", "لعبة ويب 3",
    "مطالبة ومكافآت", "ستيكينغ",
    "dynex", "firo", "zano", "ergo", "conflux", "octaspace", "ethereum classic",
    "clore.ai", "runonflux", "ai power grid", "alephium", "tari (", "quai network",
    "0xbitcoin", "fodinamine", "gram (grm)",
)

ADMIN_NOISE_PREFIXES = (
    "adminmint", "ownermint", "setminter", "addminter", "removeminter",
    "grantrole", "bridgemint", "mintposition", "increaseliquidity",
)

# Exact tokens/signatures that are routine transfers, approvals, DEX swaps, or multisig/bridge noise
NOISE_FUNC_NAMES = {
    "transfer", "transferfrom", "approve", "approvedelegation", "permit",
    "transferwithauthorization", "receivewithauthorization", "swap",
    "exactinput", "exactoutput", "multicall", "execute", "exectransaction",
    "approvehash", "deposit", "withdraw", "latestrounddata", "submitsignatures",
    "submitandpass", "submitretryable", "submittransactionschecked",
    "blacklist", "increaseliquidity", "deploy", "deployandexecute",
    "createproxywithnonce", "sealepoch", "sealepochvalidators", "mintpublic",
    "mintonlyobjektefficient",
}


def is_actionable_mining_protocol(item: dict[str, Any]) -> bool:
    """Strict filter: user-mineable / fair-mint protocols with BOTH a real mint UI website AND a live DexScreener token."""
    if item.get("is_standard_token_noise"):
        return False
    addr_l = str(item.get("address") or "").strip().lower()
    if addr_l in NON_MINING_ADDRESSES:
        return False
    mkt = item.get("market_profile") or {}
    chain_l = str(item.get("chain_name") or "").lower()
    cid_l = str(item.get("chain_id") or "").lower()
    if cid_l in ("arc", "robinhood", "46630") or any(
        t in chain_l for t in ("testnet", "sepolia", "goerli", "holesky", "amoy", "devnet", "robinhood")
    ) or "arc " in chain_l or chain_l == "arc":
        return False
    pname = str(item.get("protocol_name") or "").lower()
    ptype = str(item.get("protocol_type") or "").lower()
    cat_l = str(item.get("category") or "").lower()
    vname = str(mkt.get("verified_contract_name") or "").lower()
    blob = f"{pname} {ptype} {cat_l} {vname}"
    if item.get("wtm_name") or "gpu proof-of-work" in blob or "gpu_pow(" in " ".join(item.get("decoded_functions") or []).lower():
        return False
    if any(bad in blob for bad in NON_MINING_KEYWORDS):
        return False
    if "amber" in blob or "jagent" in blob:
        return False

    # Strictly require passing live Sandbox Wallet & Web3 Connect-Wallet Mint UI verification
    sb = item.get("sandbox_test")
    if not (
        isinstance(sb, dict)
        and sb.get("tested")
        and sb.get("site_live")
        and sb.get("is_actionable_web3_mint")
        and not sb.get("paused")
    ):
        return False

    # 1. Must have a real non-GitHub Mint / Mine interface website
    websites = [
        w for w in (mkt.get("websites") or [])
        if isinstance(w, str) and w.startswith(("http://", "https://"))
    ]
    ui_sites = [w for w in websites if "github.com" not in w.lower() and "mint.club" not in w.lower()]
    if not ui_sites:
        return False

    # 2. Must have a live token listed & priced on DexScreener
    dex_url = str(mkt.get("dex_url") or "").lower()
    try:
        px = float(mkt.get("price_usd") or 0)
    except Exception:
        px = 0.0
    if "dexscreener.com" not in dex_url or px <= 0:
        return False

    fns = " ".join(item.get("decoded_functions") or []).lower()
    has_mining_signal = bool(item.get("is_curated_miner")) or any(
        k in f"{ptype} {fns}"
        for k in (
            "pow", "mine", "drill", "nonce", "difficulty", "glaze",
            "claimmintreward", "claimrank", "startmint", "claimmint", "transform",
            "mintx28", "mintreward", "blockreward", "fair-mint",
        )
    )
    return has_mining_signal


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tokenize_signature(sig: str) -> tuple[str, set[str]]:
    """Extract lowercase function name and camelCase/word tokens from a Solidity signature."""
    fn_part = sig.split("(", 1)[0].strip()
    fn_lower = fn_part.lower()
    # Split camelCase & underscores/digits cleanly
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", fn_part)
    tokens = {w.lower() for w in re.split(r"[^A-Za-z0-9]+", words) if w}
    if fn_lower:
        tokens.add(fn_lower)
    return fn_lower, tokens


def classify_evm_candidate(
    decoded_functions: list[str],
    mint_events: int,
    unique_callers: int,
) -> tuple[bool, str, str]:
    """Return (is_mining_protocol, category, detection_reason) with false-positive filtering."""
    fn_names: list[str] = []
    all_tokens: set[str] = set()
    for sig in decoded_functions:
        fn_lower, toks = tokenize_signature(str(sig))
        if fn_lower:
            fn_names.append(fn_lower)
            all_tokens |= toks

    # Explicit exclusion if every decoded function is routine DEX/ERC20/oracle/bridge/multisig noise
    has_pow_strict = bool(all_tokens & POW_STRICT_TOKENS)
    is_admin_only = (
        bool(fn_names)
        and all(any(f.startswith(p) for p in ADMIN_NOISE_PREFIXES) for f in fn_names)
        and not has_pow_strict
    )
    only_noise = bool(fn_names) and all(f in NOISE_FUNC_NAMES for f in fn_names) and not has_pow_strict
    if is_admin_only or only_noise or (unique_callers <= 1 and not has_pow_strict and mint_events < 3):
        return False, "", ""

    mining_hits = sorted(all_tokens & MINING_TOKENS)
    if mining_hits:
        if has_pow_strict:
            return True, "PoW / Hash & Epoch Mining", f"ABI Tokens: {', '.join(mining_hits[:4])}"
        return True, "On-Chain Fair-Mint Mining", f"ABI Tokens: {', '.join(mining_hits[:4])}"

    return False, "", ""


def _empty_registry() -> dict[str, Any]:
    return {
        "updated_at": None,
        "total_scans_completed": 0,
        "total_protocols": 0,
        "items": {},
        "scan_history": [],
    }


def load_registry(path: Path = REGISTRY_JSON) -> dict[str, Any]:
    """Load persistent mining registry or create an empty structure."""
    if not path.exists():
        return _empty_registry()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("items"), dict):
            data.setdefault("scan_history", [])
            data.setdefault("total_scans_completed", 0)
            return data
    except Exception:
        pass
    return _empty_registry()


def _upsert_item(
    items: dict[str, dict[str, Any]],
    uid: str,
    record: dict[str, Any],
    now: str,
    scan_num: int,
) -> bool:
    """Insert new protocol or update existing one in-place without duplicating. Returns True if newly added."""
    if uid not in items:
        items[uid] = {
            "uid": uid,
            "ecosystem": record["ecosystem"],
            "chain_id": record["chain_id"],
            "chain_name": record["chain_name"],
            "symbol": record.get("symbol", ""),
            "address": record["address"],
            "category": record["category"],
            "detection_reason": record["detection_reason"],
            "decoded_functions": list(dict.fromkeys(record.get("decoded_functions") or [])),
            "first_seen_at": now,
            "last_seen_at": now,
            "discovered_in_scan": scan_num,
            "seen_scans": 1,
            "cumulative_txs": int(record.get("tx_count", 0)),
            "cumulative_mints": int(record.get("mint_events", 0)),
            "last_window_txs": int(record.get("tx_count", 0)),
            "last_window_mints": int(record.get("mint_events", 0)),
            "unique_callers": int(record.get("unique_callers", 0)),
            "is_new_in_last_scan": True,
        }
        return True

    existing = items[uid]
    existing["last_seen_at"] = now
    existing["seen_scans"] = int(existing.get("seen_scans", 1)) + 1
    existing["cumulative_txs"] = int(existing.get("cumulative_txs", 0)) + int(record.get("tx_count", 0))
    existing["cumulative_mints"] = int(existing.get("cumulative_mints", 0)) + int(record.get("mint_events", 0))
    existing["last_window_txs"] = int(record.get("tx_count", 0))
    existing["last_window_mints"] = int(record.get("mint_events", 0))
    existing["unique_callers"] = max(int(existing.get("unique_callers", 0)), int(record.get("unique_callers", 0)))
    existing["is_new_in_last_scan"] = False
    merged_fns = list(dict.fromkeys((existing.get("decoded_functions") or []) + (record.get("decoded_functions") or [])))
    existing["decoded_functions"] = merged_fns[:12]
    return False


def merge_scan_into_registry(
    scan_report: dict[str, Any],
    duration_s: float = 0.0,
    registry_path: Path = REGISTRY_JSON,
    csv_path: Path = REGISTRY_CSV,
) -> dict[str, Any]:
    """Merge a completed scan report into mining_registry.json & CSV without duplicates."""
    reg = load_registry(registry_path)
    items: dict[str, dict[str, Any]] = reg["items"]
    now = utc_now_iso()
    scan_num = int(reg.get("total_scans_completed", 0)) + 1

    # Reset previous "is_new_in_last_scan" flags before recording this cycle's discoveries
    for obj in items.values():
        obj["is_new_in_last_scan"] = False

    new_count = 0
    matched_in_scan = 0

    # 1. EVM candidates (verified with clean token classifier)
    for c in scan_report.get("onchain_mining_candidates", []):
        fns = [str(f) for f in (c.get("decoded_functions") or [])]
        ok, category, reason = classify_evm_candidate(
            fns,
            int(c.get("mint_events_in_window", 0)),
            int(c.get("unique_callers", 0)),
        )
        if not ok:
            continue
        matched_in_scan += 1
        uid = f"evm:{c['chain_id']}:{str(c['address']).lower()}"
        added = _upsert_item(
            items,
            uid,
            {
                "ecosystem": "EVM",
                "chain_id": str(c["chain_id"]),
                "chain_name": c["chain_name"],
                "symbol": c.get("symbol", ""),
                "address": str(c["address"]).lower(),
                "category": category,
                "detection_reason": reason,
                "decoded_functions": fns,
                "tx_count": c.get("tx_count", 0),
                "mint_events": c.get("mint_events_in_window", 0),
                "unique_callers": c.get("unique_callers", 0),
            },
            now,
            scan_num,
        )
        if added:
            new_count += 1

    # 2. Solana programs emitting MintTo / Mine / Drill / PoW logs
    sol = scan_report.get("solana_direct_scan") or {}
    for p in sol.get("top_active_programs", []):
        hits = int(p.get("mint_or_mine_logs", 0))
        sigs = p.get("matched_signals") or []
        if hits > 0 or sigs:
            matched_in_scan += 1
            pid = p["program_id"]
            uid = f"solana:mainnet:{pid}"
            is_pow = any(s in POW_STRICT_TOKENS for s in sigs)
            added = _upsert_item(
                items,
                uid,
                {
                    "ecosystem": "Solana",
                    "chain_id": "solana-mainnet",
                    "chain_name": "Solana Mainnet",
                    "symbol": "SOL",
                    "address": pid,
                    "category": "PoW / Hash & Epoch Mining" if is_pow else "Solana Mint/Mine Program",
                    "detection_reason": f"{hits} Logs ({', '.join(sigs[:4]) or 'MintTo/Mine'})",
                    "decoded_functions": [f"Log: {s}" for s in sigs[:5]] or ["Instruction: MintTo/Mine/Deploy"],
                    "tx_count": p.get("calls", 0),
                    "mint_events": hits,
                    "unique_callers": p.get("unique_signers", 0),
                },
                now,
                scan_num,
            )
            if added:
                new_count += 1

    # 3. Sui Move calls with mining/mint/claim/harvest targets
    sui = scan_report.get("sui_direct_scan") or {}
    for m in sui.get("top_move_calls", []):
        target = str(m.get("target", ""))
        if target.startswith("0x2::") or target.startswith("0x0000000000000000000000000000000000000000000000000000000000000002::"):
            continue
        fn_name = target.split("::")[-1] if "::" in target else target
        _, toks = tokenize_signature(fn_name)
        if toks & MINING_TOKENS:
            matched_in_scan += 1
            uid = f"sui:mainnet:{target.lower()}"
            added = _upsert_item(
                items,
                uid,
                {
                    "ecosystem": "Sui",
                    "chain_id": "sui-mainnet",
                    "chain_name": "Sui Mainnet",
                    "symbol": "SUI",
                    "address": target,
                    "category": "PoW / Hash & Epoch Mining" if (toks & POW_STRICT_TOKENS) else "Sui Move Mint/Mine",
                    "detection_reason": f"Move Target: {fn_name}",
                    "decoded_functions": [fn_name],
                    "tx_count": m.get("count", 0),
                    "mint_events": m.get("count", 0),
                    "unique_callers": m.get("unique_senders", 1),
                },
                now,
                scan_num,
            )
            if added:
                new_count += 1

    # 4. Aptos Move entry functions
    aptos = scan_report.get("aptos_direct_scan") or {}
    for m in aptos.get("top_move_calls", []):
        target = str(m.get("target", ""))
        if target.startswith("0x1::"):
            continue
        fn_name = target.split("::")[-1] if "::" in target else target
        _, toks = tokenize_signature(fn_name)
        if toks & MINING_TOKENS:
            matched_in_scan += 1
            uid = f"aptos:mainnet:{target.lower()}"
            added = _upsert_item(
                items,
                uid,
                {
                    "ecosystem": "Aptos",
                    "chain_id": "aptos-mainnet",
                    "chain_name": "Aptos Mainnet",
                    "symbol": "APT",
                    "address": target,
                    "category": "PoW / Hash & Epoch Mining" if (toks & POW_STRICT_TOKENS) else "Aptos Move Mint/Mine",
                    "detection_reason": f"Aptos Entry: {fn_name}",
                    "decoded_functions": [fn_name],
                    "tx_count": m.get("count", 0),
                    "mint_events": m.get("count", 0),
                    "unique_callers": m.get("unique_senders", 1),
                },
                now,
                scan_num,
            )
            if added:
                new_count += 1

    # 5. Near FunctionCall actions
    near = scan_report.get("near_direct_scan") or {}
    for m in near.get("top_contract_calls", []):
        method = str(m.get("method", ""))
        receiver = str(m.get("receiver", ""))
        _, toks = tokenize_signature(method)
        if toks & MINING_TOKENS:
            matched_in_scan += 1
            uid = f"near:mainnet:{receiver.lower()}:{method.lower()}"
            added = _upsert_item(
                items,
                uid,
                {
                    "ecosystem": "Near",
                    "chain_id": "near-mainnet",
                    "chain_name": "Near Protocol",
                    "symbol": "NEAR",
                    "address": receiver,
                    "category": "PoW / Hash & Epoch Mining" if (toks & POW_STRICT_TOKENS) else "Near Contract Mint/Mine",
                    "detection_reason": f"Near Method: {method}",
                    "decoded_functions": [method],
                    "tx_count": m.get("count", 0),
                    "mint_events": m.get("count", 0),
                    "unique_callers": m.get("unique_signers", 1),
                },
                now,
                scan_num,
            )
            if added:
                new_count += 1

    # 6. TON blockchain operations (PoW Givers / Jetton Mint / Mining)
    ton = scan_report.get("ton_direct_scan") or {}
    for m in ton.get("candidates", []):
        op_name = str(m.get("op_name", ""))
        addr = str(m.get("address", ""))
        _, toks = tokenize_signature(op_name)
        if toks & MINING_TOKENS or m.get("is_pow_hint"):
            matched_in_scan += 1
            uid = f"ton:mainnet:{addr}"
            added = _upsert_item(
                items,
                uid,
                {
                    "ecosystem": "TON",
                    "chain_id": "ton-mainnet",
                    "chain_name": "TON Mainnet",
                    "symbol": "TON",
                    "address": addr,
                    "category": "PoW / Hash & Epoch Mining" if (toks & POW_STRICT_TOKENS or m.get("is_pow_hint")) else "TON Jetton Mint/Mine",
                    "detection_reason": f"TON Op: {op_name}",
                    "decoded_functions": [op_name],
                    "tx_count": m.get("count", 1),
                    "mint_events": m.get("count", 1),
                    "unique_callers": m.get("unique_callers", 1),
                },
                now,
                scan_num,
            )
            if added:
                new_count += 1

    # 7. Cosmos / IBC CosmWasm contracts & module messages
    for c in scan_report.get("cosmos_candidates", []):
        matched_in_scan += 1
        slug = c.get("slug", "cosmos")
        addr = str(c.get("address") or slug)
        uid = f"cosmos:{slug}:{addr}"
        fns = [str(f) for f in (c.get("actions") or [])]
        added = _upsert_item(
            items,
            uid,
            {
                "ecosystem": "Cosmos",
                "chain_id": str(c.get("chain_id") or slug),
                "chain_name": c.get("chain_name") or slug,
                "symbol": c.get("symbol", ""),
                "address": addr,
                "category": c.get("category", "Cosmos Mint/Mine"),
                "detection_reason": c.get("detection_reason", "Cosmos Block Msg"),
                "decoded_functions": fns,
                "tx_count": c.get("tx_count", 1),
                "mint_events": c.get("tx_count", 1),
                "unique_callers": c.get("unique_callers", 1),
            },
            now,
            scan_num,
        )
        if added:
            new_count += 1

    reg["updated_at"] = now
    reg["total_scans_completed"] = scan_num
    reg["total_protocols"] = len(items)
    history_entry = {
        "scan_id": scan_num,
        "timestamp": now,
        "duration_s": round(duration_s, 1),
        "evm_chains_scanned": scan_report.get("evm_chains_scanned", 0),
        "total_chains_scanned": scan_report.get("total_chains_scanned", scan_report.get("evm_chains_scanned", 0)),
        "raw_blocks_scanned": scan_report.get("total_raw_blocks_scanned", 0),
        "raw_txs_scanned": scan_report.get("total_raw_txs_scanned", 0),
        "matched_in_scan": matched_in_scan,
        "newly_registered": new_count,
        "total_registry_size": len(items),
    }
    reg["scan_history"] = ([history_entry] + reg.get("scan_history", []))[:60]

    save_registry(reg, registry_path, csv_path)
    return history_entry


def save_registry(
    reg: dict[str, Any],
    registry_path: Path = REGISTRY_JSON,
    csv_path: Path = REGISTRY_CSV,
) -> None:
    """Persist registry JSON and matching CSV cleanly."""
    reg["total_protocols"] = len(reg.get("items") or {})
    registry_path.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    _export_registry_csv(reg.get("items") or {}, csv_path)


def _export_registry_csv(items: dict[str, dict[str, Any]], csv_path: Path) -> None:
    rows = sorted(
        items.values(),
        key=lambda x: (bool(x.get("is_new_in_last_scan")), x.get("last_seen_at", ""), x.get("cumulative_mints", 0)),
        reverse=True,
    )
    fieldnames = [
        "uid", "ecosystem", "chain_id", "chain_name", "symbol", "address", "token_address",
        "explorer_name", "explorer_url",
        "protocol_name", "protocol_type", "standard", "security_verdict",
        "price_usd", "liquidity_usd", "sourcify_verified", "is_standard_token_noise",
        "category", "detection_reason", "decoded_functions",
        "first_seen_at", "last_seen_at", "discovered_in_scan", "seen_scans",
        "cumulative_txs", "cumulative_mints", "unique_callers",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            row = dict(r)
            mkt = r.get("market_profile") or {}
            sec = r.get("security_profile") or {}
            row["standard"] = (r.get("onchain_profile") or {}).get("standard", "")
            row["security_verdict"] = sec.get("verdict", "")
            row["price_usd"] = mkt.get("price_usd", "")
            row["liquidity_usd"] = mkt.get("liquidity_usd", "")
            row["sourcify_verified"] = bool(mkt.get("sourcify_verified"))
            row["decoded_functions"] = ", ".join(r.get("decoded_functions") or [])
            w.writerow({k: row.get(k, "") for k in fieldnames})
