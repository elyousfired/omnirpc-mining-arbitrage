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

# Exact function/camelCase token keywords indicating genuine mining, minting, PoW, or reward claims
MINING_TOKENS = {
    "mine", "miner", "mining", "mint", "minter", "safemint", "minttokens",
    "claim", "claimreward", "claimrewards", "claimtokens", "claimmintreward",
    "claimmintrewardandshare", "harvest", "dig", "drill", "glaze", "forge",
    "hatch", "prove", "provepossession", "sealepoch", "submitepoch",
    "nonce", "pow", "difficulty", "grid", "checkpoint", "automate",
    "hash", "giver", "reward", "stake",
}

POW_STRICT_TOKENS = {
    "mine", "miner", "mining", "dig", "drill", "glaze", "nonce", "pow",
    "difficulty", "prove", "provepossession", "sealepoch", "submitepoch",
    "grid", "checkpoint", "automate", "giver",
}

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
}


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

    # Explicit exclusion if every decoded function is routine DEX/ERC20/oracle/bridge noise
    non_noise_fns = [f for f in fn_names if f not in NOISE_FUNC_NAMES and not f.startswith("0x")]
    has_only_noise = bool(fn_names) and all(
        (f in NOISE_FUNC_NAMES or (f.startswith("0x") and len(fn_names) == 1))
        for f in fn_names
    ) and not (all_tokens & MINING_TOKENS)

    # Filter out single-caller admin/owner/bridge mints unless strict PoW signals exist
    has_pow_strict = bool(all_tokens & POW_STRICT_TOKENS)
    is_admin_only = (
        bool(fn_names)
        and all(any(f.startswith(p) for p in ADMIN_NOISE_PREFIXES) for f in fn_names)
        and not has_pow_strict
    )
    if is_admin_only or (unique_callers <= 1 and not has_pow_strict and mint_events < 3):
        return False, "", ""

    mining_hits = sorted(all_tokens & MINING_TOKENS)
    if mining_hits:
        if has_pow_strict:
            return True, "PoW / Hash & Epoch Mining", f"ABI Tokens: {', '.join(mining_hits[:4])}"
        return True, "On-Chain Mint / Claim Mining", f"ABI Tokens: {', '.join(mining_hits[:4])}"

    # Multi-caller Mint(Transfer 0x0) pattern ONLY when not known pure ERC20 approve/transfer noise
    only_erc20_ops = bool(fn_names) and all(f in NOISE_FUNC_NAMES for f in fn_names)
    if mint_events >= 2 and unique_callers >= 2 and not only_erc20_ops and not has_only_noise:
        return True, "Multi-Caller Public Mint", f"{mint_events} Mint Events ({unique_callers} Callers)"

    if non_noise_fns and mint_events >= 1 and not only_erc20_ops:
        return True, "Contract Mint Activity", f"{mint_events} Mint Events"

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
