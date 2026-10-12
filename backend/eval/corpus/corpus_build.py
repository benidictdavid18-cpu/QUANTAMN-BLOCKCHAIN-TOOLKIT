"""
Stage 1 of the independent-corpus harness: acquire contracts and generate
candidate lines for blind human adjudication.

Two things must be true for the resulting corpus to support an accuracy claim,
and both are properties of this script rather than of the labelling:

  1. The sampling frame is documented and not chosen by us. Contracts come from
     creation transactions in a randomly selected range of recent blocks, so we
     do not pick which contracts enter the corpus.

  2. The candidate set is a SUPERSET of anything the detector under test can
     report. Candidate generation here is deliberately cruder than the detector:
     bare case-insensitive substrings, no word boundaries, no comment masking,
     no deduplication. Every line the detector could flag is therefore offered
     to the annotator, which is what makes detector false negatives measurable.

The annotator never sees detector output. This script does not import the
detector at all, by design.

Residual limitation, to be stated in any paper using this corpus: a line that
implements a vulnerable primitive with no lexical trace of its name -- a
hand-rolled modular exponentiation, say -- is invisible to the candidate
generator as well as to the detector, so recall is measured against
lexically-signalled call sites rather than against all cryptography.

Usage
-----
    export ETHERSCAN_API_KEY=<key>          # free tier is sufficient
    python corpus/corpus_build.py --target 40
    python corpus/corpus_build.py --addresses my_addresses.txt

Outputs
-------
    corpus/sources/<address>__<name>.sol    verified source, one file per unit
    corpus/candidates.json                  candidate lines for labelling
    corpus/sampling.json                    the frame, for the methods section
"""
import argparse
import json
import os
import random
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(HERE, "sources")

ETHERSCAN = "https://api.etherscan.io/v2/api"
PUBLIC_RPC = os.getenv("WEB3_RPC_URL", "https://ethereum-rpc.publicnode.com")
CHAIN_ID = 1

# Free-tier Etherscan allows 5 calls/second. Stay well under it.
RATE_DELAY = 0.25

# ---------------------------------------------------------------------------
# Candidate generation
#
# These are intentionally crude. Each is a bare case-insensitive substring with
# no boundaries, so it over-matches by construction: "rsa" fires on
# "rsa_config", "dh" fires on "bandwidth", "aes" fires on "aesthetic". That is
# the point -- the annotator decides, and over-matching costs annotator time
# while under-matching would silently cap measured recall.
# ---------------------------------------------------------------------------
CANDIDATE_TERMS = [
    # ECDSA / elliptic curve
    "ecdsa", "ecrecover", "secp256k1", "elliptic", "signingkey", "eth_keys",
    "recoversigner", "tryrecover", "signature",
    # RSA / factorisation
    "rsa", "pkcs", "modexp", "publickey", "privatekey",
    # hashing
    "sha256", "sha-256", "sha2", "keccak", "sha3", "ripemd",
    # key agreement
    "diffie", "hellman", "ecdh", "dh", "keyexchange", "key_exchange",
    # symmetric
    "aes", "rijndael", "mode_", "gcm", "cbc", "ecb",
    # post-quantum, so an annotator can mark already-migrated code
    "dilithium", "kyber", "sphincs", "ml-dsa", "ml_dsa", "ml-kem", "ml_kem",
    "falcon", "xmss", "lms",
]

CANDIDATE_RE = re.compile("|".join(re.escape(t) for t in CANDIDATE_TERMS), re.IGNORECASE)

CONTEXT_LINES = 3


def _get(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "pq-corpus-builder/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _rpc(method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        PUBLIC_RPC,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "pq-corpus-builder/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def latest_block() -> int:
    res = _rpc("eth_blockNumber", [])
    return int(res["result"], 16)


def sample_created_addresses(target: int, lookback_blocks: int, seed: int) -> tuple:
    """
    Draw contract addresses from creation transactions in randomly chosen blocks
    within the last `lookback_blocks`. Returns (addresses, frame_description).

    Choosing blocks at random rather than taking a contiguous recent run avoids
    coupling the sample to whatever was being deployed in one short window.
    """
    rng = random.Random(seed)
    head = latest_block()
    low = max(1, head - lookback_blocks)

    tried_blocks = []
    addresses = []
    seen = set()

    # Each creation tx needs one receipt lookup to learn the deployed address,
    # so request a generous multiple of the target to survive the verified filter.
    while len(addresses) < target * 6 and len(tried_blocks) < 400:
        bn = rng.randint(low, head)
        if bn in tried_blocks:
            continue
        tried_blocks.append(bn)

        try:
            blk = _rpc("eth_getBlockByNumber", [hex(bn), True]).get("result")
        except Exception as e:
            print(f"  block {bn}: {e}", file=sys.stderr)
            continue
        if not blk:
            continue

        for tx in blk.get("transactions", []):
            if tx.get("to") is not None:
                continue  # not a contract creation
            try:
                rc = _rpc("eth_getTransactionReceipt", [tx["hash"]]).get("result")
            except Exception:
                continue
            addr = (rc or {}).get("contractAddress")
            if addr and addr.lower() not in seen:
                seen.add(addr.lower())
                addresses.append(addr)

        print(f"  scanned block {bn}: {len(addresses)} creations so far", file=sys.stderr)

    frame = {
        "method": "random blocks from the recent chain head, contract-creation txs",
        "head_block": head,
        "lookback_blocks": lookback_blocks,
        "blocks_sampled": sorted(tried_blocks),
        "seed": seed,
        "creations_found": len(addresses),
    }
    return addresses, frame


# ---------------------------------------------------------------------------
# Source retrieval
# ---------------------------------------------------------------------------

def fetch_source(address: str, api_key: str) -> list:
    """
    Return [(unit_name, source_text)] for a verified contract, or [] if the
    contract is unverified. Etherscan returns either a plain source string or,
    for multi-file builds, a standard-JSON-input blob wrapped in {{...}}.
    """
    q = urllib.parse.urlencode({
        "chainid": CHAIN_ID,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    })
    data = _get(f"{ETHERSCAN}?{q}")

    if str(data.get("status")) != "1" or not data.get("result"):
        return []

    entry = data["result"][0]
    raw = (entry.get("SourceCode") or "").strip()
    name = (entry.get("ContractName") or "Contract").strip() or "Contract"
    if not raw:
        return []

    # Multi-file: standard JSON input, double-brace wrapped
    if raw.startswith("{{") and raw.endswith("}}"):
        try:
            parsed = json.loads(raw[1:-1])
        except json.JSONDecodeError:
            return [(name, raw)]
        units = []
        for path, obj in (parsed.get("sources") or {}).items():
            content = obj.get("content") if isinstance(obj, dict) else None
            if content:
                units.append((os.path.basename(path) or name, content))
        return units or [(name, raw)]

    # Occasionally a bare JSON object with a sources map
    if raw.startswith("{") and '"sources"' in raw[:400]:
        try:
            parsed = json.loads(raw)
            units = []
            for path, obj in (parsed.get("sources") or {}).items():
                content = obj.get("content") if isinstance(obj, dict) else None
                if content:
                    units.append((os.path.basename(path) or name, content))
            if units:
                return units
        except json.JSONDecodeError:
            pass

    return [(name, raw)]


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:60]


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

def candidates_for(rel_path: str, text: str) -> list:
    """One candidate per matching LINE (not per match), with surrounding context."""
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines, start=1):
        if not CANDIDATE_RE.search(line):
            continue
        lo = max(0, i - 1 - CONTEXT_LINES)
        hi = min(len(lines), i + CONTEXT_LINES)
        out.append({
            "file": rel_path,
            "line": i,
            "text": line.rstrip()[:400],
            "context": [
                {"n": n + 1, "t": lines[n].rstrip()[:200]}
                for n in range(lo, hi)
            ],
            "terms": sorted({m.group(0).lower() for m in CANDIDATE_RE.finditer(line)}),
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", type=int, default=40,
                    help="number of verified contracts to collect (default 40)")
    ap.add_argument("--lookback", type=int, default=200000,
                    help="how many recent blocks form the sampling frame")
    ap.add_argument("--seed", type=int, default=20261012,
                    help="RNG seed; record it in the paper for reproducibility")
    ap.add_argument("--addresses", metavar="FILE",
                    help="skip block sampling; read one address per line")
    ap.add_argument("--max-lines", type=int, default=1200,
                    help="skip source units longer than this, to bound annotator effort")
    args = ap.parse_args()

    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        print("ETHERSCAN_API_KEY is not set. Get a free key at "
              "https://etherscan.io/apis and export it.", file=sys.stderr)
        return 2

    os.makedirs(SRC_DIR, exist_ok=True)

    # --- choose addresses -------------------------------------------------
    if args.addresses:
        with open(args.addresses, encoding="utf-8") as f:
            addresses = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        frame = {
            "method": "author-supplied address list",
            "source_file": os.path.basename(args.addresses),
            "count": len(addresses),
            "note": "Document how this list was produced; it is the sampling frame.",
        }
        print(f"Using {len(addresses)} supplied addresses.", file=sys.stderr)
    else:
        print(f"Sampling contract creations from the last {args.lookback} blocks "
              f"(seed {args.seed})...", file=sys.stderr)
        addresses, frame = sample_created_addresses(args.target, args.lookback, args.seed)
        print(f"Found {len(addresses)} created contracts.", file=sys.stderr)

    # --- fetch verified sources ------------------------------------------
    collected = []
    unverified = 0
    print("\nFetching verified sources...", file=sys.stderr)

    for addr in addresses:
        if len(collected) >= args.target:
            break
        time.sleep(RATE_DELAY)
        try:
            units = fetch_source(addr, api_key)
        except Exception as e:
            print(f"  {addr[:12]}... error: {e}", file=sys.stderr)
            continue
        if not units:
            unverified += 1
            continue

        kept = []
        for unit_name, text in units:
            n_lines = text.count("\n") + 1
            if n_lines > args.max_lines:
                continue
            fname = f"{addr.lower()}__{_safe(unit_name)}"
            if not fname.endswith(".sol"):
                fname += ".sol"
            with open(os.path.join(SRC_DIR, fname), "w", encoding="utf-8") as f:
                f.write(text)
            kept.append({"unit": unit_name, "file": fname, "lines": n_lines})

        if kept:
            collected.append({"address": addr, "units": kept})
            print(f"  [{len(collected):>3}/{args.target}] {addr[:12]}... "
                  f"{len(kept)} unit(s)", file=sys.stderr)

    if not collected:
        print("\nNo verified contracts collected. Check the API key and try a "
              "larger --lookback.", file=sys.stderr)
        return 1

    # --- generate candidates ---------------------------------------------
    print("\nGenerating candidate lines...", file=sys.stderr)
    candidates = []
    cid = 0
    for c in collected:
        for unit in c["units"]:
            path = os.path.join(SRC_DIR, unit["file"])
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for cand in candidates_for(unit["file"], text):
                cid += 1
                cand["cid"] = cid
                cand["address"] = c["address"]
                candidates.append(cand)

    total_lines = sum(u["lines"] for c in collected for u in c["units"])
    frame.update({
        "contracts_collected": len(collected),
        "source_units": sum(len(c["units"]) for c in collected),
        "total_lines": total_lines,
        "unverified_skipped": unverified,
        "max_lines_per_unit": args.max_lines,
        "candidate_terms": CANDIDATE_TERMS,
        "candidate_lines": len(candidates),
    })

    with open(os.path.join(HERE, "sampling.json"), "w", encoding="utf-8") as f:
        json.dump(frame, f, indent=2)

    with open(os.path.join(HERE, "candidates.json"), "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sampling": frame,
            "candidates": candidates,
        }, f, indent=2)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Contracts:       {len(collected)}", file=sys.stderr)
    print(f"Source units:    {frame['source_units']}", file=sys.stderr)
    print(f"Lines of code:   {total_lines}", file=sys.stderr)
    print(f"Candidate lines: {len(candidates)}", file=sys.stderr)
    print(f"Unverified:      {unverified} skipped", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print("\nNext: python corpus/label.py --annotator <your-initials>", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
