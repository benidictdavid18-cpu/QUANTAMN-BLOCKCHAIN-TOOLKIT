"""
Evaluation harness for the quantum-vulnerable cryptography scanner.

Scores detector output against the hand-labelled benchmark in
eval/ground_truth.json and prints a precision/recall/F1 table.

A prediction is a true positive only when BOTH the line number and the
algorithm family match a label. This is deliberately strict: reporting the
right family on the wrong line is not actionable for a migration engineer.

Three configurations are scored so the effect of each mechanism is visible:

  v1-baseline     original pattern set, raw text, no deduplication
  v2-boundaries   word-bounded pattern set, raw text, no deduplication
  v3-full         word-bounded patterns + comment/string masking + dedup
                  (this is what the shipped scanner does)

Usage:
    python eval/run_eval.py            # from the backend/ directory
    python eval/run_eval.py --json     # machine-readable only
"""
import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_scanner import CryptoScanner, _mask_noncode  # noqa: E402

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH_DIR = os.path.join(EVAL_DIR, "benchmark")

# The pattern set as originally shipped, kept verbatim so the ablation measures
# a real historical configuration rather than a reconstruction.
V1_PATTERNS: Dict[str, List[str]] = {
    "ECDSA": [
        r"ecrecover\s*\(",
        r"ECDSA\s*\.",
        r"secp256k1",
        r"elliptic\.curve",
        r"from\s+ecdsa\s+import",
        r"eth_keys\.keys",
        r"Web3\.eth\.account",
    ],
    "RSA": [
        r"RSA\s*\.",
        r"rsa\.newkeys",
        r"from\s+Crypto\.PublicKey\s+import\s+RSA",
        r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa",
    ],
    "SHA256": [
        r"sha256\s*\(",
        r"keccak256\s*\(",
        r"hashlib\.sha256",
        r"SHA256\s*\.",
    ],
    "DH": [
        r"Diffie.*Hellman",
        r"dh\s*\.",
        r"diffie_hellman",
    ],
    "AES_SHORT": [
        r"AES\.new\(.*?,\s*AES\.MODE_",
        r"aes-128",
        r"AES-128",
    ],
}

Finding = Tuple[int, str]  # (line_number, algorithm)


def _match(content: str, patterns: Dict[str, List[str]], mask: bool) -> Set[Finding]:
    """
    Run one detector configuration and return its distinct findings.

    Set semantics collapse repeated (line, algorithm) pairs, which is exactly
    the deduplication step under test; the duplicate-sensitive totals are
    reported separately by _raw_count.
    """
    haystack = _mask_noncode(content) if mask else content
    hits: Set[Finding] = set()
    for algo, pattern_list in patterns.items():
        for pattern in pattern_list:
            for m in re.finditer(pattern, haystack, re.IGNORECASE):
                line = haystack[:m.start()].count("\n") + 1
                hits.add((line, algo))
    return hits


def _raw_count(content: str, patterns: Dict[str, List[str]], mask: bool) -> int:
    """Total regex hits before any collapsing - the number the v1 tool reported."""
    haystack = _mask_noncode(content) if mask else content
    return sum(
        len(re.findall(pattern, haystack, re.IGNORECASE))
        for pattern_list in patterns.values()
        for pattern in pattern_list
    )


def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def _score(predictions: Dict[str, Set[Finding]], labels: Dict[str, List[dict]]) -> dict:
    """Aggregate per-algorithm and overall confusion counts."""
    per_algo = {a: {"tp": 0, "fp": 0, "fn": 0} for a in sorted(V1_PATTERNS)}

    for filename, truth_entries in labels.items():
        truth: Set[Finding] = {(e["line"], e["algorithm"]) for e in truth_entries}
        predicted = predictions.get(filename, set())

        for finding in predicted - truth:
            per_algo.setdefault(finding[1], {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
        for finding in predicted & truth:
            per_algo[finding[1]]["tp"] += 1
        for finding in truth - predicted:
            per_algo[finding[1]]["fn"] += 1

    for counts in per_algo.values():
        p, r, f = _prf(counts["tp"], counts["fp"], counts["fn"])
        counts.update(precision=p, recall=r, f1=f)

    tp = sum(c["tp"] for c in per_algo.values())
    fp = sum(c["fp"] for c in per_algo.values())
    fn = sum(c["fn"] for c in per_algo.values())
    p, r, f = _prf(tp, fp, fn)

    return {
        "per_algorithm": per_algo,
        "overall": {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f},
    }


def main() -> int:
    with open(os.path.join(EVAL_DIR, "ground_truth.json"), "r", encoding="utf-8") as f:
        labels = json.load(f)["files"]

    sources: Dict[str, str] = {}
    for filename in labels:
        path = os.path.join(BENCH_DIR, filename)
        if not os.path.exists(path):
            print(f"MISSING benchmark file: {filename}", file=sys.stderr)
            return 1
        with open(path, "r", encoding="utf-8") as f:
            sources[filename] = f.read()

    scanner = CryptoScanner()
    v3_patterns = {a: d["patterns"] for a, d in scanner.vulnerable_patterns.items()}

    configs = {
        "v1-baseline": (V1_PATTERNS, False),
        "v2-boundaries": (v3_patterns, False),
        "v3-full": (v3_patterns, True),
    }

    results = {}
    raw_totals = {}
    for name, (patterns, mask) in configs.items():
        predictions = {
            filename: _match(content, patterns, mask)
            for filename, content in sources.items()
        }
        results[name] = _score(predictions, labels)
        raw_totals[name] = sum(_raw_count(c, patterns, mask) for c in sources.values())

    # Cross-check: the shipped scanner must agree with the v3 configuration.
    shipped = {}
    for filename, content in sources.items():
        scan = scanner.scan_file(filename, content)
        shipped[filename] = {(v["line_number"], v["algorithm"]) for v in scan["vulnerabilities"]}
    shipped_score = _score(shipped, labels)
    agrees = shipped_score["overall"] == results["v3-full"]["overall"]

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "benchmark_files": len(sources),
        "labelled_findings": sum(len(v) for v in labels.values()),
        "configs": results,
        "raw_match_totals": raw_totals,
        "shipped_scanner_matches_v3": agrees,
    }

    out_path = os.path.join(EVAL_DIR, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    if "--json" in sys.argv:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"\nBenchmark: {len(sources)} files, {payload['labelled_findings']} labelled findings")
    print(f"Negative (zero-label) files: {sum(1 for v in labels.values() if not v)}\n")

    print("Overall, by configuration")
    print("| Configuration | TP | FP | FN | Precision | Recall |    F1 | Raw hits |")
    print("|---------------|---:|---:|---:|----------:|-------:|------:|---------:|")
    for name in configs:
        o = results[name]["overall"]
        print(
            f"| {name:<13} | {o['tp']:>2} | {o['fp']:>2} | {o['fn']:>2} "
            f"| {o['precision']:>9.3f} | {o['recall']:>6.3f} | {o['f1']:>5.3f} | {raw_totals[name]:>8} |"
        )

    print("\nPer algorithm (v3-full, as shipped)")
    print("| Algorithm | TP | FP | FN | Precision | Recall |    F1 |")
    print("|-----------|---:|---:|---:|----------:|-------:|------:|")
    for algo, c in sorted(results["v3-full"]["per_algorithm"].items()):
        print(
            f"| {algo:<9} | {c['tp']:>2} | {c['fp']:>2} | {c['fn']:>2} "
            f"| {c['precision']:>9.3f} | {c['recall']:>6.3f} | {c['f1']:>5.3f} |"
        )

    print(f"\nShipped scanner agrees with v3-full: {agrees}")
    print(f"Written: {out_path}\n")

    if not agrees:
        print("WARNING: the shipped scanner and the v3 configuration disagree.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
