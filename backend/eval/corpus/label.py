"""
Stage 2 of the independent-corpus harness: blind human adjudication.

This tool shows the annotator one candidate line at a time, with surrounding
context, and asks what cryptography that line actually invokes. It NEVER shows
the detector's prediction, and it does not import the detector. That is the
whole point: if the annotator can see what the tool guessed, the labels inherit
the tool's biases and the resulting accuracy figure means nothing.

For the same reason, the person labelling should ideally not be the person who
wrote the detector's pattern set.

Progress is saved after every decision, so the session can be interrupted and
resumed. Run it twice with two different annotators to obtain an
inter-annotator agreement figure, which score_corpus.py computes.

Usage
-----
    python corpus/label.py --annotator ab
    python corpus/label.py --annotator ab --review      # revisit UNSURE items

Output
------
    corpus/labels_<annotator>.json
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

VERDICTS = {
    "1": ("ECDSA", "ECDSA / elliptic-curve signature or recovery"),
    "2": ("RSA", "RSA encryption, signature or key generation"),
    "3": ("DH", "Diffie-Hellman or ECDH key agreement"),
    "4": ("SHA256", "SHA-256 or Keccak-256 hashing"),
    "5": ("AES_SHORT", "AES with a 128-bit key, or an unauthenticated mode"),
    "n": ("NONE", "Not a cryptographic call site"),
    "p": ("PQ", "Post-quantum primitive (already migrated)"),
    "u": ("UNSURE", "Cannot determine -- flag for adjudication"),
}

GUIDANCE = """
LABELLING POLICY  (identical to backend/eval/ground_truth.json)

  Label the FAMILY when the line is an ACTIVE CALL SITE or an IMPORT of a
  vulnerable primitive. An import counts: it is part of the migration surface.
  A function definition counts when its body implements the primitive.

  Label NONE when:
    - the name appears only in a comment, docstring or string literal
    - the identifier merely contains the name as a substring
      (bandwidth, sha256_cache, rsa_config_path, aesthetic)
    - the line declares a type, event or variable without invoking anything

  Label PQ for post-quantum primitives (Dilithium, Kyber, SPHINCS+, ML-DSA,
  ML-KEM, Falcon, XMSS, LMS).

  Label UNSURE rather than guessing. Unsure items are excluded from the primary
  score and reported separately.

  Judge the LINE SHOWN, using the context only to understand it.
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_candidates():
    path = os.path.join(HERE, "candidates.json")
    if not os.path.exists(path):
        print("candidates.json not found. Run corpus_build.py first.", file=sys.stderr)
        sys.exit(2)
    with open(path, encoding="utf-8") as f:
        return json.load(f)["candidates"]


def load_labels(annotator):
    path = os.path.join(HERE, f"labels_{annotator}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"annotator": annotator, "started_at": _now(), "updated_at": _now(), "labels": {}}


def save_labels(annotator, state):
    state["updated_at"] = _now()
    path = os.path.join(HERE, f"labels_{annotator}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def show(cand, done, total):
    pct = (done / total * 100) if total else 0
    print("\n" + "=" * 72)
    print(f"  {done + 1} of {total}   ({pct:.0f}% complete)")
    print(f"  {cand['file']}  line {cand['line']}")
    print("=" * 72)

    for c in cand["context"]:
        marker = ">>" if c["n"] == cand["line"] else "  "
        print(f" {marker} {c['n']:>5} | {c['t']}")

    print("-" * 72)
    print("  " + "  ".join(f"[{k}] {v[0]}" for k, v in VERDICTS.items()))
    print("  [?] policy   [b] back   [q] save and quit")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--annotator", required=True,
                    help="short identifier, e.g. initials. Keeps label files separate.")
    ap.add_argument("--review", action="store_true",
                    help="revisit only items previously marked UNSURE")
    args = ap.parse_args()

    candidates = load_candidates()
    state = load_labels(args.annotator)
    labels = state["labels"]

    if args.review:
        queue = [c for c in candidates if labels.get(str(c["cid"]), {}).get("verdict") == "UNSURE"]
        if not queue:
            print("No UNSURE items to review.")
            return 0
        print(f"Reviewing {len(queue)} UNSURE item(s).")
    else:
        queue = [c for c in candidates if str(c["cid"]) not in labels]

    total_all = len(candidates)
    if not queue:
        print(f"\nAll {total_all} candidates already labelled by '{args.annotator}'.")
        print("Next: python corpus/score_corpus.py")
        return 0

    print(GUIDANCE)
    print(f"{len(queue)} item(s) to label. Progress saves after every decision.")
    try:
        input("Press Enter to begin... ")
    except EOFError:
        print("\nThis tool needs an interactive terminal.", file=sys.stderr)
        return 2

    i = 0
    while i < len(queue):
        cand = queue[i]
        show(cand, len(labels), total_all)

        try:
            choice = input("  verdict > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nSaving and exiting.")
            break

        if choice == "q":
            print("Saved. Re-run the same command to resume.")
            break
        if choice == "?":
            print(GUIDANCE)
            continue
        if choice == "b":
            if i > 0:
                i -= 1
                labels.pop(str(queue[i]["cid"]), None)
                save_labels(args.annotator, state)
            else:
                print("  Already at the first item.")
            continue
        if choice not in VERDICTS:
            print("  Unrecognised key. Press ? for the policy.")
            continue

        verdict, _desc = VERDICTS[choice]
        labels[str(cand["cid"])] = {
            "verdict": verdict,
            "file": cand["file"],
            "line": cand["line"],
            "at": _now(),
        }
        save_labels(args.annotator, state)
        i += 1

    # summary
    counts = {}
    for rec in labels.values():
        counts[rec["verdict"]] = counts.get(rec["verdict"], 0) + 1

    print("\n" + "=" * 72)
    print(f"  Labelled {len(labels)} of {total_all} candidates as '{args.annotator}'")
    for v in ["ECDSA", "RSA", "DH", "SHA256", "AES_SHORT", "PQ", "NONE", "UNSURE"]:
        if counts.get(v):
            print(f"    {v:<11} {counts[v]:>4}")
    print("=" * 72)

    remaining = total_all - len(labels)
    if remaining:
        print(f"\n{remaining} remaining. Re-run to continue.")
    else:
        print("\nComplete. Next: python corpus/score_corpus.py")
        if counts.get("UNSURE"):
            print(f"Consider resolving {counts['UNSURE']} UNSURE item(s) first:")
            print(f"  python corpus/label.py --annotator {args.annotator} --review")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
