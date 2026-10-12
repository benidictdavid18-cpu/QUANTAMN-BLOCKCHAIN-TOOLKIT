"""
Stage 3 of the independent-corpus harness: agreement and accuracy.

Run only after labelling is complete. This is the first stage permitted to see
both the human labels and the detector output; stages 1 and 2 keep them apart
so that the comparison here is meaningful.

What it reports
---------------
  1. Inter-annotator agreement (Cohen's kappa) when two or more annotators
     labelled the same candidates. Kappa below about 0.6 means the labelling
     policy is ambiguous and the accuracy figures should not be trusted.

  2. Detector precision, recall and F1 against the adjudicated labels, overall
     and per algorithm family, with Wilson 95% confidence intervals. The
     intervals matter: on a few hundred candidates a point estimate alone
     invites over-reading.

  3. A disagreement listing, so every false positive and false negative can be
     inspected by hand rather than taken on trust.

Scoring rules
-------------
  - A candidate labelled with a family is a positive for that family.
  - A candidate labelled NONE or PQ is a negative: the detector should report
    nothing there.
  - Candidates labelled UNSURE are excluded from the primary figures and
    counted separately.
  - A detector finding on a line that was never a candidate should be
    impossible, since candidate generation is a strict superset. If one appears
    it is reported as a harness error, because the superset assumption has been
    violated and recall would be overstated.

Usage
-----
    python corpus/score_corpus.py
    python corpus/score_corpus.py --annotator ab      # score one annotator only
    python corpus/score_corpus.py --show-disagreements
"""
import argparse
import glob
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(HERE, "sources")
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))  # backend/

from crypto_scanner import CryptoScanner  # noqa: E402

FAMILIES = ["ECDSA", "RSA", "DH", "SHA256", "AES_SHORT"]


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval. Degrades gracefully at n = 0."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def cohen_kappa(a: dict, b: dict):
    """Kappa over the candidates both annotators labelled."""
    shared = sorted(set(a) & set(b))
    if not shared:
        return None, 0, 0.0
    cats = sorted({a[c] for c in shared} | {b[c] for c in shared})
    n = len(shared)
    agree = sum(1 for c in shared if a[c] == b[c])
    po = agree / n
    pe = 0.0
    for cat in cats:
        pa = sum(1 for c in shared if a[c] == cat) / n
        pb = sum(1 for c in shared if b[c] == cat) / n
        pe += pa * pb
    kappa = (po - pe) / (1 - pe) if (1 - pe) > 1e-12 else 1.0
    return kappa, n, po


def kappa_reading(k):
    if k is None:
        return "not computable"
    if k < 0.20:
        return "poor -- the policy is not usable as written"
    if k < 0.40:
        return "fair -- clarify the policy before relying on these labels"
    if k < 0.60:
        return "moderate -- borderline; report with caution"
    if k < 0.80:
        return "substantial -- acceptable for publication"
    return "almost perfect"


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load_label_sets(only=None):
    sets = {}
    for path in sorted(glob.glob(os.path.join(HERE, "labels_*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        name = data.get("annotator") or os.path.basename(path)
        if only and name != only:
            continue
        sets[name] = {cid: rec["verdict"] for cid, rec in data["labels"].items()}
    return sets


def adjudicate(sets):
    """
    Merge annotators. Unanimous verdicts stand. Disagreements become UNSURE and
    are excluded from the primary score rather than silently resolved by
    majority, which would manufacture confidence the data does not support.
    """
    merged = {}
    conflicts = []
    all_cids = set()
    for s in sets.values():
        all_cids |= set(s)

    for cid in all_cids:
        votes = {name: s[cid] for name, s in sets.items() if cid in s}
        distinct = set(votes.values())
        if len(distinct) == 1:
            merged[cid] = next(iter(distinct))
        else:
            merged[cid] = "UNSURE"
            conflicts.append((cid, votes))
    return merged, conflicts


def detector_findings():
    """(file, line) -> set of families the detector reports."""
    scanner = CryptoScanner()
    out = defaultdict(set)
    files = sorted(glob.glob(os.path.join(SRC_DIR, "*.sol")))
    for path in files:
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        scan = scanner.scan_file(name, text)
        for v in scan["vulnerabilities"]:
            out[(name, v["line_number"])].add(v["algorithm"])
    return out, len(files)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--annotator", help="score a single annotator's labels")
    ap.add_argument("--show-disagreements", action="store_true",
                    help="list every false positive and false negative")
    args = ap.parse_args()

    cand_path = os.path.join(HERE, "candidates.json")
    if not os.path.exists(cand_path):
        print("candidates.json not found. Run corpus_build.py first.", file=sys.stderr)
        return 2
    with open(cand_path, encoding="utf-8") as f:
        blob = json.load(f)
    candidates = {str(c["cid"]): c for c in blob["candidates"]}
    candidate_keys = {(c["file"], c["line"]) for c in candidates.values()}

    sets = load_label_sets(args.annotator)
    if not sets:
        print("No labels_*.json found. Run label.py first.", file=sys.stderr)
        return 2

    # --- agreement --------------------------------------------------------
    names = sorted(sets)
    agreement = None
    print("\n" + "=" * 68)
    print("  INTER-ANNOTATOR AGREEMENT")
    print("=" * 68)
    if len(names) < 2:
        print(f"  Only one annotator ('{names[0]}'). Agreement not computable.")
        print("  A second independent annotator is needed for a publishable")
        print("  reliability figure.")
    else:
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                k, n, po = cohen_kappa(sets[names[i]], sets[names[j]])
                if k is None:
                    print(f"  {names[i]} vs {names[j]}: no shared candidates")
                    continue
                print(f"  {names[i]} vs {names[j]}:  n={n}  "
                      f"observed={po:.3f}  kappa={k:.3f}")
                print(f"      {kappa_reading(k)}")
                if agreement is None:
                    agreement = {"pair": [names[i], names[j]], "n": n,
                                 "observed": round(po, 4),
                                 "cohen_kappa": round(k, 4)}

    merged, conflicts = adjudicate(sets)
    if conflicts:
        print(f"\n  {len(conflicts)} candidate(s) disagreed on -> excluded as UNSURE")

    # --- detector ---------------------------------------------------------
    found, n_files = detector_findings()

    labelled = {}
    for cid, verdict in merged.items():
        c = candidates.get(cid)
        if c:
            labelled[(c["file"], c["line"])] = verdict

    per = {f: {"tp": 0, "fp": 0, "fn": 0} for f in FAMILIES}
    unsure = sum(1 for v in merged.values() if v == "UNSURE")
    fps, fns = [], []

    for key, verdict in labelled.items():
        if verdict == "UNSURE":
            continue
        predicted = found.get(key, set())
        truth = {verdict} if verdict in FAMILIES else set()

        for fam in predicted - truth:
            if fam in per:
                per[fam]["fp"] += 1
                fps.append((key, fam, verdict))
        for fam in predicted & truth:
            per[fam]["tp"] += 1
        for fam in truth - predicted:
            per[fam]["fn"] += 1
            fns.append((key, fam))

    # superset assumption: every detector finding must sit on a candidate line
    superset_violations = [
        (key, sorted(fams)) for key, fams in found.items() if key not in candidate_keys
    ]

    # --- report -----------------------------------------------------------
    print("\n" + "=" * 68)
    print("  CORPUS")
    print("=" * 68)
    print(f"  Source units:      {n_files}")
    print(f"  Candidate lines:   {len(candidates)}")
    print(f"  Labelled:          {len(merged)}")
    print(f"  Excluded (unsure): {unsure}")
    print(f"  Scored:            {len(merged) - unsure}")

    print("\n" + "=" * 68)
    print("  DETECTOR ACCURACY vs INDEPENDENT LABELS")
    print("=" * 68)
    print("| Family    |  TP |  FP |  FN | Prec. | Rec.  |  F1   | Prec. 95% CI   |")
    print("|-----------|----:|----:|----:|------:|------:|------:|----------------|")

    out_per = {}
    for fam in FAMILIES:
        c = per[fam]
        p, r, f = prf(c["tp"], c["fp"], c["fn"])
        lo, hi = wilson(c["tp"], c["tp"] + c["fp"])
        out_per[fam] = {**c, "precision": round(p, 4), "recall": round(r, 4),
                        "f1": round(f, 4), "precision_ci95": [round(lo, 4), round(hi, 4)]}
        print(f"| {fam:<9} | {c['tp']:>3} | {c['fp']:>3} | {c['fn']:>3} "
              f"| {p:>5.3f} | {r:>5.3f} | {f:>5.3f} | [{lo:.3f}, {hi:.3f}] |")

    TP = sum(per[f]["tp"] for f in FAMILIES)
    FP = sum(per[f]["fp"] for f in FAMILIES)
    FN = sum(per[f]["fn"] for f in FAMILIES)
    P, R, F = prf(TP, FP, FN)
    plo, phi = wilson(TP, TP + FP)
    rlo, rhi = wilson(TP, TP + FN)

    print(f"| {'OVERALL':<9} | {TP:>3} | {FP:>3} | {FN:>3} "
          f"| {P:>5.3f} | {R:>5.3f} | {F:>5.3f} | [{plo:.3f}, {phi:.3f}] |")
    print(f"\n  Precision 95% CI: [{plo:.3f}, {phi:.3f}]")
    print(f"  Recall    95% CI: [{rlo:.3f}, {rhi:.3f}]")

    if superset_violations:
        print(f"\n  HARNESS ERROR: {len(superset_violations)} detector finding(s) "
              "fell outside the candidate set.")
        print("  The candidate generator is not a superset of the detector. Add the")
        print("  missing term(s) to CANDIDATE_TERMS in corpus_build.py and relabel.")
        for key, fams in superset_violations[:10]:
            print(f"    {key[0]}:{key[1]} -> {fams}")

    if args.show_disagreements:
        if fps:
            print(f"\n  FALSE POSITIVES ({len(fps)})")
            for (fname, ln), fam, truth in fps[:60]:
                print(f"    {fname}:{ln}  predicted {fam}, labelled {truth}")
        if fns:
            print(f"\n  FALSE NEGATIVES ({len(fns)})")
            for (fname, ln), fam in fns[:60]:
                print(f"    {fname}:{ln}  missed {fam}")
        if not fps and not fns:
            print("\n  No disagreements.")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "annotators": names,
        "agreement": agreement,
        "corpus": {
            "source_units": n_files,
            "candidate_lines": len(candidates),
            "labelled": len(merged),
            "excluded_unsure": unsure,
            "scored": len(merged) - unsure,
        },
        "per_family": out_per,
        "overall": {
            "tp": TP, "fp": FP, "fn": FN,
            "precision": round(P, 4), "recall": round(R, 4), "f1": round(F, 4),
            "precision_ci95": [round(plo, 4), round(phi, 4)],
            "recall_ci95": [round(rlo, 4), round(rhi, 4)],
        },
        "superset_violations": len(superset_violations),
        "false_positives": [{"file": k[0], "line": k[1], "predicted": fam, "labelled": t}
                            for k, fam, t in fps],
        "false_negatives": [{"file": k[0], "line": k[1], "missed": fam} for k, fam in fns],
    }

    out_path = os.path.join(HERE, "corpus_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  Written: {out_path}")

    if len(names) < 2:
        print("\n  NOTE: single annotator. Report this as a limitation; a")
        print("  reliability figure needs a second independent labeller.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
