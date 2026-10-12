# COMS2 2026 — submission checklist

Target: International Conference on Computing Science, Communication and
Security (COMS2), Ganpat University. Proceedings publish in Springer **CCIS**
(Communications in Computer and Information Science), which uses the Springer
**LNCS** LaTeX class.

**Full paper deadline: 25 October 2026.** Notification 25 Nov, camera-ready
1 Dec 2026.

Context for calibration: COMS2 2025 accepted 28 of 238 submissions (~12%).

---

## 1. Build it

1. Download the Springer LNCS LaTeX package (`llncs.cls`):
   https://www.springernature.com/gp/computer-science/lncs/conference-proceedings-guidelines
2. Put `llncs.cls` next to `coms2_paper.tex`.
3. `pdflatex coms2_paper` — run twice so `\ref` cross-references resolve.

No LaTeX locally? Upload `coms2_paper.tex` to Overleaf and pick the
*Springer LNCS* template — it ships `llncs.cls` already.

## 2. Fill the 17 placeholders

Every `<...>` must go. Search the file for `<`:

- author names, affiliations, emails
- **ORCID identifiers** — mandatory per the call for papers. Register free at
  https://orcid.org if you don't have one. Each author needs their own.
- acknowledgements (or delete that section)

## 3. Check the page count

The paper must be **12–15 pages**. Body text is ~6,500 words, which I estimate
at 15–17 pages once tables, the figure and references are set. **Verify the real
number after your first compile.**

If it runs over 15 pages, cut in this order — these are the least load-bearing
passages:

| Order | Cut | Approx. saving |
|---|---|---|
| 1 | §6.2 *Sector Applicability* entirely | ~190 words |
| 2 | §2.1 second paragraph (Grover detail, already in §1) | ~90 words |
| 3 | §5.1 the four positive-artefact descriptions → one sentence | ~110 words |
| 4 | §6.4 *Ethical Considerations* → 4 sentences | ~120 words |
| 5 | §4 stage paragraphs → a single paragraph, keep Fig. 1 | ~160 words |

Do **not** cut, in any circumstance:

- §5.3 the paragraph *"What these numbers do and do not establish"*
- §6.3 *Limitations and Threats to Validity*
- the hard-negative description in §5.1

Those three are what make the evaluation credible. A reviewer who sees
precision 1.000 with no acknowledgement of construct validity will reject the
paper. Cutting them to save space defeats the purpose of the submission.

If it runs **under** 12 pages, expand §7 Future Work with the corpus-sampling
protocol, and add a short subsection to §5 reporting per-artefact finding
counts.

## 4. Verify every citation

15 references. **Open each one and confirm it exists** before submitting. I
assembled them from knowledge of the literature and did not fetch any DOI while
drafting, so treat all 15 as unverified. The ones most worth double-checking:

- `nistir8547` — confirm whether it is still a draft, and get the exact title
- `crysl` — confirm journal, volume, year
- `webber2022` — confirm the qubit figure you quote matches the paper
- `cyclonedx` — cite the versioned spec, with the URL and access date

A fabricated or wrong citation found in review is worse than a missing one.

## 5. Plagiarism and AI-content policy — read this properly

The call requires: overall similarity **≤10%**, single-source **≤3%**, and
AI-generated content **≤20%**.

**The prose in `coms2_paper.tex` was written by an AI assistant. As it stands it
is 100% AI-generated and will not pass a 20% threshold.** No paraphrasing tool
changes that honestly, and "humanising" tools do not reliably fool current
detectors — they mainly degrade the writing.

What the draft actually is: a correct technical scaffold. The architecture, the
method, the measurements, the tables and the argument structure are all drawn
from your real code and real measured results. What it is not is your writing.

To submit this honestly, rewrite it section by section in your own words. That
is also the only approach that genuinely lowers a detector score. Practical
method:

1. Read a subsection, close the file, and write the same point from memory in
   your own phrasing. Don't edit the existing sentences — replace them.
2. Keep every number exactly as measured. Those are facts, not prose.
3. Add what only you can add: why you built it, what broke, what you tried that
   failed, how your institution's context shaped it. First-hand detail is the
   hardest thing for a detector to flag and the easiest thing for you to write.
4. Keep your own terminology where it differs.
5. Run your institution's similarity check **before** submitting, not after.

Sections where rewriting matters most, because they are the most obviously
machine-written: the Abstract, §1 Introduction, and §8 Conclusion. The tables,
equations and §5 Evaluation are mostly numbers and will read as yours once the
surrounding sentences are.

Also check whether COMS2 requires a disclosure statement for AI assistance.
Many Springer venues now do, and declaring tool use is usually permitted
whereas undeclared use is misconduct.

## 6. Reproducibility

The paper claims the artefacts are released. Before submitting, confirm:

- [ ] `backend/eval/` — benchmark, `ground_truth.json`, `run_eval.py`
- [ ] `python eval/run_eval.py` reproduces Table 3 exactly
- [ ] the risk-score figures in Table 4 reproduce
- [ ] repo URL in the paper resolves publicly
- [ ] live demo URL resolves

Current measured values the paper reports:

| Claim | Value | Source |
|---|---|---|
| Ablation v1 → v3 precision | 0.633 → 1.000 | `eval/results.json` |
| Recall, all configurations | 1.000 | `eval/results.json` |
| Raw hits v1 / v2 / v3 | 39 / 38 / 26 | `eval/results.json` |
| Benchmark size | 7 artefacts, 19 findings, 3 negatives | `ground_truth.json` |
| Python↔JS agreement | 7/7 artefacts, 6/6 fields | equivalence harness |
| Dev-scan mean under old score | 99.5 | 19 scan records |

## 7. Still missing for a strong submission

The honest gap: the evaluation is an ablation on a self-authored benchmark. If
you have time before 25 October, the single highest-value addition is an
independent corpus — 30 or more verified contracts pulled from Etherscan,
labelled by someone who did not write the detector. That converts Section 5
from "our mechanisms work on our data" into an accuracy estimate, and it is the
difference a reviewer will look for.
