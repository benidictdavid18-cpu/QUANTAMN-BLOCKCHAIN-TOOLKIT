# Independent corpus harness

The benchmark in `../benchmark/` was written by the same people who wrote the
detector. That makes it useful for an ablation — it shows each precision
mechanism removes the error class it targets — but useless as an accuracy
estimate, because the negatives were authored to exercise faults we had already
decided to fix. A reviewer will say so, and they will be right.

This harness produces the thing the ablation cannot: **detector accuracy against
labels the detector's authors did not create.**

---

## The design constraint that matters

**The annotator must never see the detector's output.** If the tool shows a
prediction and asks "is this correct?", the labels inherit the detector's
biases and the resulting accuracy figure is circular. `label.py` therefore does
not import the detector, and `corpus_build.py` does not either. Only
`score_corpus.py` sees both, and it runs after labelling is finished.

Second constraint: **the candidate set must be a superset of what the detector
can report.** A human cannot read forty contracts line by line for five
algorithm families, so some pre-filter is unavoidable. The filter in
`corpus_build.py` is deliberately cruder than the detector — bare
case-insensitive substrings, no word boundaries, no comment masking, no
deduplication — so `rsa` fires on `rsa_config`, `dh` fires on `bandwidth`, `aes`
fires on `aesthetic`. Over-matching costs annotator time; under-matching would
silently cap measured recall. `score_corpus.py` verifies the superset property
holds and reports a harness error if any detector finding falls outside the
candidate set.

---

## Running it

### Stage 1 — build the corpus

```bash
export ETHERSCAN_API_KEY=<free key from https://etherscan.io/apis>
cd backend
python corpus/corpus_build.py --target 40
```

Samples contract-creation transactions from randomly chosen blocks in the recent
chain, keeps the verified ones, and writes:

- `sources/<address>__<unit>.sol` — the verified source
- `candidates.json` — candidate lines with 3 lines of context either side
- `sampling.json` — the frame: head block, blocks sampled, seed, counts

Record the `--seed` in your paper. The frame is part of the methodology.

If you would rather supply your own addresses:

```bash
python corpus/corpus_build.py --addresses my_addresses.txt
```

Then document in the paper how that list was produced — a self-selected list is
a weaker frame than random block sampling, and a reviewer will ask.

### Stage 2 — blind labelling

```bash
python corpus/label.py --annotator ab
```

Shows one candidate at a time with context and asks what the line actually
invokes. Keys: `1`–`5` for the families, `n` for not-cryptographic, `p` for
post-quantum, `u` for unsure, `?` for the policy, `b` to go back, `q` to save
and quit. Progress saves after every decision, so it can be interrupted freely.

**Run it with two annotators**, each with a different `--annotator` value, to get
an agreement figure. A single annotator gives you no reliability measure and the
scorer will say so.

**Ideally neither annotator wrote the detector's pattern set.** If you must be
one of them, say so in the paper's limitations.

Afterwards, revisit the items you flagged:

```bash
python corpus/label.py --annotator ab --review
```

### Stage 3 — score

```bash
python corpus/score_corpus.py --show-disagreements
```

Reports:

- **Cohen's kappa** between annotators. Below ~0.6 means the labelling policy is
  ambiguous and the accuracy numbers should not be trusted — fix the policy and
  relabel rather than publishing them.
- **Precision, recall, F1** per family and overall, with **Wilson 95% confidence
  intervals**.
- Every false positive and false negative, so you can inspect them by hand.

Writes `corpus_results.json`.

---

## Read the confidence intervals, not the point estimates

This is the part most likely to save you in review. A self-test of the harness
over the 19 positives in the existing benchmark produced:

```
| Family    |  TP |  FP |  FN | Prec. | Prec. 95% CI   |
| ECDSA     |   4 |   0 |   0 | 1.000 | [0.510, 1.000] |
| AES_SHORT |   1 |   0 |   0 | 1.000 | [0.207, 1.000] |
| OVERALL   |  19 |   0 |   0 | 1.000 | [0.832, 1.000] |
```

A perfect 19 out of 19 only supports **precision ≥ 0.832** at 95% confidence.
A perfect 1 out of 1 supports **≥ 0.207**, which is to say nothing at all.

So quote intervals alongside every point estimate in the paper. And note the
practical consequence: to claim precision above 0.95 with a tight interval you
need on the order of 150+ labelled positives, which means considerably more than
40 contracts. Size the corpus to the claim you want to make.

---

## Effort estimate

The self-test produced 81 candidate lines from 7 short fixtures, roughly 11 per
file. Real contracts are longer, and `signature`, `keccak` and `dh` are common
substrings in Solidity, so expect **300–800 candidates from 40 contracts**.

At 10–20 seconds per decision that is **2–4 hours per annotator**, and you want
two. Budget a full day of someone's time. `--max-lines` bounds it by skipping
very long source units; lowering it trades corpus breadth for annotator hours.

---

## Honest limits of this corpus

State these in the paper. They are not fatal, but omitting them invites the
reviewer to find them for you.

1. **Lexically silent cryptography is invisible.** A hand-rolled modular
   exponentiation with no identifier naming RSA or Diffie–Hellman is missed by
   the candidate generator as well as by the detector. Measured recall is
   therefore recall over *lexically signalled* call sites, not over all
   cryptography. Say exactly that.

2. **The sampling frame is recent deployments.** Contracts created in the
   sampled block range skew toward whatever is currently being deployed — a lot
   of token and proxy boilerplate. That is a real population, but it is not
   "all Ethereum contracts", and it under-represents older high-value contracts.

3. **Solidity only.** `corpus_build.py` collects from Etherscan, so the corpus
   says nothing about the detector's accuracy on the Python, JavaScript and Go
   paths the tool also supports.

4. **Verified contracts only.** Unverified contracts have no source to analyse.
   The scorer reports how many were skipped for this reason; include that
   number, since it bounds how representative the corpus is.

5. **Disagreements are excluded, not resolved.** When annotators conflict, the
   item becomes UNSURE and leaves the primary score rather than being settled by
   majority vote. This avoids manufacturing confidence, but it means the scored
   subset is slightly easier than the full candidate set. Report the excluded
   count.

---

## Reporting it in the paper

If the corpus run succeeds, Section 5 of `paper/coms2_paper.tex` gains a second
evaluation and the framing changes substantially:

- Keep Table 3 (the ablation) — it still shows *why* the mechanisms work.
- Add a table of corpus results with confidence intervals — this is the
  accuracy claim.
- Report corpus size, candidate count, annotator count and kappa in the
  Benchmark Construction subsection.
- Rewrite the paragraph *"What these numbers do and do not establish"*: the
  construct-validity caveat still applies to the ablation, but no longer to the
  headline result. That is the single biggest strengthening available to this
  paper.
- Move the lexically-silent-cryptography limitation into Threats to Validity
  under external validity.
