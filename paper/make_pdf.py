"""
Builds the conference paper as a PDF directly, with no LaTeX toolchain.

    python paper/make_pdf.py

Output: paper/Quantum_PQ_Blockchain_Paper.pdf  (+ paper/figures/*.png)

Structure follows the supplied template: Title, Abstract, Keywords, then
1 Introduction (problem statement, objectives, research questions, brief
description, contributions, remaining sections), 2 Related Work (review,
summary table, research gap), 3 Methodology (dataset, architecture + diagram,
algorithm, equations, experimental setup), 4 Results (metrics, performance
analysis, table, graphs, baseline comparison), 5 Discussion (answers to RQs,
comparison with previous studies), 6 Conclusion and Future Work (findings,
limitations, future scope), 7 References in IEEE style.

Every number is one measured in this project; see backend/eval/results.json.
Charts use the first three slots of a CVD-validated categorical palette with
direct value labels on every bar, so colour never carries the reading alone and
the figures survive greyscale printing.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, Image, KeepTogether)

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

# Validated categorical palette, slots 1-3 (CVD all-pairs dE 9.2 / normal 24.0)
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#8a8984"
SURFACE = "#fcfcfb"
GRID = "#e4e3df"

# ------------------------------- measured data ------------------------------
ABLATION = [
    ("v1-baseline",   19, 11, 0, 0.633, 1.000, 0.776, 39),
    ("v2-boundaries", 19, 11, 0, 0.633, 1.000, 0.776, 38),
    ("v3-full",       19,  0, 0, 1.000, 1.000, 1.000, 26),
]

PER_FAMILY = [
    ("ECDSA", 4, 0, 0, 1.000, 1.000, 1.000),
    ("RSA", 4, 0, 0, 1.000, 1.000, 1.000),
    ("SHA-256", 8, 0, 0, 1.000, 1.000, 1.000),
    ("Diffie-Hellman", 2, 0, 0, 1.000, 1.000, 1.000),
    ("AES (short key)", 1, 0, 0, 1.000, 1.000, 1.000),
]

SCORES = [
    ("Python settlement signer",  9, 4, 108, 100.0, 91.2),
    ("Python key service",        5, 4,  26, 100.0, 94.6),
    ("Solidity consent registry", 3, 2,  81,  60.0, 75.5),
    ("Half-migrated contract",    2, 2,  32,  45.0, 79.3),
    ("Post-quantum module",       0, 0,  39,   0.0,  0.0),
    ("Prose-only module",         0, 0,  23,   0.0,  0.0),
    ("Trick-names module",        0, 0,  38,   0.0,  0.0),
]


# ================================= FIGURES ==================================

def fig_architecture():
    fig, ax = plt.subplots(figsize=(7.2, 2.5), dpi=220)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.set_xlim(0, 100); ax.set_ylim(0, 34); ax.axis("off")

    stages = ["Source\nfile", "Hide comments\nand strings", "Search\npatterns",
              "Group per\nline", "Risk score\n+ plan"]
    w, h, gap, y = 16.0, 10.0, 4.6, 20
    for i, label in enumerate(stages):
        x = 1 + i * (w + gap)
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                                    boxstyle="round,pad=0.35,rounding_size=1.2",
                                    fc="white", ec=S1, lw=1.3))
        ax.text(x + w / 2, y + h / 2, label, ha="center", va="center",
                fontsize=7.4, color=INK, linespacing=1.45)
        if i < len(stages) - 1:
            ax.add_patch(FancyArrowPatch((x + w, y + h / 2),
                                         (x + w + gap - 0.6, y + h / 2),
                                         arrowstyle="-|>", mutation_scale=9,
                                         color=INK2, lw=1.1))

    for label, src in [("CycloneDX\ninventory", 2), ("Regulator\nreport", 3),
                       ("Blockchain\nrecord", 4)]:
        sx = 1 + src * (w + gap) + w / 2
        ax.add_patch(FancyBboxPatch((sx - w / 2, 2), w, h - 1.4,
                                    boxstyle="round,pad=0.35,rounding_size=1.2",
                                    fc="white", ec=S3, lw=1.1,
                                    linestyle=(0, (3, 2))))
        ax.text(sx, 2 + (h - 1.4) / 2, label, ha="center", va="center",
                fontsize=7.0, color=INK2, linespacing=1.45)
        ax.add_patch(FancyArrowPatch((sx, y), (sx, 2 + h - 1.4),
                                     arrowstyle="-|>", mutation_scale=8,
                                     color=MUTED, lw=1.0))

    fig.tight_layout(pad=0.2)
    p = os.path.join(FIG, "fig1_architecture.png")
    fig.savefig(p, facecolor=SURFACE, bbox_inches="tight"); plt.close(fig)
    return p


def fig_equation():
    fig = plt.figure(figsize=(7.0, 0.95), dpi=220)
    fig.patch.set_facecolor(SURFACE)
    eq = (r"$S \;=\; \min\!\left(100,\;"
          r"\max_{f \in F}\sigma(f)"
          r"\;+\;\min\!\left(20,\,5(|A|-1)\right)"
          r"\;+\;20\left(1 - e^{-\rho/5}\right)\right)$")
    fig.text(0.5, 0.5, eq, ha="center", va="center", fontsize=13, color=INK)
    p = os.path.join(FIG, "fig2_equation.png")
    fig.savefig(p, facecolor=SURFACE, bbox_inches="tight"); plt.close(fig)
    return p


def _style_axes(ax, ymax, ylabel):
    ax.set_facecolor(SURFACE)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(GRID)
    ax.spines["bottom"].set_color(GRID)
    ax.yaxis.grid(True, color=GRID, lw=0.7)
    ax.set_axisbelow(True)
    ax.set_ylim(0, ymax)
    ax.set_ylabel(ylabel, fontsize=8, color=INK2)
    ax.tick_params(colors=INK2, labelsize=8, length=0)


def fig_ablation():
    fig, ax = plt.subplots(figsize=(6.6, 2.9), dpi=220)
    fig.patch.set_facecolor(SURFACE)

    names = [r[0] for r in ABLATION]
    series = [("Precision", [r[4] for r in ABLATION], S1),
              ("Recall",    [r[5] for r in ABLATION], S2),
              ("F1",        [r[6] for r in ABLATION], S3)]

    n, bw = len(series), 0.26
    xs = list(range(len(names)))
    for k, (label, vals, col) in enumerate(series):
        off = (k - (n - 1) / 2) * bw
        pos = [x + off for x in xs]
        ax.bar(pos, vals, bw * 0.92, label=label, color=col,
               edgecolor=SURFACE, linewidth=1.2, zorder=3)
        for x, v in zip(pos, vals):
            ax.text(x, v + 0.025, f"{v:.3f}", ha="center", va="bottom",
                    fontsize=7.0, color=INK)

    _style_axes(ax, 1.18, "Score")
    ax.set_xticks(xs); ax.set_xticklabels(names, fontsize=8.2)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.legend(frameon=False, fontsize=7.8, ncol=3, loc="upper center",
              bbox_to_anchor=(0.5, 1.16), labelcolor=INK2)
    fig.tight_layout(pad=0.3)
    p = os.path.join(FIG, "fig3_ablation.png")
    fig.savefig(p, facecolor=SURFACE, bbox_inches="tight"); plt.close(fig)
    return p


def fig_scores():
    rows = [r for r in SCORES if r[1] > 0]
    fig, ax = plt.subplots(figsize=(6.6, 3.0), dpi=220)
    fig.patch.set_facecolor(SURFACE)

    labels = ["Settlement\nsigner", "Key\nservice", "Consent\nregistry",
              "Half-\nmigrated"]
    old = [r[4] for r in rows]
    new = [r[5] for r in rows]

    bw = 0.34
    xs = list(range(len(rows)))
    for k, (lab, vals, col) in enumerate([("Severity-sum (old)", old, S1),
                                          ("Three-part (new)", new, S2)]):
        off = (k - 0.5) * bw
        pos = [x + off for x in xs]
        ax.bar(pos, vals, bw * 0.92, label=lab, color=col,
               edgecolor=SURFACE, linewidth=1.2, zorder=3)
        for x, v in zip(pos, vals):
            ax.text(x, v + 1.6, f"{v:.1f}", ha="center", va="bottom",
                    fontsize=7.0, color=INK)

    _style_axes(ax, 122, "Risk score (0-100)")
    ax.set_xticks(xs); ax.set_xticklabels(labels, fontsize=7.8)
    ax.axhline(100, color=MUTED, lw=0.8, ls=(0, (4, 3)), zorder=2)
    ax.text(len(rows) - 0.42, 103, "cap", fontsize=6.8, color=MUTED, ha="right")
    ax.legend(frameon=False, fontsize=7.8, ncol=2, loc="upper center",
              bbox_to_anchor=(0.5, 1.15), labelcolor=INK2)
    fig.tight_layout(pad=0.3)
    p = os.path.join(FIG, "fig4_scores.png")
    fig.savefig(p, facecolor=SURFACE, bbox_inches="tight"); plt.close(fig)
    return p


# ================================= STYLES ===================================

ss = getSampleStyleSheet()


def mk(name, **kw):
    base = dict(fontName="Times-Roman", fontSize=10, leading=13.2,
                alignment=TA_JUSTIFY, textColor=colors.HexColor("#111111"))
    base.update(kw)
    return ParagraphStyle(name, **base)


TITLE    = mk("ti", fontName="Times-Bold", fontSize=17, leading=21,
              alignment=TA_CENTER, spaceAfter=10)
AUTHOR   = mk("au", fontSize=11, leading=14, alignment=TA_CENTER, spaceAfter=2)
AFFIL    = mk("af", fontSize=9.2, leading=12, alignment=TA_CENTER,
              textColor=colors.HexColor("#444444"), spaceAfter=1)
ABSHEAD  = mk("ah", fontName="Times-Bold", fontSize=10.5, leading=13,
              spaceBefore=12, spaceAfter=4)
ABSTRACT = mk("ab", fontSize=9.4, leading=12.4)
KEYWORDS = mk("kw", fontSize=9.4, leading=12.4, spaceBefore=7)
H1       = mk("h1", fontName="Times-Bold", fontSize=12.5, leading=15.5,
              spaceBefore=13, spaceAfter=5)
H2       = mk("h2", fontName="Times-Bold", fontSize=10.6, leading=13.4,
              spaceBefore=9, spaceAfter=3)
BODY     = mk("bd", spaceAfter=5)
BULLET   = mk("bu", leftIndent=14, bulletIndent=4, spaceAfter=2.5)
CAPTION  = mk("cap", fontSize=8.6, leading=11, alignment=TA_CENTER,
              textColor=colors.HexColor("#444444"), spaceBefore=4, spaceAfter=9)
CODE     = mk("co", fontName="Courier", fontSize=8.0, leading=10.4,
              alignment=0, leftIndent=8)
REF      = mk("rf", fontSize=8.8, leading=11.4, leftIndent=18,
              firstLineIndent=-18, alignment=0, spaceAfter=2.6)

story = []
A = story.append


def para(txt, st=BODY):
    A(Paragraph(txt, st))


def bullets(items):
    for it in items:
        A(Paragraph(it, BULLET, bulletText="•"))


def numbered(items):
    for i, it in enumerate(items, 1):
        A(Paragraph(it, BULLET, bulletText=f"{i}."))


def figure(path, caption, width=160 * mm):
    from PIL import Image as PILImage
    iw, ih = PILImage.open(path).size
    h = width * ih / iw
    A(KeepTogether([Image(path, width=width, height=h),
                    Paragraph(caption, CAPTION)]))


def table(data, caption, widths, align_right=(), font=8.3):
    t = Table(data, colWidths=widths, hAlign="CENTER", repeatRows=1)
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Times-Roman"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("LEADING", (0, 0), (-1, -1), font + 2.6),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")),
        ("LINEABOVE", (0, 0), (-1, 0), 0.9, colors.HexColor("#333333")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#333333")),
        ("LINEBELOW", (0, -1), (-1, -1), 0.9, colors.HexColor("#333333")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
    ]
    for c in align_right:
        style.append(("ALIGN", (c, 1), (c, -1), "RIGHT"))
    t.setStyle(TableStyle(style))
    A(KeepTogether([t, Paragraph(caption, CAPTION)]))


# ================================= CONTENT ==================================

f_arch = fig_architecture()
f_eq = fig_equation()
f_abl = fig_ablation()
f_sco = fig_scores()

para("Detecting and Migrating Quantum-Vulnerable Cryptography in "
     "Blockchain Source Code", TITLE)
para("Benidict David", AUTHOR)
para("ORCID: 0009-0003-1356-7903", AFFIL)
para("Amity Institute of Information Technology", AFFIL)
para("Amity University Rajasthan, Jaipur, Rajasthan, India", AFFIL)
para("benidictdavid18@gmail.com", AFFIL)

para("Abstract", ABSHEAD)
para(
 "Blockchains rely on RSA and ECDSA, and a sufficiently large quantum computer "
 "breaks both. Blockchains suffer more than most systems from this, because "
 "every public key they have recorded stays public forever, so an attacker who "
 "obtains a quantum computer years from now can still attack data written "
 "today. Before an organisation can move to safer algorithms it needs a list of "
 "exactly where in its code the weak ones are used. Existing smart contract "
 "tools do not produce that list, because they look for logic defects rather "
 "than for which cryptography a program uses. This paper presents a toolkit "
 "that locates quantum-vulnerable call sites in Solidity, Python, JavaScript "
 "and Go source, gives the NIST-approved replacement for each, exports a "
 "CycloneDX cryptographic bill of materials, writes a report for regulators, "
 "and records a tamper-proof summary on a public blockchain. The main result "
 "concerns accuracy. A pattern-matching detector of this kind is easy to make "
 "find everything but hard to stop from being wrong, and two causes account for "
 "almost all of its mistakes: it matches algorithm names written in comments "
 "and strings, and it reports one line several times when several patterns "
 "match it. We eliminate both using offset-preserving masking and per-line "
 "grouping, and we replace a severity-sum risk score that assigned nearly every "
 "file the same value. On a hand-labelled benchmark of seven files containing "
 "nineteen marked call sites, three of which are files written specifically to "
 "mislead the detector, these changes raise precision from 0.633 to 1.000 while "
 "recall remains at 1.000. Because the benchmark was written by the same author "
 "as the detector, the paper states explicitly what the result does and does "
 "not establish, and reports the Wilson confidence interval that bounds it. The "
 "detection logic is additionally implemented in a second runtime that executes "
 "entirely in a web browser and is verified to produce identical output, so "
 "proprietary source never has to be transmitted.", ABSTRACT)

para("<b>Keywords:</b> Post-quantum cryptography; Blockchain security; Static "
     "analysis; Cryptographic bill of materials; ML-DSA; ML-KEM; Smart contract "
     "analysis; Regulatory compliance", KEYWORDS)

# ---- 1 Introduction --------------------------------------------------------
para("1. Introduction", H1)
para(
 "Blockchains depend on a small number of cryptographic algorithms. Ethereum "
 "and Bitcoin sign transactions using ECDSA on the secp256k1 curve. Smart "
 "contracts verify signatures through the <font face='Courier'>ecrecover</font> "
 "function. The servers and scripts surrounding a deployment typically use RSA "
 "for key exchange and SHA-256 for hashing. Every one of these rests on a "
 "mathematical problem that a quantum computer solves efficiently. Shor's "
 "algorithm [1] factors large numbers and solves discrete logarithms in "
 "polynomial time, which breaks RSA and ECDSA completely rather than merely "
 "weakening them. Grover's algorithm [2] is a milder threat that speeds up "
 "brute-force search, halving the effective strength of hash functions and "
 "block ciphers.")
para(
 "Blockchains face a difficulty here that most systems do not. Normally, once a "
 "weak algorithm is retired, the data that passed through it is no longer "
 "available to an attacker. A public ledger inverts this: every public key and "
 "signature it has ever stored remains permanently retrievable [3]. An attacker "
 "who acquires quantum capability in a decade can therefore still attack the "
 "entire history. Mosca's rule [4] states the consequence plainly: when the "
 "time data must remain secret, plus the time migration takes, exceeds the time "
 "until quantum computers arrive, the organisation is already late. For an "
 "immutable ledger the secrecy requirement is unbounded, so the work should "
 "already have started.")

para("1.1 Problem Statement", H2)
para(
 "Given a source file drawn from a blockchain project, produce the list of "
 "exact locations at which quantum-vulnerable cryptography is invoked, such "
 "that the list is specific enough to plan a migration and accurate enough that "
 "a developer reading it continues to trust the tool. Accuracy is the "
 "substantive difficulty. A pattern-matching detector is straightforward to "
 "make complete, in the sense of finding every genuine call site, and "
 "surprisingly hard to make precise, because algorithm names occur heavily in "
 "comments and string literals and because overlapping patterns report a single "
 "call site more than once. Both faults inflate every downstream figure, "
 "including the risk score and the remediation estimate.")

para("1.2 Objectives", H2)
numbered([
 "Build a detector covering five families of quantum-vulnerable primitives "
 "across Solidity, Python, JavaScript and Go source.",
 "Identify the dominant sources of false positives in such a detector and "
 "eliminate them without reducing recall.",
 "Design a risk score that discriminates between source files rather than "
 "saturating at its maximum.",
 "Construct a hand-labelled benchmark that includes deliberate hard negatives, "
 "and release it with its labelling policy.",
 "Deliver outputs an organisation can act on: a standards-conformant "
 "cryptographic inventory, regulator-facing reports, and a verifiable record.",
])

para("1.3 Research Questions", H2)
bullets([
 "<b>RQ1.</b> What causes false positives in pattern-based detection of "
 "quantum-vulnerable cryptography in blockchain source code, and how much does "
 "each cause contribute?",
 "<b>RQ2.</b> Can those causes be eliminated without any loss of recall?",
 "<b>RQ3.</b> Does severity-sum risk scoring discriminate between source files, "
 "and does a multi-factor score improve on it?",
 "<b>RQ4.</b> Can the detection logic be ported to a client-side runtime "
 "without behavioural divergence from the reference implementation?",
])

para("1.4 Brief Description of the Work", H2)
para(
 "The system processes a source file through five stages: comments and string "
 "literals are blanked while preserving byte offsets, the remaining executable "
 "text is matched against patterns for five algorithm families, overlapping "
 "matches are grouped per line and family, the surviving findings are reduced "
 "to a single exposure score, and a migration plan is generated mapping each "
 "family to its NIST replacement. Three documents are derived from these "
 "results: a CycloneDX 1.6 cryptographic bill of materials, a report rendered "
 "against a regulator-specific template, and a Keccak-256 digest recorded on "
 "the Ethereum Sepolia network. The detector is implemented twice, in Python "
 "and in JavaScript, and the two are verified to agree.")

para("1.5 Main Contributions", H2)
numbered([
 "<b>Two mechanisms that make pattern-based crypto detection accurate.</b> "
 "Offset-preserving masking blanks comments and strings by substituting spaces "
 "rather than deleting characters, so reported line numbers stay exact; "
 "per-line grouping collapses overlapping matches so one call site yields one "
 "finding.",
 "<b>A non-saturating exposure score.</b> The severity-sum score used in the "
 "preliminary system reaches its cap at four high-severity findings and "
 "produced a mean of 99.5 across the 19 scan records gathered during "
 "development. It is replaced by a three-term model over worst severity, family "
 "breadth and finding density.",
 "<b>A labelled benchmark with hard negatives.</b> Seven files and nineteen "
 "marked call sites, of which three files carry zero labels: one already "
 "post-quantum, one naming the old algorithms only in prose, and one containing "
 "identifiers that merely resemble cryptographic names.",
 "<b>An ablation isolating each mechanism,</b> including the negative result "
 "that word-boundary anchoring alone removes no false positive, and an explicit "
 "account of why the absolute scores overstate field accuracy.",
 "<b>A verified dual-runtime implementation,</b> agreeing on all seven "
 "benchmark files across six compared fields, which permits assessment of "
 "proprietary source without transmitting it.",
])

para("1.6 Organisation of the Remaining Sections", H2)
para(
 "Section 2 reviews existing smart contract and cryptographic analysis tools "
 "and identifies the research gap. Section 3 describes the dataset, the system "
 "architecture, the detection algorithm, the scoring equations and the "
 "experimental setup. Section 4 reports evaluation metrics, the ablation "
 "results, the scoring comparison and the comparison against baselines. "
 "Section 5 answers the four research questions and relates the findings to "
 "previous studies. Section 6 summarises the work, states its limitations and "
 "outlines future scope.")

# ---- 2 Related Work --------------------------------------------------------
para("2. Related Work", H1)

para("2.1 Literature Review", H2)
para(
 "Research relevant to this problem falls into three groups: analysis of smart "
 "contracts, detection of cryptographic misuse, and standardisation of "
 "post-quantum algorithms and cryptographic inventories.")
para(
 "<b>Smart contract analysis.</b> Slither [5] performs static analysis over an "
 "intermediate representation of Solidity and detects a broad catalogue of "
 "vulnerability patterns including reentrancy, unchecked arithmetic and "
 "access-control defects. Mythril applies symbolic execution to EVM bytecode, "
 "and Manticore supports symbolic exploration of both source and bytecode. "
 "These tools are mature and widely deployed, but none reports which "
 "cryptographic algorithms a contract composes, because a correctly written "
 "ECDSA verification is not a defect under their threat models.")
para(
 "<b>Cryptographic misuse detection.</b> CryptoGuard [6] identifies misuse "
 "patterns such as hard-coded keys, predictable initialisation vectors and "
 "insecure cipher modes in large Java codebases, reporting low false-positive "
 "rates. CrySL [7] provides a specification language in which the correct usage "
 "protocol of a cryptographic API can be expressed and then checked "
 "statically. Both target incorrect use of algorithms that are themselves "
 "sound. The problem addressed here is the complement: correct use of "
 "algorithms that will become unsound. A misuse detector reports nothing for a "
 "textbook-correct ECDSA implementation, which is precisely the code that must "
 "be found.")
para(
 "<b>Standards and inventories.</b> NIST finalised three post-quantum "
 "standards in August 2024: FIPS 203 for ML-KEM [8], FIPS 204 for ML-DSA [9] "
 "and FIPS 205 for SLH-DSA [10], with transition guidance setting deprecation "
 "dates [11]. Bernstein and Lange [12] survey the underlying mathematics. "
 "Webber et al. [13] estimate the hardware required to attack ECDSA in "
 "practice. On the inventory side, CycloneDX [14] introduced a "
 "cryptographic-asset component type, giving machine-readable form to the "
 "notion of a cryptographic bill of materials, and NIST SP 800-57 [15] "
 "provides the key-management framing that such an inventory supports.")

LIT = [
 ["Work", "Primary focus", "Reports crypto\ninventory", "PQ migration\nguidance",
  "Blockchain\naware", "Verifiable\nrecord"],
 ["Slither [5]", "Solidity logic defects", "No", "No", "Yes", "No"],
 ["Mythril", "EVM symbolic execution", "No", "No", "Yes", "No"],
 ["Manticore", "Symbolic exploration", "No", "No", "Yes", "No"],
 ["CryptoGuard [6]", "Java crypto misuse", "Partial", "No", "No", "No"],
 ["CrySL [7]", "Crypto API usage rules", "Partial", "No", "No", "No"],
 ["CycloneDX [14]", "Inventory format only", "Format", "No", "No", "No"],
 ["FIPS 203/204/205\n[8], [9], [10]", "Algorithm standards", "No", "Target",
  "No", "No"],
 ["This work", "Quantum exposure in\nblockchain source", "Yes", "Yes", "Yes",
  "Yes"],
]
table(LIT, "Table 1. Summary of related work against the four capabilities this "
           "problem requires. No existing tool provides all four.",
      widths=[30 * mm, 37 * mm, 23 * mm, 22 * mm, 20 * mm, 21 * mm], font=7.8)

para("2.2 Research Gap", H2)
para(
 "Table 1 makes the gap explicit. Smart contract analysers are blockchain aware "
 "but report no cryptographic inventory. Cryptographic analysers report on "
 "cryptography but target misuse in non-blockchain languages and offer no "
 "migration guidance. The standards define what to migrate to but not how to "
 "find what needs migrating. CycloneDX supplies a format but no detector. No "
 "published tool combines quantum-vulnerability detection for ledger code, "
 "standards-aligned migration planning, machine-readable inventory export and "
 "a verifiable assessment record.")
para(
 "A second and less obvious gap concerns accuracy. Pattern-based cryptographic "
 "detection is widely used but its characteristic failure modes have not, to "
 "our knowledge, been isolated and measured. The literature on misuse detection "
 "reports aggregate false-positive rates without attributing them to specific "
 "causes. This paper addresses that gap directly, and the mechanisms it "
 "contributes apply to any tool that searches source text for cryptography.")

# ---- 3 Methodology ---------------------------------------------------------
para("3. Methodology", H1)

para("3.1 Dataset", H2)
para(
 "The evaluation dataset is a benchmark of seven source files in which every "
 "active call site of a quantum-vulnerable primitive has been marked by hand. "
 "Each label records a line number and an algorithm family, and a prediction "
 "counts as a true positive only when both components match. This criterion is "
 "deliberately strict: naming the correct family on the wrong line does not "
 "tell a developer where to work.")
para(
 "The labelling policy was fixed before labelling began and is released with "
 "the data. Import statements are labelled, since importing a vulnerable "
 "primitive forms part of the migration surface. Call sites are labelled. A "
 "function definition is labelled when its body implements the primitive. "
 "Occurrences inside comments, documentation strings and string literals are "
 "not labelled, and neither are identifiers that merely contain an algorithm "
 "name as a substring.")
para(
 "Four files are positive cases: a Solidity consent registry using "
 "<font face='Courier'>ecrecover</font> and "
 "<font face='Courier'>keccak256</font>; a Python settlement signer combining "
 "ECDSA, RSA, SHA-256, short-key AES and a Diffie-Hellman exchange; a Python "
 "key service; and a partially migrated Solidity contract in which an ML-DSA "
 "path has been added while the legacy "
 "<font face='Courier'>ecrecover</font> path remains live. The last of these "
 "tests that a half-migrated file still reports its residual classical "
 "exposure, which is the common real-world state.")
para(
 "The remaining three files carry zero labels and form the hard-negative "
 "component. The first is fully post-quantum code importing "
 "<font face='Courier'>dilithium2</font> and "
 "<font face='Courier'>kyber512</font> and hashing with SHA-384. The second "
 "documents a completed migration in prose, naming "
 "<font face='Courier'>RSA.generate</font>, "
 "<font face='Courier'>hashlib.sha256</font>, "
 "<font face='Courier'>ECDSA.sign</font>, Diffie-Hellman and "
 "<font face='Courier'>ecrecover</font> across comments, a documentation string "
 "and a literal, while invoking none of them. The third contains identifiers "
 "such as <font face='Courier'>bandwidth</font>, "
 "<font face='Courier'>sha256_cache_enabled</font> and "
 "<font face='Courier'>rsa_config_path</font>, none of which is cryptographic. "
 "Each negative targets one of the three error classes analysed in Section 3.5. "
 "The benchmark totals nineteen labelled call sites across 347 lines of "
 "source.")

para("3.2 Threat Model and Scope", H2)
para(
 "The adversary assumed throughout follows a harvest-now, decrypt-later "
 "strategy. They record public blockchain data continuously in the present and "
 "acquire cryptographically relevant quantum capability at an unknown future "
 "point, after which they can recover private keys from the public keys already "
 "recorded and forge signatures. This adversary never needs access to the "
 "organisation's systems, because the material required is already public, "
 "which is what distinguishes the blockchain case from a conventional one.")
para(
 "The scope of the tool is correspondingly narrow and is stated explicitly "
 "because it bounds every result reported later. The tool answers one question: "
 "at which source locations does this file invoke a primitive that the above "
 "adversary defeats? It does not evaluate protocol design, key management, "
 "randomness quality, or whether a correctly named primitive is used correctly. "
 "The output is a migration worklist rather than a cryptographic audit, and the "
 "generated reports carry that statement in the document itself.")
para(
 "Four design goals follow. First, accuracy is prioritised over volume: a "
 "developer must be able to trust that every reported location requires work, "
 "because a worklist that flags documentation is discarded at first review. "
 "Second, every finding must carry an exact line, a named replacement and the "
 "standard governing it. Third, assessing proprietary code must not require "
 "transmitting it, since the organisations with the greatest exposure are the "
 "least willing to upload source to a third party. Fourth, an assessment shown "
 "to a regulator or insurer must be independently checkable for integrity and "
 "date without trusting the assessing party.")

para("3.3 Detection Scope: Algorithm Families", H2)
para(
 "Five families are covered, listed in Table 2 with the severity assigned to "
 "each and its standardised replacement. A family is rated HIGH when the "
 "adversary defeats it outright and MEDIUM when the primitive is weakened but "
 "survives with larger parameters. Each pattern targets an invocation or import "
 "form rather than a bare algorithm name, which is the first and weakest of the "
 "accuracy measures; the two mechanisms in Section 3.5 do the substantive "
 "work.")
table([["Family", "Severity", "Replacement", "Standard", "Representative pattern"]] +
      [["ECDSA", "HIGH", "ML-DSA (Dilithium)", "FIPS 204",
        "ecrecover(, secp256k1"],
       ["RSA", "HIGH", "ML-KEM (Kyber)", "FIPS 203",
        "RSA., Crypto.PublicKey"],
       ["Diffie-Hellman", "HIGH", "ML-KEM (Kyber)", "FIPS 203",
        "diffie_hellman, ECDH"],
       ["SHA-256", "MEDIUM", "SHA-384 / SHA-512", "FIPS 180-4",
        "hashlib.sha256(, keccak256("],
       ["AES (short key)", "MEDIUM", "AES-256-GCM", "FIPS 197",
        "AES.new(..MODE_, AES-128"]],
      "Table 2. The five algorithm families covered, with severity, "
      "standardised replacement and an example of the patterns matched.",
      widths=[28 * mm, 19 * mm, 34 * mm, 22 * mm, 45 * mm], font=7.9)
para(
 "Two constraints shape the replacements offered for on-chain code. ML-DSA "
 "signatures and public keys are substantially larger than their ECDSA "
 "counterparts, and lattice verification is not expressible within current "
 "Ethereum gas limits at acceptable cost, so the recommendation for a contract "
 "verifying signatures on-chain is an architectural change rather than a "
 "substitution. Separately, because Ethereum address derivation depends on "
 "Keccak-256, a deployed contract cannot change its hash function without "
 "breaking every address derived from it, so hash recommendations are scoped to "
 "off-chain code.")

para("3.4 Proposed Approach and Architecture", H2)
para(
 "The system is a five-stage pipeline in which each stage is independent and "
 "communicates through JSON, so any stage can be replaced without disturbing "
 "the others. Figure 1 shows the arrangement.")
figure(f_arch,
 "Fig. 1. System architecture. Solid boxes are the five analysis stages; dashed "
 "boxes are the governance documents derived from the stage above them.")
para(
 "Stages one to three constitute detection and are specified as Algorithm 1. "
 "Stage four groups findings by family and emits, for each, the replacement "
 "algorithm, its governing standard, the affected line numbers and a "
 "language-appropriate code template. For Solidity the template is the "
 "off-chain verification pattern rather than a direct substitution, because "
 "ML-DSA signatures and keys are substantially larger than their ECDSA "
 "equivalents and lattice verification cannot be executed within current "
 "Ethereum gas limits at acceptable cost. Stage five derives the three "
 "governance documents. Only a Keccak-256 digest is published on-chain; no "
 "source material is disclosed. The transaction is signed by the wallet of the "
 "party performing the assessment, so the service holds no private key.")

para("3.5 Algorithm", H2)
para(
 "Algorithm 1 states the detection procedure. The two mechanisms this paper "
 "contributes are line 2 and lines 9 to 14. Line 2 blanks non-code regions by "
 "substituting spaces rather than deleting characters, which preserves both the "
 "total length and the line structure of the buffer, so an offset in the masked "
 "copy indexes the same position in the original file and reported line numbers "
 "remain exact. Lines 9 to 14 collapse matches sharing a family and a line, "
 "retaining the longest matched text as the most specific description of the "
 "call site. Family is retained in the grouping key, so a line genuinely "
 "invoking two families still yields two findings, because it requires two "
 "separate remediations.")
for ln in [
 "Algorithm 1: Precision-oriented detection of quantum-vulnerable cryptography",
 "-" * 74,
 "Input : source text T; pattern set P grouped by family; severity map sigma",
 "Output: findings V; informational mentions M; exposure score S",
 "",
 " 1  L  <- split T into lines",
 " 2  C  <- MASK(T)        // replace each char inside a comment or string",
 "                         // literal with a space; preserve all newlines",
 " 3  R  <- empty list     // raw matches",
 " 4  for each family a in P do",
 " 5      for each pattern p in P[a] do",
 " 6          for each match m of p in C do",
 " 7              append (a, LINE(C, m.start), m.text) to R",
 " 8",
 " 9  B  <- empty map      // best match per (family, line)",
 "10  for each (a, n, text) in R do",
 "11      if (a,n) not in B or |text| > |B[a,n].text| then",
 "12          B[a,n] <- (a, n, text)",
 "13",
 "14  V  <- sort values of B by (line, family)",
 "15",
 "16  M  <- empty list     // names occurring ONLY in masked regions",
 "17  for each family a in P, pattern p in P[a], match m of p in T do",
 "18      if C[m.start .. m.end] is all whitespace then",
 "19          append (a, LINE(T, m.start)) to M",
 "20",
 "21  S  <- SCORE(V, |L|)  // Equation (1)",
 "22  return V, M, S",
 "-" * 74,
]:
    para(ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
           .replace(" ", "&nbsp;"), CODE)
A(Spacer(1, 7))

para(
 "A worked example makes both mechanisms concrete. Consider the two-line "
 "fragment below, taken from a file mid-migration. Line 12 is documentation "
 "describing work already completed; line 13 is a live call site.")
for ln in [
 "ORIGINAL SOURCE",
 "  12 |  # replaced RSA.generate with ML-KEM; see migration note",
 "  13 |  digest = hashlib.sha256(payload).digest()",
 "",
 "AFTER MASKING (line length and newlines preserved)",
 "  12 |                                                        ",
 "  13 |  digest = hashlib.sha256(payload).digest()",
 "",
 "RAW MATCHES AGAINST THE MASKED BUFFER",
 "  (SHA256, line 13, 'hashlib.sha256(')     <- qualified pattern",
 "  (SHA256, line 13, 'sha256(')             <- bare pattern",
 "",
 "AFTER PER-LINE GROUPING",
 "  (SHA256, line 13, 'hashlib.sha256(')     <- longest match retained",
 "",
 "REPORTED SEPARATELY, NOT COUNTED",
 "  (RSA, line 12)  mentioned in a comment, not a call site",
]:
    para(ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
           .replace(" ", "&nbsp;"), CODE)
A(Spacer(1, 7))
para(
 "A detector searching the raw text reports two findings here, one of them the "
 "comment on line 12, and counts line 13 twice. The masked buffer removes the "
 "first error while leaving line 13 at line 13, so the reported location stays "
 "correct; grouping removes the second. The RSA mention is surfaced in the "
 "informational list rather than discarded, so a reviewer can confirm the tool "
 "saw it and chose not to count it.")

para("3.6 Mathematical Formulation", H2)
para(
 "The preliminary system scored a file by summing severity weights, 30 points "
 "per high-severity finding, capped at 100. Four high-severity findings reach "
 "120, so any file containing four or more scores exactly 100 regardless of its "
 "size, the breadth of algorithms involved or their density. Across the 19 scan "
 "records accumulated during development the mean was 99.5 with negligible "
 "variance. A score that assigns nearly every input the same value carries no "
 "information, and since this figure is printed on compliance documentation the "
 "defect is consequential. It is replaced by Equation (1).")
figure(f_eq, "Equation (1). The three-term exposure score.", width=150 * mm)
para(
 "Here F is the set of findings and sigma maps a severity level to base points, "
 "with HIGH mapping to 60, MEDIUM to 35 and LOW to 15. A is the set of distinct "
 "algorithm families present, so the breadth term contributes 5 points per "
 "additional family up to 20. The density term uses rho = 100|F| / L, the "
 "number of findings per hundred lines in a file of L lines, and saturates "
 "smoothly so that a densely affected file outranks a sparse one without a "
 "single pathological file dominating the scale. The score is monotonic in all "
 "three inputs and reaches 100 only for a file that is both broadly and densely "
 "affected.")
para("Detection quality is measured by the standard quantities in Equations (2) "
     "to (4), where a prediction is correct only if both its line number and "
     "its family match a label:")
para("&nbsp;&nbsp;&nbsp;&nbsp;Precision = TP / (TP + FP)"
     "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(2)", CODE)
para("&nbsp;&nbsp;&nbsp;&nbsp;Recall&nbsp;&nbsp;&nbsp;&nbsp;= TP / (TP + FN)"
     "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(3)", CODE)
para("&nbsp;&nbsp;&nbsp;&nbsp;F1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
     "= 2 &middot; Precision &middot; Recall / (Precision + Recall)"
     "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(4)", CODE)
para(
 "Because the benchmark is small, point estimates alone would be misleading, so "
 "Wilson score intervals are reported alongside them. For k correct out of n "
 "predictions at the 95% level the interval is centred at "
 "(p + z&sup2;/2n) / (1 + z&sup2;/n) with p = k/n and z = 1.96.")

para("3.7 Experimental Setup", H2)
para(
 "The reference implementation is Python 3.13 exposed through a FastAPI service "
 "of twelve endpoints. The second implementation is JavaScript executing in the "
 "browser, with no server component. Reports are produced with ReportLab in the "
 "Python runtime and jsPDF in the browser runtime. Blockchain records are "
 "written to the Ethereum Sepolia test network through a registry contract "
 "exposing a single <font face='Courier'>storeProof</font> function.")
para(
 "Three detector configurations are evaluated in order to attribute the "
 "improvement to specific mechanisms. <b>v1-baseline</b> is the original "
 "pattern set matched against raw text with no grouping; this is a genuine "
 "earlier configuration of the system, retained verbatim rather than "
 "reconstructed. <b>v2-boundaries</b> is the revised, word-anchored pattern "
 "set, still matched against raw text without grouping. <b>v3-full</b> is the "
 "revised pattern set with masking and per-line grouping, and is the shipped "
 "configuration. Runtime equivalence is checked by executing the JavaScript "
 "detection module outside the browser and comparing six fields against the "
 "Python implementation for every benchmark file: the finding set as "
 "(line, family) pairs, the finding count, the informational-mention set, the "
 "post-quantum algorithms detected, the exposure score and the line count. The "
 "full evaluation is reproducible by running the released harness.")

# ---- 4 Results -------------------------------------------------------------
para("4. Results", H1)

para("4.1 Evaluation Metrics", H2)
para(
 "Detection is assessed by precision, recall and F1 as defined in Equations (2) "
 "to (4), computed overall and per algorithm family, with Wilson 95% intervals. "
 "Two auxiliary quantities are also reported. <i>Raw hits</i> is the total "
 "number of pattern matches before grouping, which exposes the duplicate-"
 "counting behaviour that precision alone conceals. The <i>exposure score</i> "
 "is evaluated not for accuracy, which would require expert rankings, but for "
 "discrimination: whether it assigns distinct values to files of differing "
 "severity.")

para("4.2 Performance Analysis", H2)
table([["Version", "TP", "FP", "FN", "Precision", "Recall", "F1", "Raw hits"]] +
      [[r[0], str(r[1]), str(r[2]), str(r[3]), f"{r[4]:.3f}", f"{r[5]:.3f}",
        f"{r[6]:.3f}", str(r[7])] for r in ABLATION],
      "Table 3. Ablation across three detector configurations. Seven files, "
      "nineteen labelled call sites.",
      widths=[34 * mm, 13 * mm, 13 * mm, 13 * mm, 22 * mm, 19 * mm, 17 * mm,
              20 * mm],
      align_right=(1, 2, 3, 4, 5, 6, 7))
figure(f_abl,
 "Fig. 2. Precision, recall and F1 by configuration. Recall is unchanged "
 "throughout; precision rises only when masking and grouping are both applied.",
 width=152 * mm)
para(
 "Three observations follow. First, recall remains 1.000 in every "
 "configuration: the accuracy mechanisms never suppress a genuine call site, "
 "which is the property that must hold for them to be acceptable, since "
 "precision bought with recall would be a poor trade in a security inventory.")
para(
 "Second, word-boundary anchoring alone yields no improvement. The v2 "
 "configuration removes one raw match relative to v1 but eliminates no false "
 "positive. This negative result is worth reporting: the substring-identifier "
 "error class that anchoring targets is real, and one benchmark file was written "
 "specifically to exercise it, but on this data the dominant error source is "
 "comment and string matching, which anchoring does not address. Anchoring is "
 "the intuitive first remedy and is insufficient alone.")
para(
 "Third, masking combined with per-line grouping eliminates all eleven false "
 "positives, and reduces raw hits from 38 to 26. The residual difference "
 "between 26 and the nineteen labelled call sites is accounted for entirely by "
 "the hard-negative files, where the correct count is zero. Table 4 confirms "
 "the result is uniform across families rather than driven by one of them.")
CI95 = {"ECDSA": "[0.510, 1.000]", "RSA": "[0.510, 1.000]",
        "SHA-256": "[0.676, 1.000]", "Diffie-Hellman": "[0.342, 1.000]",
        "AES (short key)": "[0.207, 1.000]"}
table([["Family", "TP", "FP", "FN", "Precision", "Recall", "F1",
        "Precision 95% CI"]] +
      [[r[0], str(r[1]), str(r[2]), str(r[3]), f"{r[4]:.3f}", f"{r[5]:.3f}",
        f"{r[6]:.3f}", CI95[r[0]]] for r in PER_FAMILY],
      "Table 4. Per-family results for the shipped configuration (v3-full), "
      "with Wilson 95% intervals on precision. The intervals are wide because "
      "each family contributes few call sites; the single AES observation "
      "carries essentially no information.",
      widths=[33 * mm, 11 * mm, 11 * mm, 11 * mm, 20 * mm, 17 * mm, 15 * mm,
              30 * mm],
      align_right=(1, 2, 3, 4, 5, 6), font=7.9)

para("4.3 Exposure Score Discrimination", H2)
table([["File", "Found", "Families", "Lines", "Old score", "New score"]] +
      [[r[0], str(r[1]), str(r[2]), str(r[3]), f"{r[4]:.1f}", f"{r[5]:.1f}"]
       for r in SCORES],
      "Table 5. Exposure scores for every benchmark file under both scoring "
      "models. The severity-sum model ties the two most affected files at the "
      "cap; the three-term model separates all four.",
      widths=[52 * mm, 18 * mm, 21 * mm, 17 * mm, 23 * mm, 23 * mm],
      align_right=(1, 2, 3, 4, 5))
figure(f_sco,
 "Fig. 3. Old and new exposure scores for the four affected files. The old "
 "model saturates at the cap for the two worst files; the new model assigns "
 "four distinct values.", width=152 * mm)
para(
 "The predicted saturation appears exactly where Section 3.6 anticipates it. "
 "The two files whose weighted severity sum exceeds the cap both receive 100.0, "
 "so the old model cannot distinguish a file with 9 findings across 108 lines "
 "from one with 5 findings across 26 lines, although the second is more than "
 "twice as densely affected. The 19 development scan records exhibit the same "
 "effect at greater scale, with a mean of 99.5 and almost no variance.")
para(
 "Two properties of the new model deserve statement rather than concealment. On "
 "small files it can return a higher value than the severity sum: the "
 "half-migrated contract rises from 45.0 to 79.3, because two live "
 "high-severity families within 32 lines is genuinely dense exposure, which a "
 "count-based sum understates. And the ordering is not by finding count, since "
 "the key service outranks the settlement signer on density, 19.2 findings per "
 "hundred lines against 8.3. This is the intended behaviour, but it means the "
 "score must be read as exposure concentration rather than as a proxy for "
 "finding count.")

para("4.4 Comparison with Baseline Models", H2)
para(
 "Two kinds of baseline are relevant. The first is the detector's own earlier "
 "configuration, v1-baseline, reported in Table 3: precision improves from "
 "0.633 to 1.000, an absolute gain of 0.367, with recall held at 1.000 and F1 "
 "rising from 0.776 to 1.000. Because v1 is a real prior version retained "
 "verbatim, this comparison measures an actual historical improvement rather "
 "than a reconstruction.")
para(
 "The second baseline is the existing tooling a practitioner would otherwise "
 "reach for. Slither, Mythril and Manticore report zero findings of this class "
 "by construction, because cryptographic composition lies outside their "
 "detection scope; they are not weaker at the task so much as not addressed to "
 "it. CryptoGuard and CrySL do analyse cryptography but target misuse rules in "
 "Java and report nothing for a correct ECDSA implementation. The comparison in "
 "Table 1 is therefore one of capability coverage rather than of competing "
 "accuracy figures, and no prior tool provides a quantitative baseline on this "
 "specific task. Establishing one is part of the contribution of releasing the "
 "benchmark.")
para(
 "<b>What these numbers do and do not establish.</b> The absolute scores must "
 "not be read as field accuracy. The benchmark is small, at seven files and "
 "nineteen call sites, and it was authored alongside the detector by the same "
 "author; under those conditions a perfect score for the final configuration is "
 "close to guaranteed by construction, because the hard negatives were written "
 "to exercise error classes already identified for repair. What the ablation "
 "does establish is narrower and still useful: each mechanism removes the error "
 "class it targets, the removal is complete even on data designed to be "
 "adversarial, and recall does not pay for it. The defensible reading is the "
 "change from 0.633 to 1.000 under a comparison that isolates its cause.")
para(
 "Sample size compounds this. Nineteen correct predictions out of nineteen "
 "support a Wilson 95% interval on precision of only [0.832, 1.000]. Per family "
 "the position is weaker still: the single short-key AES call site yields "
 "[0.207, 1.000], which is to say nothing at all about that family. No "
 "particular level of accuracy is therefore claimed from this benchmark, only a "
 "difference between configurations measured on identical data. An interval "
 "tight enough to support a claim above 0.95 would require on the order of 150 "
 "labelled call sites.")

para("4.5 Runtime Equivalence", H2)
para(
 "The equivalence harness reports agreement between the Python and JavaScript "
 "implementations on all seven benchmark files across all six compared fields. "
 "The browser runtime therefore carries the measured behaviour of the evaluated "
 "reference implementation rather than an approximation of it, which is a "
 "necessary condition for reporting results obtained from one implementation "
 "while deploying another.")

# ---- 5 Discussion ----------------------------------------------------------
para("5. Discussion", H1)

para("5.1 Answers to the Research Questions", H2)
para(
 "<b>RQ1. What causes false positives, and how much does each contribute?</b> "
 "Two causes account for all eleven false positives observed in the baseline. "
 "Matches inside comments, documentation strings and string literals are the "
 "dominant cause, and duplicate matches on a single call site by overlapping "
 "patterns are the second. A third cause, substring matches inside "
 "non-cryptographic identifiers, is real and reproducible but contributed no "
 "false positive on this data, which is itself informative: the intuitive first "
 "remedy addresses the least damaging cause.")
para(
 "<b>RQ2. Can those causes be eliminated without loss of recall?</b> Yes. "
 "Offset-preserving masking and per-line grouping together remove all eleven "
 "false positives while recall remains exactly 1.000, and raw hits fall from 38 "
 "to 26. Preserving offsets rather than deleting characters is what makes this "
 "possible without sacrificing the line numbers that give the output its "
 "value.")
para(
 "<b>RQ3. Does severity-sum scoring discriminate, and does a multi-factor score "
 "improve on it?</b> Severity-sum scoring does not discriminate: it assigns the "
 "identical maximum to files differing by a factor of 4.5 in finding count and "
 "a factor of 2 in family breadth, and produced a mean of 99.5 across 19 "
 "development scans. The three-term model assigns four distinct values to the "
 "four affected files and preserves zero across all three negatives, so it "
 "discriminates where the previous model could not. It is important to be "
 "precise about the scope of this claim: discrimination is demonstrated, "
 "validity is not, since no study has established that the model's ordering "
 "matches expert risk judgement.")
para(
 "<b>RQ4. Can the logic be ported to a client-side runtime without "
 "divergence?</b> Yes, and the question is worth asking precisely because "
 "maintaining two implementations invites drift that would invalidate the "
 "evaluation. Agreement on all seven files across six fields is verified "
 "mechanically and is intended to be re-run whenever the pattern set changes.")

para("5.2 Comparison with Previous Studies", H2)
para(
 "The accuracy result sits in a different position from the figures reported by "
 "CryptoGuard [6], which achieves low false-positive rates on large Java "
 "codebases by means of refinement insights specific to misuse rules. That work "
 "reduces false positives arising from imprecise data flow; the false positives "
 "characterised here arise earlier, at the lexical layer, and are therefore "
 "orthogonal to it. A tool combining both would be stronger than either, and "
 "the mechanisms contributed here are independent of language and of the "
 "downstream analysis.")
para(
 "Relative to CrySL [7], which requires a usage specification per API, the "
 "approach here needs no specification and consequently gives up the ability to "
 "judge whether an algorithm is used correctly. The two address complementary "
 "questions, and the limitation is intrinsic rather than incidental.")
para(
 "Against the smart contract analysis literature represented by Slither [5], "
 "there is no overlap in detected defect classes. That literature has treated "
 "cryptographic composition as out of scope because, until the standardisation "
 "of post-quantum algorithms, it was not actionable. Our position is that "
 "standardisation has changed this: with FIPS 203, 204 and 205 finalised and a "
 "transition timetable published [11], which algorithms a contract composes is "
 "now a reportable property with a defined remediation.")
para(
 "On the quantitative side, the resource estimates of Webber et al. [13] inform "
 "urgency rather than method, and this work takes no position on the timeline. "
 "The relevant deadline, as Mosca's framing [4] makes clear and as the "
 "transition guidance [11] formalises, is set by secrecy lifetime and migration "
 "duration rather than by any single hardware estimate, which is what makes an "
 "inventory tool useful now rather than later.")

# ---- 6 Conclusion ----------------------------------------------------------
para("6. Conclusion and Future Work", H1)

para("6.1 Summary of Findings", H2)
para(
 "Organisations operating blockchain systems must migrate their cryptography, "
 "and the first step is an inventory of where the vulnerable primitives are "
 "invoked. Existing tools do not produce it: smart contract analysers report "
 "logic defects, and cryptographic analysers report incorrect use of sound "
 "primitives, whereas the problem here is correct use of primitives that are "
 "about to become unsound. This paper presented a toolkit that produces that "
 "inventory and carries it through to migration planning, standards-conformant "
 "export, regulator-facing documentation and a verifiable record.")
para(
 "The substantive finding concerns accuracy. A pattern-based detector for this "
 "task is easy to make complete and hard to make precise, and its errors are "
 "dominated by two systematic classes rather than by scattered noise. "
 "Offset-preserving masking and per-line family grouping remove both, raising "
 "precision from 0.633 to 1.000 at unchanged recall on a benchmark constructed "
 "to be adversarial for this class of detector, while word-boundary anchoring "
 "alone removes no false positive at all. The severity-sum scoring such tools "
 "normally use was shown to saturate, assigning an identical maximum to files "
 "differing severalfold in extent, and a three-term alternative was given that "
 "separates them. The detection logic was additionally shown to port to a "
 "browser runtime with verified identical behaviour.")

para("6.2 Limitations", H2)
bullets([
 "<b>Detection is lexical.</b> The tool identifies cryptographic API usage but "
 "cannot determine whether a correctly named primitive is used correctly, and "
 "cannot follow indirection: a project wrapping ECDSA behind a generic signing "
 "facade yields one finding at the wrapper rather than one per caller. For "
 "migration planning this is often desirable, since the wrapper is the correct "
 "place to change, but it understates the blast radius.",
 "<b>Masking approximates parsing.</b> Unusual or nested string delimiters can "
 "mask imprecisely. Damage is bounded by forbidding single-line literal "
 "patterns from crossing newlines, but a per-language parser would be strictly "
 "more accurate.",
 "<b>Construct validity is the dominant evaluation limitation.</b> The "
 "benchmark was authored alongside the detector, so the hard negatives test "
 "error classes already identified for repair and the final scores are "
 "correspondingly optimistic.",
 "<b>External validity is limited.</b> Seven files of a few dozen lines cannot "
 "represent production blockchain codebases, which are larger, use more "
 "libraries and contain idioms not anticipated here.",
 "<b>The matching criterion is strict.</b> A finding one line from its label "
 "counts as both a false positive and a false negative, penalising near misses "
 "more heavily than a developer would.",
 "<b>Deployment scope.</b> Blockchain records are written to a test network and "
 "so carry no economic finality, and certificates are backed by a local "
 "registry rather than a public verification service.",
])

para("6.3 Future Scope", H2)
para(
 "The clear priority is an independent evaluation corpus, and the harness for "
 "it has been implemented and released so that the protocol is fixed before any "
 "data is collected. It operates in three stages whose separation does the "
 "methodological work. The first samples contracts from creation transactions "
 "in randomly chosen recent blocks, retains those with verified source, and "
 "generates candidate lines using a search deliberately cruder than the "
 "detector, so that the candidate set is a strict superset of anything the "
 "detector can report and detector false negatives become measurable. The "
 "second presents each candidate with surrounding context to a human annotator; "
 "it does not import the detector and never displays its prediction, because an "
 "annotator shown a prediction produces labels that inherit the detector's "
 "biases. Two annotators label independently and disagreements are excluded "
 "rather than resolved by majority vote. The third reports Cohen's kappa "
 "alongside precision, recall and F1 with Wilson intervals, treating kappa "
 "below approximately 0.6 as a gate requiring the labelling policy to be "
 "revised before any accuracy figure is quoted.")
para(
 "Three further directions follow. Replacing lexical masking with per-language "
 "parsing would eliminate the approximation noted above and would permit "
 "call-graph analysis, resolving indirection through wrappers and reporting the "
 "true blast radius. Calibrating the weights of Equation (1) against expert "
 "risk rankings would move the score from discriminating to validated. Finally, "
 "measuring the gas cost of on-chain lattice verification under current and "
 "proposed precompiles would establish when the off-chain architectural "
 "workaround can be retired in favour of direct verification.")

# ---- 7 References ---------------------------------------------------------
para("7. References", H1)
refs = [
 "P. W. Shor, “Polynomial-time algorithms for prime factorization and "
 "discrete logarithms on a quantum computer,” <i>SIAM J. Comput.</i>, "
 "vol. 26, no. 5, pp. 1484–1509, 1997.",
 "L. K. Grover, “A fast quantum mechanical algorithm for database "
 "search,” in <i>Proc. 28th Annu. ACM Symp. Theory of Computing "
 "(STOC)</i>, 1996, pp. 212–219.",
 "S. Nakamoto, “Bitcoin: a peer-to-peer electronic cash system,” "
 "White Paper, 2008.",
 "M. Mosca, “Cybersecurity in an era with quantum computers: will we be "
 "ready?,” <i>IEEE Security &amp; Privacy</i>, vol. 16, no. 5, "
 "pp. 38–41, 2018.",
 "J. Feist, G. Grieco, and A. Groce, “Slither: a static analysis framework "
 "for smart contracts,” in <i>Proc. 2nd Int. Workshop on Emerging Trends "
 "in Software Engineering for Blockchain (WETSEB)</i>, 2019, pp. 8–15.",
 "S. Rahaman <i>et al.</i>, “CryptoGuard: high precision detection of "
 "cryptographic vulnerabilities in massive-sized Java projects,” in "
 "<i>Proc. ACM SIGSAC Conf. Computer and Communications Security (CCS)</i>, "
 "2019, pp. 2455–2472.",
 "S. Krüger, J. Späth, K. Ali, E. Bodden, and M. Mezini, "
 "“CrySL: an extensible approach to validating the correct usage of "
 "cryptographic APIs,” <i>IEEE Trans. Softw. Eng.</i>, vol. 47, no. 11, "
 "pp. 2382–2400, 2021.",
 "National Institute of Standards and Technology, “Module-lattice-based "
 "key-encapsulation mechanism standard,” NIST FIPS 203, 2024.",
 "National Institute of Standards and Technology, “Module-lattice-based "
 "digital signature standard,” NIST FIPS 204, 2024.",
 "National Institute of Standards and Technology, “Stateless hash-based "
 "digital signature standard,” NIST FIPS 205, 2024.",
 "National Institute of Standards and Technology, “Transition to "
 "post-quantum cryptography standards,” NIST IR 8547, 2024.",
 "D. J. Bernstein and T. Lange, “Post-quantum cryptography,” "
 "<i>Nature</i>, vol. 549, no. 7671, pp. 188–194, 2017.",
 "M. Webber, V. Elfving, S. Weidt, and W. B. Hensinger, “The impact of "
 "hardware specifications on reaching quantum advantage in the fault tolerant "
 "regime,” <i>AVS Quantum Sci.</i>, vol. 4, no. 1, 013801, 2022.",
 "OWASP Foundation, “CycloneDX bill of materials specification, version "
 "1.6,” 2024.",
 "E. Barker, “Recommendation for key management: Part 1 — "
 "general,” NIST SP 800-57 Part 1 Rev. 5, 2020.",
]
for i, r in enumerate(refs, 1):
    para(f"[{i}]&nbsp;&nbsp;{r}", REF)


# ================================== BUILD ===================================

def footer(canv, doc_):
    canv.saveState()
    canv.setFont("Times-Roman", 8.4)
    canv.setFillColor(colors.HexColor("#777777"))
    canv.drawCentredString(A4[0] / 2, 12 * mm, str(doc_.page))
    canv.restoreState()


OUT = os.path.join(HERE, "Quantum_PQ_Blockchain_Paper.pdf")
doc = SimpleDocTemplate(
    OUT, pagesize=A4,
    leftMargin=22 * mm, rightMargin=22 * mm,
    topMargin=20 * mm, bottomMargin=20 * mm,
    title="Detecting and Migrating Quantum-Vulnerable Cryptography in "
          "Blockchain Source Code",
    author="Benidict David",
    subject="Post-quantum cryptography migration for blockchain source code",
)
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("WROTE:", OUT)
print("PAGES:", doc.page)
