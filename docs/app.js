/* ───────────────────────────────────────────────────────────────
   Lattice — post-quantum migration console (client side)

   The detection logic here is a direct port of backend/crypto_scanner.py:
   same pattern set, same comment/string masking, same per-line
   deduplication, same three-term risk model. Keep the two in step — the
   Python implementation is what backend/eval/run_eval.py scores.
   ─────────────────────────────────────────────────────────────── */

'use strict';

/* ═══════════════ detection ═══════════════ */

const VULNERABLE = {
  ECDSA: {
    patterns: [
      /ecrecover\s*\(/gi,
      /\bECDSA\s*\./gi,
      /\bsecp256k1\b/gi,
      /elliptic\.curve/gi,
      /from\s+ecdsa\s+import/gi,
      /eth_keys\.keys/gi,
      /Web3\.eth\.account/gi,
      /SigningKey\.generate/gi,
    ],
    description: 'Elliptic Curve Digital Signature Algorithm (vulnerable to quantum attacks)',
    severity: 'HIGH',
  },
  RSA: {
    patterns: [
      /\bRSA\s*\./gi,
      /\brsa\.newkeys\b/gi,
      /from\s+Crypto\.PublicKey\s+import\s+RSA/gi,
      /from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa/gi,
    ],
    description: 'RSA encryption (vulnerable to Shor’s algorithm)',
    severity: 'HIGH',
  },
  SHA256: {
    patterns: [
      /\bhashlib\.sha256\s*\(/gi,
      /\bsha256\s*\(/gi,
      /\bkeccak256\s*\(/gi,
      /\bSHA256\s*\./gi,
    ],
    description: 'SHA-256 hashing (preimage security halved by Grover search)',
    severity: 'MEDIUM',
  },
  DH: {
    patterns: [
      /\bdiffie[-_ ]?hellman/gi,
      /\bDH\.(?:generate|new)\b/gi,
      /\bECDH\b/gi,
    ],
    description: 'Diffie–Hellman key exchange (vulnerable to quantum attacks)',
    severity: 'HIGH',
  },
  AES_SHORT: {
    patterns: [
      /AES\.new\([^)]*?,\s*AES\.MODE_/gi,
      /\bAES[-_]128\b/gi,
    ],
    description: 'AES with potentially insufficient key length for quantum resistance',
    severity: 'MEDIUM',
  },
};

/* No trailing boundary: real module names carry a parameter suffix
   (dilithium2, kyber512, sphincsharaka128f). */
const PQ_SAFE = {
  'ML-DSA':  [/\bml[-_]?dsa/gi, /\bdilithium/gi],
  'ML-KEM':  [/\bml[-_]?kem/gi, /\bkyber/gi],
  'SLH-DSA': [/\bslh[-_]?dsa/gi, /\bsphincs/gi],
  XMSS:      [/\bxmss/gi],
  LMS:       [/\blms[-_ ]hash/gi],
};

const SEVERITY_BASE = { HIGH: 60, MEDIUM: 35, LOW: 15 };

/* Comments and string literals. Triple-quoted strings and block comments come
   first so their single-line counterparts cannot bite into them. */
const NONCODE = /"""[\s\S]*?"""|'''[\s\S]*?'''|\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;

/** Blank comments and strings, preserving length and newlines so offsets and
 *  line numbers still line up with the original source. */
function maskNoncode(src) {
  return src.replace(NONCODE, (m) => m.replace(/[^\n]/g, ' '));
}

/** Line number (1-based) of a character offset. */
function lineAt(text, offset) {
  let n = 1;
  for (let i = 0; i < offset; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function detectLanguage(src) {
  if (/pragma\s+solidity/.test(src)) return 'Solidity';
  if (/contract\s+\w+\s*\{/.test(src)) return 'Solidity';
  if (/def\s+\w+\s*\(/.test(src)) return 'Python';
  if (/package\s+main/.test(src)) return 'Go';
  if (/function\s+\w+\s*\(/.test(src)) return 'JavaScript';
  return 'Unknown';
}

function scanSource(filename, src) {
  const lines = src.split('\n');
  const code = maskNoncode(src);

  // Collect every regex hit against masked (code-only) text.
  const raw = [];
  for (const [algo, def] of Object.entries(VULNERABLE)) {
    for (const re of def.patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(code)) !== null) {
        if (m[0] === '') { re.lastIndex++; continue; }
        const ln = lineAt(code, m.index);
        raw.push({
          algorithm: algo,
          description: def.description,
          severity: def.severity,
          line_number: ln,
          line_content: (lines[ln - 1] || '').trim(),
          matched_pattern: m[0],
          quantum_vulnerable: true,
        });
      }
    }
  }

  // One finding per (family, line); the longest match is the most specific.
  const best = new Map();
  for (const hit of raw) {
    const key = hit.algorithm + ':' + hit.line_number;
    const prev = best.get(key);
    if (!prev || hit.matched_pattern.length > prev.matched_pattern.length) best.set(key, hit);
  }
  const vulnerabilities = [...best.values()].sort(
    (a, b) => a.line_number - b.line_number || a.algorithm.localeCompare(b.algorithm)
  );

  // Names that appear only in prose: reported, never counted.
  const mentions = new Map();
  for (const [algo, def] of Object.entries(VULNERABLE)) {
    for (const re of def.patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(src)) !== null) {
        if (m[0] === '') { re.lastIndex++; continue; }
        if (code.slice(m.index, m.index + m[0].length).trim() !== '') continue;
        const ln = lineAt(src, m.index);
        const key = algo + ':' + ln;
        if (mentions.has(key)) continue;
        mentions.set(key, {
          algorithm: algo,
          line_number: ln,
          line_content: (lines[ln - 1] || '').trim(),
          matched_pattern: m[0],
        });
      }
    }
  }

  const pq = [];
  for (const [algo, pats] of Object.entries(PQ_SAFE)) {
    if (pats.some((re) => { re.lastIndex = 0; return re.test(code); })) pq.push(algo);
  }

  return {
    file_path: filename,
    language: detectLanguage(src),
    total_lines: lines.length,
    vulnerabilities,
    vulnerability_count: vulnerabilities.length,
    informational_mentions: [...mentions.values()].sort((a, b) => a.line_number - b.line_number),
    raw_match_count: raw.length,
    quantum_ready: vulnerabilities.length === 0,
    pq_algorithms_detected: pq,
    source: src,
  };
}

/**
 * Risk score, 0-100. Three independent terms instead of a severity sum, which
 * saturated at 100 for any file with four HIGH findings and so gave every
 * vulnerable file the same score.
 */
function riskScore(scan) {
  const v = scan.vulnerabilities;
  if (!v.length) return { total: 0, base: 0, breadth: 0, density: 0, families: 0, perHundred: 0 };

  const base = Math.max(...v.map((x) => SEVERITY_BASE[x.severity] ?? 15));
  const families = new Set(v.map((x) => x.algorithm)).size;
  const breadth = Math.min(20, 5 * (families - 1));
  const perHundred = (v.length * 100) / Math.max(1, scan.total_lines);
  const density = 20 * (1 - Math.exp(-perHundred / 5));

  return {
    total: Math.round(Math.min(100, base + breadth + density) * 10) / 10,
    base,
    breadth: Math.round(breadth * 10) / 10,
    density: Math.round(density * 10) / 10,
    families,
    perHundred: Math.round(perHundred * 10) / 10,
  };
}

/* ═══════════════ migration mapping ═══════════════ */

const MIGRATION = {
  ECDSA: {
    replacement: 'ML-DSA (Dilithium)', standard: 'FIPS 204',
    note: 'Module-lattice digital signatures. On-chain verification is impractical at current gas costs, so verify off-chain and anchor the result.',
    python: `from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

public_key, secret_key = generate_keypair()
signature = sign(message, secret_key)
verify(signature, message, public_key)   # raises on failure`,
    solidity: `// ML-DSA cannot run on-chain within current gas limits.
// Verify off-chain, then commit the verified digest.
bytes32 public mldsaPublicKeyHash;
mapping(bytes32 => bool) public verifiedOffChain;

function registerVerified(bytes32 digest) external onlyVerifier {
    verifiedOffChain[digest] = true;
}`,
  },
  RSA: {
    replacement: 'ML-KEM (Kyber)', standard: 'FIPS 203',
    note: 'Replace RSA key transport with module-lattice key encapsulation, then use the derived key with AES-256-GCM.',
    python: `from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

public_key, secret_key = generate_keypair()
ciphertext, shared_secret = encrypt(public_key)
shared_secret == decrypt(secret_key, ciphertext)`,
  },
  DH: {
    replacement: 'ML-KEM (Kyber)', standard: 'FIPS 203',
    note: 'Key agreement becomes key encapsulation. Run both classical and ML-KEM in parallel during transition and concatenate the secrets before the KDF.',
    python: `from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt

# Hybrid: concatenate the classical and PQ secrets before the KDF
shared = hkdf(classical_secret + pq_shared_secret)`,
  },
  SHA256: {
    replacement: 'SHA-384 / SHA-512', standard: 'FIPS 180-4',
    note: 'Grover search halves effective preimage resistance. SHA-384 retains a 192-bit margin. Keccak-256 on-chain cannot be swapped without breaking address derivation, so scope this to off-chain hashing.',
    python: `import hashlib

digest = hashlib.sha384(data).digest()   # 192-bit post-quantum margin`,
  },
  AES_SHORT: {
    replacement: 'AES-256-GCM', standard: 'FIPS 197',
    note: 'Grover search halves the effective key length, leaving AES-128 at a 64-bit margin. Move to a 256-bit key with an AEAD mode.',
    python: `from Crypto.Cipher import AES

key = os.urandom(32)                     # 256-bit
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)`,
  },
};

function buildPlan(scan) {
  const groups = new Map();
  for (const v of scan.vulnerabilities) {
    if (!groups.has(v.algorithm)) groups.set(v.algorithm, []);
    groups.get(v.algorithm).push(v);
  }

  const order = ['ECDSA', 'RSA', 'DH', 'AES_SHORT', 'SHA256'];
  const steps = [];
  for (const algo of order) {
    if (!groups.has(algo)) continue;
    const hits = groups.get(algo);
    const map = MIGRATION[algo];
    steps.push({
      algorithm: algo,
      occurrences: hits.length,
      lines: hits.map((h) => h.line_number),
      severity: hits[0].severity,
      replacement: map.replacement,
      standard: map.standard,
      note: map.note,
      template: scan.language === 'Solidity' && map.solidity ? map.solidity : map.python,
    });
  }

  const effort = steps.reduce((n, s) => n + s.occurrences, 0);
  const complexity = effort === 0 ? 'None' : effort <= 3 ? 'Low' : effort <= 9 ? 'Moderate' : 'High';
  const weeks = effort === 0 ? '—' : effort <= 3 ? '1–2 weeks' : effort <= 9 ? '3–6 weeks' : '2–4 months';

  return { steps, complexity, timeline: weeks, families: steps.length };
}

/** Annotate the source at each finding with its replacement target. */
function applyMigrations(scan) {
  const plan = buildPlan(scan);
  const isSol = scan.language === 'Solidity';
  const c = isSol ? '//' : '#';
  const byLine = new Map();
  for (const v of scan.vulnerabilities) {
    if (!byLine.has(v.line_number)) byLine.set(v.line_number, []);
    byLine.get(v.line_number).push(v);
  }

  const out = scan.source.split('\n').map((line, i) => {
    const hits = byLine.get(i + 1);
    if (!hits) return line;
    const indent = line.match(/^\s*/)[0];
    const notes = hits.map((h) => {
      const m = MIGRATION[h.algorithm];
      return `${indent}${c} [PQ-MIGRATE ${h.severity}] ${h.algorithm} -> ${m.replacement} (${m.standard})`;
    });
    return notes.join('\n') + '\n' + line;
  });

  const deps = isSol
    ? `${c} Solidity cannot execute lattice cryptography within current gas limits.\n${c} Verify post-quantum signatures off-chain and commit the verified digest.`
    : `${c} Required: pip install pqcrypto        # or liboqs-python (Open Quantum Safe)`;

  const header = [
    `${c} ==============================================================`,
    `${c} POST-QUANTUM MIGRATION PLAN - generated by Lattice`,
    `${c} Source: ${scan.file_path}   Language: ${scan.language}`,
    `${c} Findings: ${scan.vulnerability_count} across ${plan.families} algorithm family(ies)`,
    `${c} Exposure: ${riskScore(scan).total}/100   Effort: ${plan.complexity} (${plan.timeline})`,
    `${c}`,
    deps,
    `${c}`,
    `${c} Each annotated line below names its replacement target. Review every`,
    `${c} one: this tool marks call sites, it does not rewrite semantics.`,
    `${c} ==============================================================`,
    '',
  ].join('\n');

  return header + out.join('\n');
}

/* ═══════════════ CycloneDX CBOM ═══════════════ */

const PRIMITIVE = {
  ECDSA: ['signature', 'ML-DSA', 'FIPS 204'],
  RSA: ['pke', 'ML-KEM', 'FIPS 203'],
  DH: ['key-agree', 'ML-KEM', 'FIPS 203'],
  SHA256: ['hash', 'SHA-384/SHA-512', 'FIPS 180-4'],
  AES_SHORT: ['block-cipher', 'AES-256', 'FIPS 197'],
};

function buildCbom(scan, meta) {
  const families = [...new Set(scan.vulnerabilities.map((v) => v.algorithm))].sort();
  const components = families.map((algo) => {
    const hits = scan.vulnerabilities.filter((v) => v.algorithm === algo);
    const [primitive, replacement, standard] = PRIMITIVE[algo] || ['unknown', 'N/A', 'N/A'];
    return {
      type: 'cryptographic-asset',
      name: algo,
      'bom-ref': 'crypto/' + algo.toLowerCase(),
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive,
          executionEnvironment: 'software-plain-ram',
          cryptoFunctions: [primitive === 'signature' ? 'verify' : 'other'],
        },
      },
      properties: [
        { name: 'quantumVulnerable', value: 'true' },
        { name: 'severity', value: hits[0].severity },
        { name: 'occurrences', value: String(hits.length) },
        { name: 'affectedLines', value: hits.map((h) => h.line_number).join(',') },
        { name: 'recommendedReplacement', value: replacement },
        { name: 'nistStandard', value: standard },
      ],
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:' + meta.scanId,
    version: 1,
    metadata: {
      timestamp: meta.timestamp,
      tools: [{ vendor: 'Lattice', name: 'pq-migration-console', version: '2.0.0' }],
      component: { type: 'file', name: scan.file_path, 'bom-ref': 'file/' + meta.scanId },
      properties: [
        { name: 'language', value: scan.language },
        { name: 'riskScore', value: String(riskScore(scan).total) },
        { name: 'organization', value: meta.company },
        { name: 'sector', value: meta.sector },
        { name: 'postQuantumDetected', value: scan.pq_algorithms_detected.join(',') || 'none' },
      ],
    },
    components,
  };
}

/* ═══════════════ state ═══════════════ */

const state = { scan: null, meta: null, plan: null, risk: null };

const EXAMPLE_SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ConsentRegistry
 * @dev Patient-consent registry. Signature path is quantum-vulnerable.
 */
contract ConsentRegistry {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public consentGiven;
    address public owner;

    event ConsentRecorded(address indexed patient, bytes32 recordHash);

    constructor() {
        owner = msg.sender;
    }

    /// @dev Recovers the signer. ecrecover is ECDSA - broken by Shor.
    function verifySignature(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        public pure returns (address)
    {
        return ecrecover(messageHash, v, r, s);
    }

    function recordConsent(
        bytes32 recordHash, uint8 v, bytes32 r, bytes32 s
    ) public {
        address patient = verifySignature(recordHash, v, r, s);
        require(patient != address(0), "bad signature");
        consentGiven[recordHash] = true;
        emit ConsentRecorded(patient, recordHash);
    }

    function hashRecord(string memory data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(data));
    }

    function commitment(address user, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }
}
`;

const EXAMPLE_PY = `"""
Batch settlement signer for a pharmaceutical supply chain.
Pre-migration: every primitive here is quantum-vulnerable.
"""
from ecdsa import SigningKey, SECP256k1
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
import os


class SettlementSigner:
    def __init__(self):
        self.signing_key = SigningKey.generate(curve=SECP256k1)
        self.transport_key = RSA.generate(2048)
        self.session_key = os.urandom(16)

    def sign_batch(self, payload: bytes) -> bytes:
        digest = hashlib.sha256(payload).digest()
        return self.signing_key.sign(digest)

    def seal(self, payload: bytes) -> bytes:
        cipher = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, _tag = cipher.encrypt_and_digest(payload)
        return ciphertext

    def manifest_id(self, batch: list) -> str:
        joined = "|".join(sorted(batch)).encode()
        return hashlib.sha256(joined).hexdigest()

    def diffie_hellman_exchange(self, peer_public: int, modulus: int) -> int:
        secret = int.from_bytes(self.session_key, "big")
        return pow(peer_public, secret, modulus)
`;

/* ═══════════════ rendering ═══════════════ */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function gaugeColour(total) {
  if (total === 0) return 'var(--safe)';
  if (total < 60) return 'var(--medium)';
  return 'var(--high)';
}

function render() {
  const { scan, risk, plan, meta } = state;

  $('heroLines').textContent = scan.total_lines;
  $('heroFindings').textContent = scan.vulnerability_count;
  $('scanSubject').textContent = `${meta.filename} · ${scan.language} · ${scan.total_lines} lines`;

  const g = $('gauge');
  g.style.setProperty('--pct', risk.total);
  g.style.setProperty('--gauge-col', gaugeColour(risk.total));
  $('riskValue').textContent = risk.total;

  $('gaugeBreak').innerHTML = risk.total === 0
    ? '<div><dt>Result</dt><dd>No vulnerable call sites</dd></div>'
    : [
        ['Worst severity', `${risk.base} / 60`],
        ['Family breadth', `${risk.breadth} / 20 (${risk.families})`],
        ['Finding density', `${risk.density} / 20 (${risk.perHundred}/100 ln)`],
        ['Raw regex hits', `${scan.raw_match_count} → ${scan.vulnerability_count} deduped`],
      ].map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('');

  const famList = $('famList');
  if (!scan.vulnerability_count) {
    famList.innerHTML = `<li class="empty-safe">
      <strong>No quantum-vulnerable call sites</strong>
      <span>This file is eligible for a quantum-safe certificate.</span>
    </li>`;
  } else {
    const counts = {};
    for (const v of scan.vulnerabilities) {
      counts[v.algorithm] = counts[v.algorithm] || { n: 0, sev: v.severity };
      counts[v.algorithm].n++;
    }
    const max = Math.max(...Object.values(counts).map((c) => c.n));
    famList.innerHTML = Object.entries(counts)
      .sort((a, b) => b[1].n - a[1].n)
      .map(([algo, c]) => {
        const m = MIGRATION[algo];
        return `<li class="famrow">
          <div class="famrow-top">
            <span class="famrow-name">${esc(algo)}</span>
            <span class="famrow-meta">${c.n} × → ${esc(m.replacement)}</span>
          </div>
          <div class="fambar"><span class="sev-${c.sev}" style="width:${(c.n / max) * 100}%"></span></div>
        </li>`;
      }).join('');
  }

  if (scan.pq_algorithms_detected.length) {
    $('pqFound').textContent = scan.pq_algorithms_detected.join(' · ');
    $('pqBox').hidden = false;
  } else {
    $('pqBox').hidden = true;
  }

  $('findingCount').textContent = scan.vulnerability_count;
  $('findingRows').innerHTML = scan.vulnerability_count
    ? scan.vulnerabilities.map((v) => `<tr>
        <td>${v.line_number}</td>
        <td class="cell-fam">${esc(v.algorithm)}</td>
        <td><span class="sev-tag ${v.severity}">${v.severity}</span></td>
        <td><span class="cell-match">${esc(v.matched_pattern)}</span></td>
        <td class="cell-src">${esc(v.line_content)}</td>
      </tr>`).join('')
    : `<tr><td colspan="5" style="padding:22px;text-align:center;color:var(--safe)">
         No active call sites found.</td></tr>`;

  const mentions = scan.informational_mentions;
  $('infoDetails').hidden = mentions.length === 0;
  $('infoCount').textContent = mentions.length;
  $('infoList').innerHTML = mentions.map((m) =>
    `<li><b>L${m.line_number} · ${esc(m.algorithm)}</b> — ${esc(m.line_content)}</li>`).join('');

  $('planMeta').textContent = scan.vulnerability_count
    ? `${plan.families} family(ies) · effort ${plan.complexity} · ${plan.timeline}`
    : 'Nothing to migrate.';
  $('planSteps').innerHTML = plan.steps.length
    ? plan.steps.map((s, i) => `<div class="step">
        <div class="step-head">
          <span class="step-n">${i + 1}</span>
          <span class="step-title">${esc(s.algorithm)} <em>→ ${esc(s.replacement)}</em></span>
          <span class="step-std">${esc(s.standard)}</span>
          <span class="sev-tag ${s.severity}">${s.severity}</span>
        </div>
        <div class="step-body">
          <p>${esc(s.note)}</p>
          <div class="step-lines">Affected line(s): <b>${s.lines.join(', ')}</b> (${s.occurrences} call site${s.occurrences > 1 ? 's' : ''})</div>
          <pre>${esc(s.template)}</pre>
        </div>
      </div>`).join('')
    : `<div class="empty-safe"><strong>Already post-quantum</strong>
       <span>No classical primitives remain in this file.</span></div>`;

  $('btnBadge').disabled = scan.vulnerability_count > 0;
}

function out(html, kind) {
  const box = $('outBox');
  box.className = 'outbox' + (kind ? ' ' + kind : '');
  box.innerHTML = html;
  box.hidden = false;
}

/* ═══════════════ scanning ═══════════════ */

function runScan(filename, src) {
  const scan = scanSource(filename, src);
  state.scan = scan;
  state.risk = riskScore(scan);
  state.plan = buildPlan(scan);
  state.meta = {
    scanId: (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()),
    timestamp: new Date().toISOString(),
    filename,
    company: $('companyName').value.trim() || 'Unnamed organisation',
    sector: $('sector').value,
    email: $('contactEmail').value.trim(),
  };
  render();
  $('outBox').hidden = true;
}

/* ═══════════════ deliverables ═══════════════ */

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function doMigrate() {
  const { scan, meta } = state;
  const ext = (meta.filename.match(/\.[^.]+$/) || ['.txt'])[0];
  const stem = meta.filename.replace(/\.[^.]+$/, '');
  download(new Blob([applyMigrations(scan)], { type: 'text/plain' }), `${stem}.pq-migrated${ext}`);
  out(`<strong>Migrated source downloaded</strong>
       <span>${scan.vulnerability_count} call site(s) annotated with their replacement target.
       Review each one — the tool marks sites, it does not rewrite semantics.</span>`, 'ok');
}

function doCbom() {
  const cbom = buildCbom(state.scan, state.meta);
  download(new Blob([JSON.stringify(cbom, null, 2)], { type: 'application/json' }),
           `cbom_${state.meta.scanId.slice(0, 8)}.cdx.json`);
  out(`<strong>CBOM exported</strong>
       <span>CycloneDX 1.6, ${cbom.components.length} cryptographic-asset component(s).
       Readable by any standard SBOM/CBOM tool.</span>`, 'ok');
}

function doReport() {
  const { scan, meta, risk, plan } = state;
  const type = $('reportType').value;
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const W = doc.internal.pageSize.getWidth();
  const M = 52;
  let y = M;

  const TITLES = {
    'RBI': 'Quantum Readiness Disclosure — RBI Cybersecurity Framework',
    'CERT-In': 'Cryptographic Vulnerability Note — CERT-In Format',
    'Insurance': 'Cyber Risk Annexure — Cryptographic Exposure',
    'General': 'Post-Quantum Cryptography Assessment',
  };

  const line = (gap) => { y += (gap || 16); if (y > 760) { doc.addPage(); y = M; } };
  const text = (s, size, style, colour) => {
    doc.setFont('helvetica', style || 'normal');
    doc.setFontSize(size || 10);
    doc.setTextColor(colour || '#1a2433');
    doc.text(String(s), M, y);
  };

  doc.setFillColor('#0b1320');
  doc.rect(0, 0, W, 86, 'F');
  doc.setFont('helvetica', 'bold'); doc.setFontSize(17); doc.setTextColor('#e9f0f9');
  doc.text('LATTICE', M, 40);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor('#35e8d0');
  doc.text('POST-QUANTUM MIGRATION ASSESSMENT', M, 58);
  doc.setTextColor('#93a7c4');
  doc.text(new Date(meta.timestamp).toLocaleString(), W - M, 58, { align: 'right' });

  y = 126;
  text(TITLES[type] || TITLES.General, 13, 'bold'); line(26);

  text('ORGANISATION', 8, 'bold', '#65789a'); line(14);
  text(meta.company, 11, 'bold'); line(15);
  text(`Sector: ${meta.sector}`, 10); line(14);
  text(`Contact: ${meta.email || 'not supplied'}`, 10); line(14);
  text(`Artefact: ${meta.filename}  (${scan.language}, ${scan.total_lines} lines)`, 10); line(14);
  text(`Assessment ID: ${meta.scanId}`, 9, 'normal', '#65789a'); line(26);

  doc.setFillColor(risk.total === 0 ? '#e8faf6' : risk.total < 60 ? '#fff6e6' : '#ffecef');
  doc.roundedRect(M, y - 12, W - M * 2, 62, 6, 6, 'F');
  text('EXPOSURE SCORE', 8, 'bold', '#65789a'); line(22);
  doc.setFont('helvetica', 'bold'); doc.setFontSize(24);
  doc.setTextColor(risk.total === 0 ? '#0f7a68' : risk.total < 60 ? '#9a6200' : '#c0243c');
  doc.text(`${risk.total} / 100`, M, y);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10); doc.setTextColor('#1a2433');
  doc.text(`${scan.vulnerability_count} vulnerable call site(s) across ${plan.families} family(ies)`, M + 130, y - 6);
  doc.setFontSize(9); doc.setTextColor('#65789a');
  doc.text(`Severity ${risk.base}/60 · breadth ${risk.breadth}/20 · density ${risk.density}/20`, M + 130, y + 9);
  line(44);

  text('FINDINGS', 8, 'bold', '#65789a'); line(18);
  if (!scan.vulnerability_count) {
    text('No quantum-vulnerable cryptographic call sites were detected.', 10); line(20);
  } else {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold'); doc.setTextColor('#65789a');
    doc.text('LINE', M, y); doc.text('FAMILY', M + 48, y);
    doc.text('SEV', M + 140, y); doc.text('CALL SITE', M + 190, y);
    line(6);
    doc.setDrawColor('#d4dced'); doc.line(M, y, W - M, y); line(13);
    doc.setFont('helvetica', 'normal'); doc.setTextColor('#1a2433');
    for (const v of scan.vulnerabilities) {
      doc.text(String(v.line_number), M, y);
      doc.text(v.algorithm, M + 48, y);
      doc.setTextColor(v.severity === 'HIGH' ? '#c0243c' : '#9a6200');
      doc.text(v.severity, M + 140, y);
      doc.setTextColor('#48566e');
      const snippet = doc.splitTextToSize(v.line_content || v.matched_pattern, W - M - 190 - 10)[0] || '';
      doc.text(snippet, M + 190, y);
      doc.setTextColor('#1a2433');
      line(14);
    }
    line(10);
  }

  text('REQUIRED MIGRATION', 8, 'bold', '#65789a'); line(18);
  for (const s of plan.steps) {
    text(`${s.algorithm} → ${s.replacement}  (${s.standard})`, 10, 'bold'); line(14);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor('#48566e');
    for (const ln of doc.splitTextToSize(s.note, W - M * 2)) { doc.text(ln, M, y); line(12); }
    doc.setTextColor('#65789a');
    doc.text(`Lines: ${s.lines.join(', ')}`, M, y); line(20);
    doc.setTextColor('#1a2433');
  }
  if (!plan.steps.length) { text('None required.', 10); line(20); }

  text(`Estimated effort: ${plan.complexity} — ${plan.timeline}`, 10, 'bold'); line(28);

  text('APPLICABLE STANDARDS', 8, 'bold', '#65789a'); line(14);
  doc.setFontSize(9); doc.setTextColor('#48566e');
  for (const ln of [
    'NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA)',
    'RBI Guidelines on Cybersecurity Framework · CERT-In Vulnerability Notes',
    'ISO/IEC 27001 Information Security Management',
  ]) { doc.text(ln, M, y); line(13); }
  line(10);
  doc.setTextColor('#65789a'); doc.setFontSize(8);
  for (const ln of doc.splitTextToSize(
    'Method: lexical analysis over comment- and string-masked source, with per-line '
    + 'deduplication. Detects cryptographic API usage; does not detect misuse of a correctly '
    + 'named primitive and does not follow indirection through wrapper functions. This '
    + 'assessment is a migration worklist and is not a substitute for a cryptographic audit.',
    W - M * 2)) { doc.text(ln, M, y); line(11); }

  doc.save(`lattice_${type}_${meta.scanId.slice(0, 8)}.pdf`);
  out(`<strong>${esc(type)} report generated</strong>
       <span>${doc.internal.getNumberOfPages()} page(s), covering ${scan.vulnerability_count} finding(s)
       and ${plan.families} migration step(s).</span>`, 'ok');
}

function doBadge() {
  const { scan, meta } = state;
  if (scan.vulnerability_count > 0) {
    out(`<strong>Not certified</strong>
         <span>${scan.vulnerability_count} quantum-vulnerable finding(s) remain. Apply the
         migration, then re-scan the migrated file to qualify.</span>`, 'warn');
    return;
  }

  const d = new Date();
  const badgeId = 'QS-' + d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0')
                + '-' + meta.scanId.slice(0, 8).toUpperCase();

  const S = 2;
  const cv = document.createElement('canvas');
  cv.width = 820 * S; cv.height = 520 * S;
  const x = cv.getContext('2d');
  x.scale(S, S);

  const grad = x.createLinearGradient(0, 0, 820, 520);
  grad.addColorStop(0, '#0b1320'); grad.addColorStop(1, '#101b2c');
  x.fillStyle = grad; x.fillRect(0, 0, 820, 520);

  x.strokeStyle = 'rgba(53,232,208,0.13)'; x.lineWidth = 1;
  for (let i = 0; i <= 820; i += 34) { x.beginPath(); x.moveTo(i, 0); x.lineTo(i, 520); x.stroke(); }
  for (let j = 0; j <= 520; j += 34) { x.beginPath(); x.moveTo(0, j); x.lineTo(820, j); x.stroke(); }

  x.strokeStyle = '#35e8d0'; x.lineWidth = 2;
  x.strokeRect(24, 24, 772, 472);
  x.strokeStyle = 'rgba(124,107,255,0.55)';
  x.strokeRect(34, 34, 752, 452);

  x.textAlign = 'center';
  x.fillStyle = '#35e8d0';
  x.font = '600 13px "IBM Plex Mono", monospace';
  x.fillText('QUANTUM-SAFE CERTIFICATION', 410, 96);

  x.fillStyle = '#e9f0f9';
  x.font = '700 15px "IBM Plex Mono", monospace';
  x.fillText('NIST FIPS 203 / 204 / 205', 410, 124);

  x.font = '700 34px "Chakra Petch", sans-serif';
  const name = meta.company.length > 34 ? meta.company.slice(0, 33) + '…' : meta.company;
  x.fillText(name, 410, 196);

  x.fillStyle = '#93a7c4';
  x.font = '400 14px "IBM Plex Sans", sans-serif';
  x.fillText(`${meta.sector} sector`, 410, 222);

  x.fillStyle = '#c9d8ea';
  x.font = '400 13px "IBM Plex Sans", sans-serif';
  [
    'The source artefact below was analysed for quantum-vulnerable',
    'cryptography and contains no classical primitives at risk from',
    'Shor’s or Grover’s algorithms at the time of assessment.',
  ].forEach((t, i) => x.fillText(t, 410, 282 + i * 22));

  x.save();
  x.translate(410, 388); x.rotate(Math.PI / 4);
  x.strokeStyle = '#35e8d0'; x.lineWidth = 2;
  x.strokeRect(-19, -19, 38, 38);
  x.fillStyle = 'rgba(53,232,208,0.22)';
  x.fillRect(-12, -12, 24, 24);
  x.restore();

  x.fillStyle = '#65789a';
  x.font = '400 11px "IBM Plex Mono", monospace';
  x.fillText(`CERTIFICATE ${badgeId}`, 410, 442);
  x.fillText(`${meta.filename}  ·  ${scan.language}  ·  ${scan.total_lines} lines`, 410, 460);
  x.fillText(`Issued ${d.toISOString().slice(0, 10)}  ·  exposure score 0/100`, 410, 478);

  const dataUrl = cv.toDataURL('image/png');
  cv.toBlob((blob) => {
    download(blob, `badge_${badgeId}.png`);
    out(`<strong>Badge issued — ${esc(badgeId)}</strong>
         <span>Certificate downloaded. Anchor the proof on-chain to make it
         independently verifiable.</span>
         <img src="${dataUrl}" alt="Quantum-safe certificate for ${esc(meta.company)}">`, 'ok');
  }, 'image/png');
}

/* ═══════════════ on-chain anchoring (viewer's wallet) ═══════════════ */

const CONTRACT = '0x9F7946197AD3693e79948a229AAf177fAC3644Bf';
const ABI = ['function storeProof(string scanId, string company, uint256 riskScore, bytes32 dataHash)'];
const SEPOLIA_HEX = '0xaa36a7';

async function doChain() {
  const btn = $('btnChain');
  if (!window.ethereum) {
    out(`<strong>No wallet detected</strong>
         <span>Anchoring signs a Sepolia transaction from your own wallet, so this site
         never holds a private key. Install a browser wallet such as MetaMask, or run the
         Python backend from the repository if you prefer server-side anchoring.</span>`, 'warn');
    return;
  }
  if (!window.ethers) {
    out('<strong>Wallet library unavailable</strong><span>The ethers bundle did not load. Check the network and reload.</span>', 'err');
    return;
  }

  btn.disabled = true;
  try {
    out('<strong>Awaiting wallet…</strong><span>Approve the connection, then the transaction.</span>');

    const provider = new ethers.providers.Web3Provider(window.ethereum, 'any');
    await provider.send('eth_requestAccounts', []);

    const net = await provider.getNetwork();
    if (net.chainId !== 11155111) {
      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: SEPOLIA_HEX }],
        });
      } catch (switchErr) {
        out('<strong>Wrong network</strong><span>Switch your wallet to Ethereum Sepolia and try again.</span>', 'warn');
        return;
      }
    }

    const { scan, meta, risk } = state;
    const proof = JSON.stringify({
      scan_id: meta.scanId,
      company_name: meta.company,
      timestamp: meta.timestamp,
      vulnerabilities_count: scan.vulnerability_count,
      risk_score: risk.total,
    });
    const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(proof));

    const signer = new ethers.providers.Web3Provider(window.ethereum, 'any').getSigner();
    const contract = new ethers.Contract(CONTRACT, ABI, signer);
    const tx = await contract.storeProof(meta.scanId, meta.company, Math.round(risk.total), dataHash);

    out(`<strong>Transaction submitted</strong>
         <span>Waiting for confirmation…</span>
         <a href="https://sepolia.etherscan.io/tx/${tx.hash}" target="_blank" rel="noopener">${tx.hash}</a>`);

    const receipt = await tx.wait();
    out(`<strong>Proof anchored on Sepolia</strong>
         <span>Block ${receipt.blockNumber} · digest <code>${dataHash.slice(0, 22)}…</code></span>
         <a href="https://sepolia.etherscan.io/tx/${tx.hash}" target="_blank" rel="noopener">View on Etherscan</a>`, 'ok');
  } catch (err) {
    const msg = (err && (err.reason || err.message)) || String(err);
    out(`<strong>Anchoring failed</strong><span>${esc(msg.slice(0, 220))}</span>`, 'err');
  } finally {
    btn.disabled = false;
  }
}

/* ═══════════════ lattice field ═══════════════ */

function startLattice() {
  const cv = $('lattice');
  if (!cv || !cv.getContext) return;
  const x = cv.getContext('2d');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // A 3D point lattice: the mathematical object post-quantum hardness rests on.
  const N = 4, GAP = 66;
  const pts = [];
  for (let i = -N; i <= N; i++)
    for (let j = -N; j <= N; j++)
      for (let k = -N; k <= N; k++)
        if (i * i + j * j + k * k <= N * N + 2)
          pts.push({ x: i * GAP, y: j * GAP, z: k * GAP });

  // Precompute lattice bonds once: nearest neighbour along one axis.
  const bonds = [];
  for (let i = 0; i < pts.length; i++)
    for (let j = i + 1; j < pts.length; j++) {
      const d = Math.abs(pts[i].x - pts[j].x) + Math.abs(pts[i].y - pts[j].y) + Math.abs(pts[i].z - pts[j].z);
      if (d === GAP) bonds.push([i, j]);
    }

  let w = 0, h = 0;
  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = cv.clientWidth; h = cv.clientHeight;
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    x.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener('resize', resize);

  function frame(t) {
    const a = reduce ? 0.6 : t / 16000;
    const b = reduce ? 0.3 : Math.sin(t / 23000) * 0.32 + 0.24;
    const ca = Math.cos(a), sa = Math.sin(a), cb = Math.cos(b), sb = Math.sin(b);
    const cx = w / 2, cy = h * 0.42, FOV = 640, DIST = 820;

    x.clearRect(0, 0, w, h);

    const proj = new Array(pts.length);
    for (let i = 0; i < pts.length; i++) {
      const p = pts[i];
      const rx = p.x * ca - p.z * sa;
      const rz = p.x * sa + p.z * ca;
      const ry = p.y * cb - rz * sb;
      const rz2 = p.y * sb + rz * cb + DIST;
      const s = FOV / Math.max(1, rz2);
      proj[i] = { sx: cx + rx * s, sy: cy + ry * s, s };
    }

    x.lineWidth = 1;
    for (const [i, j] of bonds) {
      const a1 = proj[i], a2 = proj[j];
      const alpha = (a1.s + a2.s) * 0.14 - 0.07;
      if (alpha <= 0.004) continue;
      x.strokeStyle = `rgba(86,126,196,${Math.min(0.26, alpha)})`;
      x.beginPath(); x.moveTo(a1.sx, a1.sy); x.lineTo(a2.sx, a2.sy); x.stroke();
    }

    for (const p of proj) {
      const alpha = p.s * 0.7 - 0.1;
      if (alpha <= 0.01) continue;
      x.fillStyle = `rgba(53,232,208,${Math.min(0.42, alpha * 0.5)})`;
      x.beginPath(); x.arc(p.sx, p.sy, Math.max(0.4, p.s * 1.5), 0, Math.PI * 2); x.fill();
    }

    if (!reduce) requestAnimationFrame(frame);
  }

  requestAnimationFrame(frame);
}

/* ═══════════════ wiring ═══════════════ */

function readFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    $('fileName').textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} kB · never uploaded`;
    runScan(file.name, String(reader.result || ''));
    $('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  reader.readAsText(file);
}

document.addEventListener('DOMContentLoaded', () => {
  startLattice();

  const dz = $('dropZone');
  const input = $('codeFile');

  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) readFile(e.target.files[0]);
  });
  ['dragenter', 'dragover'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dz.addEventListener(ev, () => dz.classList.remove('over')));
  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readFile(f);
  });

  $('scanForm').addEventListener('submit', (e) => {
    e.preventDefault();
    if (input.files && input.files[0]) readFile(input.files[0]);
    else if (state.scan) runScan(state.meta.filename, state.scan.source);
    else runScan('ConsentRegistry.sol', EXAMPLE_SOL);
  });

  $('loadSolidity').addEventListener('click', () => {
    $('fileName').textContent = 'ConsentRegistry.sol · bundled example';
    runScan('ConsentRegistry.sol', EXAMPLE_SOL);
    $('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  $('loadPython').addEventListener('click', () => {
    $('fileName').textContent = 'settlement_signer.py · bundled example';
    runScan('settlement_signer.py', EXAMPLE_PY);
    $('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  $('btnMigrate').addEventListener('click', doMigrate);
  $('btnCbom').addEventListener('click', doCbom);
  $('btnReport').addEventListener('click', doReport);
  $('btnBadge').addEventListener('click', doBadge);
  $('btnChain').addEventListener('click', doChain);

  // Open in a real working state rather than an empty shell.
  runScan('ConsentRegistry.sol', EXAMPLE_SOL);
  $('scanSubject').textContent = 'ConsentRegistry.sol · bundled example · Solidity';
});
