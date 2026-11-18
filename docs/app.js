/* ───────────────────────────────────────────────────────────────
   QRBST Web Scanner — post-quantum migration (client side)

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
      /(?<![A-Za-z0-9])(?<!id_)ECDSA\d*(?![A-Za-z0-9_])/gi,
      /\bECDSA_(?:sign|verify|do_sign|do_verify|size|SIG_\w+|P(?:256|384)_\w+)\b/gi,
      /\bsecp256k1\b/gi,
      /elliptic\.curve/gi,
      /from\s+ecdsa\s+import/gi,
      /from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec\b/gi,
      /eth_keys\.keys/gi,
      /Web3\.eth\.account/gi,
      /SigningKey\.generate/gi,
      /(?<![A-Za-z0-9])(?<!id_)ed(?:25519|448)/gi,
      /\beddsa\b/gi,
      /\bsec[pt]\d{3}[rk][12]\b/gi,
      /\bprime(?:192|239|256)v[123]\b/gi,
      /\bNIST(?:192|224|256|384|521)p\b/gi,
      /\bbrainpoolP\d{3}[rt]1\b/gi,
      /\belliptic\.P(?:224|256|384|521)\b/gi,
      /\bEC(?:Public|Private)Key(?:Spec)?\b/gi,
      /\bECDSASigner\b/gi,
      /\bEC_KEY_\w+/gi,
      /\bEVP_PKEY_EC\b/gi,
      /\bNID_(?:X9_62_prime\d+v\d|secp\d+[rk]1|brainpoolP\d+r1)\b/gi,
      /#include\s*<openssl\/(?:ec|ecdsa)\.h>/gi,
      /\b(?:p256|p384|p521|k256)::/gi,
      /\bjava\.security\.(?:spec|interfaces)\.EC\w*/gi,
      /\bEllipticCurve(?:Public|Private)(?:Key|Numbers)\b/gi,
      /\bEdDSA[A-Za-z]\w*/gi,
    ],
    calls: [
      /\bgenerateKeyPair(?:Sync)?\)?\s*\(\s*['\"`](?:ec|ed25519|ed448)['\"`]/gi,
      /\bname\s*:\s*['\"`](?:ECDSA|Ed25519)['\"`]/gi,
      /\bnamedCurve\s*:\s*['\"`](?:P-(?:256|384|521)|secp256k1|prime256v1)['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`](?:EC|ECDSA|Ed25519|Ed448|EdDSA)['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`][\w-]*withECDSA/gi,
      /\bECGenParameterSpec\s*\(\s*['\"`]/gi,
      /\b(?:curve|curve_name|crv)\s*(?:==|!=|=)\s*['\"`](?:ed25519|ed448|secp\d{3}[rk]1|prime\d{3}v\d|P-(?:256|384|521)|brainpoolP\d{3}r1)['\"`]/gi,
      /\b_?(?:algorithms?|alg|algo|hash_?alg\w*|digest_?alg\w*)\s*(?:==|!=|=|:)\s*\[?\s*['\"`](?:ES(?:256K?|384|512)|EdDSA)['\"`]/gi,
    ],
    config: [
      /\b(?:algorithm|key_?algorithm|keyAlgorithm|key_?type|keyType)\s*[:=]\s*[\"']?(?:ECDSA|ED25519|EdDSA|EC_)/gi,
      /\b(?:key_?spec|customer_master_key_spec)\s*[:=]\s*[\"']?ECC_/gi,
      /\becdsa_curve\s*[:=]/gi,
      /(?<![A-Za-z0-9!])aECDSA(?![A-Za-z0-9])/gi,
      /(?<![A-Za-z0-9!])(?:ECDHE-)?ECDSA-(?:AES|CHACHA20|DES|3DES|CAMELLIA|NULL)/gi,
      /\bTLS_ECDHE_ECDSA_WITH_/gi,
      /\becdsa-sha2-nistp\d+/gi,
      /\bsec[pt]\d{3}[rk][12]\b/gi,
      /\bprime(?:192|239|256)v[123]\b/gi,
      /\bbrainpoolP\d{3}[rt]1\b/gi,
      /(?<![A-Za-z0-9!])(?<!id_)ed(?:25519|448)/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"(?:crypto\/(?:ecdsa|ed25519|elliptic)|golang\.org\/x\/crypto\/ed25519)\"/gim,
    ],
    description: 'Elliptic-curve signatures, incl. ECDSA and Ed25519/EdDSA (broken by Shor’s algorithm)',
    severity: 'HIGH',
    quantumVulnerable: true,
    quantumThreat: 'shor',
  },
  RSA: {
    patterns: [
      /\bRSA\s*\./gi,
      /\brsa\.newkeys\b/gi,
      /from\s+Crypto\.PublicKey\s+import\s+RSA/gi,
      /from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa/gi,
      /\b(?:public|private)(?:En|De)crypt\s*\(/gi,
      /\bRSA(?:Public|Private)(?:Crt)?Key(?:Spec|Parameters)?\b/gi,
      /\bRSACryptoServiceProvider\b/gi,
      /\bRSA_(?:generate_key(?:_ex)?|new|sign|verify|public_encrypt|private_decrypt|private_encrypt|public_decrypt)\b/gi,
      /\bEVP_PKEY_RSA\b/gi,
      /#include\s*<openssl\/rsa\.h>/gi,
      /\buse\s+rsa::/gi,
      /\bPKCS1_(?:OAEP|v1_5)\b/gi,
      /\bjava\.security\.(?:spec|interfaces)\.RSA\w*/gi,
      /\bpadding\.(?:PKCS1v15|PSS|OAEP)\b/gi,
    ],
    calls: [
      /\bgenerateKeyPair(?:Sync)?\)?\s*\(\s*['\"`]rsa(?:-pss)?['\"`]/gi,
      /\bcreate(?:Sign|Verify)\)?\s*\(\s*['\"`]rsa-/gi,
      /\bname\s*:\s*['\"`](?:RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5)['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`](?:RSA(?:\/|['\"`])|RSASSA-|RSA-(?:OAEP|PSS)|[\w-]*withRSA)/gi,
      /\b_?(?:algorithms?|alg|algo|hash_?alg\w*|digest_?alg\w*)\s*(?:==|!=|=|:)\s*\[?\s*['\"`](?:RS|PS)(?:256|384|512)['\"`]/gi,
      /\b_?(?:algorithms?|alg|algo|hash_?alg\w*|digest_?alg\w*)\s*(?:==|!=|=|:)\s*\[?\s*['\"`](?:RSA-OAEP(?:-256)?|RSA1_5)['\"`]/gi,
    ],
    config: [
      /\b(?:algorithm|key_?algorithm|keyAlgorithm|key_?spec|customer_master_key_spec|key_?type|keyType)\s*[:=]\s*[\"']?RSA/gi,
      /(?<![A-Za-z0-9!])(?:ECDHE-|DHE-|EDH-)?RSA-(?:AES|CHACHA20|DES|3DES|CAMELLIA|SEED|NULL)/gi,
      /\bTLS_(?:(?:EC)?DHE_)?RSA_WITH_/gi,
      /(?<![A-Za-z0-9!])[ak]RSA(?![A-Za-z0-9])/gi,
      /\brsa_bits\s*[:=]/gi,
      /\bssh-rsa\b/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"crypto\/rsa\"/gim,
    ],
    description: 'RSA encryption (broken by Shor’s algorithm)',
    severity: 'HIGH',
    quantumVulnerable: true,
    quantumThreat: 'shor',
  },
  SHA256: {
    patterns: [
      /\bhashlib\.sha256\s*\(/gi,
      /\b(?:digestmod|hashfunc|hash_name)\s*=\s*hashlib\.sha256\b/gi,
      /\bsha256\s*\(/gi,
      /\bkeccak256\s*\(/gi,
      /\bSHA256\s*\./gi,
      /\bkeccak\s*\(/gi,
      /(?<![A-Za-z0-9])keccak_?256/gi,
      /from\s+hashlib\s+import\s+[^\n]*\bsha256\b/gi,
      /\bSHA256_(?:Init|Update|Final)\b/gi,
      /\bEVP_sha256\b/gi,
      /\bsha256::/gi,
      /\bsha2::Sha256\b/gi,
      /\buse\s+sha2::[^;]*\bSha256\b/gi,
      /\bSHA256_\w+\s*\(/gi,
      /\bSHA256Hash\b/gi,
    ],
    calls: [
      /\b(?:createHash|createHmac|createSign|createVerify|hashlib\.new)\)?\s*\(\s*['\"`]sha-?256['\"`]/gi,
      /\bdigest\s*\(\s*(?:\{\s*name\s*:\s*)?['\"`]sha-256['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`]SHA-?256['\"`]/gi,
      /\b(?:hash_name|digestmod|hashfunc)\s*=\s*['\"`]sha-?256['\"`]/gi,
      /\b_?(?:algorithms?|alg|algo|hash_?alg\w*|digest_?alg\w*)\s*(?:==|!=|=|:)\s*\[?\s*['\"`](?:SHA-?256|HS256)['\"`]/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"crypto\/sha256\"/gim,
    ],
    description: 'SHA-256 hashing. Grover gives a quadratic speedup only, leaving ~128-bit effective preimage resistance — NOT a Shor-style break like RSA/ECDSA. Review only where a digest must stay collision-bound for decades; prefer SHA-384/512 there.',
    severity: 'LOW',
    quantumVulnerable: true,
    quantumThreat: 'grover',
  },
  DH: {
    patterns: [
      /\bdiffie[-_ ]?hellman/gi,
      /\bDH\.(?:generate|new)\b/gi,
      /(?<![A-Za-z0-9])ECDH\d*(?![A-Za-z0-9_])/gi,
      /\bECDH_compute_key\b/gi,
      /(?<![A-Za-z0-9])x(?:25519|448)/gi,
      /(?<![A-Za-z0-9])curve25519/gi,
      /\bcreateECDH\s*\(/gi,
      /\bcreateDiffieHellman(?:Group)?\s*\(/gi,
      /\bECDiffieHellman/gi,
      /\bKeyAgreement\.getInstance\b/gi,
      /\bDH_(?:new|generate_key|compute_key|generate_parameters(?:_ex)?)\b/gi,
      /\bEVP_PKEY_DHX?\b/gi,
      /#include\s*<openssl\/(?:dh|ecdh)\.h>/gi,
      /\bjavax\.crypto\.(?:KeyAgreement\b|interfaces\.DH\w*|spec\.DH\w*)/gi,
    ],
    calls: [
      /\bgenerateKeyPair(?:Sync)?\)?\s*\(\s*['\"`](?:x25519|x448|dh)['\"`]/gi,
      /\bname\s*:\s*['\"`](?:ECDH|X25519)['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`](?:DH|DiffieHellman|ECDH|X25519|X448|XDH)['\"`]/gi,
      /\b(?:curve|curve_name|crv)\s*(?:==|!=|=)\s*['\"`](?:x25519|x448|curve25519)['\"`]/gi,
    ],
    config: [
      /(?<![A-Za-z0-9!])(?:ECDHE|DHE|EECDH|EDH|kEECDH|kEDH|kDHE|kECDHE)(?=[-_+:])/gi,
      /\bssl_dhparam\b/gi,
      /\bTLS_(?:EC)?DHE_/gi,
      /(?<![A-Za-z0-9!])x(?:25519|448)/gi,
      /\b(?:ssl_)?ecdh_curve\b/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"(?:crypto\/ecdh|golang\.org\/x\/crypto\/curve25519)\"/gim,
    ],
    description: 'Diffie–Hellman / ECDH key exchange, incl. X25519/Curve25519 (broken by Shor’s algorithm)',
    severity: 'HIGH',
    quantumVulnerable: true,
    quantumThreat: 'shor',
  },
  DSA: {
    patterns: [
      /\bDSA\s*\./gi,
      /\bDSA(?:Public|Private)(?:Key|Numbers)(?:Spec)?\b/gi,
      /\bDSACryptoServiceProvider\b/gi,
      /\bDSA_(?:new|generate_key|generate_parameters(?:_ex)?|sign|verify|do_sign|do_verify)\b/gi,
      /\bEVP_PKEY_DSA\b/gi,
      /#include\s*<openssl\/dsa\.h>/gi,
      /\bjava\.security\.(?:spec|interfaces)\.DSA\w*/gi,
    ],
    calls: [
      /\bgetInstance\s*\(\s*['\"`](?:DSA|[\w-]*withDSA)['\"`]/gi,
    ],
    config: [
      /\bssh-dss\b/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"crypto\/dsa\"/gim,
    ],
    description: "DSA (finite-field Digital Signature Algorithm), broken by Shor's algorithm like RSA and ECDSA; already disallowed for new signatures by FIPS 186-5. Migrate to ML-DSA.",
    severity: 'HIGH',
    quantumVulnerable: true,
    quantumThreat: 'shor',
  },
  AES_SHORT: {
    patterns: [
      /AES\.new\(.*?,\s*AES\.MODE_/gi,
      /\bAES[-_]128\b/gi,
      /\bEVP_aes_128_\w+/gi,
      /\balgorithms\.AES128\b/gi,
    ],
    calls: [
      /\bcreate(?:Cipher|Decipher)(?:iv)?\)?\s*\(\s*['\"`]aes-128-/gi,
      /\bgetInstance\s*\(\s*['\"`]AES_128/gi,
    ],
    config: [
      /(?<![A-Za-z0-9!])AES[-_]?128(?![0-9])/gi,
    ],
    description: 'AES with potentially insufficient key length. Grover halves the effective key strength, so AES-128 retains ~64 bits; AES-256 remains comfortable. Not a Shor-style break.',
    severity: 'MEDIUM',
    quantumVulnerable: true,
    quantumThreat: 'grover',
  },
  DES3: {
    patterns: [
      /\bDES3\.new\s*\(/gi,
      /\bDES\.new\s*\(/gi,
      /from\s+Crypto\.Cipher\s+import\s+(?:DES3|DES)\b/gi,
      /\bTripleDES\b/gi,
      /\bDESede\b/gi,
      /\bEVP_des_\w+/gi,
      /\bDES_(?:ecb|cbc|ede3|ncbc)\w*/gi,
      /\bDES\.Create\s*\(/gi,
    ],
    calls: [
      /\bcreate(?:Cipher|Decipher)(?:iv)?\)?\s*\(\s*['\"`]des(?:-|3|['\"`])/gi,
      /\bgetInstance\s*\(\s*['\"`](?:DES|DESede|TripleDES)(?:\/|['\"`])/gi,
    ],
    config: [
      /(?<![A-Za-z0-9!])(?:3DES|DES-CBC3|DES-CBC|DES-EDE3)(?![A-Za-z0-9])/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"crypto\/des\"/gim,
    ],
    description: 'DES / Triple-DES symmetric cipher. The effective key is short (DES 56-bit, 3DES ~112-bit) and Grover halves it further. Ranked HIGH for urgency because both are already broken/deprecated today (NIST SP 800-131A), independent of quantum. The quantum mechanism is still Grover, not a Shor-style break — migrate to AES-256.',
    severity: 'HIGH',
    quantumVulnerable: true,
    quantumThreat: 'grover',
  },
  MD5_SHA1: {
    patterns: [
      /\bhashlib\.(?:md5|sha1)\s*\(/gi,
      /\b(?:digestmod|hashfunc|hash_name)\s*=\s*hashlib\.(?:md5|sha1)\b/gi,
      /\b(?:md5|sha1)\s*\(/gi,
      /\b(?:MD5|SHA1)\s*\./gi,
      /\b(?:MD5|SHA1)_(?:Init|Update|Final)\b/gi,
      /\bEVP_(?:md5|sha1)\b/gi,
      /from\s+hashlib\s+import\s+[^\n]*\b(?:md5|sha1)\b/gi,
      /\b(?:md5|sha1)::/gi,
      /\b(?:MD5|SHA1)_\w+\s*\(/gi,
      /\b(?:MD5|SHA1)Hash\b/gi,
      /\bhmac_?(?:md5|sha1)\s*\(/gi,
    ],
    calls: [
      /\b(?:createHash|createHmac|hashlib\.new)\)?\s*\(\s*['\"`](?:md5|sha-?1)['\"`]/gi,
      /\bgetInstance\s*\(\s*['\"`](?:MD5|SHA-?1)(?:['\"`]|with)/gi,
      /\bdigest\s*\(\s*(?:\{\s*name\s*:\s*)?['\"`]sha-1['\"`]/gi,
      /\b(?:hash_name|digestmod|hashfunc)\s*=\s*['\"`](?:md5|sha-?1)['\"`]/gi,
      /\b_?(?:algorithms?|alg|algo|hash_?alg\w*|digest_?alg\w*)\s*(?:==|!=|=|:)\s*\[?\s*['\"`](?:MD5(?:-sess)?|SHA-?1)['\"`]/gi,
    ],
    config: [
      /(?<![A-Za-z0-9!])hmac-(?:md5|sha1)(?![A-Za-z0-9])/gi,
    ],
    go_imports: [
      /^[ \t]*(?:import[ \t]+)?(?:[A-Za-z_.]\w*[ \t]+)?\"crypto\/(?:md5|sha1)\"/gim,
    ],
    description: "MD5 / SHA-1 hashing. Collisions are practical today (SHA-1: SHAttered, 2017), so both are broken classically, independent of quantum. Not a quantum finding: replace with SHA-256 or better, SHA-384 where the digest must last.",
    severity: 'MEDIUM',
    quantumVulnerable: false,
    quantumThreat: 'classical',
  },
};

const PY_IMPORT_FAMILY = {
  "rsa": 'RSA',
  "ecdsa": 'ECDSA',
  "cryptography.hazmat.primitives.asymmetric.rsa": 'RSA',
  "cryptography.hazmat.primitives.asymmetric.ec": 'ECDSA',
  "cryptography.hazmat.primitives.asymmetric.ed25519": 'ECDSA',
  "cryptography.hazmat.primitives.asymmetric.ed448": 'ECDSA',
  "cryptography.hazmat.primitives.asymmetric.dh": 'DH',
  "cryptography.hazmat.primitives.asymmetric.dsa": 'DSA',
  "Crypto.PublicKey.DSA": 'DSA',
  "cryptography.hazmat.primitives.asymmetric.x25519": 'DH',
  "cryptography.hazmat.primitives.asymmetric.x448": 'DH',
  "Crypto.PublicKey.RSA": 'RSA',
  "Crypto.PublicKey.ECC": 'ECDSA',
  "Crypto.Signature.eddsa": 'ECDSA',
  "Crypto.Signature.pss": 'RSA',
  "Crypto.Signature.pkcs1_15": 'RSA',
  "Crypto.Cipher.PKCS1_OAEP": 'RSA',
  "Crypto.Cipher.PKCS1_v1_5": 'RSA',
  "Crypto.Cipher.DES": 'DES3',
  "Crypto.Cipher.DES3": 'DES3',
  "Crypto.Hash.SHA256": 'SHA256',
  "Crypto.Hash.MD5": 'MD5_SHA1',
  "Crypto.Hash.SHA1": 'MD5_SHA1',
  "nacl.signing": 'ECDSA',
  "nacl.public": 'DH',
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

/* Comments and string literals, masked per language: parity with
   backend/qrbst/langprofiles.py. Multi-line forms come first so their
   single-line counterparts cannot bite into them. */
const NC = {
  pyDoc: String.raw`"""[\s\S]*?"""|'''[\s\S]*?'''`,
  block: String.raw`\/\*[\s\S]*?\*\/`,
  slash: String.raw`\/\/[^\n]*`,
  hash: String.raw`#[^\n]*`,
  dash: String.raw`--[^\n]*`,
  dq: String.raw`"(?:\\.|[^"\\\n])*"`,
  sq: String.raw`'(?:\\.|[^'\\\n])*'`,
  ch: String.raw`'(?:\\.|[^'\\\n])'`,   // Rust: ' opens a char or a lifetime
  bt: '`[^`]*`',                                    // Go raw strings
  tpl: String.raw`\x60(?:\\[\s\S]|\$\{[^{}\x60]*\}|[^\x60\\])*\x60`, // JS/TS templates
  none: '(?!)',
};
const NC_INTERPOLATION = /\$\{([^{}`]*)\}/g;
const ncProfile = (...k) => new RegExp(k.map((x) => NC[x]).join('|'), 'g');
const NC_C = ncProfile('block', 'slash', 'dq', 'sq');
const NC_JS = ncProfile('block', 'slash', 'dq', 'sq', 'tpl');
const NC_GO = ncProfile('block', 'slash', 'dq', 'sq', 'bt');
const NC_PROFILES = {
  Python: ncProfile('pyDoc', 'hash', 'dq', 'sq'),
  Solidity: NC_C, JavaScript: NC_JS, TypeScript: NC_JS, Go: NC_GO,
  Java: NC_C, C: NC_C, 'C++': NC_C, 'C#': NC_C, Swift: NC_C, Kotlin: NC_C, Scala: NC_C,
  Rust: ncProfile('block', 'slash', 'dq', 'ch'),
  PHP: ncProfile('block', 'slash', 'hash', 'dq', 'sq'),
  Ruby: ncProfile('hash', 'dq', 'sq'), Shell: ncProfile('hash', 'dq', 'sq'),
  SQL: ncProfile('block', 'dash', 'dq', 'sq'),
  Config: ncProfile('block', 'hash'),        // values are the evidence
  'Key material': ncProfile('none'),
};
const NC_FALLBACK = ncProfile('pyDoc', 'block', 'slash', 'hash', 'dq', 'sq');

const EXT_LANGUAGE = {
  '.py': 'Python', '.pyi': 'Python', '.sol': 'Solidity',
  '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JavaScript',
  '.ts': 'TypeScript', '.tsx': 'TypeScript', '.go': 'Go', '.java': 'Java',
  '.c': 'C', '.h': 'C', '.cpp': 'C++', '.hpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
  '.cs': 'C#', '.rs': 'Rust', '.swift': 'Swift', '.kt': 'Kotlin', '.kts': 'Kotlin',
  '.scala': 'Scala', '.php': 'PHP', '.rb': 'Ruby', '.sh': 'Shell', '.bash': 'Shell', '.sql': 'SQL',
  '.pem': 'Key material', '.key': 'Key material', '.crt': 'Key material', '.cer': 'Key material',
  '.pub': 'Key material', '.csr': 'Key material', '.ppk': 'Key material',
  '.tf': 'Config', '.hcl': 'Config', '.yaml': 'Config', '.yml': 'Config', '.conf': 'Config',
};
const BASENAME_LANGUAGE = new Set(['id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa', 'authorized_keys', 'known_hosts']);
const SUPPORTED = new Set(['Python', 'Solidity', 'JavaScript', 'TypeScript', 'Go', 'Java', 'Kotlin',
  'C', 'C++', 'C#', 'Rust', 'Key material', 'Config']);

function languageForName(filename) {
  const base = String(filename || '').split(/[\\/]/).pop();
  if (BASENAME_LANGUAGE.has(base.toLowerCase())) return 'Key material';
  const dot = base.lastIndexOf('.');
  return dot > 0 ? EXT_LANGUAGE[base.slice(dot).toLowerCase()] || null : null;
}

/** Blank comments and strings, preserving length and newlines so offsets and
 *  line numbers still line up with the original source. */
function maskNoncode(src, language) {
  const re = NC_PROFILES[language] || NC_FALLBACK;
  const interpolates = language === 'JavaScript' || language === 'TypeScript';
  re.lastIndex = 0;
  return src.replace(re, (m) => {
    let out = m.replace(/[^\n]/g, ' ');
    // `${expr}` in a template literal is code: keep it, masked by the same
    // rules (parity with langprofiles.mask_noncode).
    if (interpolates && m[0] === '`') {
      for (const i of [...m.matchAll(NC_INTERPOLATION)]) {
        const start = i.index + 2;
        out = out.slice(0, start) + maskNoncode(i[1], language) + out.slice(start + i[1].length);
      }
    }
    return out;
  });
}

/* ── Key material: parity with backend/qrbst/keymaterial.py ──
   A PEM certificate or PRIVATE KEY names its algorithm by OID inside the
   base64 body; OpenSSH keys by type name. */
const KM_OIDS = [
  ['06092a864886f70d010101', 'RSA'], ['06092a864886f70d01010a', 'RSA'],
  ['06092a864886f70d01010b', 'RSA'], ['06092a864886f70d01010c', 'RSA'],
  ['06092a864886f70d01010d', 'RSA'], ['06092a864886f70d010105', 'RSA'],
  ['06092a864886f70d010105', 'MD5_SHA1'], ['06092a864886f70d010104', 'RSA'],
  ['06092a864886f70d010104', 'MD5_SHA1'], ['06072a8648ce3d0201', 'ECDSA'],
  ['2a8648ce3d0403', 'ECDSA'], ['06072a8648ce3d0401', 'ECDSA'],
  ['06072a8648ce3d0401', 'MD5_SHA1'], ['06032b6570', 'ECDSA'], ['06032b6571', 'ECDSA'],
  ['06032b656e', 'DH'], ['06032b656f', 'DH'], ['06072a8648ce3e0201', 'DH'],
  ['06092a864886f70d010301', 'DH'],
  ['06072a8648ce380401', 'DSA'], ['06072a8648ce380403', 'DSA'],
  ['06072a8648ce380403', 'MD5_SHA1'], ['0609608648016503040302', 'DSA'],
];
const KM_LABELS = { 'RSA PRIVATE KEY': 'RSA', 'RSA PUBLIC KEY': 'RSA', 'EC PRIVATE KEY': 'ECDSA', 'DH PARAMETERS': 'DH', 'DSA PRIVATE KEY': 'DSA' };
const KM_SSH_TYPES = [['ssh-rsa', 'RSA'], ['ssh-dss', 'DSA'], ['ssh-ed25519', 'ECDSA'], ['ssh-ed448', 'ECDSA'], ['ecdsa-sha2-nistp', 'ECDSA']];
const KM_PEM = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const KM_SSH_PUB = /(?<![\w-])(ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+AAAA[0-9A-Za-z+/]/g;
const KM_PUTTY = /PuTTY-User-Key-File-\d+:\s*(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp\d+)/g;
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Base64 body -> lowercase hex of the bytes ('' when it does not decode). */
function kmDecodeHex(body) {
  body = body.split(/\r?\n|\r/).filter((l) => !l.includes(':')).join('\n');
  const clean = body.replace(/\\[nr]/g, '').replace(/[^A-Za-z0-9+/=]/g, '').replace(/=+$/, '');
  if (clean.length % 4 === 1 || /=/.test(clean)) return '';
  let bits = 0, acc = 0, hex = '';
  for (const c of clean) {
    acc = ((acc << 6) | B64.indexOf(c)) & 0xffff; bits += 6;
    if (bits >= 8) { bits -= 8; hex += ((acc >> bits) & 255).toString(16).padStart(2, '0'); }
  }
  return hex;
}

function kmHasHex(hex, needle) {
  for (let i = hex.indexOf(needle); i !== -1; i = hex.indexOf(needle, i + 1)) if (i % 2 === 0) return true;
  return false;
}

const kmAsciiHex = (t) => [...t].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');

function scanKeyMaterial(src) {
  const out = [];
  KM_PEM.lastIndex = 0;
  let m;
  while ((m = KM_PEM.exec(src)) !== null) {
    const label = m[1];
    const ln = lineAt(src, m.index);
    let fams = [];
    if (KM_LABELS[label]) fams = [KM_LABELS[label]];
    else if (label === 'OPENSSH PRIVATE KEY') {
      const hex = kmDecodeHex(m[2]);
      fams = KM_SSH_TYPES.filter(([t]) => kmHasHex(hex, kmAsciiHex(t))).map(([, f]) => f);
    } else if (label !== 'ENCRYPTED PRIVATE KEY') {
      const hex = kmDecodeHex(m[2]);
      fams = KM_OIDS.filter(([o]) => kmHasHex(hex, o)).map(([, f]) => f);
    }
    for (const f of new Set(fams)) out.push([ln, f, `-----BEGIN ${label}-----`]);
  }
  for (const rx of [KM_SSH_PUB, KM_PUTTY]) {
    rx.lastIndex = 0;
    while ((m = rx.exec(src)) !== null) out.push([lineAt(src, m.index), ({ 'ssh-rsa': 'RSA', 'ssh-dss': 'DSA' })[m[1]] || 'ECDSA', m[1]]);
  }
  return out;
}

/** Line number (1-based) of a character offset. */
function lineAt(text, offset) {
  let n = 1;
  for (let i = 0; i < offset; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

/* ── AES key-size resolver: parity with backend/qrbst/pyast.py ──
   The AES.new(...) pattern cannot see the key length, so AES-256 was reported
   as a short key. Recover the key size by a small data-flow pass over masked
   code. Like the Python side, only SIMPLE-NAME keys are followed; an
   attribute-held key (self.session_key) stays unresolved and keeps its finding. */
const KEY_LEN_CALL = /\b(?:urandom|get_random_bytes|token_bytes|randbytes)\s*\(\s*(\d+)\s*\)/;

function pyBytesLiteralLen(body) {
  let n = 0;
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\') {
      if (body[i + 1] === 'x') i += 3; else i += 1;
    }
    n++;
  }
  return n;
}

function keyBytesFromExpr(expr) {
  const e = expr.trim();
  let m = e.match(/^(?:bytes|bytearray)\s*\(\s*(\d+)\s*\)/);
  if (m) return parseInt(m[1], 10);
  m = e.match(KEY_LEN_CALL);
  if (m) return parseInt(m[1], 10);
  m = e.match(/^b(['"])((?:\\.|(?!\1)[^\\])*)\1/);
  if (m) return pyBytesLiteralLen(m[2]);
  return null;
}

function resolveAesKeyBits(code) {
  const byName = new Map();
  const assignRe = /(?:^|\n)[ \t]*([A-Za-z_]\w*)\s*=\s*([^\n]+)/g;
  let a;
  while ((a = assignRe.exec(code)) !== null) {
    const b = keyBytesFromExpr(a[2]);
    if (b !== null) byName.set(a[1], b);
  }
  const out = new Map();
  const callRe = /AES\.new\(\s*([^,)\n]+?)\s*,/g;
  let c;
  while ((c = callRe.exec(code)) !== null) {
    const keyArg = c[1].trim();
    let b = keyBytesFromExpr(keyArg);
    if (b === null && /^[A-Za-z_]\w*$/.test(keyArg)) b = byName.has(keyArg) ? byName.get(keyArg) : null;
    out.set(lineAt(code, c.index), b === null ? null : b * 8);
  }
  return out;
}

function aesIsQuantumShort(bits) {
  if (bits === null || bits === undefined) return null;
  return bits < 256;
}

/* Direct aliases of a vulnerable callable, parity with pyast.resolve_alias_calls:
   `name = hashlib.sha256` then `name(...)` -> (line, family). */
const ALIAS_TARGETS = { 'hashlib.sha256': 'SHA256' };

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function resolveAliasCalls(code) {
  const alias = new Map();
  // RHS is a bare dotted reference ending the statement -- not a call (no '(').
  const assignRe = /(?:^|\n)[ \t]*([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)[ \t]*(?=$|\n|#)/g;
  let a;
  while ((a = assignRe.exec(code)) !== null) {
    const fam = ALIAS_TARGETS[a[2]];
    if (fam) alias.set(a[1], fam);
  }
  const out = [];
  if (alias.size) {
    const callRe = new RegExp('\\b(' + [...alias.keys()].map(escapeRe).join('|') + ')\\s*\\(', 'g');
    let c;
    while ((c = callRe.exec(code)) !== null) out.push([lineAt(code, c.index), alias.get(c[1])]);
  }
  return out;
}

/* Python imports of a vulnerable module: parity with python_import_hits in
   crypto_scanner.py. PY_IMPORT_FAMILY is generated from the Python table. */
const PY_FROM_IMPORT = /^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n]*)/gm;
const PY_IMPORT = /^[ \t]*import[ \t]+([^\n]+)/gm;

function pyImportHits(code) {
  const out = [];
  const names = (body, base, fn) => {
    const re = /[A-Za-z_][\w.]*/g;
    let n, prev = '';
    while ((n = re.exec(body)) !== null) {
      if (prev !== 'as' && n[0] !== 'as') fn(n[0], base + n.index);
      prev = n[0];
    }
  };
  let m;
  PY_FROM_IMPORT.lastIndex = 0;
  while ((m = PY_FROM_IMPORT.exec(code)) !== null) {
    const mod = m[1];
    const modStart = m.index + m[0].indexOf(mod, m[0].indexOf('from') + 4);
    if (Object.prototype.hasOwnProperty.call(PY_IMPORT_FAMILY, mod)) { out.push([modStart, PY_IMPORT_FAMILY[mod], mod]); continue; }
    const bodyStart = m.index + m[0].length - m[2].length;
    names(m[2], bodyStart, (name, at) => {
      const key = mod + '.' + name;
      if (Object.prototype.hasOwnProperty.call(PY_IMPORT_FAMILY, key)) out.push([at, PY_IMPORT_FAMILY[key], key]);
    });
  }
  PY_IMPORT.lastIndex = 0;
  while ((m = PY_IMPORT.exec(code)) !== null) {
    const bodyStart = m.index + m[0].length - m[1].length;
    names(m[1], bodyStart, (name, at) => {
      // Bare `import rsa` is not a finding (its use sites are); dotted imports are.
      if (name.includes('.') && Object.prototype.hasOwnProperty.call(PY_IMPORT_FAMILY, name)) out.push([at, PY_IMPORT_FAMILY[name], name]);
    });
  }
  return out;
}

function detectLanguage(filename, src) {
  const byName = languageForName(filename);
  if (byName) return byName;
  if (/pragma\s+solidity/.test(src)) return 'Solidity';
  if (/contract\s+\w+\s*\{/.test(src)) return 'Solidity';
  if (/def\s+\w+\s*\(/.test(src)) return 'Python';
  if (/package\s+main/.test(src)) return 'Go';
  if (/function\s+\w+\s*\(/.test(src)) return 'JavaScript';
  return 'Unknown';
}

function scanSource(filename, src) {
  const lines = src.split('\n');
  const language = detectLanguage(filename, src);
  const code = maskNoncode(src, language);

  // Collect every regex hit against masked (code-only) text. Config and key
  // files are data: they get only their own rules, never code patterns.
  const isCode = language !== 'Config' && language !== 'Key material';
  const raw = [];
  for (const [algo, def] of Object.entries(VULNERABLE)) {
    for (const re of isCode ? def.patterns : []) {
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
          quantum_vulnerable: def.quantumVulnerable !== false,
          quantum_threat: def.quantumThreat || 'shor',
        });
      }
    }
  }

  // Call-context patterns, parity with crypto_scanner.py: createHash("sha256")
  // names the algorithm in a string, which masking blanks. Match the raw
  // source and keep a hit only when the call name itself is code.
  for (const [algo, def] of Object.entries(VULNERABLE)) {
    for (const re of isCode ? def.calls || [] : []) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(src)) !== null) {
        if (code[m.index] !== src[m.index]) continue;
        const ln = lineAt(src, m.index);
        raw.push({
          algorithm: algo,
          description: def.description,
          severity: def.severity,
          line_number: ln,
          line_content: (lines[ln - 1] || '').trim(),
          matched_pattern: m[0],
          quantum_vulnerable: def.quantumVulnerable !== false,
          quantum_threat: def.quantumThreat || 'shor',
        });
      }
    }
  }

  // Go import paths are strings, so masking hides them; raw source, Go only.
  if (language === 'Go') {
    for (const [algo, def] of Object.entries(VULNERABLE)) {
      for (const re of def.go_imports || []) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(src)) !== null) {
          if (m[0] === '') { re.lastIndex++; continue; }
          const ln = lineAt(src, src.indexOf('"', m.index));
          raw.push({
            algorithm: algo, description: def.description, severity: def.severity,
            line_number: ln, line_content: (lines[ln - 1] || '').trim(), matched_pattern: m[0].trim(),
            quantum_vulnerable: def.quantumVulnerable !== false, quantum_threat: def.quantumThreat || 'shor',
          });
        }
      }
    }
  }

  // Config patterns: only in config files, where the value is the evidence.
  if (language === 'Config') {
    for (const [algo, def] of Object.entries(VULNERABLE)) {
      for (const re of def.config || []) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(code)) !== null) {
          if (m[0] === '') { re.lastIndex++; continue; }
          const ln = lineAt(code, m.index);
          raw.push({
            algorithm: algo, description: def.description, severity: def.severity,
            line_number: ln, line_content: (lines[ln - 1] || '').trim(), matched_pattern: m[0],
            quantum_vulnerable: def.quantumVulnerable !== false, quantum_threat: def.quantumThreat || 'shor',
          });
        }
      }
    }
  }

  // Keys and certificates, in any file: a key pasted into source is still that key.
  for (const [ln, algo, matched] of scanKeyMaterial(src)) {
    const def = VULNERABLE[algo];
    raw.push({
      algorithm: algo, description: def.description, severity: def.severity,
      line_number: ln, line_content: (lines[ln - 1] || '').trim(), matched_pattern: matched,
      quantum_vulnerable: def.quantumVulnerable !== false, quantum_threat: def.quantumThreat || 'shor',
    });
  }

  // Python imports of a vulnerable module, incl. multi-line `from x import (...)`.
  if (language === 'Python') {
    for (const [offset, algo, text] of pyImportHits(code)) {
      const def = VULNERABLE[algo];
      const ln = lineAt(code, offset);
      raw.push({
        algorithm: algo, description: def.description, severity: def.severity,
        line_number: ln, line_content: (lines[ln - 1] || '').trim(), matched_pattern: text,
        quantum_vulnerable: def.quantumVulnerable !== false, quantum_threat: def.quantumThreat || 'shor',
      });
    }
  }

  // Alias resolution (Python only), parity with crypto_scanner.py: a call
  // through an aliased vulnerable callable has no primitive name at the call
  // site, so add it before dedup as any other hit.
  if (language === 'Python') {
    for (const [ln, family] of resolveAliasCalls(code)) {
      const def = VULNERABLE[family];
      const lineText = (lines[ln - 1] || '').trim();
      raw.push({
        algorithm: family,
        description: def.description,
        severity: def.severity,
        line_number: ln,
        line_content: lineText,
        matched_pattern: lineText || (family + ' (alias call)'),
        quantum_vulnerable: def.quantumVulnerable !== false,
        quantum_threat: def.quantumThreat || 'shor',
      });
    }
  }

  // One finding per (family, line); the longest match is the most specific.
  const best = new Map();
  for (const hit of raw) {
    const key = hit.algorithm + ':' + hit.line_number;
    const prev = best.get(key);
    if (!prev || hit.matched_pattern.length > prev.matched_pattern.length) best.set(key, hit);
  }
  let vulnerabilities = [...best.values()].sort(
    (a, b) => a.line_number - b.line_number || a.algorithm.localeCompare(b.algorithm)
  );

  // A bare curve name on a line that already shows key exchange is not also
  // ECDSA: parity with crypto_scanner.py (_CURVE_NAME).
  const dhLines = new Set(vulnerabilities.filter((v) => v.algorithm === 'DH').map((v) => v.line_number));
  if (dhLines.size) {
    const curveOnly = /^(?:sec[pt]\d{3}[rk][12]|prime\d{3}v\d|NIST\d{3}p|brainpoolP\d{3}[rt]1)$/i;
    vulnerabilities = vulnerabilities.filter((v) => !(v.algorithm === 'ECDSA'
      && dhLines.has(v.line_number) && curveOnly.test(v.matched_pattern.trim())));
  }

  // AES key-size refinement (Python only), parity with crypto_scanner.py:
  // drop AES.new findings proven to use a >=256-bit key. Unknown/<256 stay.
  if (vulnerabilities.length && language === 'Python') {
    const keyBits = resolveAesKeyBits(code);
    vulnerabilities = vulnerabilities.filter((v) =>
      !(v.algorithm === 'AES_SHORT'
        && /^aes\.new/i.test(v.matched_pattern)
        && aesIsQuantumShort(keyBits.get(v.line_number)) === false)
    );
  }

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
    language,
    total_lines: lines.length,
    vulnerabilities,
    vulnerability_count: vulnerabilities.length,
    informational_mentions: [...mentions.values()].sort((a, b) => a.line_number - b.line_number),
    raw_match_count: raw.length,
    language_supported: SUPPORTED.has(language),
    quantum_ready: SUPPORTED.has(language) ? vulnerabilities.length === 0 : null,
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
  DES3: {
    replacement: 'AES-256-GCM', standard: 'FIPS 197',
    note: 'DES and Triple-DES are deprecated (NIST SP 800-131A) and short-keyed, which Grover makes worse. Replace with a 256-bit AEAD cipher; in payments, plan the key-ceremony and HSM changes alongside.',
    python: `from Crypto.Cipher import AES

key = os.urandom(32)                     # 256-bit, replaces DES/3DES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)`,
  },
  MD5_SHA1: {
    replacement: 'SHA-256 / SHA-384', standard: 'FIPS 180-4',
    note: 'Not a quantum finding: MD5 and SHA-1 have practical collisions today (SHA-1 SHAttered, 2017). Replace them now; use SHA-384 where the digest must last.',
    python: `import hashlib

digest = hashlib.sha384(data).digest()   # replaces md5/sha1`,
  },
  DSA: {
    replacement: 'ML-DSA-65', standard: 'FIPS 204',
    note: 'DSA is broken by Shor’s algorithm and FIPS 186-5 already disallows it for new signatures. Move signing to ML-DSA.',
    python: `from dilithium_py.ml_dsa import ML_DSA_65

pk, sk = ML_DSA_65.keygen()
signature = ML_DSA_65.sign(sk, message)`,
  },
};

function buildPlan(scan) {
  const groups = new Map();
  for (const v of scan.vulnerabilities) {
    if (!groups.has(v.algorithm)) groups.set(v.algorithm, []);
    groups.get(v.algorithm).push(v);
  }

  const order = ['ECDSA', 'RSA', 'DSA', 'DH', 'AES_SHORT', 'DES3', 'MD5_SHA1', 'SHA256'];
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
    `${c} POST-QUANTUM MIGRATION PLAN - generated by QRBST`,
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
  DSA: ['signature', 'ML-DSA', 'FIPS 204'],
  SHA256: ['hash', 'SHA-384/SHA-512', 'FIPS 180-4'],
  AES_SHORT: ['block-cipher', 'AES-256', 'FIPS 197'],
  DES3: ['block-cipher', 'AES-256', 'FIPS 197'],
  MD5_SHA1: ['hash', 'SHA-256/SHA-384', 'FIPS 180-4'],
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
        { name: 'quantumThreat', value: hits[0].quantum_threat || 'shor' },
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
      tools: [{ vendor: 'QRBST', name: 'web-scanner', version: '2.0.0' }],
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

}

function out(html, kind) {
  const box = $('outBox');
  box.className = 'outbox' + (kind ? ' ' + kind : '');
  box.innerHTML = html;
  box.hidden = false;
}

/* ═══════════════ scanning ═══════════════ */

function runScan(filename, src, fromUser = false) {
  state.fromUser = fromUser;
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
  // Counts only, never source. Only the hosted site listens for this, to keep
  // the signed-in user's scan history; on GitHub Pages nothing hears it. The
  // bundled examples are not the user's code, so they are not recorded.
  if (fromUser) document.dispatchEvent(new CustomEvent('qrbst:scan', { detail: {
    filename: filename.slice(0, 255) || 'untitled',
    language: scan.language,
    lines: scan.total_lines,
    findings: scan.vulnerability_count,
    high: scan.vulnerabilities.filter((v) => v.severity === 'HIGH').length,
    risk: Math.round(state.risk.total),
    algorithms: [...new Set(scan.vulnerabilities.map((v) => v.algorithm))].slice(0, 30),
  } }));
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

  doc.setFillColor('#0e1219');
  doc.rect(0, 0, W, 86, 'F');
  doc.setFont('helvetica', 'bold'); doc.setFontSize(17); doc.setTextColor('#eceff4');
  doc.text('LATTICE', M, 40);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor('#4f93d4');
  doc.text('POST-QUANTUM MIGRATION ASSESSMENT', M, 58);
  doc.setTextColor('#9aa7b8');
  doc.text(new Date(meta.timestamp).toLocaleString(), W - M, 58, { align: 'right' });

  y = 126;
  text(TITLES[type] || TITLES.General, 13, 'bold'); line(26);

  text('ORGANISATION', 8, 'bold', '#6b7889'); line(14);
  text(meta.company, 11, 'bold'); line(15);
  text(`Sector: ${meta.sector}`, 10); line(14);
  text(`Contact: ${meta.email || 'not supplied'}`, 10); line(14);
  text(`Artefact: ${meta.filename}  (${scan.language}, ${scan.total_lines} lines)`, 10); line(14);
  text(`Assessment ID: ${meta.scanId}`, 9, 'normal', '#6b7889'); line(26);

  doc.setFillColor(risk.total === 0 ? '#e8faf6' : risk.total < 60 ? '#fff6e6' : '#ffecef');
  doc.roundedRect(M, y - 12, W - M * 2, 62, 6, 6, 'F');
  text('EXPOSURE SCORE', 8, 'bold', '#6b7889'); line(22);
  doc.setFont('helvetica', 'bold'); doc.setFontSize(24);
  doc.setTextColor(risk.total === 0 ? '#0f7a68' : risk.total < 60 ? '#9a6200' : '#c0243c');
  doc.text(`${risk.total} / 100`, M, y);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10); doc.setTextColor('#1a2433');
  doc.text(`${scan.vulnerability_count} vulnerable call site(s) across ${plan.families} family(ies)`, M + 130, y - 6);
  doc.setFontSize(9); doc.setTextColor('#6b7889');
  doc.text(`Severity ${risk.base}/60 · breadth ${risk.breadth}/20 · density ${risk.density}/20`, M + 130, y + 9);
  line(44);

  text('FINDINGS', 8, 'bold', '#6b7889'); line(18);
  if (!scan.vulnerability_count) {
    text('No quantum-vulnerable cryptographic call sites were detected.', 10); line(20);
  } else {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold'); doc.setTextColor('#6b7889');
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

  text('REQUIRED MIGRATION', 8, 'bold', '#6b7889'); line(18);
  for (const s of plan.steps) {
    text(`${s.algorithm} → ${s.replacement}  (${s.standard})`, 10, 'bold'); line(14);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor('#48566e');
    for (const ln of doc.splitTextToSize(s.note, W - M * 2)) { doc.text(ln, M, y); line(12); }
    doc.setTextColor('#6b7889');
    doc.text(`Lines: ${s.lines.join(', ')}`, M, y); line(20);
    doc.setTextColor('#1a2433');
  }
  if (!plan.steps.length) { text('None required.', 10); line(20); }

  text(`Estimated effort: ${plan.complexity} — ${plan.timeline}`, 10, 'bold'); line(28);

  text('APPLICABLE STANDARDS', 8, 'bold', '#6b7889'); line(14);
  doc.setFontSize(9); doc.setTextColor('#48566e');
  for (const ln of [
    'NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA)',
    'RBI Guidelines on Cybersecurity Framework · CERT-In Vulnerability Notes',
    'ISO/IEC 27001 Information Security Management',
  ]) { doc.text(ln, M, y); line(13); }
  line(10);
  doc.setTextColor('#6b7889'); doc.setFontSize(8);
  for (const ln of doc.splitTextToSize(
    'Method: lexical analysis over comment- and string-masked source, with per-line '
    + 'deduplication. Detects cryptographic API usage; does not detect misuse of a correctly '
    + 'named primitive and does not follow indirection through wrapper functions. This '
    + 'assessment is a migration worklist and is not a substitute for a cryptographic audit.',
    W - M * 2)) { doc.text(ln, M, y); line(11); }

  doc.save(`qrbst_${type}_${meta.scanId.slice(0, 8)}.pdf`);
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
  if (!SUPPORTED.has(scan.language)) {
    out(`<strong>Not certified</strong>
         <span>This file's language is not one this detector analyses, so finding nothing in it
         is not evidence that it is quantum-safe. Supported: ${[...SUPPORTED].join(', ')}.</span>`, 'warn');
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
  grad.addColorStop(0, '#0e1219'); grad.addColorStop(1, '#141922');
  x.fillStyle = grad; x.fillRect(0, 0, 820, 520);

  x.strokeStyle = 'rgba(79,147,212,0.12)'; x.lineWidth = 1;
  for (let i = 0; i <= 820; i += 34) { x.beginPath(); x.moveTo(i, 0); x.lineTo(i, 520); x.stroke(); }
  for (let j = 0; j <= 520; j += 34) { x.beginPath(); x.moveTo(0, j); x.lineTo(820, j); x.stroke(); }

  x.strokeStyle = '#4f93d4'; x.lineWidth = 2;
  x.strokeRect(24, 24, 772, 472);
  x.strokeStyle = 'rgba(227,182,74,0.55)';
  x.strokeRect(34, 34, 752, 452);

  x.textAlign = 'center';
  x.fillStyle = '#4f93d4';
  x.font = '600 13px "IBM Plex Mono", monospace';
  x.fillText('QUANTUM-SAFE CERTIFICATION', 410, 96);

  x.fillStyle = '#eceff4';
  x.font = '700 15px "IBM Plex Mono", monospace';
  x.fillText('NIST FIPS 203 / 204 / 205', 410, 124);

  x.font = '700 34px "Chakra Petch", sans-serif';
  const name = meta.company.length > 34 ? meta.company.slice(0, 33) + '…' : meta.company;
  x.fillText(name, 410, 196);

  x.fillStyle = '#9aa7b8';
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
  x.strokeStyle = '#4f93d4'; x.lineWidth = 2;
  x.strokeRect(-19, -19, 38, 38);
  x.fillStyle = 'rgba(227,182,74,0.22)';
  x.fillRect(-12, -12, 24, 24);
  x.restore();

  x.fillStyle = '#6b7889';
  x.font = '400 11px "IBM Plex Mono", monospace';
  x.fillText(`CERTIFICATE ${badgeId}`, 410, 442);
  x.fillText(`${meta.filename}  ·  ${scan.language}  ·  ${scan.total_lines} lines`, 410, 460);
  x.fillText(`Issued ${d.toISOString().slice(0, 10)}  ·  exposure score 0/100`, 410, 478);

  const dataUrl = cv.toDataURL('image/png');
  cv.toBlob((blob) => {
    download(blob, `badge_${badgeId}.png`);
    out(`<strong>Badge issued — ${esc(badgeId)}</strong>
         <span>Certificate downloaded. Timestamp the proof on Bitcoin to show when
         it was issued.</span>
         <img src="${dataUrl}" alt="Quantum-safe certificate for ${esc(meta.company)}">`, 'ok');
  }, 'image/png');
}

/* ═══════════════ Bitcoin timestamp (OpenTimestamps, free) ═══════════════ */

async function sha256Hex(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fileLink(blob, name, label) {
  return `<a href="${URL.createObjectURL(blob)}" download="${esc(name)}">${esc(label)}</a>`;
}

/**
 * Builds a proof document for this scan, hashes it here, and sends only that
 * 32-byte hash to be timestamped on Bitcoin by the public OpenTimestamps
 * calendars. No wallet, no key, no fees. The source is represented by its
 * SHA-256, so the proof pins exactly which file was scanned without holding it.
 */
async function doTimestamp() {
  const btn = $('btnChain');
  btn.disabled = true;
  try {
    out('<strong>Timestamping…</strong><span>Sending one 32-byte hash to the free OpenTimestamps calendars.</span>');
    const { scan, meta, risk } = state;
    const enc = new TextEncoder();
    const proofDoc = JSON.stringify({
      tool: 'QRBST Web Scanner',
      scan_id: meta.scanId,
      scanned_at: meta.timestamp,
      organisation: meta.company,
      file: meta.filename,
      source_sha256: await sha256Hex(enc.encode(scan.source)),
      language: scan.language,
      lines: scan.total_lines,
      findings: scan.vulnerability_count,
      risk_score: Math.round(risk.total),
      algorithms: [...new Set(scan.vulnerabilities.map((v) => v.algorithm))],
    }, null, 2);
    const proofBytes = enc.encode(proofDoc);
    const digest = await sha256Hex(proofBytes);

    let r;
    try {
      r = await fetch('/api/anchor', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ digest, label: meta.filename.slice(0, 255) }),
      });
    } catch (netErr) {
      throw new Error('Could not reach the timestamp service. Check your connection and try again.');
    }
    if (r.status === 404 || r.status === 405) {
      throw new Error('Timestamping runs on the hosted site. Sign in at qrbst.onrender.com to use it.');
    }
    if (r.status === 401) throw new Error('Your session has ended. Sign in again, then retry.');
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || 'The timestamp service failed.');

    const base = `qrbst_proof_${meta.scanId.slice(0, 8)}.json`;
    const ots = await r.blob();
    out(`<strong>Timestamp created on Bitcoin</strong>
         <span>Download and keep both files. The calendars commit to a Bitcoin block within a
         few hours. After that, anyone can verify by dropping both files on opentimestamps.org.</span>
         ${fileLink(new Blob([proofBytes], { type: 'application/json' }), base, 'Proof document (.json)')}
         ${fileLink(ots, base + '.ots', 'Timestamp proof (.ots)')}
         <span>Digest <code>${digest.slice(0, 22)}…</code></span>`, 'ok');
  } catch (err) {
    out(`<strong>Timestamp failed</strong><span>${esc(String((err && err.message) || err).slice(0, 220))}</span>`, 'err');
  } finally {
    btn.disabled = false;
  }
}

/* ═══════════════ lattice field ═══════════════ */

function startScanner() {
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
      x.fillStyle = `rgba(79,147,212,${Math.min(0.42, alpha * 0.5)})`;
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
    runScan(file.name, String(reader.result || ''), true);
    $('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  reader.readAsText(file);
}

document.addEventListener('DOMContentLoaded', () => {
  startScanner();

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
    else if (state.scan) runScan(state.meta.filename, state.scan.source, state.fromUser);
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
  $('btnChain').addEventListener('click', doTimestamp);

  // Open in a real working state rather than an empty shell.
  runScan('ConsentRegistry.sol', EXAMPLE_SOL);
  $('scanSubject').textContent = 'ConsentRegistry.sol · bundled example · Solidity';
});
