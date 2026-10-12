# Quantum-Resistant Blockchain Security Toolkit

A web application for Indian companies to migrate their blockchain and smart
contract code from classical cryptography to post-quantum algorithms.

## Features

- 🔍 **Automated Cryptography Scanning**: Detect vulnerable classical algorithms (ECDSA, RSA, DH, SHA-256, short-key AES)
- 🛡️ **Post-Quantum Migration**: Recommendations and source rewriting toward ML-DSA/Dilithium and other NIST-approved algorithms
- ⛓️ **Blockchain Proof Storage**: Tamper-proof migration records anchored on Ethereum Sepolia
- 📄 **Compliance Reports**: PDF reports for RBI, CERT-In, and insurers
- 📋 **CBOM Export**: CycloneDX 1.6 Cryptographic Bill of Materials
- 🏅 **Quantum-Safe Badges**: Verifiable certificates, issued only for files with zero remaining findings
- 🏭 **Sector-Specific**: Tailored for Rajasthan's manufacturing, pharma, healthcare, and banking sectors

## Technology Stack

- **Backend**: Python (FastAPI)
- **Frontend**: HTML5, TailwindCSS, JavaScript
- **Blockchain**: Web3.py (Ethereum Sepolia)
- **PDF Generation**: ReportLab
- **Code Analysis**: regex pattern matching over comment/string-masked source

## Installation

```bash
cd quantum-blockchain-toolkit
pip install -r backend/requirements.txt
cp .env.example backend/.env    # then edit backend/.env
```

## Usage

```bash
# Start the backend server (serves on http://localhost:8000)
cd backend
python app.py
```

Then open `frontend/index.html`, or serve it:

```bash
cd frontend
python -m http.server 8080
```

`frontend/app.js` points `API_BASE_URL` at the hosted backend by default. Change
it to `http://localhost:8000` to run fully locally.

## API

| Method | Route | Purpose |
|--------|-------|---------|
| GET  | `/` | Liveness check |
| GET  | `/api/stats` | Aggregate scan/vulnerability/badge counters |
| POST | `/api/scan` | Upload and scan a source file |
| POST | `/api/migrate` | Return the migration plan for a scan |
| POST | `/api/migrate/download` | Apply rewrites and download migrated source |
| POST | `/api/report/generate` | Generate a compliance PDF (`RBI`, `CERT-In`, `Insurance`, `General`) |
| GET  | `/api/cbom/{scan_id}` | Export a CycloneDX 1.6 CBOM |
| POST | `/api/badge/generate` | Issue a badge (409 if findings remain) |
| GET  | `/api/badge/verify/{badge_id}` | Verify a badge |
| GET  | `/api/badge/image/{badge_id}` | Fetch the badge certificate PNG |
| POST | `/api/blockchain/store` | Anchor a scan proof on-chain (**key-guarded**) |
| GET  | `/test-blockchain` | Wallet/connection diagnostics (**key-guarded**) |

Key-guarded routes require the `X-API-Key` header when `TOOLKIT_API_KEY` is set.
They spend gas from the server wallet, so set that variable in any public
deployment.

## Evaluation

The detector is scored against a hand-labelled benchmark. Labels mark *active
call sites* only; algorithm names appearing solely in comments, docstrings, or
string literals are hard negatives, as are identifiers that merely contain a
primitive as a substring (`bandwidth`, `sha256_cache_enabled`, `rsa_config_path`).

```bash
cd backend
python eval/run_eval.py
```

This reports precision, recall, and F1 per algorithm family, and ablates three
detector configurations:

| Configuration | What it adds |
|---------------|--------------|
| `v1-baseline` | Original pattern set, raw text, no deduplication |
| `v2-boundaries` | Word-bounded patterns |
| `v3-full` | Comment/string masking + per-line deduplication (shipped) |

Benchmark sources live in `eval/benchmark/`, labels in `eval/ground_truth.json`,
and output is written to `eval/results.json`.

> **Scope note.** The benchmark is small (7 files, 19 labelled findings) and was
> authored alongside the detector, so its absolute scores overstate real-world
> accuracy. It demonstrates that the masking and deduplication stages remove the
> false positives they target; it is *not* an independent accuracy estimate. A
> held-out corpus of third-party contracts is needed for that.

## Risk Score

`calculate_risk_score` combines three signals rather than summing severity
weights (which saturated at 100 for any file with four or more HIGH findings,
making every vulnerable file score identically):

- **base** — worst severity present (up to 60)
- **breadth** — distinct algorithm families (up to 20)
- **density** — findings per 100 lines, with diminishing returns (up to 20)

## Compliance Standards

- RBI Guidelines on Cybersecurity Framework
- CERT-In Vulnerability Notes
- ISO 27001 Information Security
- NIST Post-Quantum Cryptography Standards (FIPS 203, 204, 205)

## Limitations

- Detection is lexical. It finds cryptographic API usage, not misuse of
  correctly-named primitives, and cannot follow indirection through wrappers.
- Generated post-quantum code is a template. It references `pqcrypto` /
  `liboqs-python`, which are **not** installed by `backend/requirements.txt`;
  install them in the target project before running migrated code.
- Badge verification is backed by a local JSON registry, not a public service.
- Scan state is files on disk, with no database and no authentication on read
  routes. Do not place production source on a shared deployment.

## License

MIT License - See LICENSE file for details
