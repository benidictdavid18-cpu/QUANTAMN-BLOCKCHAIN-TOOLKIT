from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import glob
import os
import json
import uuid
from datetime import datetime
from typing import Optional

from crypto_scanner import CryptoScanner
from pq_migrator import PostQuantumMigrator
from blockchain_storage import BlockchainStorage
from pdf_generator import ComplianceReportGenerator
from badge_generator import BadgeGenerator

app = FastAPI(
    title="Quantum-Resistant Blockchain Security Toolkit",
    version="1.0.0"
)

# Set ALLOWED_ORIGINS to a comma-separated list in production.
# Credentials cannot be combined with a "*" origin, so they are only enabled
# once an explicit origin list is configured.
_origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
_allowed_origins = ["*"] if _origins_env == "*" else [o.strip() for o in _origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_allowed_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Write endpoints that spend gas are guarded when TOOLKIT_API_KEY is set.
# Left unset (local development) the guard is inactive.
API_KEY = os.getenv("TOOLKIT_API_KEY")


def _require_api_key(provided: Optional[str]) -> None:
    """Reject the request when an API key is configured and does not match."""
    if API_KEY and provided != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")

crypto_scanner = CryptoScanner()
pq_migrator = PostQuantumMigrator()
report_generator = ComplianceReportGenerator()
badge_generator = BadgeGenerator()

# BlockchainStorage needs a funded key. Building it at import time took the
# whole API down when BLOCKCHAIN_PRIVATE_KEY was unset, so it is built on first
# use and only the blockchain routes fail when it is not configured.
_blockchain_storage = None


def get_blockchain_storage() -> BlockchainStorage:
    global _blockchain_storage
    if _blockchain_storage is None:
        if not os.getenv("BLOCKCHAIN_PRIVATE_KEY"):
            raise HTTPException(
                status_code=503,
                detail="Blockchain anchoring is not configured (BLOCKCHAIN_PRIVATE_KEY unset)"
            )
        _blockchain_storage = BlockchainStorage()
    return _blockchain_storage

os.makedirs("uploads", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("badges", exist_ok=True)

@app.get("/")
async def root():
    return {"status": "active"}


@app.get("/api/stats")
async def stats():
    """
    Aggregate counters for the dashboard tiles. Derived by walking the scan
    metadata on disk, since there is no database.
    """
    total_scans = 0
    total_vulnerabilities = 0
    risk_scores = []

    for path in glob.glob("uploads/*_metadata.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                scan = json.load(f)
        except (json.JSONDecodeError, OSError):
            # A partially written or hand-edited file must not break the dashboard
            continue

        total_scans += 1
        total_vulnerabilities += len(scan.get("vulnerabilities", {}).get("vulnerabilities", []))
        if isinstance(scan.get("risk_score"), (int, float)):
            risk_scores.append(scan["risk_score"])

    return {
        "total_scans": total_scans,
        "total_vulnerabilities_detected": total_vulnerabilities,
        "badges_issued": len(badge_generator.badge_registry),
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
    }

# Diagnostics. Key-guarded: it discloses the server wallet and its balance.
@app.get("/test-blockchain")
async def test_blockchain(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    _require_api_key(x_api_key)
    try:
        b = get_blockchain_storage()
        return {
            "connected": b.w3.is_connected(),
            "wallet": b.account.address,
            "balance": str(b.w3.eth.get_balance(b.account.address))
        }
    except HTTPException:
        raise
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/scan")
async def scan_code(
    file: UploadFile = File(...),
    company_name: str = Form(...),
    sector: str = Form(...),
    contact_email: str = Form(...)
):
    try:
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        file_path = f"uploads/{scan_id}_{file.filename}"
        content = await file.read()

        with open(file_path, "wb") as f:
            f.write(content)

        scan_results = crypto_scanner.scan_file(file_path, content.decode('utf-8', errors='ignore'))
        migration_plan = pq_migrator.generate_migration_plan(scan_results)
        risk_score = crypto_scanner.calculate_risk_score(scan_results)

        scan_data = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "company_name": company_name,
            "sector": sector,
            "contact_email": contact_email,
            "filename": file.filename,
            "vulnerabilities": scan_results,
            "migration_plan": migration_plan,
            "risk_score": risk_score
        }

        with open(f"uploads/{scan_id}_metadata.json", "w") as f:
            json.dump(scan_data, f, indent=2)

        return {
            "success": True,
            "scan_id": scan_id,
            "risk_score": risk_score,
            "scan_results": scan_results,
            "migration_plan": migration_plan
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/blockchain/store")
async def store_on_blockchain(
    scan_id: str = Form(...),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    # This route spends gas from the server wallet, so it is key-guarded.
    _require_api_key(x_api_key)

    storage = get_blockchain_storage()
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"

        with open(metadata_path, "r") as f:
            scan_data = json.load(f)

        tx_hash, block_number = storage.store_migration_proof(
            scan_id=scan_id,
            company_name=scan_data["company_name"],
            timestamp=scan_data["timestamp"],
            vulnerabilities_count=len(scan_data["vulnerabilities"].get("vulnerabilities", [])),
            risk_score=scan_data["risk_score"]
        )

        return {
            "success": True,
            "tx_hash": tx_hash,
            "block_number": block_number,
            "explorer_url": f"https://sepolia.etherscan.io/tx/{tx_hash}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    
@app.post("/api/report/generate")
async def generate_report(scan_id: str = Form(...), report_type: str = Form(...)):
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"

        with open(metadata_path, "r") as f:
            scan_data = json.load(f)

        pdf_path = report_generator.generate_report(scan_data, report_type, "reports")

        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"report_{scan_id}.pdf"
        )

    except Exception as e:
        print("PDF ERROR:", str(e))
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/migrate")
async def migrate_code(scan_id: str = Form(...)):
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"

        with open(metadata_path, "r") as f:
            scan_data = json.load(f)

        migration_plan = scan_data.get("migration_plan", {})

        return {
            "success": True,
            "migration_plan": migration_plan
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/migrate/download")
async def migrate_and_download(scan_id: str = Form(...)):
    """
    Apply actual post-quantum code replacements to the uploaded source file
    and return the migrated file as a download.
    """
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"

        with open(metadata_path, "r") as f:
            scan_data = json.load(f)

        original_filename = scan_data.get("filename", "code.txt")
        file_path = f"uploads/{scan_id}_{original_filename}"

        with open(file_path, "r", errors="ignore") as f:
            source_code = f.read()

        scan_results = scan_data.get("vulnerabilities", {})
        migrated_code = pq_migrator.apply_migrations_to_source(source_code, scan_results)

        # Write migrated file
        ext = os.path.splitext(original_filename)[1] or ".txt"
        migrated_filename = f"pq_migrated_{scan_id}{ext}"
        migrated_path = f"uploads/{migrated_filename}"

        with open(migrated_path, "w") as f:
            f.write(migrated_code)

        return FileResponse(
            migrated_path,
            media_type="application/octet-stream",
            filename=migrated_filename
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/badge/generate")
async def generate_badge(
    scan_id: str = Form(...),
    blockchain_tx: str = Form(""),
):
    """
    Issue a quantum-safe certification badge for a completed scan.
    Refuses to certify a file that still contains quantum-vulnerable crypto.
    """
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"
        with open(metadata_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Unknown scan_id")

    findings = scan_data.get("vulnerabilities", {}).get("vulnerabilities", [])
    if findings:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot certify: {len(findings)} quantum-vulnerable finding(s) remain. "
                "Apply the migration and re-scan the migrated file first."
            ),
        )

    try:
        badge = badge_generator.generate_badge(
            scan_id=scan_id,
            company_name=scan_data["company_name"],
            sector=scan_data["sector"],
            blockchain_tx=blockchain_tx,
            output_dir="badges",
        )
        return {"success": True, **badge}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/badge/verify/{badge_id}")
async def verify_badge(badge_id: str):
    """Look up a badge in the registry."""
    try:
        return {"success": True, **badge_generator.verify_badge(badge_id)}
    except ValueError:
        raise HTTPException(status_code=404, detail="Badge not found")


@app.get("/api/badge/image/{badge_id}")
async def badge_image(badge_id: str):
    """Serve the rendered badge certificate."""
    path = f"badges/badge_{badge_id}.png"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Badge image not found")
    return FileResponse(path, media_type="image/png", filename=f"{badge_id}.png")


@app.get("/api/cbom/{scan_id}")
async def cbom_export(scan_id: str):
    """
    Export the scan as a CycloneDX 1.6 Cryptographic Bill of Materials.
    Each distinct algorithm family becomes one cryptographic-asset component,
    so the inventory is consumable by standard SBOM/CBOM tooling.
    """
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"
        with open(metadata_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Unknown scan_id")

    scan_results = scan_data.get("vulnerabilities", {})
    findings = scan_results.get("vulnerabilities", [])

    # NIST replacement target per family, mirroring pq_migrator's mapping.
    primitive_map = {
        "ECDSA": ("signature", "ML-DSA", "FIPS 204"),
        "RSA": ("pke", "ML-KEM", "FIPS 203"),
        "DH": ("key-agree", "ML-KEM", "FIPS 203"),
        "SHA256": ("hash", "SHA-384/SHA-512", "FIPS 180-4"),
        "AES_SHORT": ("block-cipher", "AES-256", "FIPS 197"),
    }

    components = []
    for algo in sorted({f["algorithm"] for f in findings}):
        occurrences = [f for f in findings if f["algorithm"] == algo]
        primitive, replacement, standard = primitive_map.get(algo, ("unknown", "N/A", "N/A"))
        components.append({
            "type": "cryptographic-asset",
            "name": algo,
            "bom-ref": f"crypto/{algo.lower()}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": primitive,
                    "executionEnvironment": "software-plain-ram",
                    "cryptoFunctions": ["verify"] if primitive == "signature" else ["other"],
                },
                "oid": "",
            },
            "properties": [
                {"name": "quantumVulnerable", "value": "true"},
                {"name": "severity", "value": occurrences[0]["severity"]},
                {"name": "occurrences", "value": str(len(occurrences))},
                {"name": "affectedLines", "value": ",".join(str(o["line_number"]) for o in occurrences)},
                {"name": "recommendedReplacement", "value": replacement},
                {"name": "nistStandard", "value": standard},
            ],
        })

    return JSONResponse({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{scan_id}",
        "version": 1,
        "metadata": {
            "timestamp": scan_data.get("timestamp"),
            "component": {
                "type": "file",
                "name": scan_data.get("filename", "unknown"),
                "bom-ref": f"file/{scan_id}",
            },
            "properties": [
                {"name": "language", "value": scan_results.get("language", "Unknown")},
                {"name": "riskScore", "value": str(scan_data.get("risk_score", 0))},
                {"name": "organization", "value": scan_data.get("company_name", "")},
                {"name": "sector", "value": scan_data.get("sector", "")},
            ],
        },
        "components": components,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
    