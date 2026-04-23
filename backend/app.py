from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import json
import uuid
from datetime import datetime

from crypto_scanner import CryptoScanner
from pq_migrator import PostQuantumMigrator
from blockchain_storage import BlockchainStorage
from pdf_generator import ComplianceReportGenerator
from badge_generator import BadgeGenerator

app = FastAPI(
    title="Quantum-Resistant Blockchain Security Toolkit",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

crypto_scanner = CryptoScanner()
pq_migrator = PostQuantumMigrator()
blockchain_storage = BlockchainStorage()
report_generator = ComplianceReportGenerator()
badge_generator = BadgeGenerator()

os.makedirs("uploads", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("badges", exist_ok=True)

@app.get("/")
async def root():
    return {"status": "active"}

# ✅ TEST BLOCKCHAIN CONNECTION
@app.get("/test-blockchain")
async def test_blockchain():
    try:
        b = BlockchainStorage()
        return {
            "connected": b.w3.is_connected(),
            "wallet": b.account.address,
            "balance": str(b.w3.eth.get_balance(b.account.address))
        }
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
async def store_on_blockchain(scan_id: str = Form(...)):
    try:
        metadata_path = f"uploads/{scan_id}_metadata.json"

        with open(metadata_path, "r") as f:
            scan_data = json.load(f)

        tx_hash, block_number = blockchain_storage.store_migration_proof(
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    