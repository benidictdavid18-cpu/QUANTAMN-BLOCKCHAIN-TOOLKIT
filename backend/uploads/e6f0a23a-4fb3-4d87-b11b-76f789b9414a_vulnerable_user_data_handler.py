"""
Sample Code - Vulnerable Sensitive Data Storage
This code stores real user data (financial records, Aadhaar, biometric) using classical cryptography.
Quantum computers can break this in the future.
"""

from ecdsa import SigningKey, SECP256k1          # Vulnerable ECDSA
from Crypto.PublicKey import RSA                 # Vulnerable RSA
from Crypto.Cipher import AES                    # Weak AES-128
import hashlib
import face_recognition                          # Biometric template
import json

# ==================== SENSITIVE DATA ====================
USER_DATA = {
    "aadhaar_number": "9876-5432-1098-7654",
    "bank_account": "123456789012",
    "balance": 2450000,
    "pan_card": "ABCDE1234F",
    "email": "user@bank.com",
    "phone": "+91-9876543210"
}

# ==================== CLASSICAL CRYPTOGRAPHY (VULNERABLE) ====================

# 1. ECDSA - Digital Signature (Vulnerable to Shor's)
sk = SigningKey.generate(curve=SECP256k1)
private_key_hex = sk.to_string().hex()
print("ECDSA Private Key (vulnerable):", private_key_hex[:20] + "...")

# 2. RSA - Encrypting sensitive user data (Vulnerable to Shor's)
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
encrypted_data = public_key.encrypt(json.dumps(USER_DATA).encode(), 32)[0]

# 3. AES-128 - Encrypting financial records (Weak against Grover)
aes_key = hashlib.sha256(b"secret123").digest()[:16]   # Only 128-bit effective
cipher = AES.new(aes_key, AES.MODE_ECB)
encrypted_financial = cipher.encrypt(b"Balance: 2450000 INR | Loan Approved")

# 4. Biometric Template Storage (Cannot be changed)
face_image = "user_face.jpg"  # simulate
face_encoding = face_recognition.face_encodings(face_image)[0] if face_image else b"dummy"
biometric_hash = hashlib.sha256(face_encoding.tobytes()).digest()

# 5. Stored in database (simulated)
database_record = {
    "user_id": 1001,
    "encrypted_personal_data": encrypted_data.hex(),
    "encrypted_financial": encrypted_financial.hex(),
    "biometric_template_hash": biometric_hash.hex(),
    "signature_key": private_key_hex
}

print("✅ Sensitive data stored with classical cryptography")
print("   → Aadhaar, Bank details, Biometrics, and Private Keys are protected only by RSA/ECDSA/AES-128")
print("   → Quantum computers can decrypt this in the future using Shor's & Grover's algorithms")