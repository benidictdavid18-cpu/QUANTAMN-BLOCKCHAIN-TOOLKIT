import ecdsa
import hashlib
import base64
import time

# Simulated doctor's private key (insecure - for demo only!)
PRIVATE_KEY = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
PUBLIC_KEY = PRIVATE_KEY.verifying_key

def sign_consent(patient_id: str, consent_text: str) -> dict:
    timestamp = int(time.time())
    message = f"{patient_id}:{consent_text}:{timestamp}".encode('utf-8')
    message_hash = hashlib.sha256(message).digest()

    signature = PRIVATE_KEY.sign_digest_deterministic(
        message_hash,
        hashfunc=hashlib.sha256
    )

    return {
        "patient_id": patient_id,
        "consent": consent_text,
        "timestamp": timestamp,
        "signature_b64": base64.b64encode(signature).decode('utf-8'),
        "pubkey_hex": PUBLIC_KEY.to_string().hex(),
        "curve": "secp256k1",
        "hash": "sha256"
    }

# Example usage
if __name__ == "__main__":
    result = sign_consent("P-12345", "Patient consents to share anonymized data for research")
    print(result)