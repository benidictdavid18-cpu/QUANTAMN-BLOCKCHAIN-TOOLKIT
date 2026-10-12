"""
NEGATIVE CASE: already migrated to post-quantum primitives.
Expected findings: 0 (and ML-DSA / ML-KEM should be reported as PQ-ready)
"""
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from pqcrypto.kem.kyber512 import encrypt as kem_encrypt, decrypt as kem_decrypt
import hashlib


class QuantumSafeSigner:
    def __init__(self):
        self.public_key, self.secret_key = generate_keypair()

    def sign_message(self, message: bytes) -> bytes:
        return sign(message, self.secret_key)

    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            verify(signature, message, public_key)
            return True
        except ValueError:
            return False


class QuantumSafeKEM:
    def __init__(self):
        self.public_key, self.secret_key = generate_keypair()

    def encapsulate(self, recipient_public_key: bytes):
        return kem_encrypt(recipient_public_key)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return kem_decrypt(self.secret_key, ciphertext)


def quantum_safe_hash(data: bytes) -> bytes:
    """SHA-384 retains 192-bit security against Grover search."""
    return hashlib.sha384(data).digest()
