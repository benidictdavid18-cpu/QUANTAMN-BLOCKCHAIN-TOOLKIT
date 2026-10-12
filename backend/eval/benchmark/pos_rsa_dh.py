"""
POSITIVE CASE: RSA key handling plus a Diffie-Hellman exchange.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
import os


class LegacyKeyService:
    def __init__(self):
        self.keypair = RSA.generate(2048)
        self.session_key = os.urandom(16)

    def wrap(self, payload: bytes) -> bytes:
        cipher = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, _tag = cipher.encrypt_and_digest(payload)
        return ciphertext

    def fingerprint(self, payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def diffie_hellman_exchange(self, peer_public, modulus):
        secret = int.from_bytes(self.session_key, "big")
        return pow(peer_public, secret, modulus)
