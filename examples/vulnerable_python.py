"""
Example Python code with quantum-vulnerable cryptography
USE FOR TESTING ONLY - Contains intentional vulnerabilities
"""

from ecdsa import SigningKey, SECP256k1  # VULNERABLE: ECDSA
from Crypto.PublicKey import RSA  # VULNERABLE: RSA
from Crypto.Cipher import AES  # May need larger key size
import hashlib

class VulnerableBlockchain:
    """
    Example blockchain implementation with quantum vulnerabilities
    """
    
    def __init__(self):
        # VULNERABILITY: ECDSA key generation
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        
        # VULNERABILITY: RSA encryption
        self.rsa_key = RSA.generate(2048)  # Vulnerable to Shor's algorithm
        
        self.chain = []
    
    def sign_transaction(self, transaction_data):
        """
        Sign transaction using ECDSA (VULNERABLE)
        """
        # VULNERABILITY: ECDSA signature
        message_hash = hashlib.sha256(transaction_data.encode()).digest()
        signature = self.private_key.sign(message_hash)
        return signature
    
    def verify_signature(self, transaction_data, signature, public_key):
        """
        Verify ECDSA signature (VULNERABLE)
        """
        try:
            message_hash = hashlib.sha256(transaction_data.encode()).digest()
            public_key.verify(signature, message_hash)
            return True
        except:
            return False
    
    def encrypt_data(self, data):
        """
        Encrypt using RSA (VULNERABLE)
        """
        # VULNERABILITY: RSA encryption vulnerable to quantum attacks
        encrypted = self.rsa_key.encrypt(data.encode(), 32)
        return encrypted
    
    def create_block(self, transactions):
        """
        Create new block with weak hashing
        """
        # VULNERABILITY: SHA-256 may need larger output for quantum resistance
        block_data = {
            'index': len(self.chain),
            'transactions': transactions,
            'previous_hash': self.get_last_block_hash(),
            'timestamp': str(hashlib.sha256(str(len(self.chain)).encode()).hexdigest())
        }
        
        # VULNERABILITY: Single SHA-256 hash
        block_hash = hashlib.sha256(str(block_data).encode()).hexdigest()
        block_data['hash'] = block_hash
        
        self.chain.append(block_data)
        return block_data
    
    def get_last_block_hash(self):
        """Get hash of last block"""
        if len(self.chain) > 0:
            return self.chain[-1]['hash']
        return "0" * 64
    
    def diffie_hellman_exchange(self, other_public_key):
        """
        VULNERABILITY: Diffie-Hellman key exchange
        Vulnerable to quantum attacks
        """
        # Simplified DH exchange (vulnerable)
        shared_secret = pow(other_public_key, int.from_bytes(self.private_key.to_string(), 'big'), 2**256)
        return shared_secret


# Example usage
if __name__ == "__main__":
    blockchain = VulnerableBlockchain()
    
    # Sign a transaction (VULNERABLE)
    tx_data = "Transfer 100 coins from Alice to Bob"
    signature = blockchain.sign_transaction(tx_data)
    
    # Verify signature (VULNERABLE)
    is_valid = blockchain.verify_signature(tx_data, signature, blockchain.public_key)
    print(f"Signature valid: {is_valid}")
    
    # Create block
    block = blockchain.create_block([tx_data])
    print(f"Block created: {block['hash'][:16]}...")
    
    # Encrypt data (VULNERABLE)
    encrypted = blockchain.encrypt_data("Sensitive blockchain data")
    print(f"Data encrypted: {len(encrypted)} bytes")
