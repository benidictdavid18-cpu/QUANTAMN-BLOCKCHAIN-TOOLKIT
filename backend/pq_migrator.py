"""
Post-Quantum Migrator - Generates migration recommendations and applies transformations
"""
from typing import Dict, List, Any
import re

class PostQuantumMigrator:
    def __init__(self):
        # Mapping of classical to post-quantum algorithms
        self.migration_map = {
            "ECDSA": {
                "pq_replacement": "ML-DSA (Dilithium)",
                "nist_standard": "FIPS 204",
                "key_size": "2048-4096 bits",
                "description": "Module-Lattice-Based Digital Signature Algorithm",
                "implementation": "liboqs-python or pqcrypto library",
                "code_template_solidity": """
// Post-Quantum Signature Verification using ML-DSA (Dilithium)
// Off-chain verification recommended due to gas costs

contract QuantumSafeContract {
    mapping(bytes32 => bool) public validSignatures;
    
    // Store hash of ML-DSA public key
    bytes32 public mldsaPublicKeyHash;
    
    constructor(bytes32 _publicKeyHash) {
        mldsaPublicKeyHash = _publicKeyHash;
    }
    
    // Verify ML-DSA signature (computed off-chain, verified via oracle)
    function verifyMLDSASignature(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory publicKey
    ) public view returns (bool) {
        require(keccak256(publicKey) == mldsaPublicKeyHash, "Invalid public key");
        // Actual verification done off-chain via oracle or ZK proof
        // Store result on-chain after verification
        return validSignatures[messageHash];
    }
    
    // Admin function to register verified signatures (called by oracle)
    function registerVerifiedSignature(bytes32 messageHash) external {
        // Access control needed here
        validSignatures[messageHash] = true;
    }
}
""",
                "code_template_python": """
# Post-Quantum Signature using ML-DSA (Dilithium)
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

class QuantumSafeSigner:
    def __init__(self):
        self.public_key, self.secret_key = generate_keypair()
    
    def sign_message(self, message: bytes) -> bytes:
        '''Sign message using ML-DSA (Dilithium)'''
        signature = sign(message, self.secret_key)
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        '''Verify ML-DSA signature'''
        try:
            verify(signature, message, public_key)
            return True
        except:
            return False

# Usage example
signer = QuantumSafeSigner()
message = b"Quantum-safe transaction"
signature = signer.sign_message(message)
is_valid = signer.verify_signature(message, signature, signer.public_key)
"""
            },
            "RSA": {
                "pq_replacement": "ML-KEM (Kyber) for encryption",
                "nist_standard": "FIPS 203",
                "key_size": "3072+ bits",
                "description": "Module-Lattice-Based Key Encapsulation Mechanism",
                "implementation": "liboqs-python",
                "code_template_python": """
# Post-Quantum Key Encapsulation using ML-KEM (Kyber)
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

class QuantumSafeEncryption:
    def __init__(self):
        self.public_key, self.secret_key = generate_keypair()
    
    def encapsulate(self, recipient_public_key: bytes):
        '''Generate shared secret using ML-KEM'''
        ciphertext, shared_secret = encrypt(recipient_public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        '''Recover shared secret using ML-KEM'''
        shared_secret = decrypt(ciphertext, self.secret_key)
        return shared_secret

# Usage
encryptor = QuantumSafeEncryption()
ct, secret1 = encryptor.encapsulate(encryptor.public_key)
secret2 = encryptor.decapsulate(ct)
assert secret1 == secret2  # Shared secret established
"""
            },
            "DH": {
                "pq_replacement": "ML-KEM (Kyber)",
                "nist_standard": "FIPS 203",
                "key_size": "N/A (lattice-based)",
                "description": "Replaces Diffie-Hellman key exchange with quantum-safe KEM",
                "implementation": "liboqs-python"
            },
            "SHA256": {
                "pq_replacement": "SHA-384 or SHA-512",
                "nist_standard": "FIPS 180-4",
                "key_size": "384-512 bits output",
                "description": "Increase hash output size for quantum resistance (Grover's algorithm)",
                "implementation": "hashlib (Python standard library)",
                "code_template_python": """
import hashlib

# Quantum-resistant hashing (larger output size)
def quantum_safe_hash(data: bytes) -> bytes:
    '''Use SHA-384 or SHA-512 for quantum resistance'''
    return hashlib.sha512(data).digest()  # 512-bit output

# For blockchain applications
def quantum_safe_merkle_root(transactions: list) -> bytes:
    '''Build Merkle tree with SHA-512'''
    if len(transactions) == 1:
        return quantum_safe_hash(transactions[0])
    
    # Recursively build tree
    mid = len(transactions) // 2
    left = quantum_safe_merkle_root(transactions[:mid])
    right = quantum_safe_merkle_root(transactions[mid:])
    return quantum_safe_hash(left + right)
"""
            },
            "AES_SHORT": {
                "pq_replacement": "AES-256",
                "nist_standard": "FIPS 197",
                "key_size": "256 bits",
                "description": "Increase AES key size to 256 bits for quantum resistance",
                "implementation": "PyCryptodome",
                "code_template_python": """
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class QuantumSafeAES:
    def __init__(self):
        self.key = get_random_bytes(32)  # 256-bit key (quantum-resistant)
    
    def encrypt(self, plaintext: bytes) -> tuple:
        '''Encrypt with AES-256-GCM'''
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, ciphertext, tag
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        '''Decrypt with AES-256-GCM'''
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
"""
            }
        }
    
    def generate_migration_plan(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed migration plan based on scan results
        """
        vulnerabilities = scan_results.get("vulnerabilities", [])
        language = scan_results.get("language", "Unknown")
        
        migration_steps = []
        recommendations = []
        
        # Group vulnerabilities by algorithm
        algo_groups = {}
        for vuln in vulnerabilities:
            algo = vuln["algorithm"]
            if algo not in algo_groups:
                algo_groups[algo] = []
            algo_groups[algo].append(vuln)
        
        # Generate migration steps for each algorithm
        for algo, vulns in algo_groups.items():
            if algo in self.migration_map:
                pq_algo = self.migration_map[algo]
                
                migration_steps.append({
                    "step": len(migration_steps) + 1,
                    "algorithm": algo,
                    "occurrences": len(vulns),
                    "pq_replacement": pq_algo["pq_replacement"],
                    "nist_standard": pq_algo["nist_standard"],
                    "description": pq_algo["description"],
                    "implementation": pq_algo["implementation"],
                    "affected_lines": [v["line_number"] for v in vulns],
                    "code_template": self._get_code_template(algo, language)
                })
                
                # Add specific recommendations
                recommendations.append({
                    "priority": "HIGH" if vulns[0]["severity"] == "HIGH" else "MEDIUM",
                    "action": f"Replace {algo} with {pq_algo['pq_replacement']}",
                    "reason": f"Vulnerable to quantum attacks ({pq_algo['description']})",
                    "standard": pq_algo["nist_standard"]
                })
        
        # Add general recommendations
        recommendations.extend([
            {
                "priority": "HIGH",
                "action": "Conduct security audit after migration",
                "reason": "Ensure post-quantum implementations are correctly integrated",
                "standard": "ISO 27001"
            },
            {
                "priority": "MEDIUM",
                "action": "Implement hybrid cryptography (classical + post-quantum)",
                "reason": "Provides defense-in-depth during transition period",
                "standard": "NIST Transitional Guidance"
            },
            {
                "priority": "MEDIUM",
                "action": "Update key management practices",
                "reason": "Post-quantum keys are larger and require updated infrastructure",
                "standard": "NIST SP 800-57"
            }
        ])
        
        return {
            "migration_steps": migration_steps,
            "recommendations": recommendations,
            "estimated_complexity": self._estimate_complexity(migration_steps),
            "timeline_estimate": self._estimate_timeline(migration_steps)
        }
    
    def apply_migrations(self, scan_id: str, migration_plan: Dict[str, Any]) -> str:
        """
        Apply migration transformations (generates example migrated code)
        """
        migrated_code_sections = []
        
        migrated_code_sections.append("""
// QUANTUM-SAFE SMART CONTRACT
// Migration ID: {}
// Post-Quantum Cryptography Applied
// Standards: NIST FIPS 203, 204, 205

pragma solidity ^0.8.0;

/**
 * @title QuantumSafeContract
 * @dev Smart contract with post-quantum cryptographic primitives
 * @notice This contract uses off-chain PQ verification with on-chain state management
 */
contract QuantumSafeContract {{
    
    // Events
    event SignatureVerified(bytes32 indexed messageHash, address indexed verifier);
    event PublicKeyRegistered(bytes32 indexed keyHash, string algorithm);
    
    // State variables
    mapping(bytes32 => bool) public verifiedSignatures;
    mapping(address => bytes32) public mldsaPublicKeys;  // ML-DSA public key hashes
    mapping(address => bytes32) public mlkemPublicKeys;  // ML-KEM public key hashes
    
    address public oracle;  // Trusted oracle for off-chain PQ verification
    
    modifier onlyOracle() {{
        require(msg.sender == oracle, "Only oracle can call");
        _;
    }}
    
    constructor(address _oracle) {{
        oracle = _oracle;
    }}
    
    /**
     * @dev Register ML-DSA (Dilithium) public key
     * @param publicKeyHash Hash of the ML-DSA public key
     */
    function registerMLDSAKey(bytes32 publicKeyHash) external {{
        mldsaPublicKeys[msg.sender] = publicKeyHash;
        emit PublicKeyRegistered(publicKeyHash, "ML-DSA");
    }}
    
    /**
     * @dev Verify ML-DSA signature (verification done off-chain by oracle)
     * @param messageHash Hash of the message
     * @param signatureHash Hash of the ML-DSA signature
     * @param signer Address of the signer
     */
    function verifyMLDSASignature(
        bytes32 messageHash,
        bytes32 signatureHash,
        address signer
    ) external onlyOracle {{
        require(mldsaPublicKeys[signer] != bytes32(0), "Signer not registered");
        
        // Oracle has verified the ML-DSA signature off-chain
        verifiedSignatures[messageHash] = true;
        emit SignatureVerified(messageHash, signer);
    }}
    
    /**
     * @dev Check if signature is verified
     */
    function isSignatureVerified(bytes32 messageHash) external view returns (bool) {{
        return verifiedSignatures[messageHash];
    }}
    
    /**
     * @dev Quantum-safe hash function (uses double SHA-512 off-chain, stores hash on-chain)
     * @param dataHash Pre-computed SHA-512 hash
     */
    function storeQuantumSafeHash(bytes32 dataHash) external {{
        // In production: verify the hash was computed correctly off-chain
        // Store for future reference
    }}
}}

// MIGRATION NOTES:
// 1. ECDSA replaced with ML-DSA (Dilithium) - FIPS 204
// 2. Key exchange uses ML-KEM (Kyber) - FIPS 203  
// 3. Hash functions upgraded to SHA-512 minimum
// 4. AES encryption uses 256-bit keys minimum
// 5. Off-chain verification pattern used due to gas costs
""".format(scan_id))
        
        # Add Python helper code
        migrated_code_sections.append("""

# PYTHON OFF-CHAIN VERIFICATION HELPER
# For use with quantum-safe smart contract

from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from pqcrypto.kem.kyber512 import generate_keypair as kem_generate_keypair
import hashlib
from web3 import Web3

class QuantumSafeOracle:
    '''Oracle service for off-chain post-quantum cryptography verification'''
    
    def __init__(self, contract_address, web3_provider):
        self.w3 = Web3(Web3.HTTPProvider(web3_provider))
        self.contract_address = contract_address
        # Load contract ABI
    
    def verify_mldsa_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        '''Verify ML-DSA signature off-chain'''
        try:
            verify(signature, message, public_key)
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False
    
    def quantum_safe_hash(self, data: bytes) -> bytes:
        '''Double SHA-512 for quantum resistance'''
        hash1 = hashlib.sha512(data).digest()
        hash2 = hashlib.sha512(hash1).digest()
        return hash2
    
    def submit_verification_to_chain(self, message_hash: bytes, signature_hash: bytes, signer: str):
        '''Submit verified signature to smart contract'''
        # Call contract's verifyMLDSASignature function
        # This requires oracle to be authorized in the contract
        pass

# Example usage
oracle = QuantumSafeOracle("0x...", "https://polygon-mumbai.g.alchemy.com/v2/...")
""")
        
        return "\n\n".join(migrated_code_sections)
    
    def _get_code_template(self, algo: str, language: str) -> str:
        """Get appropriate code template"""
        if algo not in self.migration_map:
            return ""
        
        template_key = f"code_template_{language.lower()}"
        return self.migration_map[algo].get(template_key, 
            self.migration_map[algo].get("code_template_python", ""))
    
    def _estimate_complexity(self, migration_steps: List[Dict]) -> str:
        """Estimate migration complexity"""
        total_occurrences = sum(step["occurrences"] for step in migration_steps)
        
        if total_occurrences <= 5:
            return "LOW"
        elif total_occurrences <= 15:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _estimate_timeline(self, migration_steps: List[Dict]) -> str:
        """Estimate migration timeline"""
        total_occurrences = sum(step["occurrences"] for step in migration_steps)
        
        if total_occurrences <= 5:
            return "1-2 weeks"
        elif total_occurrences <= 15:
            return "2-4 weeks"
        else:
            return "4-8 weeks"

    def apply_migrations_to_source(self, source_code: str, scan_results: Dict[str, Any]) -> str:
        """
        Apply actual post-quantum replacements to the original source code.
        Returns the migrated source code as a string.
        """
        language = scan_results.get("language", "Unknown")
        migrated = source_code

        # Header comment injected at the top
        header = (
            "# ============================================================\n"
            "# POST-QUANTUM MIGRATION APPLIED\n"
            "# Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)\n"
            "# Tool: Quantum-Resistant Blockchain Security Toolkit\n"
            "# ============================================================\n\n"
        )
        if language == "Solidity":
            header = (
                "// ============================================================\n"
                "// POST-QUANTUM MIGRATION APPLIED\n"
                "// Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)\n"
                "// Tool: Quantum-Resistant Blockchain Security Toolkit\n"
                "// ============================================================\n\n"
            )
        elif language in ("JavaScript",):
            header = (
                "// ============================================================\n"
                "// POST-QUANTUM MIGRATION APPLIED\n"
                "// Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)\n"
                "// Tool: Quantum-Resistant Blockchain Security Toolkit\n"
                "// ============================================================\n\n"
            )

        # ---- Python replacements ----
        if language == "Python":
            # ECDSA imports → ML-DSA (Dilithium)
            migrated = re.sub(
                r"from\s+ecdsa\s+import.*",
                "from pqcrypto.sign.dilithium2 import generate_keypair as ecdsa_keypair, sign as ecdsa_sign, verify as ecdsa_verify  # MIGRATED: ECDSA → ML-DSA (FIPS 204)",
                migrated
            )
            migrated = re.sub(
                r"from\s+eth_keys\.keys.*",
                "from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify  # MIGRATED: eth_keys ECDSA → ML-DSA (FIPS 204)",
                migrated
            )
            # RSA imports → ML-KEM (Kyber)
            migrated = re.sub(
                r"from\s+Crypto\.PublicKey\s+import\s+RSA",
                "from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt  # MIGRATED: RSA → ML-KEM/Kyber (FIPS 203)",
                migrated
            )
            migrated = re.sub(
                r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa",
                "from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt  # MIGRATED: RSA → ML-KEM/Kyber (FIPS 203)",
                migrated
            )
            # SHA256 → SHA512
            migrated = re.sub(
                r"hashlib\.sha256\s*\(",
                "hashlib.sha512(  # MIGRATED: SHA-256 → SHA-512 (quantum-resistant, FIPS 180-4)",
                migrated
            )
            migrated = re.sub(
                r"SHA256\s*\.\s*new\s*\(",
                "SHA512.new(  # MIGRATED: SHA-256 → SHA-512 (FIPS 180-4)",
                migrated
            )
            # AES-128 → AES-256
            migrated = re.sub(
                r"aes-128",
                "aes-256  # MIGRATED: AES-128 → AES-256 (quantum-resistant)",
                migrated, flags=re.IGNORECASE
            )
            migrated = re.sub(
                r"AES-128",
                "AES-256  # MIGRATED: AES-128 → AES-256 (quantum-resistant)",
                migrated
            )
            # get_random_bytes(16) → get_random_bytes(32)
            migrated = re.sub(
                r"get_random_bytes\(16\)",
                "get_random_bytes(32)  # MIGRATED: 128-bit → 256-bit key (quantum-resistant)",
                migrated
            )
            # AES.new key mode fix (comment only, logic preserved)
            migrated = re.sub(
                r"(AES\.new\(.*?AES\.MODE_CBC)",
                r"\1  # NOTE: Ensure 256-bit key is used (32 bytes)",
                migrated
            )
            # DH / Diffie-Hellman
            migrated = re.sub(
                r"(from\s+cryptography.*diffie.*hellman.*|import\s+dh\b.*)",
                r"# MIGRATED (line below): Diffie-Hellman → ML-KEM/Kyber (FIPS 203)\nfrom pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt",
                migrated, flags=re.IGNORECASE
            )
            # Web3.eth.account usage inline comment
            migrated = re.sub(
                r"(Web3\.eth\.account)",
                r"\1  # WARNING: Uses ECDSA internally — migrate signing to ML-DSA off-chain",
                migrated
            )

        # ---- Solidity replacements ----
        elif language == "Solidity":
            # ecrecover → note
            migrated = re.sub(
                r"ecrecover\s*\(",
                "ecrecover(  /* MIGRATED: Replace with off-chain ML-DSA verification + oracle pattern (FIPS 204) */",
                migrated
            )
            # keccak256 → sha512 note
            migrated = re.sub(
                r"keccak256\s*\(",
                "keccak256(  /* NOTE: Upgrade to SHA-512 equivalent off-chain; keccak256 used on-chain for now */",
                migrated
            )
            # secp256k1
            migrated = re.sub(
                r"secp256k1",
                "/* MIGRATED: secp256k1 → ML-DSA (Dilithium) off-chain oracle pattern (FIPS 204) */",
                migrated
            )

        # ---- JavaScript replacements ----
        elif language == "JavaScript":
            migrated = re.sub(
                r"(Web3\.eth\.account)",
                r"\1  // WARNING: Uses ECDSA — migrate signing to ML-DSA off-chain (FIPS 204)",
                migrated
            )
            migrated = re.sub(
                r"(ECDSA\.)",
                r"// MIGRATED: ECDSA → ML-DSA (FIPS 204)\n\1",
                migrated
            )
            migrated = re.sub(
                r"sha256\s*\(",
                "sha512(  // MIGRATED: SHA-256 → SHA-512 (FIPS 180-4)",
                migrated, flags=re.IGNORECASE
            )

        # Append PQ library installation note at the bottom
        install_note = (
            "\n\n"
            "# ============================================================\n"
            "# REQUIRED DEPENDENCIES FOR POST-QUANTUM MIGRATION:\n"
            "#   pip install pqcrypto        # ML-DSA (Dilithium) + ML-KEM (Kyber)\n"
            "#   pip install liboqs-python   # Alternative: Open Quantum Safe\n"
            "#   pip install pycryptodome    # AES-256\n"
            "# ============================================================\n"
        )
        if language == "Solidity":
            install_note = (
                "\n\n"
                "// ============================================================\n"
                "// MIGRATION NOTE: Solidity cannot natively run PQ algorithms.\n"
                "// Use off-chain ML-DSA verification with an oracle contract.\n"
                "// Reference: https://openquantumsafe.org/\n"
                "// ============================================================\n"
            )
        elif language == "JavaScript":
            install_note = (
                "\n\n"
                "// ============================================================\n"
                "// REQUIRED DEPENDENCIES FOR POST-QUANTUM MIGRATION:\n"
                "//   npm install @noble/post-quantum   // ML-DSA + ML-KEM\n"
                "//   npm install pqcrypto-js           // Alternative\n"
                "// ============================================================\n"
            )

        return header + migrated + install_note
