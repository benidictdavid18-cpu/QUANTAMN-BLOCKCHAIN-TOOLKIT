"""
Cryptography Scanner - Detects vulnerable classical cryptography algorithms
"""
import re
import ast
from typing import Dict, List, Any

class CryptoScanner:
    def __init__(self):
        # Vulnerable cryptographic patterns
        self.vulnerable_patterns = {
            "ECDSA": {
                "patterns": [
                    r"ecrecover\s*\(",
                    r"ECDSA\s*\.",
                    r"secp256k1",
                    r"elliptic\.curve",
                    r"from\s+ecdsa\s+import",
                    r"eth_keys\.keys",
                    r"Web3\.eth\.account"
                ],
                "description": "Elliptic Curve Digital Signature Algorithm (vulnerable to quantum attacks)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "RSA": {
                "patterns": [
                    r"RSA\s*\.",
                    r"rsa\.newkeys",
                    r"from\s+Crypto\.PublicKey\s+import\s+RSA",
                    r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa"
                ],
                "description": "RSA encryption (vulnerable to Shor's algorithm)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "SHA256": {
                "patterns": [
                    r"sha256\s*\(",
                    r"keccak256\s*\(",
                    r"hashlib\.sha256",
                    r"SHA256\s*\."
                ],
                "description": "SHA-256 hashing (partially vulnerable, need larger key sizes)",
                "severity": "MEDIUM",
                "quantum_vulnerable": True
            },
            "DH": {
                "patterns": [
                    r"Diffie.*Hellman",
                    r"dh\s*\.",
                    r"diffie_hellman"
                ],
                "description": "Diffie-Hellman key exchange (vulnerable to quantum attacks)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "AES_SHORT": {
                "patterns": [
                    r"AES\.new\(.*?,\s*AES\.MODE_",
                    r"aes-128",
                    r"AES-128"
                ],
                "description": "AES with potentially insufficient key length for quantum resistance",
                "severity": "MEDIUM",
                "quantum_vulnerable": True
            }
        }
        
        # Post-quantum safe patterns (for future verification)
        self.pq_safe_patterns = {
            "ML-DSA": [r"ml_dsa", r"dilithium"],
            "ML-KEM": [r"ml_kem", r"kyber"],
            "SLH-DSA": [r"slh_dsa", r"sphincs"],
            "XMSS": [r"xmss"],
            "LMS": [r"lms\s+hash"]
        }
    
    def scan_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Scan file for vulnerable cryptography
        """
        vulnerabilities = []
        lines = content.split('\n')
        
        for algo_name, algo_data in self.vulnerable_patterns.items():
            for pattern in algo_data["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Find line number
                    line_number = content[:match.start()].count('\n') + 1
                    line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                    
                    vulnerabilities.append({
                        "algorithm": algo_name,
                        "description": algo_data["description"],
                        "severity": algo_data["severity"],
                        "line_number": line_number,
                        "line_content": line_content,
                        "matched_pattern": match.group(0),
                        "quantum_vulnerable": algo_data["quantum_vulnerable"]
                    })
        
        # Detect smart contract language
        language = self._detect_language(content)
        
        # Additional context analysis
        has_signature_verification = bool(re.search(r"verify|signature|sign", content, re.IGNORECASE))
        has_key_exchange = bool(re.search(r"key.*exchange|ecdh|dh", content, re.IGNORECASE))
        
        return {
            "file_path": file_path,
            "language": language,
            "total_lines": len(lines),
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "has_signature_verification": has_signature_verification,
            "has_key_exchange": has_key_exchange,
            "quantum_ready": len(vulnerabilities) == 0
        }
    
    def calculate_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """
        Calculate overall risk score (0-100, higher is worse)
        """
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {
            "HIGH": 30,
            "MEDIUM": 15,
            "LOW": 5
        }
        
        total_score = sum(severity_weights.get(v["severity"], 10) for v in vulnerabilities)
        
        # Cap at 100
        return min(100.0, total_score)
    
    def _detect_language(self, content: str) -> str:
        """
        Detect programming language from content
        """
        if re.search(r"pragma\s+solidity", content):
            return "Solidity"
        elif re.search(r"contract\s+\w+\s*{", content):
            return "Solidity"
        elif re.search(r"def\s+\w+\s*\(", content):
            return "Python"
        elif re.search(r"function\s+\w+\s*\(", content):
            return "JavaScript"
        elif re.search(r"package\s+main", content):
            return "Go"
        else:
            return "Unknown"
