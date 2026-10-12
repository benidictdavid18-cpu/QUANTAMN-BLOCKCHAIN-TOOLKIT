"""
Cryptography Scanner - Detects vulnerable classical cryptography algorithms
"""
import re
import math
from typing import Dict, List, Any

# Matches comments and string literals so they can be masked out before scanning.
# Order matters: triple-quoted strings and block comments are consumed before
# their single-line counterparts can bite into them.
_NONCODE_RE = re.compile(
    r'"""[\s\S]*?"""'          # Python docstring (double)
    r"|'''[\s\S]*?'''"         # Python docstring (single)
    r"|/\*[\s\S]*?\*/"         # C-style block comment (Solidity/JS/Go)
    r"|//[^\n]*"               # C-style line comment
    r"|\#[^\n]*"               # Python/shell line comment
    r'|"(?:\\.|[^"\\\n])*"'    # double-quoted string
    r"|'(?:\\.|[^'\\\n])*'"    # single-quoted string
)


def _mask_noncode(content: str) -> str:
    """
    Blank out comments and string literals, preserving newlines and total
    length so byte offsets and line numbers still line up with the original.
    """
    return _NONCODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), content)


class CryptoScanner:
    def __init__(self):
        # Vulnerable cryptographic patterns
        self.vulnerable_patterns = {
            "ECDSA": {
                "patterns": [
                    r"ecrecover\s*\(",
                    r"\bECDSA\s*\.",
                    r"\bsecp256k1\b",
                    r"elliptic\.curve",
                    r"from\s+ecdsa\s+import",
                    r"eth_keys\.keys",
                    r"Web3\.eth\.account",
                    r"SigningKey\.generate",
                ],
                "description": "Elliptic Curve Digital Signature Algorithm (vulnerable to quantum attacks)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "RSA": {
                "patterns": [
                    r"\bRSA\s*\.",
                    r"\brsa\.newkeys\b",
                    r"from\s+Crypto\.PublicKey\s+import\s+RSA",
                    r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa"
                ],
                "description": "RSA encryption (vulnerable to Shor's algorithm)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "SHA256": {
                "patterns": [
                    r"\bhashlib\.sha256\s*\(",
                    r"\bsha256\s*\(",
                    r"\bkeccak256\s*\(",
                    r"\bSHA256\s*\.",
                ],
                "description": "SHA-256 hashing (partially vulnerable, need larger key sizes)",
                "severity": "MEDIUM",
                "quantum_vulnerable": True
            },
            "DH": {
                "patterns": [
                    # No trailing \b: must still match diffie_hellman_exchange()
                    r"\bdiffie[-_ ]?hellman",
                    r"\bDH\.(?:generate|new)\b",
                    r"\bECDH\b",
                ],
                "description": "Diffie-Hellman key exchange (vulnerable to quantum attacks)",
                "severity": "HIGH",
                "quantum_vulnerable": True
            },
            "AES_SHORT": {
                "patterns": [
                    r"AES\.new\(.*?,\s*AES\.MODE_",
                    r"\bAES[-_]128\b",
                ],
                "description": "AES with potentially insufficient key length for quantum resistance",
                "severity": "MEDIUM",
                "quantum_vulnerable": True
            }
        }

        # Post-quantum safe patterns. No trailing \b: real module names carry a
        # parameter suffix (dilithium2, kyber512, sphincsharaka128f).
        self.pq_safe_patterns = {
            "ML-DSA": [r"\bml[-_]?dsa", r"\bdilithium"],
            "ML-KEM": [r"\bml[-_]?kem", r"\bkyber"],
            "SLH-DSA": [r"\bslh[-_]?dsa", r"\bsphincs"],
            "XMSS": [r"\bxmss"],
            "LMS": [r"\blms[-_ ]hash"]
        }

        # Severity -> base contribution to the risk score (see calculate_risk_score)
        self.severity_base = {"HIGH": 60, "MEDIUM": 35, "LOW": 15}

    def scan_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Scan file for vulnerable cryptography.

        Only real code is counted: comments and string literals are masked out
        first, then overlapping matches on the same line are collapsed so a
        single call site yields a single finding.
        """
        lines = content.split('\n')
        code_only = _mask_noncode(content)

        raw_hits: List[Dict[str, Any]] = []
        for algo_name, algo_data in self.vulnerable_patterns.items():
            for pattern in algo_data["patterns"]:
                for match in re.finditer(pattern, code_only, re.IGNORECASE):
                    line_number = code_only[:match.start()].count('\n') + 1
                    line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ""

                    raw_hits.append({
                        "algorithm": algo_name,
                        "description": algo_data["description"],
                        "severity": algo_data["severity"],
                        "line_number": line_number,
                        "line_content": line_content,
                        "matched_pattern": match.group(0),
                        "quantum_vulnerable": algo_data["quantum_vulnerable"],
                    })

        vulnerabilities = self._deduplicate(raw_hits)

        # Mentions that appear only in comments/strings. Reported for context,
        # deliberately excluded from the count and the risk score.
        informational = self._comment_only_mentions(content, code_only, lines)

        language = self._detect_language(content)

        # Context analysis (word-bounded so identifiers like "width" don't match)
        has_signature_verification = bool(
            re.search(r"\b(?:verify|signature|sign)\b", code_only, re.IGNORECASE)
        )
        has_key_exchange = bool(
            re.search(r"\bkey[-_ ]?exchange|\bECDH\b|\bdiffie[-_ ]?hellman", code_only, re.IGNORECASE)
        )

        return {
            "file_path": file_path,
            "language": language,
            "total_lines": len(lines),
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "informational_mentions": informational,
            "raw_match_count": len(raw_hits),
            "has_signature_verification": has_signature_verification,
            "has_key_exchange": has_key_exchange,
            "quantum_ready": len(vulnerabilities) == 0,
            "pq_algorithms_detected": self._detect_pq_algorithms(code_only),
        }

    def _deduplicate(self, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collapse redundant matches. Two hits are redundant when they report the
        same algorithm on the same line (e.g. 'hashlib.sha256(' also matches the
        broader 'sha256(' pattern). The longest match wins, since it is the most
        specific description of the call site.
        """
        best: Dict[tuple, Dict[str, Any]] = {}
        for hit in hits:
            key = (hit["algorithm"], hit["line_number"])
            incumbent = best.get(key)
            if incumbent is None or len(hit["matched_pattern"]) > len(incumbent["matched_pattern"]):
                best[key] = hit

        return sorted(best.values(), key=lambda h: (h["line_number"], h["algorithm"]))

    def _comment_only_mentions(
        self, content: str, code_only: str, lines: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Find algorithm names that appear ONLY in comments or strings. These are
        documentation, not call sites, so they are surfaced separately rather
        than counted as vulnerabilities.
        """
        mentions: Dict[tuple, Dict[str, Any]] = {}
        for algo_name, algo_data in self.vulnerable_patterns.items():
            for pattern in algo_data["patterns"]:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Blank in the masked copy == this match sat in a comment/string
                    if code_only[match.start():match.end()].strip():
                        continue
                    line_number = content[:match.start()].count('\n') + 1
                    key = (algo_name, line_number)
                    if key in mentions:
                        continue
                    mentions[key] = {
                        "algorithm": algo_name,
                        "line_number": line_number,
                        "line_content": lines[line_number - 1].strip() if line_number <= len(lines) else "",
                        "matched_pattern": match.group(0),
                        "note": "Mentioned in a comment or string literal, not an active call site",
                    }
        return sorted(mentions.values(), key=lambda m: m["line_number"])

    def _detect_pq_algorithms(self, code_only: str) -> List[str]:
        """Report post-quantum algorithms already present in the code."""
        found = []
        for algo, patterns in self.pq_safe_patterns.items():
            if any(re.search(p, code_only, re.IGNORECASE) for p in patterns):
                found.append(algo)
        return found

    def calculate_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """
        Calculate overall risk score (0-100, higher is worse).

        Combines three independent signals instead of summing severity weights.
        The old sum saturated at 100 as soon as a file held four HIGH findings,
        so every vulnerable file scored identically:

          base    - worst severity present            (up to 60)
          breadth - distinct algorithm families       (up to 20)
          density - findings per 100 lines of code    (up to 20)

        Monotonic in all three inputs; only a broadly AND densely affected file
        approaches 100.
        """
        vulnerabilities = scan_results.get("vulnerabilities", [])
        if not vulnerabilities:
            return 0.0

        base = max(self.severity_base.get(v["severity"], 15) for v in vulnerabilities)

        distinct_algorithms = len({v["algorithm"] for v in vulnerabilities})
        breadth = min(20.0, 5.0 * (distinct_algorithms - 1))

        total_lines = max(1, scan_results.get("total_lines", 1))
        per_hundred = len(vulnerabilities) * 100.0 / total_lines
        # Diminishing returns: reaches ~17 of 20 at 10 findings per 100 lines
        density = 20.0 * (1.0 - math.exp(-per_hundred / 5.0))

        return round(min(100.0, base + breadth + density), 1)

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
