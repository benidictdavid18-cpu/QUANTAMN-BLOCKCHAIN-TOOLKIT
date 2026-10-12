"""
NEGATIVE CASE: quantum-vulnerable algorithms discussed in prose only.
This is migration documentation, not an implementation.
Expected findings: 0
"""

# This module used to call RSA.generate(2048) and hashlib.sha256(payload).
# Both were removed during the post-quantum migration. The old ECDSA.sign
# path and the Diffie-Hellman handshake are gone as well.
#
# Historical note: ecrecover(hash, v, r, s) was used on the Solidity side.

MIGRATION_NOTES = """
Replaced RSA.encrypt with ML-KEM encapsulation.
Replaced ECDSA.verify with ML-DSA verification.
Dropped the Diffie-Hellman key exchange entirely.
"""


def describe_migration():
    """Return human-readable migration notes. Performs no cryptography."""
    return MIGRATION_NOTES
