// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * POSITIVE CASE: hybrid contract. The ML-DSA path is already present but the
 * legacy ecrecover path is still live, so the classical finding must stand.
 */
contract HybridVerifier {
    bytes32 public mldsaPublicKeyHash;
    mapping(bytes32 => bool) public verifiedOffChain;

    constructor(bytes32 _pkHash) {
        mldsaPublicKeyHash = _pkHash;
    }

    function legacyVerify(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        public
        pure
        returns (address)
    {
        return ecrecover(digest, v, r, s);
    }

    function commitment(bytes memory payload) public pure returns (bytes32) {
        return keccak256(payload);
    }

    function registerDilithiumResult(bytes32 digest) external {
        verifiedOffChain[digest] = true;
    }
}
