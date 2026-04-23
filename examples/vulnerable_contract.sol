// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableContract
 * @dev Example contract with quantum-vulnerable cryptography
 * USE FOR TESTING ONLY - Contains intentional vulnerabilities
 */
contract VulnerableContract {
    
    mapping(address => uint256) public balances;
    address public owner;
    
    // Uses ECDSA for signature verification (QUANTUM VULNERABLE)
    event SignatureVerified(address indexed signer, bytes32 messageHash);
    
    constructor() {
        owner = msg.sender;
        balances[msg.sender] = 1000000;
    }
    
    /**
     * @dev Verify ECDSA signature (VULNERABLE to quantum attacks)
     */
    function verifySignature(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        // ecrecover uses ECDSA - vulnerable to Shor's algorithm
        return ecrecover(messageHash, v, r, s);
    }
    
    /**
     * @dev Transfer tokens with signature authorization
     * VULNERABILITY: ECDSA signature can be broken by quantum computers
     */
    function transferWithSignature(
        address to,
        uint256 amount,
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        address signer = verifySignature(messageHash, v, r, s);
        require(balances[signer] >= amount, "Insufficient balance");
        
        balances[signer] -= amount;
        balances[to] += amount;
        
        emit SignatureVerified(signer, messageHash);
    }
    
    /**
     * @dev Simple hash function (may need larger output for quantum resistance)
     */
    function hashData(string memory data) public pure returns (bytes32) {
        // keccak256 (SHA-3 variant) - consider SHA-512 for quantum resistance
        return keccak256(abi.encodePacked(data));
    }
    
    /**
     * @dev Weak authentication mechanism
     */
    function authenticate(address user, bytes memory signature) public pure returns (bool) {
        // Relies on ECDSA signature verification
        bytes32 hash = keccak256(abi.encodePacked(user));
        // Vulnerable signature verification logic
        return signature.length == 65; // Simplified for example
    }
    
    /**
     * @dev Get balance
     */
    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }
}
