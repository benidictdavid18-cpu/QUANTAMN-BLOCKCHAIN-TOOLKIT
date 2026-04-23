# User Guide - Quantum-Resistant Blockchain Security Toolkit

## Overview

This toolkit helps Indian companies, especially in Rajasthan's key sectors (Manufacturing, Pharmaceutical, Healthcare, Banking), to assess and migrate their blockchain and smart contract code from quantum-vulnerable cryptography to post-quantum algorithms.

## Getting Started

### 1. Access the Application

Open your web browser and navigate to the application URL (local: `http://localhost:8080`)

### 2. Prepare Your Code

Gather your blockchain or smart contract code files:
- Solidity contracts (.sol)
- Python blockchain code (.py)
- JavaScript smart contracts (.js)
- Go blockchain implementations (.go)

### 3. Scan Your Code

#### Step-by-Step:

1. **Enter Company Information**
   - Company Name: Your organization's legal name
   - Sector: Select from Manufacturing, Pharmaceutical, Healthcare, or Banking
   - Contact Email: Email for receiving reports and updates

2. **Upload Code File**
   - Click the upload area or drag-and-drop your file
   - Supported formats: .sol, .py, .js, .go
   - Maximum file size: 10MB

3. **Start Scan**
   - Click "Scan for Vulnerabilities"
   - Wait for analysis to complete (typically 10-30 seconds)

### 4. Review Results

The scan results will show:

#### Risk Score (0-100)
- **0-29**: LOW RISK - Minimal quantum vulnerabilities
- **30-69**: MEDIUM RISK - Some vulnerable algorithms detected
- **70-100**: HIGH RISK - Critical quantum vulnerabilities

#### Detected Vulnerabilities
- Algorithm type (ECDSA, RSA, etc.)
- Severity level
- Line numbers in your code
- Description of the vulnerability

#### Migration Plan
- Recommended post-quantum algorithms
- NIST standards compliance
- Implementation timeline
- Complexity assessment

### 5. Take Action

#### Option A: Apply Migration
- Click "Apply Migration" to generate quantum-safe code
- Review the migrated code
- Download for implementation

#### Option B: Store Proof on Blockchain
- Click "Store on Blockchain" to create tamper-proof audit trail
- Receive transaction hash and block number
- Use for regulatory compliance verification

#### Option C: Generate Compliance Report
- Click "Generate Report"
- Select report type:
  - **RBI**: For Reserve Bank of India compliance
  - **CERT-In**: For Indian CERT compliance
  - **Insurance**: For cyber insurance providers
  - **General**: Standard security assessment
- Download professional PDF report

### 6. Obtain Quantum-Safe Badge

For companies with LOW risk scores (<30):
- Request a quantum-safe certification badge
- Receive verifiable digital certificate
- Present to regulators, auditors, and insurance providers

## Understanding the Results

### Common Vulnerabilities

#### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Risk**: HIGH
- **Quantum Threat**: Shor's algorithm
- **Replacement**: ML-DSA (Dilithium)
- **Found in**: Ethereum smart contracts, Web3 applications

#### RSA Encryption
- **Risk**: HIGH
- **Quantum Threat**: Shor's algorithm
- **Replacement**: ML-KEM (Kyber)
- **Found in**: Key exchange, data encryption

#### SHA-256 Hashing
- **Risk**: MEDIUM
- **Quantum Threat**: Grover's algorithm
- **Replacement**: SHA-512 or SHA-384
- **Found in**: Block hashing, Merkle trees

#### Diffie-Hellman Key Exchange
- **Risk**: HIGH
- **Quantum Threat**: Shor's algorithm
- **Replacement**: ML-KEM (Kyber)
- **Found in**: Secure communication protocols

### Post-Quantum Algorithms

#### ML-DSA (Dilithium) - FIPS 204
- **Purpose**: Digital signatures
- **Replaces**: ECDSA, DSA
- **Key Size**: 2048-4096 bits
- **Performance**: Fast signing and verification

#### ML-KEM (Kyber) - FIPS 203
- **Purpose**: Key encapsulation/encryption
- **Replaces**: RSA, Diffie-Hellman
- **Key Size**: Variable (512-1024 security level)
- **Performance**: Efficient key generation

#### SLH-DSA (SPHINCS+) - FIPS 205
- **Purpose**: Stateless signatures (backup)
- **Replaces**: ECDSA, RSA signatures
- **Key Size**: Larger than ML-DSA
- **Performance**: Slower but more conservative

## Sector-Specific Compliance

### Manufacturing
- Supply chain integrity
- IoT device security
- Product authenticity tracking
- **Key Regulation**: ISO 27001

### Pharmaceutical
- Drug traceability
- Clinical trial data protection
- Anti-counterfeiting measures
- **Key Regulation**: FDA 21 CFR Part 11, CDSCO

### Healthcare
- Patient data privacy
- Electronic health records
- Medical device security
- **Key Regulation**: DISHA, ABDM guidelines

### Banking & Finance
- Transaction security
- Digital identity management
- Payment system integrity
- **Key Regulation**: RBI Master Directions, PCI DSS

## Best Practices

### 1. Migration Strategy
- **Phase 1**: Hybrid approach (classical + post-quantum)
- **Phase 2**: Gradual rollout of PQ algorithms
- **Phase 3**: Complete migration
- **Phase 4**: Continuous monitoring

### 2. Testing
- Test migrated code thoroughly
- Conduct security audits
- Verify compliance with standards
- Monitor performance impacts

### 3. Documentation
- Keep audit trails of all changes
- Store blockchain proofs
- Maintain compliance reports
- Document key management procedures

### 4. Timeline Planning
- LOW complexity: 1-2 weeks
- MEDIUM complexity: 2-4 weeks
- HIGH complexity: 4-8 weeks

## Frequently Asked Questions

### Q: Why do I need to migrate to post-quantum cryptography?
A: Quantum computers capable of breaking current cryptography (ECDSA, RSA) are projected to emerge within 10-15 years. Organizations must begin migration now to ensure long-term security.

### Q: Is the blockchain proof legally valid?
A: Yes, blockchain records provide tamper-proof audit trails that can be verified by regulators and auditors.

### Q: Can I use this for production systems?
A: This toolkit provides assessment and recommendations. Always conduct thorough security audits before deploying to production.

### Q: What if my risk score is HIGH?
A: A high risk score indicates critical vulnerabilities. We recommend immediate migration planning and consultation with security experts.

### Q: Are post-quantum algorithms standardized?
A: Yes, NIST has standardized ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).

### Q: How much does blockchain storage cost?
A: Storing proofs on Polygon Mumbai testnet is free. Production deployment on Polygon mainnet costs minimal gas fees (typically <$0.01).

## Support and Resources

### Technical Support
- Email: support@quantum-toolkit.example.com
- Documentation: https://docs.quantum-toolkit.example.com

### Learning Resources
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- Open Quantum Safe: https://openquantumsafe.org/
- RBI Cybersecurity Framework: https://www.rbi.org.in

### Regulatory Contacts
- **RBI**: For banking sector queries
- **CERT-In**: For cybersecurity incident reporting
- **Ministry of Electronics and IT**: For IT regulations

## Glossary

- **ECDSA**: Elliptic Curve Digital Signature Algorithm
- **ML-DSA**: Module-Lattice-Based Digital Signature Algorithm (Dilithium)
- **ML-KEM**: Module-Lattice-Based Key Encapsulation Mechanism (Kyber)
- **NIST**: National Institute of Standards and Technology
- **PQC**: Post-Quantum Cryptography
- **Shor's Algorithm**: Quantum algorithm that breaks RSA and ECDSA
- **Grover's Algorithm**: Quantum algorithm that weakens symmetric encryption
- **CRQC**: Cryptographically Relevant Quantum Computer

## Next Steps

1. Scan your blockchain code
2. Review migration recommendations
3. Generate compliance report
4. Store proof on blockchain
5. Implement migration plan
6. Obtain quantum-safe certification

For detailed technical documentation, see `TECHNICAL_DOCS.md`
