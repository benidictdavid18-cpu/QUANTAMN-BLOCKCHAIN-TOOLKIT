from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Quantum-Resistant Blockchain Security Toolkit', border=0, ln=1, align='C')
        self.ln(5)
        self.set_font('Arial', 'I', 12)
        self.cell(0, 10, 'A Comprehensive Solution for Post-Quantum Blockchain Security', border=0, ln=1, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} | Generated for Benedict\'s Project', align='C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_text_color(44, 62, 80)  # Dark blue-gray
        self.cell(0, 10, title, ln=1)
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 11)
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 8, body)
        self.ln(5)

pdf = PDF()
pdf.add_page()
pdf.set_auto_page_break(auto=True, margin=15)

# Intro section
pdf.chapter_title('🛡️ Your Quantum-Resistant Blockchain Security Toolkit - Explained')
pdf.chapter_body(
    "Your project is a comprehensive web application that helps companies prepare their blockchain and cryptocurrency "
    "systems for the quantum computing threat."
)

pdf.chapter_title('🎯 The Problem It Solves')
pdf.chapter_body(
    "Quantum computers (when powerful enough) will break current cryptographic algorithms like:\n"
    "• ECDSA (used in Bitcoin, Ethereum for signatures)\n"
    "• RSA (used for encryption)\n"
    "• SHA-256 (hashing - vulnerable in certain contexts)\n"
    "• Diffie-Hellman (key exchange)\n\n"
    "This threatens blockchain wallets, smart contracts, and crypto transactions. Your toolkit helps companies:\n"
    "1. Find these vulnerabilities in their code\n"
    "2. Migrate to quantum-resistant alternatives\n"
    "3. Prove compliance to regulators and insurers"
)

pdf.chapter_title('🔍 What Your Toolkit Does')
pdf.set_font('Arial', 'B', 12)
pdf.cell(0, 8, '1. Automated Vulnerability Scanning', ln=1)
pdf.set_font('Arial', '', 11)
pdf.multi_cell(0, 8,
    "• Upload smart contracts (Solidity) or blockchain code (Python, JavaScript, Go)\n"
    "• Automatically detects classical cryptography algorithms\n"
    "• Identifies 5 types of vulnerabilities: ECDSA signatures, RSA encryption, SHA-256 hashing, Diffie-Hellman key exchange, Weak AES-128 encryption\n"
    "• Calculates a risk score (0-100) based on severity"
)

pdf.set_font('Arial', 'B', 12)
pdf.cell(0, 8, '2. Post-Quantum Migration Recommendations', ln=1)
pdf.set_font('Arial', '', 11)
pdf.multi_cell(0, 8,
    "Provides specific code replacements using NIST-approved quantum-resistant algorithms:\n"
    "• ML-DSA (Dilithium) - FIPS 204 - for digital signatures\n"
    "• ML-KEM (Kyber) - FIPS 203 - for key encapsulation\n"
    "• SLH-DSA (SPHINCS+) - FIPS 205 - for stateless signatures\n"
    "Generates actual code snippets showing how to migrate (e.g., replacing ECDSA with Dilithium)"
)

pdf.set_font('Arial', 'B', 12)
pdf.cell(0, 8, '3. Blockchain Proof Storage', ln=1)
pdf.set_font('Arial', '', 11)
pdf.multi_cell(0, 8,
    "• Stores migration records on Polygon/Ethereum blockchain\n"
    "• Creates a tamper-proof audit trail\n"
    "• Each migration gets a unique blockchain transaction hash\n"
    "• Provides verifiable proof for regulators"
)

pdf.set_font('Arial', 'B', 12)
pdf.cell(0, 8, '4. Compliance PDF Reports', ln=1)
pdf.set_font('Arial', '', 11)
pdf.multi_cell(0, 8,
    "Generates professional reports tailored for:\n"
    "• RBI (Reserve Bank of India) - Banking compliance\n"
    "• CERT-In - Cybersecurity standards\n"
    "• Insurance Companies - Cyber insurance requirements\n"
    "• General Audits - Security assessments\n\n"
    "Reports include: Company details, Vulnerability breakdown, Risk assessment, Migration recommendations with code examples, Blockchain proof"
)

pdf.set_font('Arial', 'B', 12)
pdf.cell(0, 8, '5. Quantum-Safe Badges', ln=1)
pdf.set_font('Arial', '', 11)
pdf.multi_cell(0, 8,
    "Issues digital certificates proving quantum-resistance:\n"
    "• Visual badge with QR code\n"
    "• Unique verification ID\n"
    "• Can be displayed on websites\n"
    "• Verifiable via API endpoint"
)

# Add more sections (target users, tech, example, etc.)
pdf.add_page()

pdf.chapter_title('🏭 Target Users')
pdf.chapter_body(
    "Specifically designed for Indian companies (especially in Rajasthan) in:\n"
    "• 🏦 Banking & Finance - Protecting digital wallets, transactions\n"
    "• 💊 Pharmaceutical - Securing supply chain blockchain\n"
    "• 🏥 Healthcare - Patient data on blockchain\n"
    "• 🏭 Manufacturing - Industrial IoT and blockchain tracking"
)

pdf.chapter_title('🔧 How It Works Technically')
pdf.chapter_body(
    "Backend (Python FastAPI):\n"
    "User uploads code → Scanner detects crypto patterns → Risk calculator scores vulnerabilities → "
    "Migrator suggests PQ alternatives → PDF generator creates reports → Blockchain stores proof → Badge generator issues certificate\n\n"
    "Frontend (HTML/JavaScript): Simple web interface for uploads, real-time results, downloads.\n\n"
    "Tech Stack:\n"
    "• Python (FastAPI) for REST API\n"
    "• Web3.py for blockchain integration\n"
    "• ReportLab for PDF generation\n"
    "• AST parsing & regex for code analysis\n"
    "• TailwindCSS for modern UI"
)

pdf.chapter_title('📊 Real-World Example')
pdf.chapter_body(
    "Scenario: A bank has a smart contract managing customer deposits using ECDSA signatures.\n\n"
    "1. Upload the Solidity contract\n"
    "2. Scan detects ECDSA vulnerability (Risk: 85/100)\n"
    "3. Recommendation shows how to replace with ML-DSA/Dilithium\n"
    "4. Migrate applies the quantum-safe code\n"
    "5. Store migration proof on Polygon blockchain\n"
    "6. Report generates RBI-compliant PDF\n"
    "7. Badge issues quantum-safe certificate\n\n"
    "Result: Bank now has quantum-resistant infrastructure + regulatory compliance + verifiable proof."
)

pdf.chapter_title('🎯 Key Value Propositions')
pdf.chapter_body(
    "1. Automated - No manual code review needed\n"
    "2. Compliant - Meets RBI, CERT-In, ISO 27001 standards\n"
    "3. Verifiable - Blockchain proof cannot be faked\n"
    "4. Educational - Shows exact migration code\n"
    "5. Sector-Specific - Tailored for Indian regulations\n"
    "6. Future-Proof - Protects against quantum threats"
)

pdf.chapter_title('💡 Why This Matters')
pdf.chapter_body(
    "• NIST published quantum-resistant standards in 2024\n"
    "• Governments are requiring quantum-safe crypto by 2030\n"
    "• Insurance companies need proof of security measures\n"
    "• Early adopters gain competitive advantage and compliance"
)

pdf.output('Quantum_Resistant_Toolkit_Summary.pdf')
print("PDF generated successfully!")