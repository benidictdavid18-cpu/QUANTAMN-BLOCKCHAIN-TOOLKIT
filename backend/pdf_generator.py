"""
PDF Compliance Report Generator
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os
from typing import Dict, Any

class ComplianceReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a237e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#283593'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Use existing BodyText or create custom one with different name
        if 'CustomBodyText' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomBodyText',
                parent=self.styles['Normal'],
                fontSize=11,
                alignment=TA_JUSTIFY,
                spaceAfter=10
            ))
        # Use BodyText alias for backward compatibility
        if 'BodyText' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='BodyText',
                parent=self.styles['Normal'],
                fontSize=11,
                alignment=TA_JUSTIFY,
                spaceAfter=10
            ))
    
    def generate_report(self, scan_data: Dict[str, Any], report_type: str, output_dir: str) -> str:
        """
        Generate PDF compliance report
        
        Args:
            scan_data: Scan results and metadata
            report_type: Type of report (RBI, CERT-In, Insurance, General)
            output_dir: Output directory for PDF
        
        Returns:
            Path to generated PDF
        """
        os.makedirs(output_dir, exist_ok=True)
        
        scan_id = scan_data["scan_id"]
        pdf_path = f"{output_dir}/quantum_security_report_{scan_id}_{report_type}.pdf"
        
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        story = []
        
        # Title Page
        story.extend(self._create_title_page(scan_data, report_type))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Vulnerability Analysis
        story.extend(self._create_vulnerability_section(scan_data))
        story.append(PageBreak())
        
        # Migration Recommendations
        story.extend(self._create_migration_section(scan_data))
        story.append(PageBreak())
        
        # Blockchain Proof
        if "blockchain" in scan_data:
            story.extend(self._create_blockchain_section(scan_data))
            story.append(PageBreak())
        
        # Compliance Section (specific to report type)
        story.extend(self._create_compliance_section(scan_data, report_type))
        story.append(PageBreak())
        
        # Appendix
        story.extend(self._create_appendix(scan_data))
        
        # Build PDF
        doc.build(story)
        
        return pdf_path
    
    def _create_title_page(self, scan_data: Dict, report_type: str) -> list:
        """Create title page"""
        elements = []
        
        # Title
        title = Paragraph(
            "Quantum-Resistant Blockchain<br/>Security Assessment Report",
            self.styles['CustomTitle']
        )
        elements.append(Spacer(1, 1*inch))
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Company Info
        company_info = f"""
        <b>Company:</b> {scan_data.get('company_name', 'N/A')}<br/>
        <b>Sector:</b> {scan_data.get('sector', 'N/A')}<br/>
        <b>Report Type:</b> {report_type}<br/>
        <b>Assessment Date:</b> {datetime.fromisoformat(scan_data['timestamp']).strftime('%B %d, %Y')}<br/>
        <b>Report ID:</b> {scan_data['scan_id'][:16]}
        """
        elements.append(Paragraph(company_info, self.styles['BodyText']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Certification Statement
        cert_statement = f"""
        <b>Certification Statement:</b><br/><br/>
        This report certifies that the blockchain and smart contract code submitted by 
        {scan_data.get('company_name', 'the organization')} has been analyzed for quantum 
        computing vulnerabilities in accordance with NIST Post-Quantum Cryptography Standards 
        (FIPS 203, 204, 205) and Indian cybersecurity regulations.
        """
        elements.append(Paragraph(cert_statement, self.styles['BodyText']))
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict) -> list:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        risk_score = scan_data.get('risk_score', 0)
        vuln_count = len(scan_data.get('vulnerabilities', {}).get('vulnerabilities', []))
        
        risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 70 else "HIGH"
        risk_color = colors.green if risk_score < 30 else colors.orange if risk_score < 70 else colors.red
        
        summary_text = f"""
        This assessment evaluated the quantum readiness of blockchain infrastructure submitted 
        by {scan_data.get('company_name', 'the organization')}. The analysis identified 
        <b>{vuln_count}</b> instances of quantum-vulnerable cryptographic algorithms with an 
        overall risk score of <b><font color="{risk_color.hexval()}">{risk_score:.1f}/100</font></b> 
        (Risk Level: <b>{risk_level}</b>).<br/><br/>
        
        <b>Key Findings:</b><br/>
        • Classical cryptographic algorithms detected: {vuln_count}<br/>
        • Primary vulnerabilities: ECDSA, RSA, and insufficient hash functions<br/>
        • Recommended migration to NIST-approved post-quantum algorithms<br/>
        • Estimated migration timeline: {scan_data.get('migration_plan', {}).get('timeline_estimate', 'Not estimated')}<br/><br/>
        
        <b>Quantum Threat Assessment:</b><br/>
        With the advancement of quantum computing, cryptographically relevant quantum computers (CRQCs) 
        are projected to break current public-key cryptography within the next 10-15 years. Organizations 
        must begin transitioning to post-quantum cryptography immediately to ensure long-term security.
        """
        
        elements.append(Paragraph(summary_text, self.styles['BodyText']))
        
        # Risk Score Table
        risk_data = [
            ['Metric', 'Value', 'Status'],
            ['Vulnerabilities Detected', str(vuln_count), 'ATTENTION REQUIRED'],
            ['Risk Score', f'{risk_score:.1f}/100', risk_level],
            ['Quantum Ready', 'No' if vuln_count > 0 else 'Yes', 'MIGRATION NEEDED' if vuln_count > 0 else 'COMPLIANT']
        ]
        
        risk_table = Table(risk_data, colWidths=[2.5*inch, 2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283593')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(Spacer(1, 0.3*inch))
        elements.append(risk_table)
        
        return elements
    
    def _create_vulnerability_section(self, scan_data: Dict) -> list:
        """Create vulnerability analysis section"""
        elements = []
        
        elements.append(Paragraph("Vulnerability Analysis", self.styles['SectionHeader']))
        
        vulnerabilities = scan_data.get('vulnerabilities', {}).get('vulnerabilities', [])
        
        if not vulnerabilities:
            elements.append(Paragraph(
                "No quantum-vulnerable cryptographic algorithms detected. The code appears to be quantum-safe.",
                self.styles['BodyText']
            ))
            return elements
        
        intro_text = """
        The following quantum-vulnerable cryptographic algorithms were identified in the analyzed code. 
        These algorithms are susceptible to attacks by quantum computers using Shor's algorithm 
        (for factoring and discrete logarithm problems) and Grover's algorithm (for symmetric key search).
        """
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Group vulnerabilities by algorithm
        vuln_groups = {}
        for v in vulnerabilities:
            algo = v['algorithm']
            if algo not in vuln_groups:
                vuln_groups[algo] = []
            vuln_groups[algo].append(v)
        
        # Create vulnerability table
        vuln_data = [['Algorithm', 'Severity', 'Occurrences', 'Quantum Threat']]
        
        for algo, vulns in vuln_groups.items():
            severity = vulns[0]['severity']
            count = len(vulns)
            threat = "Shor's Algorithm" if algo in ['ECDSA', 'RSA', 'DH'] else "Grover's Algorithm"
            vuln_data.append([algo, severity, str(count), threat])
        
        vuln_table = Table(vuln_data, colWidths=[1.8*inch, 1.5*inch, 1.5*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffebee')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(vuln_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Detailed findings
        elements.append(Paragraph("<b>Detailed Findings:</b>", self.styles['BodyText']))
        
        for algo, vulns in vuln_groups.items():
            algo_text = f"""
            <b>{algo}</b>: {vulns[0]['description']}<br/>
            • Found in {len(vulns)} location(s)<br/>
            • Severity: {vulns[0]['severity']}<br/>
            • Affected lines: {', '.join([str(v['line_number']) for v in vulns[:5]])}
            {' (and more...)' if len(vulns) > 5 else ''}
            """
            elements.append(Paragraph(algo_text, self.styles['BodyText']))
        
        return elements
    
    def _create_migration_section(self, scan_data: Dict) -> list:
        """Create migration recommendations section"""
        elements = []
        
        elements.append(Paragraph("Post-Quantum Migration Plan", self.styles['SectionHeader']))
        
        migration_plan = scan_data.get('migration_plan', {})
        migration_steps = migration_plan.get('migration_steps', [])
        
        intro_text = """
        This section outlines the recommended migration path to post-quantum cryptography based on 
        NIST-approved algorithms (FIPS 203, 204, 205). The migration strategy follows a phased 
        approach to minimize disruption while ensuring quantum resistance.
        """
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Migration Overview Table
        if migration_steps:
            migration_data = [['Algorithm to Replace', 'Post-Quantum Replacement', 'NIST Standard']]
            
            for step in migration_steps:
                migration_data.append([
                    step['algorithm'],
                    step['pq_replacement'],
                    step['nist_standard']
                ])
            
            migration_table = Table(migration_data, colWidths=[2*inch, 2.5*inch, 2*inch])
            migration_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e7d32')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#e8f5e9')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(migration_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Implementation Timeline
        timeline_text = f"""
        <b>Implementation Timeline:</b> {migration_plan.get('timeline_estimate', 'To be determined')}<br/>
        <b>Complexity:</b> {migration_plan.get('estimated_complexity', 'Not assessed')}<br/><br/>
        
        <b>Recommended Approach:</b><br/>
        1. <b>Phase 1 (Immediate):</b> Implement hybrid cryptography combining classical and post-quantum algorithms<br/>
        2. <b>Phase 2 (3-6 months):</b> Full migration to post-quantum algorithms for new deployments<br/>
        3. <b>Phase 3 (6-12 months):</b> Complete replacement of all classical cryptography<br/>
        4. <b>Phase 4 (Ongoing):</b> Continuous monitoring and updates as standards evolve
        """
        elements.append(Paragraph(timeline_text, self.styles['BodyText']))
        
        return elements
    
    def _create_blockchain_section(self, scan_data: Dict) -> list:
        """Create blockchain proof section"""
        elements = []
        
        elements.append(Paragraph("Blockchain Verification", self.styles['SectionHeader']))
        
        blockchain_data = scan_data.get('blockchain', {})
        
        blockchain_text = f"""
        This migration assessment has been permanently recorded on the blockchain to provide 
        tamper-proof verification of the security audit and migration process.<br/><br/>
        
        <b>Blockchain Details:</b><br/>
        • Network: {blockchain_data.get('network', 'N/A')}<br/>
        • Transaction Hash: <font face="Courier">{blockchain_data.get('tx_hash', 'N/A')}</font><br/>
        • Block Number: {blockchain_data.get('block_number', 'N/A')}<br/>
        • Explorer URL: https://mumbai.polygonscan.com/tx/{blockchain_data.get('tx_hash', '')}<br/><br/>
        
        This blockchain record can be independently verified by regulatory authorities, auditors, 
        and insurance providers to confirm the authenticity of this assessment.
        """
        
        elements.append(Paragraph(blockchain_text, self.styles['BodyText']))
        
        return elements
    
    def _create_compliance_section(self, scan_data: Dict, report_type: str) -> list:
        """Create compliance section specific to report type"""
        elements = []
        
        elements.append(Paragraph(f"Regulatory Compliance - {report_type}", self.styles['SectionHeader']))
        
        compliance_templates = {
            "RBI": """
            <b>Reserve Bank of India (RBI) Compliance:</b><br/><br/>
            
            This assessment aligns with RBI's Master Direction on Cyber Security Framework for 
            banks and financial institutions:<br/><br/>
            
            • <b>Cryptographic Controls:</b> Recommendations align with RBI guidelines on strong 
            cryptography for protecting sensitive financial data<br/>
            • <b>Future-Proofing:</b> Post-quantum migration ensures long-term security of 
            digital banking infrastructure<br/>
            • <b>Risk Management:</b> Quantum threat assessment included in overall cyber risk 
            management framework<br/>
            • <b>Third-Party Risk:</b> Blockchain verification provides audit trail for 
            compliance verification<br/><br/>
            
            <b>Relevant RBI Circulars:</b><br/>
            • Master Direction on Cyber Security Framework (DPSS.CO.OD No.617/06.08.005/2016-17)<br/>
            • Guidelines on Managing Risks and Code of Conduct in Outsourcing of Financial Services<br/>
            • Cyber Security Framework for Primary Dealers
            """,
            
            "CERT-In": """
            <b>CERT-In (Indian Computer Emergency Response Team) Compliance:</b><br/><br/>
            
            This assessment supports CERT-In's mandate for strengthening cybersecurity infrastructure:<br/><br/>
            
            • <b>Vulnerability Management:</b> Systematic identification and remediation of 
            quantum-vulnerable cryptography<br/>
            • <b>Information Security Best Practices:</b> Alignment with CERT-In guidelines on 
            cryptographic standards<br/>
            • <b>Incident Prevention:</b> Proactive migration reduces risk of future quantum-based attacks<br/>
            • <b>Reporting Compliance:</b> Documentation suitable for CERT-In vulnerability reporting<br/><br/>
            
            <b>Relevant CERT-In Guidelines:</b><br/>
            • Guidelines for Chief Information Security Officers<br/>
            • Information Security Practices<br/>
            • Cryptographic Controls and Key Management
            """,
            
            "Insurance": """
            <b>Cyber Insurance Compliance:</b><br/><br/>
            
            This assessment provides documentation required for cyber insurance underwriting and claims:<br/><br/>
            
            • <b>Risk Assessment:</b> Comprehensive quantum threat evaluation with quantified risk scores<br/>
            • <b>Security Controls:</b> Evidence of proactive security measures and migration planning<br/>
            • <b>Compliance Documentation:</b> Regulatory-grade reporting for insurance verification<br/>
            • <b>Audit Trail:</b> Blockchain-verified proof of security improvements<br/><br/>
            
            <b>Insurance Considerations:</b><br/>
            • Reduced premiums for quantum-safe infrastructure<br/>
            • Enhanced coverage for forward-thinking security measures<br/>
            • Improved claims position in event of quantum-related incidents
            """,
            
            "General": """
            <b>General Cybersecurity Compliance:</b><br/><br/>
            
            This assessment supports compliance with multiple cybersecurity standards and frameworks:<br/><br/>
            
            • <b>ISO 27001:</b> Information security management system requirements<br/>
            • <b>NIST Cybersecurity Framework:</b> Cryptographic standards and post-quantum readiness<br/>
            • <b>SOC 2:</b> Security controls for service organizations<br/>
            • <b>GDPR/Data Protection:</b> Strong cryptography for personal data protection<br/><br/>
            
            <b>Industry Standards:</b><br/>
            • NIST FIPS 203 (ML-KEM/Kyber)<br/>
            • NIST FIPS 204 (ML-DSA/Dilithium)<br/>
            • NIST FIPS 205 (SLH-DSA/SPHINCS+)
            """
        }
        
        compliance_content = compliance_templates.get(report_type, compliance_templates["General"])
        elements.append(Paragraph(compliance_content, self.styles['BodyText']))
        
        return elements
    
    def _create_appendix(self, scan_data: Dict) -> list:
        """Create appendix section"""
        elements = []
        
        elements.append(Paragraph("Appendix", self.styles['SectionHeader']))
        
        appendix_text = """
        <b>A. Post-Quantum Cryptography Standards</b><br/><br/>
        
        <b>NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM):</b><br/>
        Formerly known as CRYSTALS-Kyber. Standardized for key encapsulation and encryption.<br/><br/>
        
        <b>NIST FIPS 204 - Module-Lattice-Based Digital Signature Algorithm (ML-DSA):</b><br/>
        Formerly known as CRYSTALS-Dilithium. Standardized for digital signatures.<br/><br/>
        
        <b>NIST FIPS 205 - Stateless Hash-Based Digital Signature Algorithm (SLH-DSA):</b><br/>
        Formerly known as SPHINCS+. Backup standard for digital signatures.<br/><br/>
        
        <b>B. Quantum Threat Timeline</b><br/><br/>
        
        • 2020s: Development of NISQ (Noisy Intermediate-Scale Quantum) computers<br/>
        • 2030s: Projected emergence of cryptographically relevant quantum computers (CRQCs)<br/>
        • Current Risk: "Harvest now, decrypt later" attacks on encrypted data<br/><br/>
        
        <b>C. Migration Resources</b><br/><br/>
        
        • Open Quantum Safe (OQS) Project: https://openquantumsafe.org/<br/>
        • NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography<br/>
        • liboqs-python: Python library for post-quantum cryptography<br/><br/>
        
        <b>D. Contact Information</b><br/><br/>
        
        For questions regarding this assessment, please contact:<br/>
        Email: {}<br/>
        Assessment ID: {}<br/>
        Generated: {}
        """.format(
            scan_data.get('contact_email', 'N/A'),
            scan_data.get('scan_id', 'N/A')[:16],
            datetime.now().strftime('%B %d, %Y at %H:%M')
        )
        
        elements.append(Paragraph(appendix_text, self.styles['BodyText']))
        
        return elements
