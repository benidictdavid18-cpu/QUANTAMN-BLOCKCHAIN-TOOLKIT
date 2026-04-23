"""
Quantum-Safe Badge Generator and Verification System
"""
import qrcode
import json
import os
from datetime import datetime
from typing import Dict, Any
from PIL import Image, ImageDraw, ImageFont

class BadgeGenerator:
    def __init__(self):
        self.badge_registry = {}
        self.badges_dir = "badges"
        os.makedirs(self.badges_dir, exist_ok=True)
        self._load_registry()
    
    def _load_registry(self):
        """Load badge registry from file"""
        registry_path = f"{self.badges_dir}/registry.json"
        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                self.badge_registry = json.load(f)
    
    def _save_registry(self):
        """Save badge registry to file"""
        registry_path = f"{self.badges_dir}/registry.json"
        with open(registry_path, "w") as f:
            json.dump(self.badge_registry, f, indent=2)
    
    def generate_badge(
        self,
        scan_id: str,
        company_name: str,
        sector: str,
        blockchain_tx: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """
        Generate quantum-safe verification badge
        
        Returns:
            Dictionary with badge_id, verification_url, qr_code_path, badge_image_path
        """
        badge_id = f"QS-{datetime.now().strftime('%Y%m')}-{scan_id[:8].upper()}"
        verification_url = f"https://quantum-toolkit.verify/badge/{badge_id}"
        
        # Store badge data in registry
        badge_data = {
            "badge_id": badge_id,
            "scan_id": scan_id,
            "company_name": company_name,
            "sector": sector,
            "blockchain_tx": blockchain_tx,
            "issue_date": datetime.now().isoformat(),
            "status": "active",
            "verification_url": verification_url
        }
        
        self.badge_registry[badge_id] = badge_data
        self._save_registry()
        
        # Generate QR code
        qr_code_path = self._generate_qr_code(verification_url, badge_id, output_dir)
        
        # Generate badge image
        badge_image_path = self._generate_badge_image(badge_data, output_dir)
        
        return {
            "badge_id": badge_id,
            "verification_url": verification_url,
            "qr_code_path": qr_code_path,
            "badge_image_path": badge_image_path
        }
    
    def _generate_qr_code(self, url: str, badge_id: str, output_dir: str) -> str:
        """Generate QR code for verification URL"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = f"{output_dir}/qr_{badge_id}.png"
        img.save(qr_path)
        
        return qr_path
    
    def _generate_badge_image(self, badge_data: Dict, output_dir: str) -> str:
        """Generate badge certificate image"""
        # Create image
        width, height = 800, 600
        img = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(img)
        
        # Draw border
        border_color = '#1a237e'
        draw.rectangle([(10, 10), (width-10, height-10)], outline=border_color, width=5)
        
        # Add title
        title = "QUANTUM-SAFE CERTIFICATION"
        
        # Add company name
        company_text = badge_data['company_name']
        
        # Add badge ID
        badge_id_text = f"Certificate ID: {badge_data['badge_id']}"
        
        # Add issue date
        date_text = f"Issued: {datetime.fromisoformat(badge_data['issue_date']).strftime('%B %d, %Y')}"
        
        # Add certification text
        cert_text = "This certifies that the above organization has successfully"
        cert_text2 = "migrated to quantum-resistant cryptography in accordance"
        cert_text3 = "with NIST Post-Quantum Standards (FIPS 203, 204, 205)"
        
        # Simple text rendering (in production, use proper fonts)
        y_position = 100
        draw.text((width//2, y_position), title, fill=border_color, anchor="mm")
        draw.text((width//2, y_position + 80), company_text, fill='black', anchor="mm")
        draw.text((width//2, y_position + 180), cert_text, fill='black', anchor="mm")
        draw.text((width//2, y_position + 210), cert_text2, fill='black', anchor="mm")
        draw.text((width//2, y_position + 240), cert_text3, fill='black', anchor="mm")
        draw.text((width//2, y_position + 320), badge_id_text, fill='gray', anchor="mm")
        draw.text((width//2, y_position + 350), date_text, fill='gray', anchor="mm")
        
        badge_path = f"{output_dir}/badge_{badge_data['badge_id']}.png"
        img.save(badge_path)
        
        return badge_path
    
    def verify_badge(self, badge_id: str) -> Dict[str, Any]:
        """Verify a quantum-safe badge"""
        if badge_id not in self.badge_registry:
            raise ValueError("Badge not found")
        
        badge_data = self.badge_registry[badge_id]
        
        return {
            "valid": True,
            "badge_id": badge_id,
            "company_name": badge_data['company_name'],
            "sector": badge_data['sector'],
            "issue_date": badge_data['issue_date'],
            "status": badge_data['status'],
            "blockchain_tx": badge_data['blockchain_tx']
        }
