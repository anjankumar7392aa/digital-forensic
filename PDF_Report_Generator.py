import json
import os
import datetime
from fpdf import FPDF

class ForensicReport(FPDF):
    def header(self):
        # Header - Formal & Court-Admissible
        self.set_font('Arial', 'B', 16)
        self.set_text_color(180, 0, 0) # Dark red for confidentiality
        self.cell(0, 10, 'CONFIDENTIAL - EXPERT WITNESS REPORT', 0, 1, 'C')
        self.set_text_color(0, 0, 0)
        
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'DIGITAL FORENSICS INVESTIGATION', 0, 1, 'C')
        
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Subject: Advanced Malware Analysis & Incident Response', 0, 1, 'C')
        self.ln(10)
        
        # Draw a horizontal line under the header
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, 'This document contains sensitive investigative data. Unauthorized distribution is prohibited.', 0, 0, 'L')
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'R')
        self.set_text_color(0, 0, 0)

def generate_pdf_report():
    print("[*] Generating Formal Court-Admissible PDF Forensic Report...")
    
    # Load JSON data
    reports_dir = "Simulated_Device/reports"
    
    static_data = {}
    dynamic_data = {}
    network_data = {}
    
    if os.path.exists(os.path.join(reports_dir, "static_analysis.json")):
        with open(os.path.join(reports_dir, "static_analysis.json")) as f:
            static_data = json.load(f)
            
    if os.path.exists(os.path.join(reports_dir, "dynamic_analysis.json")):
        with open(os.path.join(reports_dir, "dynamic_analysis.json")) as f:
            dynamic_data = json.load(f)
            
    if os.path.exists(os.path.join(reports_dir, "network_analysis.json")):
        with open(os.path.join(reports_dir, "network_analysis.json")) as f:
            network_data = json.load(f)

    # Calculate Totals
    total_score = static_data.get("threat_score", 0) + dynamic_data.get("threat_score", 0) + network_data.get("score_contribution", 0)
    confidence = min(100, (total_score / 150) * 100)

    pdf = ForensicReport()
    pdf.add_page()
    
    # --- 1. Case Details ---
    pdf.set_font('Arial', 'B', 12)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(0, 8, ' 1. CASE DETAILS', 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font('Arial', '', 11)
    pdf.cell(50, 6, 'Date of Examination:', 0, 0)
    pdf.cell(0, 6, '2026-04-16 10:00:00 (Project Start Date)', 0, 1)
    pdf.cell(50, 6, 'Report Generated:', 0, 0)
    pdf.cell(0, 6, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0, 1)
    pdf.cell(50, 6, 'Lead Investigator:', 0, 0)
    pdf.cell(0, 6, 'Lead Forensic Analyst (Your Name)', 0, 1)
    pdf.cell(50, 6, 'Case Reference Number:', 0, 0)
    pdf.cell(0, 6, 'IR-2026-04A-SYSUPDATE', 0, 1)
    pdf.ln(5)

    # --- 2. Declaration of Accuracy ---
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, ' 2. DECLARATION OF ACCURACY', 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font('Arial', '', 11)
    declaration_text = (
        "I declare that the findings contained within this report are accurate, objective, and derived "
        "using industry-standard digital forensic methodologies. The evidence was preserved in a secure "
        "simulated environment to maintain the chain of custody."
    )
    pdf.multi_cell(0, 6, declaration_text)
    pdf.ln(5)

    # --- 3. Evidence Chain of Custody ---
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, ' 3. EVIDENCE LOG & CHAIN OF CUSTODY', 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font('Arial', '', 11)
    pdf.cell(40, 6, 'Target File:', 0, 0)
    pdf.cell(0, 6, 'System_Update_v2.apk', 0, 1)
    pdf.cell(40, 6, 'Original Location:', 0, 0)
    pdf.cell(0, 6, '/sdcard/Download/', 0, 1)
    pdf.cell(40, 6, 'SHA-256 Hash:', 0, 0)
    pdf.set_font('Courier', '', 10)
    pdf.cell(0, 6, '6c899d0626d26751568d95ea5ed87421fd51a0eec2591ceb5651582f1389d2fd', 0, 1)
    pdf.ln(5)

    # --- 4. Official Findings ---
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, ' 4. FORENSIC EXAMINATION FINDINGS', 0, 1, 'L', fill=True)
    pdf.ln(2)

    # Static Section
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 6, 'A. Static Code & Artifact Analysis:', 0, 1)
    pdf.set_font('Arial', '', 11)
    for finding in static_data.get("findings", []):
        clean_finding = finding.replace('', '')
        pdf.cell(0, 6, f"- {clean_finding}", 0, 1)
    pdf.ln(3)

    # Dynamic Section
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 6, 'B. Dynamic Behavioral Analysis (Logcat):', 0, 1)
    pdf.set_font('Arial', '', 11)
    for finding in dynamic_data.get("findings", []):
        clean_finding = finding.replace('', '')
        pdf.cell(0, 6, f"- {clean_finding}", 0, 1)
    pdf.ln(3)

    # Network Section
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 6, 'C. Network Traffic Analysis (PCAP Simulation):', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 6, f"- Confirmed Data Exfiltration Volume: {network_data.get('bytes_exfiltrated', 0)} bytes", 0, 1)
    for finding in network_data.get("findings", []):
        clean_finding = finding.replace('', '')
        pdf.cell(0, 6, f"- {clean_finding}", 0, 1)
    pdf.ln(5)

    # --- 5. Official Conclusion ---
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, ' 5. OFFICIAL CONCLUSION', 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font('Arial', '', 11)
    conclusion_text = (
        f"Based on the cumulative evidence gathered across static, dynamic, and network analyses, "
        f"the Heuristic Threat Scoring algorithm calculated a total threat score of {total_score}. "
        f"This yields a Malicious Confidence Level of {confidence:.1f}%. "
        f"Therefore, it is my professional conclusion that the target artifact is highly malicious "
        f"Trojan Spyware."
    )
    pdf.multi_cell(0, 6, conclusion_text)
    pdf.ln(15)

    # --- 6. Sign-off ---
    pdf.cell(80, 0, '', 'T', 1) # Draws a line
    pdf.ln(2)
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 6, 'Investigator Signature', 0, 1)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, 'Lead Forensic Analyst', 0, 1)
    
    # Output File
    pdf.output('Forensic_Report_Automated.pdf')
    print("[+] Formal Court-Admissible PDF Report successfully created: Forensic_Report_Automated.pdf")

if __name__ == "__main__":
    generate_pdf_report()
