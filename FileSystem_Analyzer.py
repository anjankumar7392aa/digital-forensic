import os
import sqlite3
import xml.etree.ElementTree as ET
import hashlib
import base64
import json

# ANSI Color Codes for Terminal Aesthetics
os.system("")  # Enables ANSI colors on Windows
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file for evidence integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def analyze_filesystem(base_dir):
    print(f"{Colors.BLUE}{Colors.BOLD}--------------------------------------------------{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Starting Static File System Analysis...{Colors.END}")
    print(f"{Colors.BLUE}[*] Analyzing image path: {base_dir}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}--------------------------------------------------{Colors.END}\n")

    threat_score = 0
    findings = []

    # 1. Look for downloaded payloads
    download_dir = os.path.join(base_dir, "sdcard", "Download")
    print(f"{Colors.YELLOW}[+] Scanning Downloads directory for potential payloads...{Colors.END}")
    if os.path.exists(download_dir):
        files = os.listdir(download_dir)
        for f in files:
            if f.endswith('.apk'):
                apk_path = os.path.join(download_dir, f)
                file_hash = calculate_sha256(apk_path)
                print(f"    {Colors.RED}{Colors.BOLD}[!!!] SUSPICIOUS: Found downloaded APK:{Colors.END} {f}")
                print(f"        {Colors.GREEN}[*] SHA-256 Hash: {file_hash}{Colors.END}")
                threat_score += 10
                findings.append(f"Suspicious APK in Downloads: {f}")
    else:
        print("    [-] Download directory not found.")
        
    print(f"\n{Colors.YELLOW}[+] Scanning Installed Applications (/data/app/)...{Colors.END}")
    app_dir = os.path.join(base_dir, "data", "app")
    suspicious_packages = []
    if os.path.exists(app_dir):
        packages = os.listdir(app_dir)
        for pkg in packages:
            print(f"    [-] Found installed package folder: {pkg}")
            if "sysupdate" in pkg:
                print(f"    {Colors.RED}{Colors.BOLD}[!!!] MALICIOUS PACKAGE IDENTIFIED:{Colors.END} {pkg}")
                suspicious_packages.append(pkg)
                threat_score += 20
                findings.append(f"Malicious Package Installed: {pkg}")
                
                # Hash the base.apk
                base_apk_path = os.path.join(app_dir, pkg, "base.apk")
                if os.path.exists(base_apk_path):
                    apk_hash = calculate_sha256(base_apk_path)
                    print(f"        {Colors.GREEN}[*] Installed Binary SHA-256: {apk_hash}{Colors.END}")

                # Try to parse the Manifest
                manifest_path = os.path.join(app_dir, pkg, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    print(f"        {Colors.BLUE}[*] Forensic parsing of AndroidManifest.xml...{Colors.END}")
                    try:
                        tree = ET.parse(manifest_path)
                        root = tree.getroot()
                        permissions = [elem.attrib.get('{http://schemas.android.com/apk/res/android}name') 
                                       for elem in root.findall('uses-permission')]
                        print(f"        {Colors.YELLOW}[*] Requested Permissions:{Colors.END}")
                        dangerous = ["READ_CONTACTS", "SEND_SMS", "READ_SMS", "RECORD_AUDIO"]
                        for perm in permissions:
                            perm_name = perm.split('.')[-1] if perm else "UNKNOWN"
                            if perm_name in dangerous:
                                print(f"            {Colors.RED}{Colors.BOLD}[!!!] DANGEROUS PERMISSION DETECTED: {perm_name}{Colors.END}")
                                threat_score += 10
                                findings.append(f"Dangerous Permission: {perm_name}")
                            else:
                                print(f"            {Colors.GREEN}[-] {perm_name}{Colors.END}")
                    except Exception as e:
                         print(f"        [!] Error parsing manifest: {e}")
                
    # 2. Analyze App Data & Databases
    print(f"\n{Colors.YELLOW}[+] Scanning Application Datastores for Exfiltration Proof...{Colors.END}")
    for pkg in suspicious_packages:
        base_pkg_name = pkg.split('-')[0]
        db_path = os.path.join(base_dir, "data", "data", base_pkg_name, "databases", "stolen_data.db")
        if os.path.exists(db_path):
            print(f"    {Colors.RED}{Colors.BOLD}[!!!] Found unauthorized database activity at:{Colors.END} {db_path}")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                for table_name in tables:
                    table = table_name[0]
                    if table != "sqlite_sequence":
                        print(f"        {Colors.BLUE}[*] Reverse-engineering table '{table}' for obfuscated data...{Colors.END}")
                        cursor.execute(f"SELECT * FROM {table}")
                        rows = cursor.fetchall()
                        for row in rows:
                             try:
                                 # De-obfuscate the Base64 data
                                 dec_name = base64.b64decode(row[1]).decode('utf-8')
                                 dec_phone = base64.b64decode(row[2]).decode('utf-8')
                                 timestamp = row[3]
                                 print(f"            {Colors.GREEN}-> [BASE64 DECODED]{Colors.END} Stolen Victim: {Colors.BOLD}{dec_name}{Colors.END} ({dec_phone}) at {timestamp}")
                                 threat_score += 15 # +15 for each stolen item found
                             except Exception as decode_err:
                                 # Fallback if it's not base64
                                 print(f"            -> Stolen Record (Raw): {row}")
                conn.close()
            except Exception as e:
                print(f"    [!] Database error: {e}")
        else:
             print("    [-] No suspicious database files found.")
             
    print(f"\n{Colors.BLUE}{Colors.BOLD}[*] Static Analysis Complete. Total Threat Score: {threat_score}{Colors.END}")

    os.makedirs(os.path.join(base_dir, "reports"), exist_ok=True)
    with open(os.path.join(base_dir, "reports", "static_analysis.json"), "w") as f:
        json.dump({"threat_score": threat_score, "findings": list(set(findings))}, f, indent=4)

if __name__ == "__main__":
    analyze_filesystem("Simulated_Device")
