
import re
import os
import json

os.system("")  # Enable ANSI
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

def analyze_dynamic_logs(log_path):
    print(f"{Colors.BLUE}{Colors.BOLD}--------------------------------------------------{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}[*] Starting Dynamic Memory & Log Analysis...{Colors.END}")
    print(f"{Colors.BLUE}[*] Tracing timeline from log file: {log_path}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}--------------------------------------------------{Colors.END}\n")

    if not os.path.exists(log_path):
        print(f"[-] Error: Log file {log_path} not found.")
        return

    # Regular expressions to find suspicious log events
    installation_pattern = re.compile(r'PackageManager: START.*dat=file://(.*\.apk).*')
    permission_pattern = re.compile(r'Requested permission (android\.permission\.[A-Z_]+) granted=true')
    network_pattern = re.compile(r'Connecting to C2 Server (.*)')
    exfil_pattern = re.compile(r'Uploading (.*) payload to C2')

    suspicious_events = []
    raw_findings = []
    threat_score = 0

    with open(log_path, 'r') as file:
        logs = file.readlines()

    for line in logs:
        # Check for installation vectors
        if "PackageManager: START" in line:
            match = installation_pattern.search(line)
            if match:
                payload_path = match.group(1)
                suspicious_events.append(f"{Colors.RED}{Colors.BOLD}[!] INFECTION VECTOR:{Colors.END} Malicious Execution detected from {payload_path}")
                raw_findings.append(f"Infection Vector: {payload_path}")
                threat_score += 10
                
        # Check for dangerous permissions being granted dynamically
        if "granted=true" in line:
             match = permission_pattern.search(line)
             if match:
                 perm = match.group(1)
                 if "CONTACTS" in perm or "SMS" in perm:
                      suspicious_events.append(f"{Colors.YELLOW}[!] PERMISSION AUDIT FAIL:{Colors.END} Critical permission {perm} was dynamically granted.")
                      raw_findings.append(f"Dangerous Permission Granted: {perm}")
                      threat_score += 10

        # Check for Database access
        if "Opening database" in line and "stolen_data" in line:
             suspicious_events.append(f"{Colors.YELLOW}[!] I/O MEMORY ALERT:{Colors.END} Malware is writing to local stash -> stolen_data.db")
             raw_findings.append("Suspicious DB Write: stolen_data.db")
             threat_score += 10

        # Check for Network Activity
        if "Connecting to C2" in line:
             match = network_pattern.search(line)
             if match:
                 ip = match.group(1)
                 suspicious_events.append(f"{Colors.RED}{Colors.BOLD}[!!!] NETWORK EXFILTRATION:{Colors.END} Traffic destined for known C2 IP address {Colors.BOLD}{ip}{Colors.END} detected!")
                 raw_findings.append(f"C2 Connection: {ip}")
                 threat_score += 30
                 
        if "Uploading" in line and "payload" in line:
             match = exfil_pattern.search(line)
             if match:
                 data = match.group(1)
                 suspicious_events.append(f"{Colors.RED}{Colors.BOLD}[!!!] DATA COMPROMISE CONFIRMED:{Colors.END} Exfiltration payload of {data} sent over network.")
                 raw_findings.append(f"Data Exfiltrated: {data}")
                 threat_score += 30

    # Report Findings
    if suspicious_events:
        print(f"{Colors.BLUE}{Colors.BOLD}[+] FORENSIC TIMELINE EVENTS:{Colors.END}")
        for event in suspicious_events:
            print(f"    {event}")
    else:
        print("[-] No suspicious events found in the logs.")
        
    print(f"\n{Colors.BLUE}{Colors.BOLD}[*] Dynamic Analysis Complete. Total Threat Score: {threat_score}{Colors.END}")

    os.makedirs(os.path.dirname(log_path).replace("logs", "reports"), exist_ok=True)
    with open(os.path.dirname(log_path).replace("logs", "reports") + "/dynamic_analysis.json", "w") as f:
        json.dump({"threat_score": threat_score, "findings": list(set(raw_findings))}, f, indent=4)

if __name__ == "__main__":
    analyze_dynamic_logs("Simulated_Device/logs/logcat_dump.txt")
