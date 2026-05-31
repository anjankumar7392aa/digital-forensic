import csv
import json
import os

KNOWN_MALICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]

def analyze_network_traffic(csv_path):
    print("-" * 50)
    print("[*] Starting Network Traffic (PCAP Simulation) Analysis...")
    print(f"[*] Analyzing flow log: {csv_path}")
    print("-" * 50)
    
    findings = []
    total_bytes_exfiltrated = 0
    threat_score_increase = 0

    if not os.path.exists(csv_path):
        print("[-] Network flow log not found.")
        return findings, threat_score_increase

    print("\n[+] Scanning network flows for suspicious activity...")
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dst_ip = row['Destination IP']
            info = row['Info']
            
            if dst_ip in KNOWN_MALICIOUS_IPS:
                print(f"    [!!!] MALICIOUS CONNECTION DETECTED: Traffic to known C2 IP {dst_ip}")
                print(f"        -> Protocol: {row['Protocol']}, Info: {info}")
                findings.append(f"C2 Connection to {dst_ip} ({info})")
                threat_score_increase += 25
                
                # Check for large payloads
                if "payload" in info.lower() or "post" in info.lower():
                    bytes_transferred = int(row['Bytes'])
                    total_bytes_exfiltrated += bytes_transferred
                    print(f"    [!!!] EXFILTRATION ALERT: Suspected data upload of {bytes_transferred} bytes")
                    findings.append(f"Data Exfiltration: {bytes_transferred} bytes")
                    threat_score_increase += 25

    print(f"\n[*] Network Analysis Complete. Total threat score contribution: +{threat_score_increase}")
    
    # Save findings for the HTML report
    report_data = {
        "findings": findings,
        "bytes_exfiltrated": total_bytes_exfiltrated,
        "score_contribution": threat_score_increase
    }
    
    os.makedirs("Simulated_Device/reports", exist_ok=True)
    with open("Simulated_Device/reports/network_analysis.json", "w") as f:
        json.dump(report_data, f, indent=4)
        
    return findings, threat_score_increase

if __name__ == "__main__":
    analyze_network_traffic("Simulated_Device/logs/network_flow.csv")
