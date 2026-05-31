import os
import sqlite3
import base64
import hashlib
import json

def calculate_sha256(file_path):
    if not os.path.exists(file_path): return "File not found"
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
         for byte_block in iter(lambda: f.read(4096),b""):
             sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_report():
    base_dir = "Simulated_Device"
    
    # Extract data
    download_apk = os.path.join(base_dir, "sdcard", "Download", "System_Update_v2.apk")
    installed_apk = os.path.join(base_dir, "data", "app", "com.android.sysupdate-1", "base.apk")
    hash_dl = calculate_sha256(download_apk)
    hash_inst = calculate_sha256(installed_apk)

    # Load Reports
    total_score = 0
    static_score = 0
    dynamic_score = 0
    network_score = 0
    network_exfil_bytes = 0
    
    reports_dir = os.path.join(base_dir, "reports")
    try:
        with open(os.path.join(reports_dir, "static_analysis.json")) as f:
            static_score = json.load(f).get("threat_score", 0)
        with open(os.path.join(reports_dir, "dynamic_analysis.json")) as f:
            dynamic_score = json.load(f).get("threat_score", 0)
        with open(os.path.join(reports_dir, "network_analysis.json")) as f:
            net_data = json.load(f)
            network_score = net_data.get("score_contribution", 0)
            network_exfil_bytes = net_data.get("bytes_exfiltrated", 0)
    except:
        pass
    
    total_score = static_score + dynamic_score + network_score
    confidence = min(100, (total_score / 150) * 100) # Normalize to 100%
    confidence_color = "#f38ba8" if confidence > 70 else "#f9e2af"

    # Database
    db_path = os.path.join(base_dir, "data", "data", "com.android.sysupdate", "databases", "stolen_data.db")
    extracted_data_html = ""
    stolen_count = 0
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM contacts")
        rows = cursor.fetchall()
        for row in rows:
            try:
                name = base64.b64decode(row[1]).decode('utf-8')
                phone = base64.b64decode(row[2]).decode('utf-8')
                extracted_data_html += f"<tr><td>{name}</td><td>{phone}</td><td>{row[3]}</td><td>Base64 Decoded</td></tr>"
                stolen_count += 1
            except:
                pass
        conn.close()

    # Timeline from logs
    log_path = os.path.join(base_dir, "logs", "logcat_dump.txt")
    timeline_html = ""
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            for line in log_file:
                # Extract timestamp (e.g., "04-23 10:15:02.123")
                timestamp_match = line[:18] 
                if "PackageManager: START" in line:
                    timeline_html += f"<tr><td>{timestamp_match}</td><td>Payload Execution</td><td>Package Manager started installation of System_Update_v2.apk</td></tr>"
                elif "PackageManager: Action: install_commit" in line:
                     timeline_html += f"<tr><td>{timestamp_match}</td><td>Installation Complete</td><td>Malware successfully installed on device</td></tr>"
                elif "START u0" in line and "com.android.sysupdate/.MainActivity" in line:
                     timeline_html += f"<tr><td>{timestamp_match}</td><td>Process Launch</td><td>Malware process started by user</td></tr>"
                elif "granted=true" in line:
                     if "READ_CONTACTS" in line:
                         timeline_html += f"<tr><td>{timestamp_match}</td><td>Permission Exploit</td><td>Granted READ_CONTACTS permission</td></tr>"
                elif "Connecting to C2" in line:
                     timeline_html += f"<tr><td>{timestamp_match}</td><td style='color:#f38ba8;'>Network Exfil</td><td>Connecting to known C2 server (192.168.1.100)</td></tr>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Forensic Intelligence Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }}
            h1 {{ color: #a6e3a1; text-align: center; border-bottom: 2px solid #313244; padding-bottom: 10px; }}
            .container {{ display: flex; gap: 20px; flex-wrap: wrap; }}
            .card {{ background-color: #181825; border-radius: 10px; padding: 20px; flex: 1; min-width: 300px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-left: 5px solid #89b4fa; }}
            .card.danger {{ border-left: 5px solid #f38ba8; }}
            h2 {{ color: #89b4fa; margin-top: 0; }}
            .danger h2 {{ color: #f38ba8; }}
            code {{ background-color: #313244; padding: 5px; border-radius: 5px; color: #a6e3a1; word-break: break-all; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #313244; }}
            th {{ background-color: #313244; }}
            .badge {{ background-color: #f38ba8; color: #11111b; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
            .score-circle {{ width: 100px; height: 100px; border-radius: 50%; background-color: {confidence_color}; color: #11111b; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; margin: 0 auto; box-shadow: 0 0 20px {confidence_color}; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Threat Intelligence Dashboard</h1>
        <p style="text-align: center; color: #a6e3a1;">Investigation Start Date: 2026-04-16 10:00:00</p>

        <div class="container">
            <div class="card">
                <h2>Threat Signature (Hashes)</h2>
                <p><b>Payload:</b> System_Update_v2.apk</p>
                <p><code>{hash_dl}</code></p>
                <br>
                <p><b>Executing Binary:</b> base.apk</p>
                <p><code>{hash_inst}</code></p>
            </div>

            <div class="card danger" style="max-width: 400px; align-items: center; display:flex; flex-direction: column;">
                <h2>Risk Vector Analysis</h2>
                <canvas id="threatChart"></canvas>
            </div>

            <div class="card danger" style="text-align: center;">
                <h2>Heuristic Threat Score</h2>
                <div class="score-circle">{confidence:.1f}%</div>
                <p>Total Threat Score: <b>{total_score}</b></p>
                <p>Static: {static_score} | Dynamic: {dynamic_score} | Network: {network_score}</p>
                <p><b>Network Exfiltration:</b> {network_exfil_bytes} bytes sent</p>
            </div>
        </div>
        
        <div class="card danger" style="margin-top: 20px;">
            <h2>Execution Timeline (Dynamic Trace)</h2>
            <p>Chronological sequence of the infection based on Android logcat artifacts.</p>
            <table>
                <tr><th>System Time</th><th>Event Type</th><th>Description</th></tr>
                {timeline_html}
            </table>
        </div>

        <div class="card danger" style="margin-top: 20px;">
            <h2>Decrypted Data Exfiltration <span class="badge">Forensic Recovery</span></h2>
            <table>
                <tr><th>Victim Name</th><th>Phone Number</th><th>Time of Theft</th><th>Encryption Defeated</th></tr>
                {extracted_data_html}
            </table>
        </div>

        <script>
            const ctx = document.getElementById('threatChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Safe Operations', 'Network Exfil', 'Permission Abuse', 'Data Theft'],
                    datasets: [{{
                        label: 'Threat Events',
                        data: [1, 2, 4, {stolen_count}],
                        backgroundColor: ['#a6e3a1', '#f9e2af', '#fab387', '#f38ba8'],
                        borderColor: '#181825',
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom', labels: {{ color: '#cdd6f4' }} }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    with open("Investigation_Dashboard.html", "w", encoding='utf-8') as f:
        f.write(html_content)
    
    print("[+] Interactive HTML Report generated successfully: Investigation_Dashboard.html")

if __name__ == "__main__":
    generate_report()
