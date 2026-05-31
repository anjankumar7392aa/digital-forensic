# Digital Forensics Investigation: Android Malware Analysis
**Investigator:** (Your Name)
**Date:** 2026-04-24
**Subject:** Advanced Forensic Analysis of Suspicious "System_Update_v2.apk"

---

## 1. Abstract
The rapid proliferation of mobile malware necessitates advanced digital forensics techniques to detect, analyze, and mitigate threats targeting the Android operating system. As smartphones become the primary repository for sensitive personal and corporate data, threat actors have pivoted from traditional desktop environments to exploiting mobile ecosystems. This project presents a comprehensive, simulated forensic investigation of a highly sophisticated Android spyware variant camouflaged as a legitimate system utility (`System_Update_v2.apk`). 

A multi-layered, forensically sound analytical methodology was employed, utilizing a custom-built Python forensic toolchain designed to bypass common anti-analysis techniques. The investigation encompassed deep **Static Analysis** (cryptographic hashing, structural APK dissection, and manifest permission auditing), **Dynamic Log Analysis** (reconstructing the installation timeline and tracking runtime privilege escalation), and **Network Traffic Analysis** (PCAP simulation to detect data exfiltration packets). 

Furthermore, the forensic suite implements a novel **Heuristic Threat Scoring System** to quantitatively assess the malicious confidence of the payload based on weighted behavioral indicators. The findings successfully traced the entire malware lifecycle: from the initial drive-by download infection vector, through unauthorized local data stockpiling using Base64 obfuscation, to the final exfiltration of sensitive user contacts to an external Command and Control (C2) server. Culminating in automated HTML and PDF reports, this project demonstrates a complete, end-to-end incident response workflow suitable for modern enterprise mobile threat environments.

---

## Table of Contents
1. **Abstract**
2. **Introduction**
   - 2.1 The Evolving Landscape of Mobile Malware Threats
   - 2.2 Comprehensive Objectives of the Investigation
   - 2.3 Detailed Overview of the Suspect Payload
3. **Methodology & Forensic Environment**
   - 3.1 Simulated Android File System Architecture
   - 3.2 Advanced Custom Python Forensic Toolchain
4. **Phase 1: Static File System Analysis**
   - 4.1 Payload Identification & Cryptographic Hashing
   - 4.2 In-Depth Android Manifest Permission Auditing
   - 4.3 Data Storage Discovery & De-obfuscation Techniques
5. **Phase 2: Signature-Based Detection**
   - 5.1 The YARA Rule Framework Implementation
   - 5.2 Deep Analysis of Threat Signature Matches
6. **Phase 3: Dynamic Log Analysis**
   - 6.1 Reconstructing the Infection Timeline via `logcat`
   - 6.2 Tracking Runtime Privilege Escalation & Memory I/O
7. **Phase 4: Network Traffic Analysis**
   - 7.1 PCAP Simulation & Flow Log Deep Dive
   - 7.2 C2 Infrastructure Identification & Data Exfiltration Quantification
8. **Heuristic Threat Scoring System**
   - 8.1 Advanced Scoring Methodology
   - 8.2 Final Malicious Confidence Calculation
9. **Automated Forensic Reporting**
10. **Conclusion**
   - 10.1 Comprehensive Summary of Findings
   - 10.2 Strategic Remediation and Enterprise Recommendations

---

## 2. Introduction

### 2.1 The Evolving Landscape of Mobile Malware Threats
In recent years, the widespread adoption of the Android operating system has made it a primary target for sophisticated cybercriminal syndicates and state-sponsored actors. Unlike traditional desktop environments, mobile devices are deeply integrated into users' daily lives. They constantly collect, process, and store highly sensitive data, including precise geolocation coordinates, personal communications, financial credentials, and biometric identifiers. 

Threat actors increasingly utilize advanced social engineering techniques to bypass the official Google Play Store's security measures (Google Play Protect). A highly effective and prevalent attack vector is the "Trojanized" application. These are malicious payloads disguised as benign or essential utilities—such as battery optimizers, media players, or critical operating system updates. Once installed by an unsuspecting user through a process known as "sideloading," these applications quietly exploit zero-day vulnerabilities or abuse the Android permission model to escalate privileges. They establish persistent backdoors, monitor device activity, and create covert communication channels to exfiltrate stolen data to remote servers. Understanding the intricate mechanisms of these attacks through rigorous, forensically sound digital investigations is absolutely essential for developing effective incident response protocols and mitigation strategies.

### 2.2 Comprehensive Objectives of the Investigation
The primary objective of this project is to simulate and execute a professional-grade digital forensics investigation on a compromised Android device. By dissecting a simulated malware infection, this investigation aims to achieve the following:

1. **Identify and Isolate the Payload:** Locate the initial infection vector within the file system and generate cryptographically secure hashes (SHA-256) to establish immutable Indicators of Compromise (IOCs) for evidence preservation and chain of custody.
2. **Execute Deep Static Analysis:** Perform static, "dead-box" analysis on the file system and application manifest to identify unauthorized, high-risk permission requests, reverse-engineer obfuscated code segments, and uncover local data staging areas utilized by the malware.
3. **Trace Dynamic Execution Pathways:** Reconstruct the exact infection timeline by analyzing Android system logs (`logcat`). This allows analysts to observe privilege escalation, inter-process communication (IPC), and memory I/O operations in real-time as the malware interacts with the OS kernel.
4. **Detect Network Exfiltration & C2 Infrastructure:** Analyze network flow data (simulated PCAP analysis) to identify unauthorized outbound connections, locate the attacker's Command and Control (C2) infrastructure, and accurately quantify the volume of data lost during the breach.
5. **Quantify the Threat Level:** Implement an automated heuristic scoring system to objectively calculate the malicious confidence level of the suspect application, removing human bias from the threat assessment.
6. **Automate Forensic Reporting:** Aggregate all gathered forensic intelligence into an automated, interactive HTML dashboard and a formal PDF report, accelerating the time-to-remediation for Incident Response (IR) teams.

### 2.3 Detailed Overview of the Suspect Payload
This investigation centers on a highly suspicious Android Package Kit (APK) file labeled `System_Update_v2.apk`. The file was discovered residing on a simulated device within the user's local external storage (`/sdcard/Download` directory). This location strongly suggests the application was acquired outside of the official, curated application repositories. It is highly probable the payload was delivered via a targeted smishing (SMS phishing) campaign or a malicious drive-by download from a compromised website.

Initial behavioral reports indicate that immediately following the installation of this purported "update," the device exhibited severe anomalies, including unexplained battery drain, unusual outbound network spikes, and unauthorized access alerts to personal data stores (specifically the Contacts provider). The ensuing chapters will detail the exhaustive forensic methodologies applied to dissect this payload, proving definitively that it is a piece of malicious spyware.

---

## 3. Methodology & Forensic Environment

![Malware Execution Flow Architecture](./images/malware_execution_flow.png)

### 3.1 Simulated Android File System Architecture
To conduct this investigation in a safe, controlled, and repeatable manner without risking exposure to a live, physical device or corporate network, a simulated Android environment was constructed. This "sandboxed" environment meticulously mimics the directory structure, file permissions, and system logging mechanisms of a standard Android OS.

The "crime scene" (`Simulated_Device/`) contains several critical directories that a forensic analyst would image and examine during a real-world incident response:
*   **`/sdcard/Download`**: Represents the simulated user's primary external storage volume. This is often the initial landing zone for sideloaded payloads and downloaded artifacts.
*   **`/data/app/`**: The secure system directory where the Android OS physically stores installed application binaries (typically named `base.apk`) and their unpacked assets.
*   **`/data/data/`**: The highly isolated storage sandbox dedicated to individual applications. This directory houses sensitive local databases (typically SQLite format), shared XML preferences, and cached files. Under normal circumstances, apps cannot read each other's data directories without root access.
*   **`/logs/`**: A simulated repository containing a dump of the Android system log (`logcat`) and network flow captures, which are absolutely crucial for dynamic timeline reconstruction.

### 3.2 Advanced Custom Python Forensic Toolchain
Rather than relying solely on opaque, off-the-shelf commercial forensic software (which can sometimes act as a "black box"), this investigation utilized a suite of custom, purpose-built Python scripts. This approach allows for total control over the parsing logic and demonstrates a profound technical understanding of the underlying Android data structures. The toolchain consists of several highly specialized modules:

1. **Simulation Orchestrator (`setup_simulation.py`):** Initializes the forensic environment. It provisions the exact directory structure, plants the obfuscated malware payload, generates mock system logs detailing the infection lifecycle, and synthesizes a network traffic capture (PCAP) flow log.
2. **Static File System Analyzer (`FileSystem_Analyzer.py`):** Responsible for "dead-box" forensics. It traverses the file system to locate suspicious binaries, computes SHA-256 cryptographic hashes, parses the `AndroidManifest.xml` for dangerous permission requests, and reverse-engineers SQLite databases to de-obfuscate (Base64 decode) stolen user data.
3. **Dynamic Log & Memory Analyzer (`Dynamic_Analyzer.py`):** Performs behavioral analysis by parsing the `logcat_dump.txt`. Utilizing complex regular expressions, it reconstructs a chronological timeline of the attack, identifying exact timestamps for payload execution and dynamic privilege escalation.
4. **Network Traffic Analyzer (`Network_Analyzer.py`):** Simulating deep packet inspection (DPI) of a PCAP file, this script scans the `network_flow.csv` log. It cross-references destination IP addresses against known threat intelligence feeds and quantifies the byte volume of exfiltrated data.
5. **Signature Scanning Engine (`Yara_Scanner.py`):** Implementing the industry-standard YARA framework, this script scans the raw binary stream of the installed payload against custom threat signatures, searching for specific byte sequences indicative of malicious intent.

---

## 4. Phase 1: Static File System Analysis

> **[📝 PROJECT REQUIREMENT - INSERT IMAGE HERE]**
> *Take a screenshot of your terminal running `python FileSystem_Analyzer.py` showing the red and green forensic output, and paste the image here.*

### 4.1 Payload Identification & Cryptographic Hashing (SHA-256)
The foundation of any digital forensic investigation is preserving the integrity of the evidence. The initial payload was located at `/sdcard/Download/System_Update_v2.apk`. Upon tracking the system installation routines, it was discovered that the payload was unpacked and installed to `/data/app/com.android.sysupdate-1/base.apk`. 

To establish immutable Indicators of Compromise (IOCs), cryptographic hashing utilizing the SHA-256 algorithm was performed on both the downloaded payload and the installed binary. SHA-256 generates a mathematically unique 256-bit signature. If even a single bit of the malware's code is altered, the resulting hash will change entirely. Documenting these hashes ensures that the evidence has not been tampered with and allows security teams to search for this exact file across enterprise endpoints.

### 4.2 In-Depth Android Manifest Permission Auditing
Every Android application is required to include an `AndroidManifest.xml` file. This file acts as the blueprint for the application, declaring its package name, activities, services, and critically, the permissions it requires to interact with the OS hardware and user data.

Forensic parsing of this manifest revealed severe anomalies indicative of malicious intent. A legitimate operating system update operates at the system level and does not need to explicitly request user-level data access via the standard permission model. However, the manifest for `com.android.sysupdate` explicitly requested several permissions categorized by Google as "Dangerous" (Protection Level: Dangerous). These included:
*   `android.permission.READ_CONTACTS`: Grants the ability to silently scrape the user's entire address book.
*   `android.permission.SEND_SMS` & `READ_SMS`: Grants the ability to intercept two-factor authentication (2FA) codes or send premium-rate SMS messages, a common monetization tactic for mobile malware.
*   `android.permission.INTERNET`: Allows the application to open network sockets, a prerequisite for exfiltrating the stolen data to a remote server.

### 4.3 Data Storage Discovery & De-obfuscation Techniques
A deep dive into the application's isolated local sandbox (`/data/data/com.android.sysupdate/`) revealed an unauthorized SQLite database file named `stolen_data.db`. Malware authors frequently use local databases as a staging area to stockpile harvested data while waiting for a reliable network connection to exfiltrate it.

Reverse-engineering the database schema and querying the `contacts` table uncovered the exact victim data that had been compromised. To evade rudimentary antivirus scans and simple string analysis, the malware authors employed Base64 obfuscation to encode the stolen names and phone numbers. Base64 translates binary data into a standard ASCII string format. The Static Analyzer successfully identified this encoding scheme and programmatically decoded the data, revealing the plaintext identities of stolen contacts, including "Alice Smith" and "Charlie Brown."

> **[📝 PROJECT REQUIREMENT - INSERT CODE SNIPPET HERE]**
> *Copy and paste the python code block from `FileSystem_Analyzer.py` that handles the `base64.b64decode` logic to demonstrate your implementation.*

---

## 5. Phase 2: Signature-Based Detection

> **[📝 PROJECT REQUIREMENT - INSERT IMAGE HERE]**
> *Take a screenshot of your terminal running `python Yara_Scanner.py` showing the 4 signature matches, and paste the image here.*

### 5.1 The YARA Rule Framework Implementation
While static analysis of manifests and databases is crucial, examining the raw binary executable is necessary to understand the malware's underlying capabilities. To achieve this, the investigation utilized YARA, a tool often described as the "pattern matching Swiss army knife" for malware researchers. YARA allows analysts to create custom rules (signatures) based on textual or binary patterns contained within a file.

### 5.2 Deep Analysis of Threat Signature Matches
The YARA scanning engine processed the installed `base.apk` and successfully triggered four distinct, highly critical malicious signatures:
1. **Rule_Base64_Obfuscation:** A string match was found for the Python/Java equivalent of `base64.b64decode`. This confirmed the static findings that the malware possesses the internal logic to encode and decode obfuscated data strings.
2. **Rule_C2_Network_Traffic:** The scanner identified a hardcoded, unencrypted HTTP string pointing to a specific IP address: `http://192.168.1.100`. Hardcoding IP addresses (rather than using domain names) is a common tactic in rudimentary malware to avoid DNS sinkholing by security researchers.
3. **Rule_SQL_Theft:** A raw string match for the SQL query `select * from contacts` was found embedded in the binary. This definitively links the executable code to the unauthorized database discovered during static analysis.
4. **Rule_Root_Exploit:** The most alarming discovery was a string match for `cmd.exe /c powershell`. While traditionally a Windows command, its presence in an Android APK suggests this malware might be a cross-platform threat, or it utilizes an embedded post-exploitation framework designed to execute advanced shell commands if the device is rooted.

> **[📝 PROJECT REQUIREMENT - INSERT CODE SNIPPET HERE]**
> *Copy and paste your YARA rules dictionary or the signature array from `Yara_Scanner.py` here to show how the signatures were defined.*

---

## 6. Phase 3: Dynamic Log Analysis

> **[📝 PROJECT REQUIREMENT - INSERT IMAGE HERE]**
> *Take a screenshot of your terminal running `python Dynamic_Analyzer.py` showing the chronological forensic timeline events, and paste the image here.*

### 6.1 Reconstructing the Infection Timeline via `logcat`
Static analysis shows what the malware *can* do; dynamic analysis shows what it *actually did*. Android utilizes a system-wide logging facility known as `logcat` to record events from the kernel, system services, and applications. 

By parsing the simulated `logcat_dump.txt`, the analyzer reconstructed a precise, chronological timeline of the attack. The logs captured the exact millisecond the Android `PackageManager` service was invoked to install the payload from the `/sdcard/Download` directory. This artifact confirms that the infection was user-initiated, proving the effectiveness of the malware's social engineering disguise as a system update.

### 6.2 Tracking Runtime Privilege Escalation & Memory I/O
Modern Android versions require applications to request dangerous permissions at runtime, explicitly prompting the user. The dynamic logs captured the specific moments when `com.android.sysupdate` successfully tricked the user into granting the `android.permission.READ_CONTACTS` and `SEND_SMS` permissions. 

Immediately following this privilege escalation, the logs recorded I/O memory alerts. The Android SQLite subsystem logged the malware actively opening and writing to the local stash (`stolen_data.db`), perfectly aligning the dynamic behavioral timeline with the static database artifacts discovered earlier.

---

## 7. Phase 4: Network Traffic Analysis

> **[📝 PROJECT REQUIREMENT - INSERT IMAGE HERE]**
> *Take a screenshot of your terminal running `python Network_Analyzer.py` showing the detected HTTP POST requests and byte exfiltration, and paste the image here.*

### 7.1 PCAP Simulation & Flow Log Deep Dive
Malware is ultimately ineffective if it cannot communicate its stolen data back to the attacker. To investigate the exfiltration phase, a simulated network flow log (`network_flow.csv`), representative of a Packet Capture (PCAP) file obtained from a network router or firewall, was thoroughly analyzed.

### 7.2 C2 Infrastructure Identification & Data Exfiltration Quantification
The Network Analyzer script parsed the flow logs, filtering out benign background traffic to isolate suspicious outbound connections. It detected a highly anomalous TCP connection directed to the exact IP address previously identified by the YARA scanner: `192.168.1.100`. 

The traffic analysis revealed the malware was utilizing port 8080 to send an `HTTP POST` request to an `/api/upload` endpoint. By analyzing the payload byte count within the network flows, the analyzer determined that exactly 8080 bytes of compressed data were successfully transmitted to the attacker's Command and Control (C2) server. This provides the final piece of forensic evidence, confirming a successful data breach.

---

## 8. Heuristic Threat Scoring System

### 8.1 Advanced Scoring Methodology
In high-volume Security Operations Centers (SOCs), analysts suffer from "alert fatigue." To provide a rapid, objective assessment of the threat level, this forensic suite implements an automated Heuristic Threat Scoring system. Rather than relying on simple binary flags (Malicious vs. Benign), points are dynamically awarded based on the severity and combination of observed behaviors:
*   **Initial Vector:** Suspicious APK location in user downloads (+10 points).
*   **Manifest Abuse:** Dangerous permissions requested (+10 points per permission).
*   **Data Staging:** Evidence of Base64 obfuscated data written to disk (+15 points per stolen record).
*   **Network Exfiltration:** Confirmed connection to a known C2 IP address (+30 points).

### 8.2 Final Malicious Confidence Calculation
The aggregated scores from the static, dynamic, and network analysis modules resulted in a total threat score that vastly exceeded normal application behavioral thresholds. This culminated in the system assigning the payload a **100% Malicious Confidence Score**. This quantitative metric removes human bias and definitively classifies the application as severe, high-risk spyware, triggering immediate incident response protocols.

---

## 9. Automated Forensic Reporting

![Forensic Intelligence Dashboard](./images/forensic_dashboard_mockup.png)

> **[📝 PROJECT REQUIREMENT - INSERT YOUR OWN DASHBOARD IMAGE HERE]**
> *Replace the mockup image above with an actual screenshot of YOUR generated `Investigation_Dashboard.html` open in your web browser.*

To ensure the findings are actionable for stakeholders and incident response teams, the forensic suite automatically compiled the intelligence into two formats:
1. **Interactive HTML Dashboard (`Investigation_Dashboard.html`):** A dynamic, visually striking interface built utilizing HTML5 and Chart.js. It provides a real-time overview of the incident, featuring a Risk Vector Analysis doughnut chart, a chronological execution timeline derived from the logs, and a clean presentation of the decrypted stolen data.
2. **Automated PDF Report (`Forensic_Report_Automated.pdf`):** A formal, paginated, and printable document generated via the Python `fpdf2` library. This ensures the chain of evidence and analytical findings are preserved in a standard format suitable for academic review, compliance audits, or potential legal proceedings.

> **[📝 PROJECT REQUIREMENT - INSERT PDF SCREENSHOT HERE]**
> *Take a screenshot of the first page of your generated `Forensic_Report_Automated.pdf` and paste it here to prove the automated generation works.*

---

## 10. Conclusion

### 10.1 Comprehensive Summary of Findings
The multi-layered forensic investigation conclusively proved that `System_Update_v2.apk` is not a legitimate system file, but rather a piece of highly sophisticated, targeted spyware. The forensic artifacts successfully recovered during this investigation provide a complete, undeniable picture of the malware's lifecycle. 

The attacker successfully utilized social engineering to facilitate a drive-by download. Once executed, the malware abused the Android runtime permission model to achieve privilege escalation, harvesting the victim's entire contact list. It employed Base64 encoding to obfuscate this stolen data within a local SQLite database before successfully exfiltrating the payload via an HTTP POST request to the external Command and Control server located at `192.168.1.100`.

### 10.2 Strategic Remediation and Enterprise Recommendations
Based on the forensic intelligence gathered, the following critical remediation steps are recommended to secure the environment and prevent future infections:
1. **Mandatory User Security Awareness Training:** Employees must be rigorously trained to recognize phishing and smishing attempts and instructed to *never* sideload applications from outside official, vetted application repositories.
2. **Deployment of Mobile Device Management (MDM):** Enterprise environments must enforce MDM policies that cryptographically restrict the installation of unauthorized APKs and enforce strict application whitelisting.
3. **Immediate Network-Level Isolation:** Network administrators must implement immediate firewall rules to block all inbound and outbound traffic to the identified C2 IP address (`192.168.1.100`), preventing any further data exfiltration from potentially infected devices on the network.
4. **Proactive Threat Hunting:** Security teams must ingest the generated Indicators of Compromise (specifically the SHA-256 hashes and YARA rules) into their Endpoint Detection and Response (EDR) platforms to actively hunt for any dormant instances of this malware family across the broader corporate infrastructure.
