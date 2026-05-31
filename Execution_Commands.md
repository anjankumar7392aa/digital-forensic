# Digital Forensic Suite: Execution Commands

This document contains all the necessary commands to run the entire Android Malware Forensic Project from start to finish. 

Open your terminal (PowerShell or Command Prompt) in the project folder and run the commands in the order listed below.

---

### Step 1: Environment Setup
First, generate the simulated Android file system, malware payload, and mock log files.
```powershell
python setup_simulation.py
```

### Step 2: Forensic Analyzers
Run the analyzers to gather forensic intelligence and generate the JSON threat score reports.
```powershell
# 1. Static Analysis (Manifest, Hashing, Database Extraction)
python FileSystem_Analyzer.py

# 2. Dynamic Analysis (Logcat Timeline Reconstruction)
python Dynamic_Analyzer.py

# 3. Network Analysis (PCAP/Flow Log Inspection)
python Network_Analyzer.py

# 4. Signature Detection (YARA rule matching)
python Yara_Scanner.py
```

### Step 3: Report Generation
After the analyzers have completed and calculated the threat scores, compile the results into the final reports.
```powershell
# Generate the Interactive HTML Dashboard
python Html_Report_Generator.py

# Generate the Formal PDF Document
python PDF_Report_Generator.py
```

### Step 4: View Results
Open the generated reports to view the findings.
```powershell
Start-Process "Investigation_Dashboard.html"
Start-Process "Forensic_Report_Automated.pdf"
```

---

### Quick Run (All-in-One Command)
If you want to execute the entire simulation, all analyzers, and generate reports automatically in one go, you can copy and paste this single line:

```powershell
python setup_simulation.py; python FileSystem_Analyzer.py; python Dynamic_Analyzer.py; python Network_Analyzer.py; python Yara_Scanner.py; python Html_Report_Generator.py; python PDF_Report_Generator.py
```
