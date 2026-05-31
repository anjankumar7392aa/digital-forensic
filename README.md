# Android Malware Forensic Simulation Suite

A comprehensive Python-based Digital Forensic Suite designed to simulate an Android malware infection, analyze the artifacts, and generate automated forensic reports.

## Overview
This project simulates an Android environment containing malware artifacts and provides a complete pipeline for analyzing these artifacts through various forensic techniques:
- **Static Analysis**: Inspects the Android Manifest, performs file hashing, and extracts database information.
- **Dynamic Analysis**: Reconstructs execution timelines using simulated Logcat data.
- **Network Analysis**: Inspects PCAP/Flow logs for malicious network activity.
- **Signature Detection**: Scans files using YARA rules to identify known malware signatures.

After all analyzers have gathered intelligence and calculated threat scores, the suite automatically compiles the findings into both an interactive HTML Dashboard and a formal PDF Document.

## Project Structure
- `setup_simulation.py`: Sets up the environment by generating a simulated Android file system, malware payloads, and mock logs.
- `FileSystem_Analyzer.py`: Performs static analysis.
- `Dynamic_Analyzer.py`: Analyzes dynamic artifacts like logs and processes.
- `Network_Analyzer.py`: Analyzes network traffic and connections.
- `Yara_Scanner.py`: Scans files using predefined YARA rules.
- `Html_Report_Generator.py`: Compiles an interactive HTML investigation dashboard.
- `PDF_Report_Generator.py`: Compiles a formal automated PDF forensic report.
- `Run_Project.bat`: A batch script to automatically run the entire suite from start to finish.
- `Execution_Commands.md`: Contains manual execution commands for running the project step-by-step.

## How to Run

### Option 1: Automated Batch Script (Recommended for Windows)
The easiest way to run the full simulation and open the resulting reports is to simply execute the batch file:
```cmd
Run_Project.bat
```

### Option 2: Step-by-Step Manual Execution
Open your terminal (PowerShell or Command Prompt) and run the scripts in the following order:

**1. Setup Environment:**
```powershell
python setup_simulation.py
```

**2. Run Analyzers:**
```powershell
python FileSystem_Analyzer.py
python Dynamic_Analyzer.py
python Network_Analyzer.py
python Yara_Scanner.py
```

**3. Generate Reports:**
```powershell
python Html_Report_Generator.py
python PDF_Report_Generator.py
```

**4. View Results:**
Open the generated `Investigation_Dashboard.html` and `Forensic_Report_Automated.pdf` to review the findings.

### Option 3: One-Liner (PowerShell)
You can run all scripts back-to-back using this single command:
```powershell
python setup_simulation.py; python FileSystem_Analyzer.py; python Dynamic_Analyzer.py; python Network_Analyzer.py; python Yara_Scanner.py; python Html_Report_Generator.py; python PDF_Report_Generator.py
```

## Requirements
- Python 3.x
- Any required Python packages (e.g., libraries for generating PDFs) as specified by the individual scripts.
