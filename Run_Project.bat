@echo off
echo ====================================================
echo Starting Android Malware Forensic Simulation...
echo ====================================================
echo.

echo [*] Step 1: Setting up environment...
python setup_simulation.py
echo.

echo [*] Step 2: Running Static Analyzer...
python FileSystem_Analyzer.py
echo.

echo [*] Step 3: Running Dynamic Analyzer...
python Dynamic_Analyzer.py
echo.

echo [*] Step 4: Running Network Analyzer...
python Network_Analyzer.py
echo.

echo [*] Step 5: Running YARA Scanner...
python Yara_Scanner.py
echo.

echo [*] Step 6: Generating HTML and PDF Reports...
python Html_Report_Generator.py
python PDF_Report_Generator.py
echo.

echo ====================================================
echo Forensic Suite Complete! Opening Reports...
echo ====================================================
start Investigation_Dashboard.html
start Forensic_Report_Automated.pdf

pause
