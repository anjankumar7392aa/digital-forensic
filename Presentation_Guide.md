# Presentation Guide: Android Malware Forensics

This guide provides a structured outline and talking points for your class presentation. Use this to confidently walk your professor and classmates through your project.

## Slide 1: Introduction & Scenario
**Title:** Investigating an Android Malware Attack
*   **Talking Point:** Introduce the realistic scenario. A victim received an SMS with a link to a "Critical System Update." They downloaded and installed `System_Update_v2.apk`.
*   **Talking Point:** However, this wasn't an update. It was **Spyware**. Our objective as digital forensic analysts was to piece together what happened *after* the attack using artifacts left on the device.

## Slide 2: The Attack Surface (Installation & Location)
**Title:** The Infection Vector & Footprint
*   **Talking Point:** Explain *how* we found it. We simulated an infected file system. We found the initial payload resting in `/sdcard/Download/` showing the entry vector.
*   **Talking Point:** Explain *where* it installed. We found the live, executing binary deeply embedded in the Android app directory at `/data/app/com.android.sysupdate-1/base.apk`.

## Slide 3: Static Analysis & Evidence Integrity
**Title:** Verifying the Threat (Static Analysis)
*   *Demo Action:* Run `python FileSystem_Analyzer.py` in the background or show a screenshot.
*   **Talking Point (Hashing):** The first rule of forensics is Chain of Custody. Our script automatically calculates the **SHA-256 Hash** of the seized APK. We can use this cryptographic fingerprint to prove the evidence hasn't been tampered with.
*   **Talking Point (Permissions):** We parsed the `AndroidManifest.xml`. Despite claiming to be a "System Update," the app requested `READ_CONTACTS` and `SEND_SMS`. By applying the "Principle of Least Privilege," we immediately flagged this as malicious spyware behavior.

## Slide 4: Dynamic Logs (The Timeline)
**Title:** Tracing the Execution (Dynamic Analysis)
*   *Demo Action:* Run `python Dynamic_Analyzer.py`.
*   **Talking Point:** Malware leaves a timeline. By parsing the Android `logcat` system logs, our script pinpointed the exact moment the `PackageManager` executed the file.
*   **Talking Point:** The logs also revealed the ultimate proof of an attack: An outbound network connection to an unauthorized C2 (Command & Control) server IP address.

## Slide 5: Data Recovery (Cracking the Malware)
**Title:** Exfiltration & De-obfuscation
*   **Talking Point:** We located the malware's local staging ground—a hidden SQLite database located in `/data/data/com.android.sysupdate/databases/`.
*   **Talking Point:** The malware attempted to hide the stolen data using **Base64 Encoding**. Show how your forensic Python script successfully "cracked" the encryption on the fly, decoding the Base64 to reveal exactly who was compromised (Alice, Bob, Charlie).

## Slide 6: The Final Report
**Title:** Automated Intelligence Dashboard
*   *Demo Action:* Open your `Investigation_Dashboard.html` in the web browser on screen.
*   **Talking Point:** To conclude the investigation, we built an automated reporting engine. It takes all the hashed evidence, cracked database rows, and log timelines, and outputs a professional, actionable Intelligence Dashboard for law enforcement or IT security teams.

## Slide 7: Conclusion
**Title:** Conclusion & Mitigation
*   **Talking Point:** The forensic evidence conclusively proves `System_Update_v2.apk` is a data-exfiltrating spyware. 
*   **Talking Point:** Mitigation recommendation: Users must avoid sideloading APKs, and corporate networks should block the identified C2 IP address.
*   **Closing:** Ask if there are any questions.
