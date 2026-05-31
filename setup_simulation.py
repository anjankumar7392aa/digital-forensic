import os
import sqlite3
import datetime
import base64

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def setup_simulation():
    print("Setting up Android Malware Simulation Environment...")
    base_dir = "Simulated_Device"
    
    # 1. Directory Structure
    dirs_to_create = [
        f"{base_dir}/sdcard/Download",
        f"{base_dir}/data/app/com.android.sysupdate-1",
        f"{base_dir}/data/data/com.android.sysupdate/databases",
        f"{base_dir}/logs"
    ]
    
    for d in dirs_to_create:
        create_directory(d)
        
    # 2. Mock APKs (Just creating text files to represent them)
    apk_paths = [
        f"{base_dir}/sdcard/Download/System_Update_v2.apk",
        f"{base_dir}/data/app/com.android.sysupdate-1/base.apk"
    ]
    # Insert 'malicious' strings for the YARA scanner to find
    simulated_binary_data = "MZ...PK... \x00\x00 [OBFUSCATED CODE] \x00\x00 base64.b64decode \x00\x00 URL: http://192.168.1.100:8080/api/upload \x00\x00 cmd.exe /c powershell \x00\x00 select * from contacts \x00\x00"

    for apk in apk_paths:
        with open(apk, 'w') as f:
            f.write(simulated_binary_data)

    with open(f"{base_dir}/data/app/com.android.sysupdate-1/AndroidManifest.xml", 'w') as f:
        f.write('''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.android.sysupdate">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:label="System Update" android:icon="@drawable/ic_sys">
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        <service android:name=".DataExfilService" />
    </application>
</manifest>''')

    # 3. Create Mock SQLite Database for stolen data
    db_path = f"{base_dir}/data/data/com.android.sysupdate/databases/stolen_data.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone_number TEXT,
            stolen_at TIMESTAMP
        )
    ''')
    # Insert some mock stolen data
    mock_contacts = [
        ("Alice Smith", "+15551234567"),
        ("Bob Johnson", "+15559876543"),
        ("Charlie Brown", "+15555551212"),
        ("harry", "+918745932108"),
        ("Maddy", "+1234567890"),
        ("susan", "+6543289717"),
        ("rachel", "+1234965872"),
        ("john", "+12963258741"),
        ("peter", "+146879324"),
        ("mary", "+2589631478")
    ]
    for name, phone in mock_contacts:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Obfuscate data mimicking malware behavior (Base64 encoding)
        encoded_name = base64.b64encode(name.encode('utf-8')).decode('utf-8')
        encoded_phone = base64.b64encode(phone.encode('utf-8')).decode('utf-8')
        
        cursor.execute("INSERT INTO contacts (name, phone_number, stolen_at) VALUES (?, ?, ?)", (encoded_name, encoded_phone, timestamp))
    
    conn.commit()
    conn.close()
    
    # 4. Create Mock Logcat
    logcat_path = f"{base_dir}/logs/logcat_dump.txt"
    with open(logcat_path, 'w') as f:
        log_content = """04-23 10:15:02.123 1000 1000 I PackageManager: START u0 {act=android.intent.action.VIEW dat=file:///sdcard/Download/System_Update_v2.apk typ=application/vnd.android.package-archive cmp=com.google.android.packageinstaller/.InstallAppProgress}
04-23 10:15:10.450 1000 1000 I PackageManager: Action: install_commit for com.android.sysupdate
04-23 10:15:12.800 1000 1000 I ActivityManager: START u0 {cmp=com.android.sysupdate/.MainActivity} from uid 10123
04-23 10:15:15.105 10123 10123 W SystemUpdateApp: Requested permission android.permission.READ_CONTACTS granted=true
04-23 10:15:15.109 10123 10123 W SystemUpdateApp: Requested permission android.permission.SEND_SMS granted=true
04-23 10:15:18.400 10123 10150 I SQLite: Opening database /data/data/com.android.sysupdate/databases/stolen_data.db
04-23 10:16:05.100 10123 10160 D NetworkConnect: Connecting to C2 Server 192.168.1.100:8080
04-23 10:16:06.200 10123 10160 I DataExfilService: Uploading 3 contacts payload to C2. POST /api/upload
04-23 10:16:07.500 10123 10160 I DataExfilService: Upload successful. Code: 200"""
        f.write(log_content)

    # 5. Create Mock Network Flow (PCAP equivalent)
    network_path = f"{base_dir}/logs/network_flow.csv"
    with open(network_path, 'w') as f:
        csv_content = """Timestamp,Source IP,Destination IP,Protocol,Bytes,Info
2026-04-23 10:14:00,192.168.1.50,8.8.8.8,UDP,64,DNS Query
2026-04-23 10:15:05,192.168.1.50,172.217.164.110,TCP,443,HTTPS GET
2026-04-23 10:16:05,192.168.1.50,192.168.1.100,TCP,8080,HTTP POST /api/upload
2026-04-23 10:16:06,192.168.1.50,192.168.1.100,TCP,8080,HTTP payload 1450 bytes
2026-04-23 10:16:07,192.168.1.100,192.168.1.50,TCP,8080,HTTP 200 OK
"""
        f.write(csv_content)

    print("Simulation environment created successfully at 'Simulated_Device/'")

if __name__ == "__main__":
    setup_simulation()
