<a id="top"></a>
# 🕵️ Pwd Spray to Full Compromise - Threat Hunt
***Analyst:*** Chris Mondejar

## 🌟 Table of Contents 🌟

- [🌍 Executive Summary](#executive-summary)
- [🔬 Hypothesis](#hypothesis)
- [📅 Timeline of Events](#timeline-of-events)
- [🚩 Flag 1 — Attacker IP Address](#flag1)
- [🚩 Flag 2 — Compromised Account](#flag2)
- [🚩 Flag 3 — Executed Binary](#flag3)
- [🚩 Flag 4 — Command Line Used](#flag4)
- [🚩 Flag 5 — Persistence Mechanism](#flag5)
- [🚩 Flag 6 — Defender Setting Modified](#flag6)
- [🚩 Flag 7 — Discovery Command](#flag7)
- [🚩 Flag 8 — Archive File Created](#flag8)
- [🚩 Flag 9 — C2 Connection Destination](#flag9)
- [🚩 Flag 10 — Exfiltration Attempt](#flag10)
- [📊 Key Findings Summary](#key-findings-summary)
- [🛡️ MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [📌 Recommendations](#recommendation)

---

<a id="executive-summary"></a>
## 🌍 **Executive Summary**

On **14 September 2025**, suspicious RDP login activity was observed on a cloud-hosted Windows VM.  

Following a brute-force campaign, the adversary gained RDP access using the **slflare** account. They then:

- Staged and executed a malicious binary (`msupdate.exe`)
- Created persistence via a scheduled task
- Modified Microsoft Defender exclusions
- Performed host discovery
- Archived data into `backup_sync.zip`
- Attempted to exfiltrate the archive via `curl` to external infrastructure (`185.92.220.87:8081`)

### Attack Lifecycle
This attack demonstrates a full intrusion lifecycle:

**Initial Access** → **Execution** → **Persistence** → **Defense Evasion** → **Discovery** → **Collection** → **C2** → **Exfiltration**

### Tools Used
- Advanced Hunting (KQL) in Microsoft Defender for Endpoint
- Microsoft Sentinel



  
[Back to top](#top)

---

<a id="hypothesis"></a>
## 🔬 Hypothesis

An external attacker performed a brute-force attack against the VM containing "flare" to gain initial access using a valid account. Once inside, the attacker executed a malicious binary dropped in a user-writable directory, established persistence via a scheduled task, disabled Microsoft Defender protections by adding an exclusion, performed host discovery, and staged collected data in an archive file for potential exfiltration.

This hypothesis will be validated or refuted through KQL-based hunting across DeviceLogonEvents, DeviceProcessEvents, DeviceEvents, DeviceRegistryEvents, and DeviceFileEvents.

[Back to top](#top)


---
<a id="timeline-of-events"></a>
## 📅 Timeline of Events

| Time (UTC+09:00)       | Stage                   | Event / Artifact                                                                                  |
|-------------------------|-------------------------|--------------------------------------------------------------------------------------------------|
| Sep 16, 2025 06:40:57   | Initial Access          | Successful RDP login from attacker IP `159.26.106.84` to account `slflare`                       |
| Sep 16, 2025 06:43:46   | Initial Access          | `RemoteInteractive` logon confirms RDP session established                                       |
| Sep 16, 2025 07:38:01   | Execution               | File `msupdate.exe` created in `C:\Users\Public\` by PowerShell                                  |
| Sep 16, 2025 07:38:40   | Execution               | `msupdate.exe` launched with `-ExecutionPolicy Bypass -File update_check.ps1`                    |
| Sep 16, 2025 07:39:45   | Persistence             | Scheduled Task `MicrosoftUpdateSync` created in TaskCache registry                               |
| Sep 16, 2025 07:39:48   | Defense Evasion         | Defender exclusion added for `C:\Windows\Temp`                                                   |
| Sep 16, 2025 07:40:28   | Discovery               | Discovery command executed: `"cmd.exe" /c systeminfo`                                            |
| Sep 16, 2025 07:41:30   | Collection / Staging    | Archive file `backup_sync.zip` created by `slflare`                                              |
| Sep 16, 2025 07:42:17   | Command & Control       | Outbound connection attempt to C2 `185.92.220.87` on port 80                                     |
| Sep 16, 2025 07:43:42   | Exfiltration            | `curl` used to POST `backup_sync.zip` to `http://185.92.220.87:8081/upload`                      |

[Back to top](#top)

---

## 🎯 Flag-by-Flag Findings

<a id="flag1"></a>
### 🚩 Flag 1 — Attacker IP Address
- **Objective:** Identify the external IP that successfully logged in via RDP after repeated failures.  
- **Finding:** Attacker IP `159.26.106.84`.  
- **Evidence:** Multiple brute-force attempts observed from the same external IP starting 13 September 2025, with successful login at 2025-09-16T18:40:57.3785102Z on DeviceName containing “flare”.  
- **Query Used:** (KQL query for DeviceLogonEvents filtered by DeviceName and RemoteIP)
- **Why this matters:** Multiple failed attempts followed by a success confirms a brute-force or password spray attack, establishing the initial access vector.
- **MITRE Technique:** T1110.001 – Brute Force: Password Guessing

**KQL Query Used:**

```kql
DeviceLogonEvents
| where TimeGenerated > (datetime("2025-09-13))
| where DeviceName contains "flare"
| where RemoteIP !in ("","-")
| where ActionType == ("LogonSuccess")
| project TimeGenerated, AccountName, ActionType, DeviceName, FailureReason, RemoteIP
| order by TimeGenerated asc
```
<img width="1175" height="184" alt="image" src="https://github.com/user-attachments/assets/ebb1db1b-c4e7-460a-a7b5-8d3127c2a0c8" />


[Back to top](#top)

---

<a id="flag2"></a>

### 🚩 Flag 2 — Compromised Account
- **Objective:** Identify which account was compromised.  
- **Finding:** Account `slflare`.  
- **Evidence:** Successful logon events tied to the attacker IP on the `slflare` account at 2025-09-16T18:40:57Z (Network) and subsequent RemoteInteractive session.  
- **Query Used:** (KQL query for DeviceLogonEvents showing LogonSuccess for slflare)
- **Why this matters:** Confirms the adversary gained access with `slflare`, serving as the pivot point for all subsequent malicious activity on the host.  
- **MITRE Technique:** T1078 – Valid Accounts

**KQL Query Used:**

```kql
DeviceLogonEvents
| where TimeGenerated > (datetime("2025-09-16))
| where DeviceName contains "flare"
| where RemoteIP !in ("","-")
| project TimeGenerated, AccountName, ActionType, DeviceName, FailureReason, RemoteIP
| order by TimeGenerated asc
```

<img width="1327" height="205" alt="image" src="https://github.com/user-attachments/assets/816abacf-1fd8-44f7-9851-7b16779fd307" />


[Back to top](#top)

---

<a id="flag3"></a>

### 🚩 Flag 3 — Executed Binary
- **Objective:** Identify the binary executed after login.  
- **Finding:** `msupdate.exe`.  
- **Evidence:** Suspicious executable created and launched in `C:\Users\Public\` at 2025-09-16T19:38:40.063299Z by the compromised account.  
- **Query Used:** (KQL query for DeviceProcessEvents or DeviceFileEvents in Public/Temp/Downloads folders)
- **Why this matters:** The binary name and location are classic indicators of attacker-staged post-compromise tooling.  
- **MITRE Techniques:** T1059.003 – Command and Scripting Interpreter: Windows Command Shell, T1204.002 – User Execution: Malicious File

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated > (datetime("2025-09-16))
| where DeviceName contains "flare"
| where FolderPath has_any ("Public","Temp","Downloads") 
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc 
```
<img width="1325" height="217" alt="image" src="https://github.com/user-attachments/assets/4cecfa5b-afac-4f31-aa44-48e8bd6db2fe" />


[Back to top](#top)

---

<a id="flag4"></a>

### 🚩 Flag 4 — Command Line Used
- **Objective:** Identify the command line used to execute the binary.  
- **Finding:** "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
- **Evidence:** Process creation event showing the full command line at 2025-09-16T19:38:40Z.  
- **Query Used:** (KQL query for DeviceProcessEvents where FileName == "msupdate.exe")
- **Why this matters:** The `-ExecutionPolicy Bypass` flag is a clear sign of intent to evade PowerShell execution restrictions.  
- **MITRE Technique:** T1059 – Command and Scripting Interpreter

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated > (datetime("2025-09-16))
| where DeviceName contains "flare"
| where FolderPath has_any ("Public","Temp","Downloads") 
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc 
```
<img width="1323" height="217" alt="image" src="https://github.com/user-attachments/assets/d044270a-77ff-4dbd-8196-33e8d27acb5e" />


[Back to top](#top)

---

<a id="flag5"></a>

### 🚩 Flag 5 — Persistence Mechanism
- **Objective:** Identify the persistence mechanism created.  
- **Finding:** Scheduled task `MicrosoftUpdateSync`.  
- **Evidence:** Scheduled task registration event immediately after binary execution at 2025-09-16T19:39:45.4614515Z.  
- **Query Used:** (KQL query for DeviceEvents or DeviceRegistryEvents with ActionType ScheduledTaskCreated)
- **Why this matters:** Scheduled tasks provide reliable, SYSTEM-level persistence that survives reboots and blends with legitimate Windows activity.  
- **MITRE Technique:** T1053.005 – Scheduled Task/Job: Scheduled Task

**KQL Query Used:**

```kql
DeviceEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType, TaskName = tostring(AdditionalFields.TaskName), InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
<img width="1325" height="189" alt="image" src="https://github.com/user-attachments/assets/36871ce7-95f5-43c8-b402-03ee0a6c9c19" />

[Back to top](#top)


---

<a id="flag6"></a>

### 🚩 Flag 6 — Defender Setting Modified
- **Objective:** Identify what Defender setting was modified.  
- **Finding:** `C:\Windows\Temp`.  
- **Evidence:** Registry modification under Windows Defender Exclusions\Paths at 2025-09-16T19:39:48Z.  
- **Query Used:** (KQL query for DeviceRegistryEvents on Windows Defender Exclusions\Paths)
- **Why this matters:** Adding `C:\Windows\Temp` to exclusions prevents Defender from scanning staged payloads or exfiltration archives placed there.  
- **MITRE Technique:** T1562.001 – Impair Defenses: Disable or Modify Windows Defender

**KQL Query Used:**

```kql
DeviceRegistryEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where RegistryKey has "Windows Defender\\Exclusions\\Paths"
   or RegistryKey has "Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated desc
```
<img width="1319" height="268" alt="image" src="https://github.com/user-attachments/assets/14d64d22-74a7-4de4-a54f-289faf4e7a02" />

[Back to top](#top)

---

<a id="flag7"></a>

### 🚩 Flag 7 — Discovery Command
- **Objective:** Identify the discovery command the attacker ran.  
- **Finding:** `"cmd.exe" /c systeminfo`.  
- **Evidence:** Earliest post-execution process creation involving `cmd.exe` at 2025-09-16T19:40:28Z.  
- **Query Used:** (KQL query for DeviceProcessEvents with cmd.exe or powershell.exe post-execution)
- **Why this matters:** `systeminfo` is a standard T1082 technique for rapid host enumeration and situational awareness.  
- **MITRE Techniques:** T1082 – System Information Discovery

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where FileName contains "cmd" or FileName contains "powershell"
| order by TimeGenerated asc 
| where InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project TimeGenerated, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="1319" height="214" alt="image" src="https://github.com/user-attachments/assets/8e9f3b3f-1914-4007-81f4-ee1ed548d956" />

[Back to top](#top)

---


<a id="flag8"></a>

### 🚩 Flag 8 — Archive File Created
- **Objective:** Identify the archive file created by the attacker.  
- **Finding:** `backup_sync.zip`.  
- **Evidence:** File creation event for a .zip archive in `C:\Users\SLFlare\AppData\Local\Temp\` shortly after discovery activity.  
- **Query Used:** (KQL query for DeviceFileEvents where FileName endswith ".zip")
- **Why this matters:** Local archiving (T1560.001) stages collected data for efficient exfiltration.  
- **MITRE Technique:** T1560.001 – Archive Collected Data: Local Archiving

**KQL Query Used:**

```kql
DeviceFileEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where ActionType == "FileCreated"
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated asc 
```

<img width="1316" height="188" alt="image" src="https://github.com/user-attachments/assets/985495b7-9643-4da3-990c-256300c98cfc" />

[Back to top](#top)

---

<a id="flag9"></a>

### 🚩 Flag 9 — C2 Connection Destination
- **Objective:** Identify the C2 connection destination.  
- **Finding:** `185.92.220.87`.  
- **Evidence:** Earliest outbound network connection initiated by `msupdate.exe` to the external IP on port 80.  
- **Query Used:** (KQL query for DeviceNetworkEvents initiated by msupdate.exe)
- **Why this matters:** This establishes the attacker’s command-and-control channel and potential tool-download beacon.  
- **MITRE Techniques:** T1071.001 – Application Layer Protocol: Web Protocols (HTTP/S), T1105 – Ingress Tool Transfer


**KQL Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where InitiatingProcessFileName == "msupdate.exe"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated asc 
```
<img width="1326" height="132" alt="image" src="https://github.com/user-attachments/assets/f79c560d-b858-4c44-8b4b-e7ea2c294bd4" />

[Back to top](#top)

---

<a id="flag10"></a>

### 🚩 Flag 10 — Exfiltration Attempt
- **Objective:** Identify the exfiltration attempt.  
- **Finding:** `185.92.220.87:8081`.  
- **Evidence:** `curl.exe` POST of `backup_sync.zip` to the external endpoint over unencrypted HTTP.  
- **Query Used:** (KQL query for DeviceNetworkEvents where ProcessCommandLine contains backup_sync.zip)
- **Why this matters:** Data was staged and exfiltrated over an unencrypted protocol (T1048.003), confirming successful collection and outbound transfer.  
- **Flag Answer:**

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where InitiatingProcessCommandLine contains "backup_sync.zip"
| project TimeGenerated, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort
| order by TimeGenerated asc 
```
<img width="1415" height="138" alt="image" src="https://github.com/user-attachments/assets/c07bece6-9cdc-4883-830c-78523e064b54" />


[Back to top](#top)

---

<a id="key-findings-summary"></a>

## 📊 Key Findings Summary

| Flag | Objective                                      | Key Finding                          | Flag Answer                  |
|------|------------------------------------------------|--------------------------------------|------------------------------|
| 1    | Attacker IP Address                            | External IP used for RDP brute-force and successful login | `159.26.106.84`             |
| 2    | Compromised Account                            | Account that was successfully compromised via RDP | `slflare`                   |
| 3    | Executed Binary                                | Malicious binary dropped and executed after login | `msupdate.exe`              |
| 4    | Command Line Used                              | Full command line used to run the malicious binary | `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` |
| 5    | Persistence Mechanism                          | Persistence method created by the attacker | `MicrosoftUpdateSync`       |
| 6    | Defender Setting Modified                      | Path added to Microsoft Defender exclusions | `C:\Windows\Temp`           |
| 7    | Discovery Command                              | Command executed for host discovery | `"cmd.exe" /c systeminfo`   |
| 8    | Archive File Created                           | Compressed archive file used for data staging | `backup_sync.zip`           |
| 9    | C2 Connection Destination                      | External Command & Control server IP | `185.92.220.87`             |
| 10   | Exfiltration Attempt                           | Destination used for data exfiltration | `185.92.220.87:8081`        |


[Back to top](#top)

---

<a id="mitre-attck-mapping"></a>

## 🛡️ MITRE ATT&CK Mapping

| Flag | Description                          | MITRE ATT&CK Tactic                  | MITRE ATT&CK Technique                          | Technique ID     | Sub-Technique ID     |
|------|--------------------------------------|--------------------------------------|-------------------------------------------------|------------------|----------------------|
| 1    | Attacker IP Address (RDP Brute Force) | Initial Access                      | Brute Force                                     | T1110           | T1110.001 (Password Guessing) |
| 1    | Attacker IP Address (RDP Access)     | Initial Access                      | Remote Services: Remote Desktop Protocol        | T1021           | T1021.001           |
| 2    | Compromised Account (`slflare`)      | Initial Access / Persistence        | Valid Accounts                                  | T1078           | -                   |
| 3    | Executed Binary (`msupdate.exe`)     | Execution                           | User Execution / Command and Scripting Interpreter | T1204 / T1059   | T1059.001 (PowerShell) |
| 4    | Command Line Used                    | Execution                           | Command and Scripting Interpreter               | T1059           | T1059.001 (PowerShell) |
| 5    | Persistence Mechanism (`MicrosoftUpdateSync`) | Persistence / Privilege Escalation | Scheduled Task/Job: Scheduled Task              | T1053           | T1053.005           |
| 6    | Defender Setting Modified (`C:\Windows\Temp`) | Defense Evasion                    | Impair Defenses: Disable or Modify Tools        | T1562           | T1562.001           |
| 7    | Discovery Command (`systeminfo`)     | Discovery                           | System Information Discovery                    | T1082           | -                   |
| 8    | Archive File Created (`backup_sync.zip`) | Collection                       | Archive Collected Data: Archive via Utility     | T1560           | T1560.001           |
| 9    | C2 Connection Destination            | Command and Control                 | Application Layer Protocol                      | T1071           | -                   |
| 10   | Exfiltration Attempt (`curl` to 185.92.220.87:8081) | Exfiltration                | Exfiltration Over Alternative Protocol          | T1048           | T1048.003 (Unencrypted/Non-C2 Protocol) |

**Notes:**  
- Some flags map to multiple techniques depending on the observed behavior.  
- Mapping is derived directly from the threat hunt findings.

[Back to top](#top)

---
 
<a id="recommendation"></a>

## 📌 Recommendations
- Immediately isolate and re-image the compromised host `slflarewinsysmo`.
- Reset the `slflare` account password and enforce MFA for all RDP access.
- Review and remove the malicious scheduled task `MicrosoftUpdateSync` and Defender exclusion.
- Block the attacker IP `159.26.106.84` and C2 infrastructure `185.92.220.87` at the firewall level.
- Enable enhanced RDP logging and consider restricting RDP exposure or implementing a bastion host / Zero Trust model.
- Conduct a full credential sweep and monitor for lateral movement.

[Back to top](#top)

**End of Report**  
