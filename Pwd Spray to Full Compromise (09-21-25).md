<a id="top"></a>
# 🕵️ The Cyber Range - The Great Admin Heist CTF

## 🌟 Table of Contents 🌟

- [🌍 Executive Summary](#executive-summary)
- [🔬 Hypothesis](#hypothesis)
- [📅 Timeline of Events](#timeline-of-events)
- [🚩 Flag 1 — Attacker IP Address](#flag1)
- [🚩 Flag 2 — Compromised Account](#flag2)
- [🚩 Flag 3: Execution of the Program](#flag-3-execution-of-the-program)
- [🚩 Flag 4 - Keylogger Artifact Written](#flag-4---keylogger-artifact-written)
- [🚩 Flag 5 - Registry Persistence Entry](#flag-5---registry-persistence-entry)
- [🚩 Flag 6 - Daily Scheduled Task Created](#flag-6---daily-scheduled-task-created)
- [🚩 Flag 7 - Process Spawn Chain](#flag-7---process-spawn-chain)
- [🚩 Flag 8 - Timestamp Correlation](#flag-8---timestamp-correlation)
- [📊 Conclusion, Investigation Timeline & Key Findings](#conclusion-investigation-timeline--key-findings)
- [🛡️ MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [🛠️ Remediation](#remediation)

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
MITRE Technique: T1110.001 – Brute Force: Password Guessing

- **Objective:** Identify the external IP that successfully logged in via RDP after repeated failures.  
- **Finding:** Attacker IP `159.26.106.84`.  
- **Evidence:** Multiple brute-force attempts observed from the same external IP starting 13 September 2025, with successful login at 2025-09-16T18:40:57.3785102Z on DeviceName containing “flare”.  
- **Query Used:** (KQL query for DeviceLogonEvents filtered by DeviceName and RemoteIP)
- **Why this matters:** Multiple failed attempts followed by a success confirms a brute-force or password spray attack, establishing the initial access vector.
- **MITRE Technique:** T1110.001 – Brute Force: Password Guessing

**KQL Query Used:**

```
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

```
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

<a id="flag-3-execution-of-the-program"></a>
# 🚩 Flag 3: Execution of the Program

**Objective:**
Verify whether the dropped malicious file was manually executed by the user or attacker.

**What to Hunt:**
Search for process execution events tied to the suspicious binary.

**Hint:**
1. Bubba clicked the .exe file himself.

<img src="https://i.imgur.com/PjcYPQp.png">

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName contains "anthony-001"
| where InitiatingProcessRemoteSessionDeviceName contains "bubba"
| where FileName == "BitSentinelCore.exe"
| where Timestamp >= datetime(2025-05-07T02:00:36.794406Z)
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

To verify whether the suspicious file `BitSentinelCore.exe` was manually executed by Bubba, I ran a KQL query on the `DeviceProcessEvents` table. I filtered for the device `anthony-001` and narrowed it down to process events where the initiating process’s remote session device name included `“bubba”`, indicating actions started from Bubba’s session.

I specifically looked for events involving `BitSentinelCore.exe`, the malicious file we identified earlier. By projecting columns like the timestamp, file name, folder path, initiating process name, and command line, I was able to track exactly when and how the file was triggered.

The results confirmed that the file was executed from Bubba’s user session, aligning with the hint that he manually launched the `.exe` file. This clearly indicates user interaction and marks the official start of the malicious payload's execution. The initiating process being `explorer.exe` further supports this, as it suggests Bubba likely double-clicked the `BitSentinelCore.exe` file himself—consistent with a user-initiated action.

---

### 📑 Task: Provide the value of the command utilized to start up the program.

### ✅ Flag 3 Answer: BitSentinelCore.exe

---

<a id="flag-4---keylogger-artifact-written"></a>
# 🚩 Flag 4 – Keylogger Artifact Written

**Objective:**
Identify whether any artifact was dropped that indicates keylogger behavior.

**What to Hunt:**
Search for any file write events associated with possible keylogging activity.

**Hints:**
1. "A rather efficient way to completing a complex process." 
2. News.

<img src="https://i.imgur.com/Uc51ZeL.png">

**KQL Query Used:**

```
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where InitiatingProcessRemoteSessionDeviceName contains "bubba"
| where Timestamp >= datetime(2025-05-07T02:00:36.794406Z)
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

To identify a keylogger artifact dropped by `BitSentinelCore.exe`, I queried `DeviceFileEvents` for file write events on `anthony-001` during Bubba’s remote session (where `InitiatingProcessRemoteSessionDeviceName` includes “`bubba`”) after `2025-05-07T02:00:36.794406Z`. I projected columns like timestamp, file name, folder path, and initiating process to pinpoint suspicious files.

The results showed a shortcut file, `systemreport.lnk`, created by `explorer.exe` on `2025-05-07T02:06:51.3594039Z` in `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent`. This file’s name and location suggest it’s a disguised artifact, likely pointing to a log file that captures keystrokes, a common keylogger tactic. The folder `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent` is often used for shortcuts to recently accessed files, making it a stealthy spot for a keylogger. Since `systemreport.lnk` was created by `explorer.exe` in Bubba’s session at `2025-05-07T02:06:51.3594039Z` with a suspicious name, it likely points to a keylogging script or log file.


## Further Analysis

I wanted to check whether `systemreport.lnk` has been observed in the wild before, so I searched for it on Google.

<img src="https://i.imgur.com/P98xac1.png">

ℹ️ [View ANY.RUN Report](https://any.run/report/187124067072ab792c3b14f45ec5d499dade48a7b2a2cb6baa5d6056672bf9d8/24afbe84-5f2a-4d7a-a561-5d807d6132b8)

The search returned a result from `ANY.RUN`, a malware analysis website, showing that this file has been previously linked to malware. I also checked whether this file is part of any legitimate Windows system files but found no evidence of that. This further supports my conclusion that the file is malicious and confirms the answer to this flag.

---

### 📑 Task: What was the name of the keylogger file?

### ✅ Flag 4 Answer: systemreport.lnk

---

<a id="flag-5---registry-persistence-entry"></a>
# 🚩 Flag 5 – Registry Persistence Entry

**Objective:**
Determine if the malware established persistence via the Windows Registry.

**What to Hunt:**
Look for registry modifications that enable the malware to auto-run on startup.

**Hint:**
1. Long answer.

<img src="https://i.imgur.com/Ak3Vh7d.png">

**KQL Query Used:**

```
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where Timestamp >= datetime(2025-05-07T02:00:36.794406Z)
| where InitiatingProcessFileName has "BitSentinelCore.exe"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

To investigate whether `BitSentinelCore.exe` established persistence via the Windows Registry, I queried the `DeviceRegistryEvents` table for activity on the `anthony-001` device from `2025-05-07T02:00:36.794406Z` onwards. I filtered for registry events where the `InitiatingProcessFileName` contains `BitSentinelCore.exe`. The results showed a modification at `2025-05-07T02:02:14.9669902Z` to the registry path `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, with `RegistryValueData` set to `C:\ProgramData\BitSentinelCore.exe`, ensuring the malware runs at startup.

---

### 📑 Task: Identify the full Registry Path value.

### ✅ Flag 5 Answer: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

---

<a id="flag-6---daily-scheduled-task-created"></a>
# 🚩 Flag 6 - Daily Scheduled Task Created

**Objective:**
Identify the value proves that the attacker intents for long-term access.

**What to Hunt:**
Identify name of the associated scheduled task.

**Hints:**
1. Three.
2. Fitness.

<img src="https://i.imgur.com/SuHZLkQ.png">

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= datetime(2025-05-07T02:00:36.794406Z)
| where ProcessCommandLine has "schtasks"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

I searched for scheduled task creation commands by filtering for `schtasks` in the process command line on the device `anthony-001` from `2025-05-07T02:00:36.794406Z` onwards. At `2025-05-07T02:02:14.9749438Z`, `cmd.exe` initiated `schtasks.exe` with the command: `"cmd.exe" /c schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00`.

This task runs daily at 2PM and points to the `BitSentinelCore.exe` executable, confirming the attacker set up persistence for long-term access via a daily scheduled task. So, the answer to this flag is the scheduled task `"UpdateHealthTelemetry"`. The hint ‘`fitness`’ was useful here because it relates to ‘`health`’ in the scheduled task name.

---

### 📑 Task: What is the name of the created scheduled task?

### ✅ Flag 6 Answer: UpdateHealthTelemetry

---

<a id="flag-7---process-spawn-chain"></a>
# 🚩 Flag 7 – Process Spawn Chain

**Objective:**
Understand the full chain of process relationships that led to task creation.

**What to Hunt:**
Trace the parent process that led to cmd.exe, and subsequently to schtasks.exe.

**Hint:** (how the answer should look)
bubba.exe -> newworldorder.exe -> illuminate.exe

<img src="https://i.imgur.com/F9MwiLz.png">

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= datetime(2025-05-07T02:00:36.794406Z)
| where FileName in ("cmd.exe", "schtasks.exe")
| project Timestamp, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessId, ProcessCommandLine
| order by Timestamp asc
```

To trace the complete process chain behind the scheduled task creation, I analysed process events on the `anthony-001` device, starting from `2025-05-07T02:00:36.794406Z`. 

The command line identified was:

```
"cmd.exe" /c schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00
```

This revealed that `BitSentinelCore.exe`, via a spawned `cmd.exe`, executed `schtasks.exe` to establish a daily scheduled task named `UpdateHealthTelemetry` that runs `BitSentinelCore.exe` itself.

Examining the parent-child process relationships confirmed the sequence as:

**BitSentinelCore.exe -> cmd.exe -> schtasks.exe**

This indicates the malware initiated a command shell `(cmd.exe)`, which then leveraged the Windows Task Scheduler tool `(schtasks.exe)` to ensure its persistence on the system.

---

### 📑 Task: Provide the kill chain.

### ✅ Flag 7 Answer: BitSentinelCore.exe -> cmd.exe -> schtasks.exe

---

<a id="flag-8---timestamp-correlation"></a>
# 🚩 Flag 8 – Timestamp Correlation

**Objective:**
Correlate all observed behaviors to a single initiating event

**What to Hunt:**
Compare timestamps from the initial execution to file creation, registry modification, and task scheduling.

**Thought:**
Builds a forensic timeline that strengthens cause-and-effect analysis, confirming that all actions originated from the execution of the fake antivirus program.

I identified the initial event that triggered this entire incident early in the investigation, allowing me to correlate subsequent activities in chronological order. The timestamp for this event is `2025-05-07T02:00:36.794406Z`.

---

### 📑 Task: Provide the timestamp of the leading event that's causing all these mess.

### ✅ Flag 8 Answer: 2025-05-07T02:00:36.794406Z

---

<a id="conclusion-investigation-timeline--key-findings"></a>
# 📊 Conclusion, Investigation Timeline & Key Findings

At Acme Corp, the Phantom Hackers targeted Bubba Rockerfeatherman III’s privileged IT admin account to steal sensitive data. Using Microsoft Defender for Endpoint telemetry and KQL queries, I uncovered a multi-stage attack on the device `anthony-001`. The initial stage of the compromise began when `BitSentinelCore.exe` was written to disk at `2025-05-07T02:00:36.794406Z`, with the active phase starting upon execution by user `Bubba` at `2025-05-07T02:02:14.6264638Z`.


The timeline of events is as follows:

- **2025-05-07T02:00:36.794406Z**: `BitSentinelCore.exe` (malicious file) written to disk. This marks the earliest detection of this file, indicating the initial stage of the attack.

- **2025-05-07T02:02:14.6264638Z**: `BitSentinelCore.exe` executed by user Bubba, initiating the active phase of the malicious program.

- **2025-05-07T02:02:14.9669902Z**: Registry modification in `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` performed by `BitSentinelCore.exe` to ensure persistence on system reboot.

- **2025-05-07T02:02:14.9749438Z**: Daily scheduled task `UpdateHealthTelemetry` created through a process chain (`BitSentinelCore.exe -> cmd.exe -> schtasks.exe`) to enable repeated execution of the malicious program.

- **2025-05-07T02:06:51.3594039Z**: Keylogger artifact `systemreport.lnk` written, possibly beginning data collection or exfiltration activities.

The attack began when the malicious file BitSentinelCore.exe was created on the system using csc.exe, a legitimate Microsoft tool — likely as a way to avoid detection. Shortly after, user Bubba unknowingly executed the file, triggering the active phase of the intrusion. The malware then established persistence through registry modifications and a scheduled task. Immediate remediation is critical to secure Bubba’s account and prevent further compromise of Acme’s systems and assets.

## Click the image to explore the timeline!

[![Timeline](https://i.imgur.com/lA4t98q.png)](https://serg-luka.github.io/Threat-Hunting-CTF/timeline.html)


## Key Findings

| Flag | Objective | Key Findings | Flag Answer |
|------|-----------|--------------|-------------|
| **1** | Identify the fake antivirus program name | Queried `DeviceProcessEvents` for `.exe` files on `anthony-001` starting with A, B, or C. Identified `BitSentinelCore.exe`, likely the malicious program. | `BitSentinelCore.exe` |
| **2** | Confirm malicious file written to disk | Queried `DeviceFileEvents` for `BitSentinelCore.exe` on `anthony-001`. Found `csc.exe` (Microsoft C# compiler) compiled and wrote the binary to disk, indicating a "living off the land" tactic. | `csc.exe` |
| **3** | Verify manual execution of the program | Queried `DeviceProcessEvents` for `BitSentinelCore.exe` execution in Bubba’s session on `anthony-001`. Confirmed Bubba manually executed the file. | `BitSentinelCore.exe` |
| **4** | Identify keylogger artifact | Queried `DeviceFileEvents` for file writes in Bubba’s session post-initial event. Found `systemreport.lnk` created by `explorer.exe`, likely a keylogger artifact. | `systemreport.lnk` |
| **5** | Detect registry persistence entry | Queried `DeviceRegistryEvents` for `BitSentinelCore.exe` activity. Found modification to `HKEY_CURRENT_USER\...\Run` to run `BitSentinelCore.exe` at startup. | `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **6** | Identify scheduled task for persistence | Queried `DeviceProcessEvents` for `schtasks` commands. Found `cmd.exe` created daily task `UpdateHealthTelemetry` to run `BitSentinelCore.exe`. | `UpdateHealthTelemetry` |
| **7** | Trace process spawn chain | Analysed `DeviceProcessEvents` for `cmd.exe` and `schtasks.exe`. Established chain: `BitSentinelCore.exe` initiated `cmd.exe`, which ran `schtasks.exe`. | `BitSentinelCore.exe -> cmd.exe -> schtasks.exe` |
| **8** | Correlate behaviors to initiating event | Built forensic timeline from initial execution of `BitSentinelCore.exe` at `2025-05-07T02:00:36.794406Z`, linking all subsequent events (file writes, registry changes, task creation). | `2025-05-07T02:00:36.794406Z` |

<a id="mitre-attck-mapping"></a>
# 🛡️ MITRE ATT&CK Mapping

| ID | MITRE Tactic | MITRE Technique | Description |
|----|--------------|-----------------|-------------|
| 1  | Initial Access (TA0001) | Phishing: Spearphishing Attachment (T1566.001) | Attackers use phishing emails with malicious attachments to gain initial access to the target system. |
| 2  | Execution (TA0002) | User Execution: Malicious File (T1204.002) | A user is tricked into executing a malicious file, triggering the attack payload. |
| 3  | Execution (TA0002) | Native API (T1106) | Attackers leverage legitimate system binaries to execute malicious code, blending into normal operations. |
| 4  | Collection (TA0009) | Input Capture: Keylogging (T1056.001) | Malware captures user keystrokes to steal credentials or sensitive data. |
| 5  | Persistence (TA0003) | Registry Run Keys / Startup Folder (T1547.001) | Malware modifies registry keys to ensure execution on system startup. |
| 6  | Persistence (TA0003) | Scheduled Task/Job: Scheduled Task (T1053.005) | A scheduled task is created to maintain long-term access to the compromised system. |
| 7  | Execution (TA0002) | Command and Scripting Interpreter: Windows Command Shell (T1059.003) | Attackers use the Windows command shell to execute commands and further their attack. |

<a id="remediation"></a>
# 🛠️ Remediation

- Isolate the compromised machine (`anthony-001`) to prevent further malicious activity or lateral movement.
- Remove `BitSentinelCore.exe` from the system.
- Delete the `UpdateHealthTelemetry` scheduled task.
- Revert the registry entry in `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
- Run a comprehensive antivirus scan on `anthony-001` with updated software to detect and remove additional malicious files or artifacts. Since the fake antivirus `BitSentinelCore.exe` was dropped via `csc.exe`, a legitimate Microsoft tool, investigate scan results and logs to trace the root cause, such as a phishing email or malicious script that triggered the compilation.
- Update security policies to prevent future incidents, including enhancing user training on phishing awareness, strengthening email filtering to block malicious attachments, and implementing application allowlisting to restrict unverified executables.
- Reset Bubba’s credentials to secure Acme’s assets.
