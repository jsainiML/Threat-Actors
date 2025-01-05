## Threat Actor: LockBit 🔒
LockBit is a highly active ransomware group that has been operating since September 2019. Functioning under a Ransomware-as-a-Service (RaaS) model, it recruits affiliates to execute ransomware attacks using its tools and infrastructure.

Their operations are financially motivated, targeting various industries worldwide, including healthcare, education, financial services, and critical infrastructure. Over the course have led to significant disruptions and financial losses for numerous organizations.

In recent developments, law enforcement agencies have intensified efforts against LockBit. Notably, the group's website, infrastructure, and data have been seized, marking a substantial blow to their operations. 
Additionally, affiliates and developers associated with LockBit have faced legal actions, including arrests and charges, highlighting the ongoing international efforts to dismantle the group's activities. 

---
### Overview
- **Aliases:** ABCD ransomware(predecessor), LockBit 2.0, LockBit 3.0, LockBit Green, and LockBit Linux-ESXi Locker
- **Type:** Ransomware-as-a-Service (RaaS) Group
- **First Identified:** September 2019
- **Region of Operation:** Global, with significant activity in North America, Europe, and Asia Pacific
- **Primary Targets:** Various industries, including healthcare, education, financial services, and critical infrastructure
- **Motivation:** Primarily financial

---
### Known Campaigns
- **Campaign 1:** Accenture Attack
  - **Date:** 2021
  - **Target(s):** Accenture
  - **Impact:** Data theft and publication of stolen data

- **Campaign 2:** Attack on Hospital Center Sud Francilien
  - **Date:** 2022
  - **Target(s):** Hospital Center Sud Francilien in France
  - **Impact:**  IT system shutdown, patient data compromised, and operational disruptions

- **Campaign 3:** Royal Mail Attack
  - **Date:** 2023
  - **Target(s):** Royal Mail (UK)
  - **Impact:** Severe disruption of international export services
    
---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** [List related TTPs with links if possible]
  - Initial Access: Exploitation of public-facing applications (T1190), Phishing (T1566)
  - Privilege Escalation: Exploitation for Privilege Escalation (T1068)
  - Defense Evasion: Obfuscated Files or Information (T1027)
  - Credential Access: OS Credential Dumping (T1003)
  - Lateral Movement: Remote Services: SMB/Windows Admin Shares (T1021.002)
  - Impact: Data Encrypted for Impact (T1486)
- **Common Tools Used:**
  - Mimikatz
  - Cobalt Strike
  - Socgholish
  - PsExec
  - StealBit (data exfiltration tool)
  - Megasync
  - Meterpreter
- **Infection Vector:**
  - Phishing emails with malicious attachments or links
  - Exploitation of unpatched vulnerabilities in public-facing applications
  - Compromised Remote Desktop Protocol (RDP) credentials

---
### Known Affiliations
- **Ransomware Affiliates:** 
  - They operates under a RaaS model, recruiting affiliates to conduct attacks using LockBit ransomware tools and infrastructure
- **Initial Access Brokers:** 
  - In LockBit’s RaaS model, the primary operating group recruits Initial Access Brokers (IAB) through advertisements on the dark web to obtain stolen credentials for Remote Desktop Protocol (RDP) or Virtual Private Network (VPN) access
- **Other Threat Actors:** 
  - Previously cooperated with Maze

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - LockBit 2.0 sample: e8c398d32d4f045e4f3cb5b8ac9a03d7
  - LockBit 3.0 sample: 9a5e531af67e8bcf4ec8d2a55a349c77
- **Process Names:**
  - lockbit.exe
  - locker.exe
- **Reliable list:**
  - https://documents.trendmicro.com/images/TEx/articles/LockBit_IOCs_Update_2023.04.18NCkxjHb.txt
  - https://github.com/sophoslabs/IoCs/blob/master/Ransomware-LockBit
  
---
### References
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-lockbit
- https://www.esentire.com/blog/russia-linked-lockbit-ransomware-gang-attacks-an-msp-and-two-manufacturers
- https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/lockbit
- https://x.com/vxunderground/status/1618885718839001091?s=20
- https://github.com/RussianPanda95/IDAPython/blob/main/LockBit/lockbit_string_decrypt.py
