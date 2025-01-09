## Threat Actor: 8Base 🎱
8Base is a ransomware group that emerged in March 2022 and gained significant attention in mid-2023 due to a surge in its activities. The group positions itself as “simple penetration testers” to justify its double-extortion strategy, encrypting victims' data and threatening to publicly disclose sensitive information to compel ransom payments. 


---
### Overview
- **Aliases:** EightBase
- **Type:** Ransomware-as-a-Service
- **First Identified:** March 2022
- **Region of Operation:** Primarily targets organizations in the United States, Brazil, and the United Kingdom, with a focus on small to medium-sized businesses. 
- **Primary Targets:** Diverse range of industries, including healthcare, manufacturing, and other sectors.
- **Motivation:** Financial gain through ransom payments

---
### Known Campaigns
- **Campaign 1:** Attack on a U.S. Healthcare Organization
  - **Date:** October 2023
  - **Target(s):** Healthcare and public health sector organizations in the United States. 
  - **Impact:** Data encryption and exfiltration, leading to operational disruptions and potential exposure of sensitive patient information.
- **Campaign 2:** June 2023 Campaign
  - **Date:** June 2023
  - **Target(s):** Nearly 40 victims.
  - **Impact:** Second only to LockBit in number of victims that month.

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:**
  - T1566: Phishing
  - T1078: Valid Accounts
  - T1059: Command and Scripting Interpreter
  - T1562: Impair Defenses
  - T1027: Obfuscated Files or Information
- **Common Tools Used:** 
  - Phobos ransomware (version 2.9.1), SmokeLoader, SystemBC, MIMIKATZ, LaZagne, 	RClone.
  -  WebBrowserPassView, VNCPassView, PasswordFox, ProcDump, PCHunter, GMER, Process Hacker.
- **Infection Vector:** 
  - Phishing emails
  - Exploit kits
  - Drive-by downloads 

---
### Known Affiliations
- **Ransomware Affiliates:** Shares similarities with Phobos ransomware, though no formal relationship has been established
- **Initial Access Brokers:** Collaborates with IABs to infiltrate target systems
- **Other Threat Actors:** Similarities noted with RansomHouse in communication style

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - Also seen with ransome note::	info.hta;info.txt
- **Domains/URLs:** 
  - fp2e7a[.]wpc[.]2be4[.]phicdn.net
  - fp2e7a[.]wpc[.]2be4[.]phicdn.net
  - dexblog45[.]xyz
  - sentrex219[.]xyz
- **IP Addresses:** 
  - 40[.]119[.]148[.]38
  - 192[.]229[.]221[.]95
  - 18[.]166[.]250[.]135
  - 45[.]89[.]125[.]136
  - 45[.]131[.]66[.]120
- https://documents.trendmicro.com/images/TEx/articles/RS-8Base-IOClRKhJ8p.txt
---
### References
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-8base
- https://www.vectra.ai/threat-actors/8base
- https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/8base-ransomware-group/
- https://www.provendata.com/blog/8base-ransomware/
- https://socradar.io/dark-web-profile-8base-ransomware/
- https://github.com/threatlabz/ransomware_notes/blob/main/8base/8base_note.txt
