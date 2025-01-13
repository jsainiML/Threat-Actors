## Threat Actor: Qilin
The Qilin ransomware group, also known as Agenda, is a cybercriminal organization operating a RaaS model. Active since 2022, Qilin has targeted various industries worldwide, including healthcare, causing significant disruptions and financial losses.

---
### Overview
- **Aliases:** Agenda, AgendaCrypt
- **Type:** Ransomware-as-a-Service
- **First Identified:** July 2022
- **Region of Operation:** Global, avoiding CIS countries
- **Primary Targets:** Large enterprises, critical infrastructure, healthcare, education, manufacturing, government institutions
- **Motivation:** Primarily financial, with some claims of politically motivated attacks

---
### Known Campaigns
- **Campaign 1:** Attack on Thonburi Energy Storage Systems
  - **Date:** 2023
  - **Target(s):** Thonburi Energy Storage Systems, a battery manufacturer in Thailand
  - **Impact:** Operational disruptions and potential data exfiltration
- **Campaign 2:** Attack on Synnovis
  - **Date:** June 2024
  - **Target(s):** Synnovis, a UK-based medical laboratory company
  - **Impact:** Disruption of pathology services, affecting multiple NHS hospitals in London, leading to canceled operations and appointments, $50 million ransom demand, 400GB data leak.

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - T1566: Phishing
  - T1078: Valid Accounts
  - T1059: Command and Scripting Interpreter
  - T1562: Impair Defenses
  - T1027: Obfuscated Files or Information
- **Common Tools Used:** 
  - Custom ransomware payloads written in Go and Rust
  - Mimikatz, PsExec, VMware vCenter, PowerShell, Remote Monitoring and Management (RMM) tools
- **Infection Vector:** 
  - Phishing emails with malicious links, exploitation of vulnerabilities in Fortinet devices
  - Exploitation of vulnerable RDP services

---
### Known Affiliations
- **Ransomware Affiliates:** Operates a RaaS model, recruiting affiliates who receive 80-85% of ransom payments
- **Initial Access Brokers:** Utilizes compromised credentials and collaborates with affiliates for initial access
- **Other Threat Actors:** N/A

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527
  - 55e070a86b3ef2488d0e58f945f432aca494bfe65c9c4363d739649225efbbd1
  - 37546b811e369547c8bd631fa4399730d3bdaff635e744d83632b74f44f56cf6
- **Domains/URLs:** 
  - ikea0[.]com 
  - lebondogicoin[.]com 
  - gfs440n010.userstorage.me ga.co[.]nz 
  - gfs440n010.userstorage.me ga.co[.]nz 
- **IP Addresses:**
  - 93.115.25[.]139 
  - 194.165.16[.]13 
  - 91.238.181[.]230 
  - 184.168.123[.]220 
  - 184.168.123[.]219 
  - 184.168.123[.]236 

---
### References
- https://www.trendmicro.com/en_us/research/22/l/agenda-ransomware-uses-rust-to-target-more-vital-industries.html
- https://cybersrcc.com/2024/10/25/new-qilin-b-ransomware-variant-emerges-with-improved-encryption-and-evasion-tactics/
- https://www.avertium.com/resources/threat-reports/qilin-ransomware
- https://www.group-ib.com/blog/qilin-ransomware/
- https://darktrace.com/blog/a-busy-agenda-darktraces-detection-of-qilin-ransomware-as-a-service-operator
