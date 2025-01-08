## Threat Actor: Akira 
Akira is a ransomware group that emerged in March 2023, operating as a RaaS platform. The group has targeted over 250 entities across various sectors, including government, healthcare, and critical infrastructure, primarily in North America, Europe, and Australia. 


---
### Overview
- **Aliases:** None known.
- **Type:** Ransomware-as-a-Service
- **First Identified:** March 2023. 
- **Region of Operation:** Global.
- **Primary Targets:** Diverse range of industries, including healthcare, manufacturing, and government.
- **Motivation:** Financial gain through extortion

---
### Known Campaigns
- **Campaign 1:** Attack on Stanford University.
  - **Date:** September 2023.
  - **Target(s):** Stanford University's data systems.
  - **Impact:** Leak of data from 27,000 individuals

- **Campaign 2:** Attack on Tietoevry, a Finnish IT services provider.
  - **Date:** January 2024.
  - **Target(s):** Tietoevry's cloud services, affecting multiple Swedish organizations.
  - **Impact:** Disruption of services and data exfiltration. 

- **Campaign 1:** LATAM Airline Industry Attack:
  - **Date:** July 2024
  - **Target(s):** LATAM airline infrastructure
  - **Impact:**  Data exfiltration and ransomware deployment

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - Hide Artifacts: Run Virtual Instance	T1564.006
  - Remote Services: Remote Desktop Protocol	T1021.001
  - OS Credential Dumping	T1003
  - Archive Collected Data	T1560
  - Remote Access Software	T1219
  - Automated Exfiltration	T1020
  - Data Encrypted for Impact	T1486
  - Exploit Public-Facing Application	T1190
  - External Remote Services	T1133
  - Valid Accounts	T1078
  - File and Directory Discovery	T1083
- **Common Tools Used:** 
  - FileZilla, WinRAR, AnyDesk, Rclone, SoftPerfect Network Scanner,SharpHound.
  - LOLBAS (Living Off the Land Binaries and Scripts), ChaCha2008 encryption
- **Infection Vector:**
  - Phishing emails, Compromised credentials, often lacking multi-factor authentication
  - exploitation of VPN vulnerabilities (e.g., Cisco CVE-2020-3259 and CVE-2023-20269)

---
### Known Affiliations
- **Ransomware Affiliates:** 
  - Potential links to the now-defunct Conti ransomware group, as indicated by overlapping code and shared cryptocurrency wallets
  - Storm-1567 (also known as Punk Spider and GOLD SAHARA)
- **Initial Access Brokers:**
  - Likely acquisition of compromised credentials from brokers
- **Other Threat Actors:**
  - No confirmed alliances beyond potential Conti connections.

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - aaa647327ba5b855bedea8e889b3fafdc05a6ca75d1cfd98869432006d6fecc9
  - 3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75
  - 5e1e3bf6999126ae4aa52146280fdb913912632e8bac4f54e98c58821a307d32
  - 03aa12ac2884251aa24bf0ccd854047de403591a8537e6aba19e822807e06a45
  - 2e88e55cc8ee364bf90e7a51671366efb3dac3e9468005b044164ba0f1624422
  - 40221e1c2e0c09bc6104548ee847b6ec790413d6ece06ad675fff87e5b8dc1d5
  - 0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df2827
- **File extenstion:**
  - .akira
  - .powerranges
  - .akiranew
- **IP Addresses:** 
  - 45.227.254[.]26	
  - 80.66.88[.]203	
  - 91.240.118[.]29	
  - 152.89.196[.]111	
  - 194.26.29[.]102	
  - 185.11.61[.]114

---
### References
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-akira
- https://therecord.media/akira-ransomware-group-publishes-unprecedented-leak-data
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
- https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/akira-ransomware/
- https://socprime.com/blog/akira-ransomware-group-is-on-the-rise-hackers-target-the-airline-industry-in-latam/
- https://blog.qualys.com/vulnerabilities-threat-research/2024/10/02/threat-brief-understanding-akira-ransomware#mitre-attck-techniques
- https://github.com/rivitna/Malware/tree/main/Akira
