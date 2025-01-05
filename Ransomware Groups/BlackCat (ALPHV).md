## Threat Actor: BlackCat (ALPHV) 🐈‍⬛
BlackCat, also known as ALPHV or Noberus, is a sophisticated ransomware group that emerged in November 2021. Operating under a Ransomware-as-a-Service (RaaS) model, BlackCat is notable for being the first widely known ransomware family written in the Rust programming language, which enhances its performance and cross-platform capabilities. 

The group has targeted numerous organizations worldwide across various sectors, including healthcare, education, and critical infrastructure. Their attacks often involve double extortion tactics, where data is both encrypted and exfiltrated, with threats to publish the stolen data to pressure victims into paying ransoms. 

Law enforcement agencies, including the U.S. Department of State, have intensified efforts against BlackCat, offering rewards for information leading to the identification or location of its leaders. Despite these efforts, BlackCat remains a persistent threat in the cybersecurity landscape.

---
### Overview
- **Aliases:** ALPHV, Noberus, ALPHV-ng, AlphaV, AlphaVM, UNC4466
- **Type:** Ransomware-as-a-Service (RaaS) Group
- **First Identified:** November 2021
- **Region of Operation:** Global
- **Primary Targets:** Various industries including financial, manufacturing, legal, professional services, healthcare, government, and critical infrastructure
- **Motivation:** Primarily financial

---
### Known Campaigns
- **Campaign 1:** MGM Resorts Attack
  - **Date:** 2023
  - **Target(s):** MGM Resorts
  - **Impact:** Significant disruption to operations, estimated $100 million in damages

- **Campaign 2:** Reddit Data Breach
  - **Date:** 2023
  - **Target(s):** Reddit
  - **Impact:** 80 GB of compressed data stolen, $4.5 million ransom demand

- **Campaign 3:** Attack on Fidelity National Financial
  - **Date:** 2023
  - **Target(s):** Fidelity National Financial
  - **Impact:** Operational disruptions; ransom demanded

- **Campaign 4:** Attack on Change Healthcare
  - **Date:** 2024
  - **Target(s):** Change Healthcare
  - **Impact:** Significant operational disruptions; $22 million ransom paid 


---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - Initial Access: Exploitation of public-facing applications (T1190), Phishing (T1566)
  - Execution: Command and Scripting Interpreter: PowerShell (T1059.001)
  - Privilege Escalation: Exploitation for Privilege Escalation (T1068)
  - Defense Evasion: Obfuscated Files or Information (T1027)
  - Credential Access: OS Credential Dumping (T1003)
  - Lateral Movement: Remote Services: SMB/Windows Admin Shares (T1021.002)
  - Impact: Data Encrypted for Impact (T1486)
- **Common Tools Used:**
  - Nitrogen malware
  - Brute Ratel C4
  - Cobalt Strike
  - Evilginx2
  - POORTRY
  - STONESTOP
  - PsExec
- **Infection Vector:** 
  - Phishing
  - social engineering exploiting software vulnerabilities
  - malvertising through Google Ads

---
### Known Affiliations
- **Ransomware Affiliates:**
  - Operates a RaaS model with numerous affiliates, including Scattered Spider and Notchy
- **Initial Access Brokers:**
  - Collaborates with initial access brokers
- **Other Threat Actors:** 
  - Related to BlackMatter and DarkSide ransomware groups

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - a50ddd96edf7f66a29b407657e8548e2b026bf1ac3d4e08e396f4043d4513f9e
  - 9078564b65b9ac3ce4f59c929207f17037ef971429f0d3ef3751d46651fec8c6 	
  - 847FB7609F53ED334D5AFFBB07256C21CB5E6F68B1CC14004F5502D714D2A456
  - 3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1
  - 9802a1e8fb425ac3a7c0a7fca5a17cfcb7f3f5f0962deb29e3982f0bece95e26
  - f7a038f9b91c40e9d67f4168997d7d8c12c2d27cd9e36c413dd021796a24e083
- **Domains/URLs:** [List associated domains or URLs]
  - allpcsoftware[.]com
  - wireshhark[.]com
  - pse[.]ac
- **IP Addresses:** 
  - 194.169.175[.]132
  - 194.180.48[.]169
  - 193.42.33[.]14
  - 141.98.6[.]195
- **files:**
  - RECOVER-(seven-digit extension) FILES.txt
  - sh.txt
  - FXXX.exe

---
### References
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a
- https://cloudsek.com/blog/technical-analysis-of-alphv-blackcat-ransomware
- https://www.trustwave.com/en-us/resources/blogs/trustwave-blog/alphv-blackcat-ransomware-a-technical-deep-dive-and-mitigation-strategies/
- https://www.cshub.com/attacks/news/blackcat-ransomware-gang-attacks-corporations-public-entities-in-malvertising-campaign
- https://github.com/Bleeping/BlackCat-ALPHV-Ransomware/blob/main/config
- https://github.com/sophoslabs/IoCs/blob/master/Ransomware_BlackCat%20-%20triple%20ransomware%20attack.csv
