## Threat Actor: STOP 🛑
The STOP (Djvu) ransomware group is a cybercriminal organization known for deploying ransomware that encrypts victims' files and demands payment for decryption. Active since at least 2018, this group has targeted individuals and organizations worldwide.

---
### Overview
- **Aliases:** STOP, Djvu, STOP/Djvu
- **Type:** Ransomware-as-a-Service
- **First Identified:** 2018
- **Region of Operation:** Global, with victims reported across Europe, Asia, South America, and Africa.
- **Primary Targets:** Primarily individual users and small businesses running Windows operating systems.
- **Motivation:** Financial gain through ransom

---
### Known Campaigns
- **Campaign 1:** Distribution via Fake Software Cracks
  - **Date:** Ongoing since 2018
  - **Target(s):** Users seeking pirated software or activation tools.
  - **Impact:** Infection leads to file encryption, with ransom demands for decryption tools. 
- **Campaign 2:** 2021 Widespread Campaign
  - **Date:** 2021
  - **Target(s):** Windows users globally
  - **Impact:** Named second most detected ransomware out of 222 variants by BitDefender
- **Campaign 3:** Deployment of Information Stealers
  - **Date:** Observed in 2022
  - **Target(s):** Broad range of users.
  - **Impact:** In addition to file encryption, deployed information stealers like RedLine to exfiltrate sensitive data. 


---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - T1566: Phishing
  - T1078: Valid Accounts
  - T1059: Command and Scripting Interpreter
  - T1562: Impair Defenses
  - T1027: Obfuscated Files or Information
- **Common Tools Used:** 
  - PrivateLoader, RedLine Stealer, Vidar, Lumma Stealer, Amadey, SmokeLoader
- **Infection Vector:** 
  - Primarily through phishing campaigns (e.g., malicious emails with attachments or links).
  - Compromised software downloads, pirated software, software cracks, malvertising through Google Ads

---
### Known Affiliations
- **Ransomware Affiliates:** Primarily operates as a standalone ransomware group.
- **Initial Access Brokers:** N/A
- **Other Threat Actors:** Sometimes deployed alongside information stealers.

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - 5d294a14a491dc4e08593b2f6cdcaace1e894c449b05b4132b9ba5c005848c58
  - 6966599b3a7786f81a960f012d540866ada63a1fef5be6d775946a47f6983cb7
  - 1a1122ed7497815e96fdbb70ea31b381b5243e2b7d81750bf6f6c5ca12d3cee
updatewin.exe: 74949570d849338b3476ab699af78d89a5afa94c4529596cc0f68e4675a53c37
- **Domains/URLs:** 
  - api.2ip.ua
  - morgem.ru
- https://github.com/malienist/detections/blob/main/STOP-ransomware-djvu/IOC-list


---
### References
- https://www.cloudsek.com/blog/resurgence-of-djvu-stop-ransomware-strain-in-the-wild-part-1-2
- https://ransomware.org/blog/stop-djvu-ransomware-what-you-need-to-know/
- https://thehackernews.com/2023/11/djvu-ransomwares-latest-variant-xaro.html
- https://blogs.blackberry.com/en/2022/09/djvu-the-ransomware-that-seems-strangely-familiar
- https://github.com/struppigel/STOP-DJVU-Ransomware-Vaccine/releases/
- https://www.bleepingcomputer.com/news/security/djvu-ransomware-spreading-new-tro-variant-through-cracks-and-adware-bundles/
