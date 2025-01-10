## Threat Actor: Clop 🦞
Clop, also known as CL0P or Cl0p, is a sophisticated ransomware group that has been active since at least 2019. Operating under a RaaS model, Clop has targeted a wide range of industries globally, employing advanced tactics to extort significant ransom payments from its victims.

---
### Overview
- **Aliases:** Cl0p, CryptoMix variant
- **Type:** Ransomware-as-a-Service
- **First Identified:** 2019
- **Region of Operation:** Global, with notable activities in North America, Europe, and Asia.
- **Primary Targets:** Various sectors, including healthcare, finance, education, and energy.
- **Motivation:** Financial gain through ransom.

---
### Known Campaigns
- **Campaign 1:** Maastricht University Attack
  - **Date:** December 2019
  - **Target(s):** Maastricht University
  - **Impact:** Encrypted almost all Windows systems, disrupting university operations. The university paid a ransom of €200,000 in Bitcoin to regain access. 

- **Campaign 1:** Accellion FTA Breach
  - **Date:** December 2020
  - **Target(s):** Organizations using Accellion's File Transfer Appliance (FTA)
  - **Impact:** Exploited zero-day vulnerabilities to steal sensitive data, followed by extortion demands. 

- **Campaign 1:** SolarWinds Serv-U Exploitation
  - **Date:** November 2021
  - **Target(s):** Corporate networks
  - **Impact:** Breach of networks and deployment of Clop ransomware

- **Campaign 1:** MOVEit Transfer Exploitation
  - **Date:** 2023
  - **Target(s):** Organizations using MOVEit Transfer
  - **Impact:** Exploited a zero-day vulnerability to steal data, impacting numerous organizations, including Shell and the New York City Department of Education, Projected earnings of $75-100 million.

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:**
  - T1190: Exploit Public-Facing Application
  - T1078: Valid Accounts
  - T1059: Command and Scripting Interpreter
  - T1562: Impair Defenses
  - T1027: Obfuscated Files or Information
- **Common Tools Used:**
  - Get2 loader, SDBOT, FlawedAmmyy, Cobalt Strike, POWERTRASH malware, Lizar toolkit.
- **Infection Vector:**
  - Phishing campaigns, spam emails with HTML attachments
  - exploitation of zero-day vulnerabilities (e.g., MOVEit Transfer, SolarWinds Serv-U)

---
### Known Affiliations
- **Ransomware Affiliates:** Associated with the TA505 cybercriminal group, also known as FIN11
- **Initial Access Brokers:** Utilizes compromised credentials and exploits vulnerabilities to gain initial access.
- **Other Threat Actors:** Collaborates with various cybercriminal entities to enhance the effectiveness of their operations.

---
### Indicators of Compromise (IoCs)
- **File Hashes:** 
  - e8d98621b4cb45e027785d89770b25be0c323df553274238810872164187a45f
  - 8e91f3294883fbdc31ff17c3075f252cbfdc1fc9145c6238468847f86d590418
  - d1c04608546caf39761a0e390d8f240faa4fc821eea279f688b15d0b2cfc9729	
  - 3320f11728458d01eef62e10e48897ec1c2277c1fe1aa2d471a16b4dccfc1207	
  - eba8a0fe7b3724c4332fa126ef27daeca32e1dc9265c8bc5ae015b439744e989	
  - cf0a24f1cdf5258c132102841d5b13e1c6978d9316ba4005076606dc60ec761b	
  - 389e03b1a1fd1c527d48df74d3c26a0483a5b105f36841193172f1ee80e62c1b	
  - 85c42e1504bdce63c59361fb9b721a15a80234e0272248f9ed7eb5f9ba7b3203	
  - cb36503c08506fca731f0624fda1f7462b7f0f025a408596db1207d82174796a	
  - af1d155a0b36c14626b2bf9394c1b460d198c9dd96eb57fac06d38e36b805460	
  - ad320839e01df160c5feb0e89131521719a65ab11c952f33e03d802ecee3f51f	
- **Domains/URLs:** 
  - hxxp://27[.]70[.]196/km1	                                      
  - hxxp://91[.]38[.]135[.]67/km1	    
- **IP Addresses:** 
  - 62.182.82[.]19
  - 62.182.85[.]234
  - 66.85.26[.]215
  - 66.85.26[.]234
  - 66.85.26[.]248
  - 79.141.160[.]78
  - 216.144.248[.]20
  - 173.254.236[.]131
  - 3.101.53[.]11
  - 54.184.187[.]134
  - 100.21.161[.]34
- https://github.com/albertzsigovits/malware-notes/blob/master/Ransomware/Clop.md

---
### References
- https://www.cyber.gc.ca/en/guidance/profile-ta505-cl0p-ransomware
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
- https://flashpoint.io/intelligence-101/clop/
- https://www.csoonline.com/article/650272/clop-ransomware-dominates-ransomware-space-after-moveit-exploit-campaign.html
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-clop
- https://en.wikipedia.org/wiki/Clop_(cyber_gang)
- https://www.mimecast.com/content/clop-ransomware/
