## Threat Actor: Dark Angels 👼
The Dark Angels ransomware group is a highly targeted and financially motivated threat actor known for executing large-scale attacks against major corporations and high-value enterprises worldwide. They gained infamy in 2024 for demanding and securing the largest known ransom payment of $75 million from a major enterprise. Dark Angels primarily leverage Ransomware-as-a-Service (RaaS) models, collaborating with initial access brokers like Qakbot and SmokeLoader to gain entry into victim networks.

---
### Overview
- **Aliases:** White Rabbit and MARIO ESXi
- **Type:** Ransomware Group
- **First Identified:** 2022 (Also claimed )
- **Region of Operation:** Global
- **Primary Targets:** Large corporations, critical infrastructure, and high-value enterprises
- **Motivation:** Financial gain through extortion

---
### Known Campaigns
- **Campaign 1:** $75 Million Ransom Payment
  - **Date:** 2024
  - **Target(s):** A major undisclosed enterprise
  - **Impact:** The largest known ransom payment in history, totaling $75 million. Sensitive data was encrypted and exfiltrated, causing massive financial and reputational damage.
 
- **Campaign 2:** Johnson Controls International (JCI) Attack
  - **Date:** 2023
  - **Target(s):** Johnson Controls International
  - **Impact:** $51 million ransom demand, $27 million recovery cost.

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:**
  -  Initial Access: Exploitation of public-facing applications (T1190)
  -  Privilege Escalation: Exploiting vulnerabilities in Active Directory (T1068)
  -  Execution: Ransomware deployment through scheduled tasks (T1053.005)
  -  Exfiltration: Use of custom tools to transfer sensitive data (T1041)
Common Tools Used:
- **Common Tools Used:** 
  -  RagnarLocker Ransomware: Used for encryption
  -  Babuk Ransomware: Deployed in earlier campaigns before switching to RagnarLocker
- **Infection Vector:**
  -  Exploitation of vulnerabilities in enterprise systems
  -  Phishing emails targeting employees of large organizations

---
### Known Affiliations
- **Ransomware Affiliates:** 
  -  likely operates as a Ransomware-as-a-Service (RaaS) with a network of affiliates
- **Initial Access Brokers:**
  -  Highly targeted attacks, no use of third-party initial access brokers

---
### Indicators of Compromise (IoCs)
- **File Hashes:**
  - 38e05d599877bf18855ad4d178bcd76718cfad1505328d0444363d1f592b0838
  - 3b56cea72e8140a7044336933cf382d98dd95c732e5937a0a61e0e7296762c7b
  - f668f74d8808f5658153ff3e6aee8653b6324ada70a4aa2034dfa20d96875836
  - fe8b6b7c3c86df0ee47a3cb04a68891fd5e91f3bfb13482112dd9042e8baebdf
- **Domains/URLs:** 
  - http[:]//myob[.]live  
  - http[:]//wemo2ysyeq6km2nqhcrz63dkdhez3j25yw2nvn7xba2z4h7v7gyrfgid[.]onion
- **IP Addresses:**
  - 89.38.225[.]166

---
### Mitigation and Response
- **Defensive Recommendations:** [Steps to defend against this actor]
- **Patches and Updates:** [Related CVEs or patches to mitigate risks]
- **Detection Techniques:** [How to detect their activities]

---
### References
- https://www.watchguard.com/wgrd-ransomware/dark-angels-team
- https://www.zscaler.com/blogs/security-research/shining-light-dark-angels-ransomware-group
- https://krebsonsecurity.com/2024/08/low-drama-dark-angels-reap-record-ransoms/



