## Threat Actor: Dark Angels 👼
The Dark Angels ransomware group is a highly targeted and financially motivated threat actor known for executing large-scale attacks against major corporations and high-value enterprises worldwide. They gained infamy in 2024 for demanding and securing the largest known ransom payment of $75 million from a major enterprise. Dark Angels primarily leverage Ransomware-as-a-Service (RaaS) models, collaborating with initial access brokers like Qakbot and SmokeLoader to gain entry into victim networks.

---
### Overview
- **Aliases:** N/A
- **Type:** Ransomware Group
- **First Identified:** 2022
- **Region of Operation:** Global
- **Primary Targets:** Large corporations, critical infrastructure, and high-value enterprises
- **Motivation:** inancial gain through extortion

---
### Known Campaigns
- **Campaign 1:** $75 Million Ransom Payment
  - **Date:** 2024
  - **Target(s):** A major undisclosed enterprise
  - **Impact:** The largest known ransom payment in history, totaling $75 million. Sensitive data was encrypted and exfiltrated, causing massive financial and reputational damage.
 
- **Campaign 2:** Supply Chain Attack on Financial Institutions
  - **Date:** 2023
  - **Target(s):** Several financial institutions via a supply chain compromise
  - **Impact:** Encrypted systems, disrupted operations, and significant data theft.

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
  -  Collaborates with brokers like Qakbot and SmokeLoader for gaining entry into networks

---
### Indicators of Compromise (IoCs)
- **File Hashes:** [Provide known malicious file hashes]
- **Domains/URLs:** [List associated domains or URLs]
- **IP Addresses:** [Known IPs used in campaigns]

---
### Mitigation and Response
- **Defensive Recommendations:** [Steps to defend against this actor]
- **Patches and Updates:** [Related CVEs or patches to mitigate risks]
- **Detection Techniques:** [How to detect their activities]

---
### References
- [Link 1 to research or analysis]
- [Link 2 to news articles]



