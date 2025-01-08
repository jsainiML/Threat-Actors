## Threat Actor: Black Basta ⚫
Black Basta is a sophisticated RaaS group that emerged in early 2022 and quickly became one of the most active and notorious cybercriminal enterprises globally.


---
### Overview
- **Aliases:** None known.
- **Type:** ransomware-as-a-service
- **First Identified:** April 2022
- **Region of Operation:** Global, with a focus on the United States, Japan, Canada, the United Kingdom, Australia, and New Zealand
- **Primary Targets:** Various industries, including critical infrastructure sectors such as healthcare, public health, and energy
- **Motivation:** Financial gains

---
### Known Campaigns
- **Campaign 1:** Attack on Deutsche Windtechnik.
  - **Date:** April 2022.
  - **Target(s):** German wind energy company Deutsche Windtechnik.
  - **Impact:** Disruption of remote control capabilities for wind turbines; services restored after one day. 
- **Campaign 2:** Attack on CMAC Transportation.
  - **Date:** May 2024.
  - **Target(s):** CMAC Transportation, a logistics and transportation company.
  - **Impact:** Operational disruptions; specific details of the attack vector not disclosed.
- **Campaign 3:** disrupt 140 Ascension hospitals.
  - **Date:** May 2024.
  - **Target(s):** Catholic healthcare system Ascension.
  - **Impact:** Disrupt 140 Ascension hospitals across 19 states and Washington DC. Phones and computer systems went offline, and staff were forced to switch to paper systems.

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - T1078: Valid Accounts.
  - T1190: Exploit Public-Facing Application.
  - T1562.001: Impair Defenses: Disable or Modify Tools.
- **Common Tools Used:**
  - QakBot (QBot).
  - Mimikatz.
  - Cobalt Strike.
  - Native Windows Tools: like Windows Management Instrumentation (WMI), PowerShell, and PsExec
- **Infection Vector:**
  - Spear-phishing campaigns.
  - Exploiting known vulnerabilities such as ZeroLogon, NoPac, and PrintNightmare.

---
### Known Affiliations
- **Ransomware Affiliates:**
  - Potential links to former members of Conti and REvil ransomware groups, suggested by similarities in tactics and procedures
- **Initial Access Brokers:** 
  - Collaborates with IABs to infiltrate target systems such as Qakbot, Cobalt Strike, Brute Ratel.
- **Other Threat Actors:**
  - No confirmed alliances beyond potential connections to Conti and REvil.


---
### Indicators of Compromise (IoCs)
- https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/j/black-basta-ransomware-gang-infiltrates-networks-via-qakbot,-brute-ratel-and-cobalt-strike/ioc-black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-cobalt-strike.txt
- https://github.com/rapid7/Rapid7-Labs/blob/main/IOCs/BlackBasta_SocialEngineering_IOCs.txt


---
### References
- https://www.provendata.com/blog/black-basta-ransomware/
- https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a
- https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know
- https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis
- https://flashpoint.io/blog/understanding-black-basta-ransomware/
