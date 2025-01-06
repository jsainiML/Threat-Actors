## Initial Access Broker: Pikabot
Pikabot is a modular backdoor trojan that emerged in early 2023, designed to provide attackers with persistent access to compromised systems. It comprises a loader and a core component, enabling the execution of arbitrary commands and the injection of additional payloads from its command-and-control (C2) server. Pikabot employs sophisticated anti-analysis and evasion techniques, making it a formidable threat in the cybersecurity landscape.

---
### Overview
- **Aliases:** N/A
- **Type:** Malware Loader
- **First Seen:** Early 2023
- **Known Collaborators:** Black Basta ransomware, Water Curupira (threat actor)

---
- **Methods:**
  - **Initial Access Methods:**
    - Phishing emails, email thread hijacking, malspam, malvertising
    - Exploitation of software vulnerabilities
  - **Delivery Mechanism:**
    - Malicious HTML files leading to the download of the payload 
    - JavaScript files initiating the infection process
    - Malicious Excel documents with embedded macros
    - JAR files containing the malware
  - **Payloads:** 
    - Black Basta is a prominent payload delivered by PikaBot.
    - Cobalt Strike, arbitrary shellcode, DLLs, executable files.
---
- **Impact:**
  - **Targeted Sectors:** Various industries, enterprises
  - **Key Campaigns:**
    - **[Water Curupira Campaign (2023)]:**
      - **Target:** Multiple sectors globally.
      - **Outcome:** Deployment of backdoors, potential Black Basta ransomware attacks.

---
- **IoCs:**
  - **Known Tools:**
    - Use of the ADVobfuscator library for string obfuscation.
    - PowerShell scripts
  - **Malicious Domains:** 
    - paldiengineering[.]com/8WjmD9n/
    - gofly[.]id/P9g/
    - holyrosaryinternational[.]com/N1H3/
    - grehlingerssealcoating[.]com/3hidbt/
    - israrliaqat[.]com/6wX4/
    - saeedalkarmi[.]com/aT2ja9/
    - anadesky.firstbasedso[.]com
    - siack.firstbasedso[.]com
    - zuum.firstbasedso[.]com
  - **IPs:** 
    - 45.33.15[.]215 port 2967 - HTTPS traffic
    - 45.56.71[.]218 port 13724 - HTTPS traffic
    - 45.76.22[.]139 port 13786 - HTTPS traffic
    - 45.76.96[.]172 port 2223 - HTTPS traffic
    - 45.76.119[.]22 port 13724 - HTTPS traffic
    - 51.161.81[.]190 port 13721 - HTTPS traffic
    - 64.176.13[.]28 port 2083 - HTTPS traffic
    - 65.20.85[.]39 port 2967 - HTTPS traffic
    - 69.164.213[.]141 port 5631 - HTTPS traffic
    - 70.34.196[.]219 port 2226 - HTTPS traffic
  - **more comprehensive feeds:** 
    - https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2023-12-18-IOCs-for-Pikabot-with-Cobalt-Strike.txt
    - https://github.com/eSentire/iocs/blob/main/PikaBot/PikaBot-1-2-2024.txt

---
- **Mitigation:**
  - **Defensive Recommendations:**
    - Implement robust email filtering to block phishing attempts
    - Regularly update and patch software to mitigate vulnerabilities
    - Employ advanced endpoint protection solutions capable of detecting modular malware
  - **Detection Tips:**
    - Look for unusual network connections
    - Monitor for large-scale data exfiltration attempts
    - Check for the presence of specific file names or patterns associated with PikaBot
  - **Workarounds:**
    - Disable or restrict unused remote access protocols (e.g., RDP) where possible.
    - Implement strict access controls and least privilege principles.

---
### References
- https://malpedia.caad.fkie.fraunhofer.de/details/win.pikabot
- https://flashpoint.io/blog/emerging-threat-pikabot-malware/
- https://www.zscaler.com/blogs/security-research/technical-analysis-pikabot
- https://www.trendmicro.com/en_ca/research/24/a/a-look-into-pikabot-spam-wave-campaign.html
- https://darktrace.com/blog/pikabot-malware-battling-a-fast-moving-loader-malware-in-the-wild
- https://www.obrela.com/advisory/pikabot-a-new-emerging-threat/
