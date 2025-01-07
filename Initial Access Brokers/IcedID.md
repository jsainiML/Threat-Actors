## Initial Access Broker: IcedID 🧊
IcedID, also known as BokBot, is a banking trojan first identified in 2017. Over time, it has evolved into a versatile malware loader, facilitating the delivery of various malicious payloads, including ransomware. Operated by the threat actor group LUNAR SPIDER, IcedID has been utilized by initial access brokers to infiltrate networks, subsequently selling access to other cybercriminals. 


---
### Overview
- **Aliases:** BokBot
- **Type:** Initial Access Broker, Banking Trojan
- **First Seen:** 2017
- **Known Collaborators:** Associated with ransomware groups such as Emotet, TrickBot, Quantum and Sodinokibi (REvil).

---
- **Methods:**
  - **Initial Access Methods:**
    - Phishing emails, malspam campaigns, malvertising.
    - Exploitation of vulnerabilities in remote access services like RDP and VPNs.
  - **Delivery Mechanism:** 
    - Malicious documents with macros executing PowerShell scripts.
    - Fake software installers
  - **Payloads:** 
    - Cobalt Strike beacons.
    - Various other malware families beyond ransomware, demonstrating its versatility as an IAB.

---
- **Impact:**
  - **Targeted Sectors:** Wide-ranging, targeting various sectors
  - **Key Campaigns:**
    - **[Thumbcache Viewer Campaign (2023)]:**
      - **Target:** Multiple organizations worldwide
      - **Outcome:** Deployment of IcedID malware disguised as legitimate software
    - **[Exchange Server Campaign (2022)]:**
      - **Target:** Organizations with compromised Exchange servers
      - **Outcome:** Increased success rate of phishing attacks using trusted internal email addresses
    - **[COVID-19 and FMLA Campaigns]:**
      - **Target:** Various organizations during the COVID-19 pandemic.
      - **Outcome:** Distribution of IcedID via phishing emails exploiting COVID-19 themes.

---
- **IoCs:**
  - **Known Tools:** PowerShell scripts, VBA macros, WebDAV protocol
  - **Malicious Domains:** 
    - alishaskainz[.]com
    - akermonixalif[.]com
    - hxxps://yelsopotre[.]com/news/
    - hxxps://qoipaboni[.]com/news/
    - hxxps://halicopnow[.]com/news/
    - hxxps://oilbookongestate[.]com/news/
  - **IPs:** 
    - 194[.]5[.]249[.]72
    - 192.[.]42[.]116[.]41
  - **Hashes:** 
    - 19e898f7f78d4f9508427259634c59a42488fe927a
  - **more comprehensive feeds:**
    - https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2023-10-31-IOCs-for-IcedID-infection.txt

---
- **Mitigation:**
  - **Defensive Recommendations:** 
    - Implement robust email filtering to block phishing attempts.
    - Regularly update and patch software to mitigate vulnerabilities.
    - Employ advanced endpoint protection solutions capable of detecting modular malware.
  - **Detection Tips:**
    - Monitor for suspicious PowerShell activity
    - Look for unusual network connections, especially on port 49157
    - Watch for man-in-the-browser attacks and web injections
  - **Workarounds:** [E.g., Disable unused remote access protocol
    - Implement multi-factor authentication
    - Use application whitelisting
    - Regularly patch and update Microsoft Exchange servers

---
### References
- https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/report-icedid-infections-on-the-rise.pdf
- https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/icedid-malware/
- https://www.cisecurity.org/insights/white-papers/security-primer-icedid
- https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid
- https://www.cybereason.com/blog/threat-analysis-from-icedid-to-domain-compromise
