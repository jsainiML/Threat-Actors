## Initial Access Broker: SmokeLoader 💨
SmokeLoader is a modular malware loader that has been active since at least 2011. It is primarily used as an Initial Access Broker (IAB) to facilitate ransomware attacks and the distribution of other malicious payloads. Known for its modular architecture, SmokeLoader enables attackers to customize infections based on their objectives, making it a versatile and persistent threat.

---
### Overview
- **Aliases:** Dofoil, S0226 (MITRE ATT&CK)
- **Type:** Modular malware loader
- **First Seen:** 2011
- **Known Collaborators:** REvil, ProLock, Lockbit, Conti, Egregor

---
- **Methods:**
  - **Initial Access Methods:**
    - Phishing emails with malicious attachments or links
    - Drive-by downloads via compromised websites
    - Exploiting software vulnerabilities, (e.g., CVE-2017-0199, CVE-2017-11882)
  - **Delivery Mechanism:** 
    - Acts as a loader, downloading and executing subsequent payloads on the compromised system.
  - **Payloads:** 
    - Various malware including backdoors, ransomware, cryptominers, password stealers, banking trojans
  
---
- **Impact:**
  - **Targeted Sectors:**
    - Manufacturing
    - healthcare
    - IT
    - financial institutions
    - government organizations
  - **Key Campaigns:**
    - **[2018 Dofoil Campaign]:**
      - **Target:** Over 400,000 Windows users globally
      - **Outcome:** Distributed cryptocurrency mining malware and info-stealers, causing significant financial and data losses
    - **[2023 Ukraine Campaign]:**
      - **Target:** Ukrainian financial institutions and government organizations
      - **Outcome:** Credential theft, unauthorized fund transfers
    - **[2024 Taiwan Campaign]:**
      - **Target:** Organizations in Taiwan across manufacturing, healthcare, and IT sectors
      - **Outcome:** Information theft, potential for follow-on attacks

---
- **IoCs:**
  - **Known Tools:** 
    - SmokeLoader modules for credential harvesting, keylogging, and lateral movement
    - PowerShell scripts, PROPagate injection technique, AndeLoader
  - **Malicious Domains:** 
    - Uses fast flux DNS technique
  - **IPs:** 
    - 45.138.74.191:443
    - 65.108.218.24:443
  - Agregated list:: https://github.com/stamparm/maltrail/blob/master/trails/static/malware/smokeloader.txt

---
- **Mitigation:**
  - **Defensive Recommendations:** 
    - Implement email filtering solutions to block malicious attachments and links.
    - Use endpoint protection tools capable of detecting modular malware.
    - Regularly update and patch operating systems and software.
  - **Detection Tips:** 
    - Monitor for unusual outbound traffic to known malicious IPs or domains.
    - Analyze for SmokeLoader’s characteristic process injection behavior.
  - **Workarounds:** 
    - Restrict user access to prevent downloading and executing unverified files.
    - Enable strict browsing policies to block drive-by download websites.

    
---
### References
- https://malpedia.caad.fkie.fraunhofer.de/details/win.smokeloader
- https://www.spamhaus.org/resource-hub/malware/smoke-loader-malware-improves-after-microsoft-spoils-its-campaign/
- https://darktrace.com/blog/how-darktrace-extinguished-the-threat-of-smokeloader-malware
- https://www.fortinet.com/blog/threat-research/sophisticated-attack-targets-taiwan-with-smokeloader
- https://therecord.media/surge-in-smokeloader-malware-attacks-targeting-ukrainian-financial-gov-orgs
- https://threatlibrary.zscaler.com/threats/aeeaad8d-35e1-4c09-8da8-36b3128beb21
