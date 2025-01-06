## Initial Access Broker: Qakbot 🦆
Qakbot is a notorious malware loader that has evolved into one of the most widely used IABs. It facilitates ransomware deployments and other malicious operations by providing attackers access to compromised networks. Despite multiple law enforcement operations targeting its infrastructure, Qakbot has resurfaced, demonstrating its adaptability and continued threat to organizations worldwide.

--- 
### Overview
- **Aliases:** QBot, QuackBot, Pinkslipbot
- **Type:** Initial Access Broker (IAB), Malware Loader
- **First Seen:** 2007
- **Known Collaborators:** Black Basta, Conti, REvil, LockBit

---
- **Methods:**
  - **Initial Access Methods:** 
    - Phishing emails with malicious attachments or links
    - Exploiting unpatched vulnerabilities in software
    - Credential stuffing and brute-force attacks on RDP
  - **Delivery Mechanism:**
    - Malicious macros in Microsoft Office documents
    - Weaponized PDFs and ZIP files
    - Links to compromised websites
  - **Payloads:**
    - Ransomware families like LockBit, Black Basta, Conti
    - Banking trojans and info-stealers

---
- **Impact:**
  - **Targeted Sectors:** Healthcare, financial, hospitality, various industries globally
  - **Key Campaigns:**
    - **[2020 Campaign]:** 
      - **Target:** Healthcare systems in North America
      - **Outcome:** Widespread infections, credential theft
    - **[2023 Campaign]:** 
      - **Target:** Hospitality industry
      - **Outcome:** Qakbot malware distribution via IRS-themed phishing emails
     

---
- **IoCs:**
  - **Known Tools:** 
    - Powershell scripts
    - Cobalt Strike
    - Mimikatz
  - **IPs:**
    - 23[.]81[.]246[.]2
    - 94[.]131[.]117[.]111
    - 104[.]225[.]129[.]114
    - 85[.]239[.]41[.]205	
  - **Hashes:**
    - 0A354C9637EFA27F5B41A525574CB8FC496677E16CE06832CCF0AF699FCCEECA
    - EC3F1349AC0196FF3EBCC30435B16B7E290FA8C2FDC0223F72AD9BC08C7B4486	
    - 6291579CD41491CC045D7E0ED05B9A3A72C5CCA6F74F8BDEBC1C85459C423B60
    - 8C8CF24571C836636A25040CE36EEA9036B0CC4F09DA14780ED2618A488FDFE8	
  https://www.trellix.com/assets/docs/qakbot-iocs.pdf

---
- **Mitigation:**
  - **Defensive Recommendations:** 
    - Employee Security Awareness Training: Focus on phishing threats, safe email practices, and how to identify malicious attachments.
    - Strong Password Policies: Implement and enforce strong password policies across the organization.
    - Multi-Factor Authentication (MFA): Deploy MFA for all critical accounts and services.
    - Regular Software Updates: Keep operating systems, applications, and security software up-to-date with the latest patches and security updates
  - **Detection Tips:**
    - Monitor for suspicious PowerShell activity
    - Look for unusual network connections
    - Watch for large-scale data exfiltration attempts
  - **Workarounds:** 
    - Disable or restrict unused remote access protocols (e.g., RDP) where possible.
    - Implement network segmentation to limit lateral movement.
    - Disable macros in Office documents

---
### References
- https://www.zscaler.com/blogs/security-research/hibernating-qakbot-comprehensive-study-and-depth-campaign-analysis
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a
- https://www.cisa.gov/sites/default/files/2023-02/202010221030_qakbot_tlpwhite.pdf
- https://www.esentire.com/security-advisories/increase-in-observations-of-qakbot-malware
