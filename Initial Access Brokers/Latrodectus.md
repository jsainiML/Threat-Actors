## Initial Access Broker: Latrodectus 🪷
Latrodectus, also known as BlackWidow, is a malware loader that emerged in late 2023, believed to be developed by the creators of IcedID. It is primarily distributed through phishing campaigns and serves as an initial access broker, facilitating the deployment of additional malicious payloads, including ransomware. 


---
### Overview
- **Aliases:** BlackWidow, IceNova, Lotus, Unidentified 111
- **Type:** Malware Loader, Initial Access Broker
- **First Seen:** October 2023
- **Known Collaborators:** Associated with threat actors such as TA577 and TA578, LUNAR SPIDER (creators).

---
- **Methods:**
  - **Initial Access Methods:**
    - Phishing emails with Reply-chain tactic, leveraging compromised email accounts to hijack existing email threads.
    - malvertising, SEO poisoning
  - **Delivery Mechanism:**
    - Malicious documents (e.g., PDFs, HTML files) containing embedded URLs leading to malware downloads.
    - JavaScript and MSI droppers that execute the Latrodectus payload
  - **Payloads:** 
    - Cobalt Strike, IcedID, Lumma Stealers, Danabot, ransomware

---
- **Impact:**
  - **Targeted Sectors:** Financial institutions, healthcare, automotive, government agencies, critical infrastructure, corporate networks
  - **Key Campaigns:**
    - **[Operation Endgame (May 2024)]:**
      - **Target:** Various sectors, filling the void left by disabled malware families
      - **Outcome:** Establishment of Latrodectus as a formidable threat, using Brute Ratel C4
  - **Key Campaigns:**
    - **[TA577 Campaigns]:**
      - **Target:** Various industries via phishing emails.
      - **Outcome:** Distribution of Latrodectus leading to further malware infections. 
  - **Key Campaigns:**
    - **[TA578 Campaigns]:**
      - **Target:** Organizations in multiple sectors.
      - **Outcome:** Deployment of Latrodectus as a loader for additional payloads

---
- **IoCs:**
  - **Known Tools:** 
    - PowerShell scripts and JavaScript-based downloaders.
  - **Malicious Domains:**
    - https[:]//ultroawest[.]com/live/
    - https[:]//lettecoft[.]com/live/
    - https[:]//kalopvard[.]com/live/
    - https[:]//minrezviko[.]com/test/
    - https[:]//agrahusrat[.]com/test/
    - https[:]//pikchestop[.]com/test/
    - https[:]//indepahote[.]com/test/
  - **IPs:** 
    - 193.203.203[.]40
    - 185.93.221[.]108
    - 81.99.162[.]48	
  - **Hashes:** 
    - aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c
    - 5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8
    - 1db686635bcdde30163e1e624c4d8f107fd2a20507690151c69cc6a0c482207a
    - 01d58793f67c3adc862fb046005aca630643ed849a58b9d480852d4df5df57c2
  - **more comprehensive feeds:** 
    - https://github.com/netskopeoss/NetskopeThreatLabsIOCs/tree/main/Malware/Latrodectus/IOCs

---
- **Mitigation:**
  - **Defensive Recommendations:** 
    - Implement strong email filtering
    - Keep systems and software up-to-date
    - Use anti-malware solutions with EDR capabilities
    - Train users to recognize phishing attempts
  - **Detection Tips:** 
    - Monitor for suspicious PowerShell activity
    - Look for unusual network connections
    - Watch for fileless techniques and dynamic API resolution
    - Check for the presence of specific file names or patterns associated with Latrodectus
  - **Workarounds:**
    - Restrict execution of unauthorized scripts and macros.
    - Enforce the principle of least privilege to limit potential damage from infections
---
### References
- https://www.elastic.co/security-labs/spring-cleaning-with-latrodectus
- https://www.logpoint.com/en/blog/emerging-threats/latrodectus-the-wrath-of-black-widow/
- https://www.bleepingcomputer.com/news/security/latrodectus-malware-and-how-to-defend-against-it-with-wazuh/
- https://www.netskope.com/blog/latrodectus-rapid-evolution-continues-with-latest-new-payload-features
- https://blog.reveng.ai/latrodectus-distribution-via-brc4/
- https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice
