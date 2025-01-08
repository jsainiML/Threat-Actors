## Initial Access Broker: Raspberry Robin 🍓
Raspberry Robin is a sophisticated worm primarily propagated through infected external drives, notably USB devices. First identified in 2021, it employs complex obfuscation techniques and leverages legitimate Windows tools to establish persistence and facilitate further malware deployment. Its associations with various ransomware groups highlight its role as a significant threat within the cybercriminal ecosystem. 


---
### Overview
- **Aliases:** QNAP Worm, Storm-0856
- **Type:** Worm, Initial Access Broker
- **First Seen:** 2019 (artifacts discovered by Microsoft), widely noticed in late 2021
- **Known Collaborators:** DEV-0206, Evil Corp (DEV-0243), FIN11, Clop Gang, BumbleBee, IcedID, TrueBot
---
- **Methods:**
  - **Initial Access Methods:** 
    - Propagation via infected external drives, particularly USB devices. 
    - Execution through malicious .LNK files that initiate the infection chain
  - **Delivery Mechanism:**
    - Utilizes Windows Installer to download and execute malicious DLLs from compromised QNAP-associated domains. 
    - Employs legitimate tools like msiexec.exe for payload execution.
  - **Payloads:**
    - Cobalt Strike, FakeUpdates malware downloader, Fauppod malware, Vidar information stealer, ransomware

---
- **Impact:**
  - **Targeted Sectors:** Wide-ranging, targeting various sectors
  - **Key Campaigns:**
    - **[USB Drive Campaign (2021-2022)]:**
      - **Target:** Multiple organizations worldwide
      - **Outcome:** Widespread infections, potential for additional payload delivery
  - **Key Campaigns:**
    - **[Discord Distribution Campaign (2024)]:**
      - **Target:** Various sectors
      - **Outcome:** Expanded infection vector using Discord for malware propagation
     

---
- **IoCs:**
  - **Known Tools:**
    - Windows Management Instrumentation (WMI), msiexec.exe
    - Utilizes compromised QNAP NAS devices for hosting malicious payloads
  - **Malicious Domains:** 
  - **IPs:**
    - 47.24.139[.]111
    - 45.138.74[.]191
    - 65.108.218[.]24
  - **Hashes:**
    - ebe231c90fad02590fc56d5840acc63b90312b0e2fee7da3c7606027ed92600e
    - 7b666b978dbbe7c032cef19a90993e8e4922b743ee839632bfa6d99314ea6c53
    - c94006bb878ec9c58bed7a882b340024ba61e997fa7e4c720f3a3e28cca0ab75
  - **more comprehensive feeds:**
    - https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-11-14-IOCs-for-Raspberry-Robin-activity.txt
    - https://github.com/sophoslabs/IoCs/blob/master/Worm-Raspberry-Robin.csv

---
- **Mitigation:**
  - **Defensive Recommendations:** 
    - Implement strong USB device control policies
    - Disable or restrict the use of autorun and autoplay features for external drives
  - **Detection Tips:**
    - Monitor for unusual use of Windows Installer (msiexec.exe) processes.
    - Inspect network traffic for connections to known malicious domains or IP addresses associated with Raspberry Robin.
  - **Workarounds:**
    - Educate employees about the risks of using unverified USB devices.
    - Use multi-factor authentication

---
### References
- https://darktrace.com/blog/the-early-bird-catches-the-worm-darktraces-hunt-for-raspberry-robin
- https://blog.checkpoint.com/security/raspberry-robin-evolving-cyber-threat-with-advanced-exploits-and-stealth-tactics/
- https://www.tanium.com/blog/raspberry-robin-usb-malware-cyber-threat-intelligence-roundup/
- https://www.trendmicro.com/en_ca/research/22/l/raspberry-robin-malware-targets-telecom-governments.html
- https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-raspberry-robin
