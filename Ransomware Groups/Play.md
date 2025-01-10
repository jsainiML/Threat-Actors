## Threat Actor: Play
Play, also known as PlayCrypt, is a ransomware group that emerged in 2022, targeting organizations across various sectors and geographies. 

---
### Overview
- **Aliases:** PlayCrypt
- **Type:** Ransomware-as-a-Service
- **First Identified:** 2022
- **Region of Operation:** Global, with reported attacks in the United States, Brazil, Argentina, Germany, Belgium, and Switzerland
- **Primary Targets:** Large enterprises across various industries, including medical institutions, financial services, manufacturing, real estate, and education.
- **Motivation:** Financial gain

---
### Known Campaigns
- **Campaign 1:** Swiss Attack Wave
  - **Date:** March-June 2023
  - **Target(s):** Swiss media, IT service providers, federal administration
  - **Impact:** Data theft including addresses of 400,000 Swiss expatriates, financial and tax information

- **Campaign 2:** Argentine Judiciary Attack
  - **Date:** 2022
  - **Target(s):** Argentine judiciary of Córdoba
  - **Impact:** Major disruption to judicial systemson

- **Campaign 3:** Attack on German Companies
  - **Date:** 2022
  - **Target(s):** Multiple German companies
  - **Impact:** Data encryption and extortion, leading to operational disruptions

---
### Techniques and Tactics
- **MITRE ATT&CK Techniques:** 
  - T1190 - Exploit Public-Facing Application
  - T1059 - Command and Scripting Interpreter
  - T1562 - Impair Defenses
  - T1070 - Indicator Removal
  - T1033 - System Owner/User Discovery
  - T1082 - System Information Discovery
  - T1083 - File and Directory Discovery
  - T1135 - Network Share Discovery
  - T1057 - Process Discovery
  - T1007 - System Service Discovery
  - T1048 - Exfiltration Over Alternative Protocol
  - T1486 - Data Encrypted for Impact
- **Common Tools Used:** 
  - Cobalt Strike, SystemBC, PsExec, Mimikatz, WinPEAS, WinRAR, WinSCP, Grixba, AdFind, Playcrypt
- **Infection Vector:**
  - Exploitation of FortiOS and Microsoft Exchange vulnerabilities
  - abuse of valid accounts, exposed RDP/VPN services
  - Phishing emails

---
### Known Affiliations
- **Ransomware Affiliates:** Suspected to be a closed group
- **Initial Access Brokers:** Utilizes compromised credentials, possibly obtained through initial access brokers.
- **Other Threat Actors:** Similarities noted with Hive and Nokoyawa ransomware groups, suspected links to Russia and North Korean APT groups

---
### Indicators of Compromise (IoCs)
- **File Hashes:**
fc2b98c4f03a246f6564cc778c03f1f9057510efb578ed3e9d8e8b0e5516bd49	
c316627897a78558356662a6c64621ae25c3c3893f4b363a4b3f27086246038d
c92c158d7c37fea795114fa6491fe5f145ad2f8c08776b18ae79db811e8e36a3	
e1c75f863749a522b244bfa09fb694b0cc2ae0048b4ab72cb74fcf73d971777b
094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde	
e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173
d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f	
c88b284bac8cd639861c6f364808fac2594f0069208e756d2f66f943a23e3022	
f18bc899bcacd28aaa016d220ea8df4db540795e588f8887fe8ee9b697ef819f
e641b622b1f180fe189e3f39b3466b16ca5040b5a1869e5d30c92cca5727d3f0
608e2b023dc8f7e02ae2000fc7dbfc24e47807d1e4264cbd6bb5839c81f91934
006ae41910887f0811a3ba2868ef9576bbd265216554850112319af878f06e55	
e4f32fe39ce7f9f293ccbfde30adfdc36caf7cfb6ccc396870527f45534b840b
8962de34e5d63228d5ab037c87262e5b13bb9c17e73e5db7d6be4212d66f1c22
5573cbe13c0dbfd3d0e467b9907f3a89c1c133c774ada906ea256e228ae885d5	
f6072ff57c1cfe74b88f521d70c524bcbbb60c561705e9febe033f51131be408
dcaf62ee4637397b2aaa73dbe41cfb514c71565f1d4770944c9b678cd2545087	
f5c2391dbd7ebb28d36d7089ef04f1bd9d366a31e3902abed1755708207498c0
3e6317229d122073f57264d6f69ae3e145decad3666ddad8173c942e80588e69
- **Domains/URLs:** 
  - z3a2[.]ssndob[.]cn[.]com
  - mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd[.]onion
  - k7kg3jqxang3wh7hnmaiokchk7qoebupfgoik6rha6mjpzwupwtj25yd[.]onion
- **IP Addresses:** 
  - 107.189.30.131
  - 45.227.252.247
  - 5.255.103.142

---
### References
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a
- https://www.picussecurity.com/resource/blog/play-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa23-352a
- https://en.wikipedia.org/wiki/Play_(hacker_group)
- https://redpiranha.net/news/play-ransomware-all-you-need-know
- https://www.obrela.com/advisory/play-ransomware-threat-advisory/
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-play
