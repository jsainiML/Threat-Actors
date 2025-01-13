<header>

# Threat Intel

Creating this repository as lookup guide for SOC analysts & detection engineers, where you will find list adversarial TTPs & behaviour patterns. 

</header>

---

### **1. Ransomware Groups**
These are groups primarily focused on using ransomware for extortion purposes.

| **Group**                 | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **Dark Angels**           | Highly targeted attacks, responsible for the largest known ransom payment of $75M. |
| **LockBit**               | Major ransomware group with a large affiliate network, high-volume attacks. |
| **BlackCat (ALPHV)**      | Known for cross-platform compatibility, affiliate-based operations.      |
| **Akira**                 | Emerged in 2023, likely an offshoot of Conti, uses various access methods. |
| **Black Basta**           | Successor to Conti, uses Qakbot and Pikabot as initial access brokers.   |
| **8Base**                 | Active ransomware extortion group.                                       |
| **Play**                  | Known for data leaks in ransomware operations.                          |
| **Clop**                  | Known for data leaks in ransomware operations.                          |
| **BianLian**              | Known for data leaks in ransomware operations.                          |
| **Medusa**                | Known for data leaks in ransomware operations.                          |
| **NoEscape**              | Known for data leaks in ransomware operations.                          |
| **Hunters**               | Known for data leaks in ransomware operations.                          |
| **Stormous**              | Known for data leaks in ransomware operations.                          |
| **Rhysida**               | Known for data leaks in ransomware operations.                          |
| **Qilin/AgendaCrypt**     | Known for data leaks in ransomware operations.                          |
| **Lorenz**                | Involved in leaking stolen data, including from pharmaceutical distributors. |
| **Stop (a.k.a. DJVU)**    | Ransomware gang using SmokeLoader.                                       |
| **Hive**                  | Rebranded as Hunters International after infrastructure shutdown.        |
| **RansomHub**             | Ransomware-as-a-service (RaaS) network where BlackCat affiliates migrated. |

---

### **2. Initial Access Brokers or Affiliate Networks**
These are groups or entities that specialize in providing access or tools for ransomware deployment.

| **Group/Entity**          | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **Qakbot**                | Initially for fraud, now an initial access broker for ransomware; disrupted in "Operation Duck Hunt." |
| **SmokeLoader**           | Malware used as an initial access broker for ransomware.                 |
| **Pikabot**               | Initial access broker used by Black Basta after Qakbot disruption.       |
| **Bumblebee**             | Tied to Conti, used for ransomware access.                               |
| **IcedID**                | Banking trojan turned initial access broker.                             |
| **Latrodectus**           | New malware loader created by IcedID developers.                         |
| **Raspberry Robin**       | Used SmokeLoader for ransomware deployment.                              |


---

### **3. Ransomware Variants**
Specific ransomware strains or payloads used in attacks.

| **Ransomware Variant**    | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **RagnarLocker**          | Used by Dark Angels.                                                     |
| **Babuk**                 | Used by Dark Angels before switching to RagnarLocker.                    |

---

### **4. Affiliate-Based Operations**
These are operations relying on affiliate networks to scale their attacks.

| **Group/Entity**          | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **BlackCat (ALPHV)**      | Operated through an affiliate network; cross-platform compatibility.     |
| **LockBit**               | Large affiliate network for high-volume attacks.                        |
| **RansomHub**             | Network supporting affiliates of BlackCat.                              |

---

### **5. Social Engineering and Sophisticated Threat Actors**
These groups use advanced techniques, including social engineering, but are not necessarily ransomware-exclusive.

| **Group/Entity**          | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **Scattered Spider**      | Effective social engineering group, affiliate of BlackCat.               |

---

### **6. Law Enforcement Operations**
Efforts to disrupt ransomware and initial access broker networks.

| **Operation**             | **Notes**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| **Operation Duck Hunt**   | Disrupted Qakbot operations.                                             |
| **Operation Endgame**     | Targeted initial access brokers like SmokeLoader, Pikabot, Bumblebee, and IcedID. |



<footer>

---

Created by Jaspreet S.

&copy; 2023 GitHub &bull; [Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md) &bull; [MIT License](https://gh.io/mit)

</footer>
