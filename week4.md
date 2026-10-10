# Week 4: The Cyber Kill Chain

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)
**Project topic:** Insider threat via trusted access - physical and digital tracks (see Week 1). This week takes the same two case studies carried through Weeks 2–3 and re-analyzes them through Lockheed Martin's Cyber Kill Chain, mapped to MITRE ATT&CK technique IDs at each stage.

---

## 1. Overview

The Kill Chain (Lockheed Martin) breaks an attack into seven stages: **Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives**. We apply it to both tracks side by side - **Case Study 2 (digital, Nx Console/GitHub)**, where the model maps cleanly onto ATT&CK, and **Case Study 1 (physical, badge cloning)**, where it doesn't map as cleanly, which is itself a useful finding (§4).

---

## 2. Case Study 2 (Digital) - Nx Console / GitHub, mapped to the Kill Chain

| Stage | What happened (from Week 2 timeline) | MITRE ATT&CK technique |
|---|---|---|
| **1. Reconnaissance** | Attacker (TeamPCP) identified mutable GitHub Actions version tags as an exploitable weakness across CI/CD pipelines, starting ~March 2026. | **T1593** - Search Open Websites/Domains |
| **2. Weaponization** | Prepared and published malicious versions of `@tanstack/*` npm packages, weaponizing a trusted distribution channel rather than building custom malware from scratch. | **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain |
| **3. Delivery** | Malicious TanStack package delivered to victims via a routine `pnpm install`, a completely ordinary developer action. | **T1195.002** (delivery phase of the same technique) |
| **4. Exploitation** | Installing the poisoned package silently exfiltrated an Nx contributor's GitHub CLI OAuth token during install-time script execution. | **T1528** - Steal Application Access Token |
| **5. Installation** | Using the stolen token, attacker pushed a malicious orphan commit into `nrwl/nx`; a trojanized **Nx Console v18.95.0** was published and auto-pushed to 2.2M+ existing installs via VS Code's update mechanism. | **T1554** - Compromise Client Software Binary |
| **6. Command & Control** | The payload inside `main.js` reached out to an external C2 domain to receive instructions and exfiltrate harvested secrets. | **T1102** - Web Service (as a C2 channel) |
| **7. Actions on Objectives** | Harvested GitHub/npm/AWS/Vault/Kubernetes/1Password tokens; used stolen keys to bulk-clone ~3,800 internal GitHub repositories. | **T1567** - Exfiltration Over Web Service; **T1213** - Data from Information Repositories |

**Observation:** every stage of this attack routes through something *legitimate* - a real npm package, a real OAuth token, a real Marketplace update channel. The Kill Chain stages are individually mundane; it's the sequence that's malicious. This is consistent with the "trusted-access abuse" theme running through Weeks 1-3.

---

## 3. Case Study 1 (Physical) - Badge Cloning, mapped to the Kill Chain

| Stage | What happened (from Week 2) | MITRE ATT&CK technique |
|---|---|---|
| **1. Reconnaissance** | Attacker harvested employee badge photos from LinkedIn/Facebook, plus building interior photos shared by partners/contractors. | **T1593.001** - Search Open Websites/Domains: Social Media |
| **2. Weaponization** | Identified the badge's RFID technology from the photos and built/programmed a physical clone using a long-range RFID reader/writer. | *No direct Enterprise ATT&CK technique* - see §4 |
| **3. Delivery** | The cloned badge itself is the "delivery mechanism" - carried to the facility door. | *No direct Enterprise ATT&CK technique* - see §4 |
| **4. Exploitation** | Cloned badge presented at the access-control reader; the system authenticates it as the legitimate employee. | **T1078** - Valid Accounts (the credential-abuse technique closest in spirit) |
| **5. Installation** | N/A in the physical sense - there's no payload to "install." The attacker's continued unauthorized presence (dwell time) is the closest analog. | *Not directly applicable* |
| **6. Command & Control** | N/A - no remote channel; the attacker is physically present and self-directing. | *Not applicable* |
| **7. Actions on Objectives** | Whatever the intruder does once inside - e.g., accessing an unlocked workstation, photographing documents, planting a device. | Depends on the specific act, e.g. **T1005** - Data from Local System |

---

## 4. Why the Kill Chain/ATT&CK mapping is uneven across tracks - and what that means

This is a deliberate finding, not a gap we're hiding: **MITRE ATT&CK Enterprise is built around software-based behavior on computer systems.** It has no dedicated technique for "clone an RFID badge" or "walk through a door," because those actions don't touch a computer at all - they touch a physical access-control system, which ATT&CK treats as out of scope. The closest fit, **T1078 (Valid Accounts)**, only captures the *exploitation* moment (presenting a valid-looking credential); it says nothing about how that credential was physically forged.

**Implication for the project:** the digital track (Case Study 2) can be fully instrumented and detected using ATT&CK-aligned tooling (which is exactly what Week 3's MISP/KQL setup does). The physical track (Case Study 1) cannot be - it needs a **parallel physical-security control framework** (e.g., badge/ACS behavioral rules, like the "impossible travel for badges" indicator already defined in Week 3) instead of relying on ATT&CK coverage. This is a concrete argument for why the project's Week 3 MISP model treats physical indicators as a first-class, separately-defined category rather than trying to force them into ATT&CK's vocabulary.

---

## 5. Recommended Reading

- Lockheed Martin, *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*
- MITRE ATT&CK Enterprise Matrix (attack.mitre.org)

## 6. Sources

- StepSecurity, "Nx Console VS Code Extension Compromised" (May 18, 2026)
- Cloud Security Alliance, "VSCode Marketplace Poisoning: How 18 Minutes Breached GitHub" (May 25, 2026)
- Rankiteo, incident summary on GitHub/npm/Microsoft/Nx compromise (May 2026)
- Pellera Technologies, "Physical Security Risks Exposed: Real-World Penetration Testing Lessons"
- MITRE ATT&CK technique references: T1593, T1195.002, T1528, T1554, T1102, T1567, T1213, T1078, T1005
