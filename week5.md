# Week 5: Threat Hunting Concept

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)
**Project topic:** Insider threat via trusted access - physical and digital tracks (see Week 1). This week turns the detection ideas from Weeks 3–4 into proactive hunts: we pick a hunting model, write a hypothesis for each track, and build hunt queries for Elastic (KQL) and Splunk (SPL).

---

## 1. Overview

Detection waits for an alert. **Threat hunting** starts from the assumption that an attacker may already be inside and goes looking for evidence that existing alerts did not raise. In this project that matters because trusted-access abuse is built to look normal: a valid badge, a valid token, a signed extension update.

---

## 2. Hunting Models

| | **Intel-driven** | **Hypothesis-driven** |
|---|---|---|
| Starting point | Threat intelligence: IOCs, reports, advisories | An analyst's assumption about attacker *behavior* |
| Typical question | "Is this known-bad hash/domain/IP present in our environment?" | "If an attacker did X, what would that look like in our logs?" |
| Strength | Fast, precise, easy to automate | Can find unknown or novel activity; not limited to known IOCs |
| Weakness | Finds only what is already known; IOCs go stale quickly | Needs good data and analyst skill; more false positives |
| Project example | Take the sha256 / C2 domain from GHSA-c9j4-9m59-847w (MISP Event 2, Week 3) and search endpoint and proxy logs for them | Hunts H1 and H2 below, based on ATT&CK techniques |

The models complement each other: an intel-driven hit confirms a known threat, and a hypothesis-driven hunt produces new behavioral patterns that go back into CTI and detection rules. A commonly used hunting loop (popularised by Sqrrl) is: **create hypothesis → investigate with tools and techniques → uncover new patterns/TTPs → turn findings into automated analytics**.

---

## 3. Hunt Scenarios (hypothesis-driven)

### H1: Suspicious PowerShell activity (syllabus example)

- **Hypothesis:** If an attacker used a malicious document or loader to run code, PowerShell will be started with encoded commands or download cradles, often from an unusual parent process (Office, script host).
- **ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell).
- **Data needed:** process creation events with full command line (Sysmon Event ID 1, Windows 4688 with command line, or Elastic Defend/Winlogbeat); optionally PowerShell script block logging (4104).
- **Look for:** `-enc` / `-EncodedCommand`, `FromBase64String`, `DownloadString`, `Invoke-Expression`.
- **Expected false positives:** management tools that legitimately use encoded commands (e.g. SCCM), and any script using a parameter like `-Encoding`. These are triaged by parent process, user and host, then added to an allowlist.

### H2: Trusted developer tool spawning credential access (project-specific)

- **Hypothesis:** If a trojanized IDE extension (as in Nx Console, Week 2) runs on a developer machine, VS Code will spawn a shell or `curl` that reads credential stores (`~/.ssh`, GitHub CLI `hosts.yml`, cloud `credentials` files). Normal development rarely combines those three things.
- **ATT&CK:** T1195.002 (initial access via supply chain), T1059 (execution), T1552.001 / T1552.004 (credentials in files, private keys), T1567 (exfiltration over web service).
- **Data needed:** process creation with parent process and command line. For Linux/macOS developers, Sysmon for Linux, auditd, or an EDR is required.
- **Expected false positives:** a developer legitimately checking keys from the integrated terminal (for example `ls ~/.ssh`). Triage: is `curl` or an outbound connection in the same command chain, and is the user a known developer on a known machine?
- **Link to the project theme:** the attacker here becomes a *compromised insider* in the eyes of the system, which is exactly why the hunt keys on behavior and not on identity.

### H3 (physical track, conceptual): badge "impossible travel"

- **Hypothesis:** A cloned badge will appear at two distant sites within minutes of each other.
- **Data needed:** ACS/badge events with `badge_id`, `site`, `door_id`, timestamp (Week 3 schema). We do not have real ACS data, so this hunt is **designed but not executed**.

---

## 4. Hunt Queries

### 4.1 Elastic (KQL, ECS field names)

**H1**
```kql
event.category: process and event.type: start
and process.name: "powershell.exe"
and process.command_line: (*-enc* or *frombase64string* or *downloadstring* or *invoke-expression*)
```

**H2**
```kql
event.category: process and event.type: start
and process.parent.name: ("Code.exe" or "code" or "Code Helper (Plugin)")
and process.name: ("bash" or "sh" or "zsh" or "powershell.exe" or "cmd.exe" or "curl" or "curl.exe")
and process.command_line: (*.ssh* or *hosts.yml* or *credentials*)
```

Notes: wildcards only work **outside** quotes in KQL. `*.ssh*` is used instead of a path with backslashes because `\` is an escape character in KQL and `~` is expanded by the shell before logging. In the test index the process fields use a lowercase normalizer, so queries are case-insensitive; in other mappings these fields may be case-sensitive.

### 4.2 Splunk (SPL, Sysmon Event ID 1)

**H1**
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-Expression*")
| stats count min(_time) AS first_seen values(CommandLine) AS command BY host, user, ParentImage
```

**H2**
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\\Code.exe"
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\curl.exe" OR Image="*\\bash.exe")
(CommandLine="*.ssh*" OR CommandLine="*hosts.yml*" OR CommandLine="*credentials*")
| stats count min(_time) AS first_seen values(CommandLine) AS command BY host, user, Image
```

**H3 (conceptual, not executed)**
```spl
index=acs sourcetype=badge_events
| sort 0 badge_id _time
| streamstats current=f last(site) AS prev_site last(_time) AS prev_time BY badge_id
| eval delta_min=(_time-prev_time)/60
| where site!=prev_site AND delta_min<5
```

---

## 5. Execution and Results

### 5.1 Logic check on a synthetic sample (done)

Because no real endpoint telemetry was available, the hunt logic was checked against a small **synthetic, labelled** sample (`sample_events.jsonl`, 10 events, script `hunt_check.py`). This is a test of the matching logic only; it is **not** a run in Elastic or Splunk.

| Hunt | Hits | True positives | False positives | Missed |
|---|---|---|---|---|
| H1 PowerShell | 2 | 1 (Word → encoded PowerShell) | 1 (SCCM agent using `-EncodedCommand`) | 0 |
| H2 VS Code credential access | 4 | 3 | 1 (developer ran `ls ~/.ssh`) | 0 |

What it shows: both rules catch the planted malicious events, and each produces one realistic false positive that needs triage by parent process, user and whether `curl`/network activity follows. Not matched on purpose: PowerShell reading `.ssh\config` started from `explorer.exe` (parent is not VS Code), and ordinary `npm run build` / `git status` from VS Code.

### 5.2 Execution in Elastic (Kibana Discover)

The synthetic sample (sample_bulk.ndjson) was loaded into an Elastic Cloud deployment (index `hunt-sample`) and the KQL queries from §4.1 were run in Discover.

H1 (suspicious PowerShell): 2 hits - screenshot 1
H2 (VS Code credential access): 4 hits - screenshot 2


<img width="1920" height="1140" alt="Снимок экрана 2026-10-07 184245" src="https://github.com/user-attachments/assets/8675a387-94cb-4d24-aeb1-fa85fc097e19" />

<img width="1920" height="1140" alt="Снимок экрана 2026-10-07 184214" src="https://github.com/user-attachments/assets/739a7a8e-67fa-4dea-9c71-108d1b8b1b5d" />



---

## 6. Hunt Outcome Template

| Field | H1 | H2 |
|---|---|---|
| Hypothesis confirmed? | Not applicable on synthetic data | Not applicable on synthetic data |
| Hits / true / false positives | 2 / 1 / 1 | 4 / 3 / 1 |
| Tuning applied | Allowlist SCCM parent (`ccmexec.exe`) | Require `curl`/network activity in the command, or known-developer allowlist |
| Detection rule created | Candidate  | Candidate (Sigma, Week 3 backlog) |
| ATT&CK coverage | T1059.001 | T1195.002, T1552.001/.004 |

---

## 7. Connection to Previous Weeks

- **Week 3:** MISP IOCs feed intel-driven hunts; the KQL rule from Week 3 is the automated form of H2.
- **Week 4:** the hunts target Kill Chain stages that are hardest to see from the outside: Exploitation/Installation (H1) and Actions on Objectives (H2).
- **Two tracks:** H1/H2 are digital; H3 is the physical counterpart, which ATT&CK does not cover (Week 4 §4).

---

## 8. Recommended Reading and Sources

- Microsoft Threat Hunting Guide; Phillip Smith, *Practical Threat Hunting* (as listed in the course syllabus - verify exact titles and editions before citing)
- SANS Threat Hunting Summit talks
- MITRE ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1552.004](https://attack.mitre.org/techniques/T1552/004/), [T1195.002](https://attack.mitre.org/techniques/T1195/002/)
- Project sources for the Nx Console case: see Week 2
