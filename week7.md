# Week 7: Using MITRE CAR (Cyber Analytics Repository)

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)
**Project topic:** Insider threat via trusted access - physical and digital tracks (see Week 1). This week takes an analytic from MITRE CAR, implements it in our SIEM (Elastic Stack, Kibana Discover), and maps it to ATT&CK techniques. It builds directly on hunt H1 from Week 5.

---

## 1. Overview

In Week 5 we wrote our own hunting queries from a hypothesis. This week we start from the other side: a published analytic from MITRE’s Cyber Analytics Repository (car.mitre.org), and we check how it behaves in our environment.

CAR gives a platform-neutral description of a detection idea (pseudocode, data model fields, ATT&CK coverage) plus example implementations for several tools. Our job is to translate it into our own stack and test it.

---

## 2. Selected Analytic: CAR-2014-04-003 (Powershell Execution)

| Field | Value |
|---|---|
| **ID / title** | CAR-2014-04-003 - Powershell Execution |
| **Information domain** | Host |
| **Data subtype** | Process |
| **Analytic type** | TTP |
| **Platform** | Windows |
| **Idea** | PowerShell is used by both administrators and attackers, and script execution is opaque and often not covered by antivirus. The analytic looks for PowerShell that was **not launched interactively**, using the parent process as the signal. |
| **ATT&CK coverage** | T1059.001 (PowerShell) - Execution (High coverage) and Defense Evasion (Moderate coverage) |
| **D3FEND** | D3-PSA - Process Spawn Analysis |

**CAR pseudocode:**

```
process = search Process:Create
powershell = filter process where (exe == "powershell.exe" AND parent_exe != "explorer.exe")
output powershell
```

### Why we chose it

- It is the CAR counterpart of **H1** from Week 5 (suspicious PowerShell), so the two weeks connect and we can compare a CAR analytic against our own hunt.
- It needs only process-creation events with a parent process, which our test index already has.
- It fits the project theme. PowerShell started by Word or by a management agent runs under a **valid user and a valid process**, so the system has no reason to distrust it. Only the process lineage shows that something is off.

---

## 3. Implementation in Elastic (KQL)

### 3.1 Mapping CAR data-model fields to ECS

| CAR data model (process / create) | ECS field used in our index |
|---|---|
| `exe` | `process.name` |
| `parent_exe` | `process.parent.name` |
| Process:Create action | `event.category: process` and `event.type: start` |

### 3.2 Query

```kql
event.category: process and event.type: start and process.name: "powershell.exe" and not process.parent.name: "explorer.exe"
```

This is a direct translation of the CAR pseudocode. Notes on the translation:

- CAR's reference Splunk query matches full paths (`C:\Windows\explorer.exe`). We match on the process name only, because that is the field our ECS mapping provides. This is slightly less strict, since a binary named `explorer.exe` in another folder would also be excluded.
- The query only looks at **process name and parent**. It does not inspect the command line, so it will return every non-interactive PowerShell start, malicious or not. That is the intended behavior of this analytic (broad, lineage-based) and the main difference from H1 in Week 5, which looks for specific command-line patterns.

### 3.3 Execution

The query was run in Kibana Discover over the last month (Sep 20, 2026 - Oct 20, 2026).

<img width="1280" height="713" alt="telegram-cloud-photo-size-2-5384114240437821332-y" src="https://github.com/user-attachments/assets/ed87e99c-4e0c-46be-9c45-fa5570e611a1" />


**Result: 4 documents**, all on Oct 1, 2026 (see the histogram spike):

| @timestamp | host.name | user.name | process.name | process.parent.name |
|---|---|---|---|---|
| Oct 1, 2026 @ 16:30:00 | SRV-02 | svc_sccm | powershell.exe | ccmexec.exe |
| Oct 1, 2026 @ 16:01:09 | WS-07 | acc1 | powershell.exe | winword.exe |
| Oct 1, 2026 @ 15:05:30 | DEV-01 | dev1 | powershell.exe | code.exe |
| Oct 1, 2026 @ 14:20:11 | DEV-03 | dev3 | powershell.exe | code.exe |

Timestamps are shown as Kibana displays them (browser time zone). The pipeline in Week 3 normalizes logs to UTC, so any timeline built from these events should be converted first.

---

## 4. Triage of the Results

| # | Host / user | Parent | Assessment | Reasoning |
|---|---|---|---|---|
| 1 | WS-07 / acc1 | `winword.exe` | **Suspicious - true positive candidate** | Word has no normal reason to start PowerShell. This is the classic malicious-macro / document-loader chain. Highest priority. |
| 2 | SRV-02 / svc_sccm | `ccmexec.exe` | **Likely benign - false positive** | `ccmexec.exe` is the SCCM (Configuration Manager) client agent and runs under a service account on a server. Same pattern as the SCCM false positive in Week 5 (H1). |
| 3 | DEV-01 / dev1 | `code.exe` | **Needs the command line** | VS Code starting PowerShell is usually the integrated terminal. It becomes interesting only if the command touches credential files, which is exactly H2 from Week 5. |
| 4 | DEV-03 / dev3 | `code.exe` | **Needs the command line** | Same as above. |

**Result of the triage:** 1 suspicious event, 1 likely false positive (SCCM), 2 undecided until the command line is checked. The analytic did what it is designed to do: it surfaced the one event with a suspicious lineage (Word → PowerShell) together with the normal-but-unusual parents that a team would have to allowlist.

**Important limit:** this analytic cannot separate case 1 from cases 2-4 on its own. The Discover view above shows no `process.command_line` column. The next triage step for each hit is to open the document and read the command line, the user's recent activity on that host, and any network connection started by the same process.

---

## 5. Tuning

The analytic is intentionally broad, so it needs tuning before it can run as an alert.

**Proposed tuned query (not executed in this report):**

```kql
event.category: process and event.type: start and process.name: "powershell.exe"
and not process.parent.name: ("explorer.exe" or "ccmexec.exe")
```

| Hit | Tuning decision |
|---|---|
| `ccmexec.exe` (SCCM) | Allowlist the parent, ideally together with the service account (`svc_sccm`) and server hosts, so an attacker cannot hide behind the same parent name from a workstation. |
| `code.exe` (VS Code) | Do **not** blanket-allowlist. VS Code is the parent used in the Nx Console case (Week 2). Keep it visible, but route it to the H2 logic: alert only when the command line also touches `.ssh`, `hosts.yml` or `credentials`. |
| `winword.exe` (Office) | Keep as a high-severity alert. Office applications are rarely a legitimate parent of PowerShell. |

---

## 6. ATT&CK Mapping

| ATT&CK technique | Tactic | How it relates to this analytic |
|---|---|---|
| **T1059.001** - Command and Scripting Interpreter: PowerShell | Execution | Primary technique. This is the behavior CAR-2014-04-003 detects (coverage level: High). |
| **T1059.001** | Defense Evasion | Secondary mapping in CAR (coverage level: Moderate). PowerShell can hide commands that are monitored elsewhere. |
| **T1204.002** - User Execution: Malicious File | Execution | Context for the Word → PowerShell hit. A user opens a document and the macro starts PowerShell. The analytic sees the second half of that chain, not the user action itself. *(Our own mapping, not a CAR mapping.)* |
| **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | Context for the `code.exe` hits only, if the command line turns out to read credentials (Week 2 Nx Console case, Week 5 H2). *(Our own mapping, not a CAR mapping.)* |

Kill Chain link (Week 4): this analytic sits at the **Exploitation / Installation** stages, after delivery has already happened. It does not see reconnaissance, weaponization or delivery.

---

## 7. Analytics vs Detections

| | **Analytic** | **Detection** |
|---|---|---|
| What it is | A reusable description of behavior and the logic to find it, independent of any product | A deployed implementation in a specific environment that produces alerts |
| Example here | CAR-2014-04-003 and its pseudocode | The KQL query in Kibana, run on our index |
| Contains | Data model fields, ATT&CK mapping, example queries | Query plus allowlists, severity, schedule, owner, response steps |
| Tuned to the environment? | No | Yes (§5) |
| Can be shared between teams? | Yes | Rarely without changes |

What we did this week is move from the first column to the second. The query in §3.2 is an implementation of the analytic. It becomes a **detection** only after the tuning in §5, a schedule, a severity level and a triage procedure.

---

## 8. Connection to Previous Weeks

- **Week 3:** the KQL rule for VS Code credential harvesting and this analytic watch the same field (`process.parent.name`) from two directions: one for a specific suspicious parent, one for any non-interactive parent.
- **Week 4:** the analytic covers the Exploitation / Installation stages on the endpoint.
- **Week 5:** H1 (encoded commands) and CAR-2014-04-003 (parent process) catch the same Word → PowerShell event by different signals. Together they are stronger than either alone: parent anomaly **plus** encoded command line is a much more specific condition than either one.
- **Two tracks:** this week is digital only. The physical track has no CAR counterpart, because CAR is also built around host and network telemetry (same limit as in Week 4 §4).

---

## 9. Limitations

- The result is from a test index, not production telemetry, so the 4 hits show that the query works, not how noisy it would be in a real environment.
- Matching on process name only (no full path, no signature check) can be bypassed by a renamed or copied binary.
- The analytic ignores `explorer.exe` as a parent, so an attacker who launches PowerShell from an interactive session is not detected by this analytic. Other CAR analytics and H1 cover part of that gap.
- The command line was not part of the reviewed view, so cases 3 and 4 remain undecided.

---

## 10. Recommended Reading

- MITRE CAR documentation (car.mitre.org), including the data model page for `process`
- MITRE ATT&CK, T1059.001 (attack.mitre.org/techniques/T1059/001/)

## 11. Sources

- MITRE CAR, "CAR-2014-04-003: Powershell Execution" - https://car.mitre.org/analytics/CAR-2014-04-003/
- MITRE ATT&CK, T1059.001 PowerShell - https://attack.mitre.org/techniques/T1059/001/
- MITRE D3FEND, D3-PSA Process Spawn Analysis - https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis
- This repository, Weeks 2-5 (case studies, KQL rule, hunt H1/H2)

---

Use of AI
Generative AI was used to help organize and edit the written explanation, to locate the matching CAR analytic, and to draft the triage and tuning tables. The project team reviewed the material and ran the query in Kibana Discover. AI was not used to access organizational systems or real endpoint data.
