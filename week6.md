# Week 6: MITRE ATT&CK Framework and PowerShell Simulation

## 1. Objective and scope

The objective was to study one ATT&CK technique, simulate its behavior safely, and map the observed results to ATT&CK tactics and techniques. The selected sub-technique was **T1059.001 — PowerShell**, under **T1059 — Command and Scripting Interpreter** and the **Execution** tactic.

The practical exercise consisted of three commands: an encoded PowerShell command that prints a test message, process enumeration, and a current-user check. These commands model individual behaviors that could occur during an intrusion without performing harmful actions. The screenshots below document the interactive run on the laptop.

## 2. ATT&CK concepts and selected technique

MITRE ATT&CK organizes observed adversary behavior into tactics, techniques, and sub-techniques. A procedure describes a concrete implementation of a behavior.

| Concept | Meaning | Application in this exercise |
|---|---|---|
| Tactic | Why an adversary performs an action | Execution: running commands; Discovery: learning about the environment |
| Technique | How the objective is achieved | T1059 — Command and Scripting Interpreter |
| Sub-technique | A more specific form of a technique | T1059.001 — PowerShell |
| Emulated procedure | The specific command used in this lab | Starting PowerShell with `-EncodedCommand` to execute a harmless test message |

PowerShell is a legitimate command-line and scripting environment that adversaries can also abuse to execute commands and scripts. MITRE associates T1059.001 with **Execution (TA0002)** and lists Windows, Linux, and macOS as supported platforms. This exercise tested Windows only. [Source: MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/).

For the project topic, PowerShell illustrates how a person with trusted access could use an existing administrative tool. Its presence or execution alone does not establish malicious activity; interpretation requires command-line, user, and process context.

## 3. Practical simulation and evidence

### 3.1 Encoded PowerShell execution

**Command executed:**

```powershell
powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAMQAwADUAOQAuADAAMAAxACAAdABlAHMAdAAiAA==
```

The Base64 argument represents the following UTF-16LE command:

```powershell
Write-Output "T1059.001 test"
```

**Expected result:** PowerShell prints the test message.  
**Observed result:** The console displayed `T1059.001 test` and returned to the prompt.

![Figure 1. Encoded PowerShell command and the resulting test message.](images/01_encoded_powershell.png)

*Figure 1. Successful execution of the harmless encoded command.*

This demonstrates PowerShell execution (T1059.001). Encoding also provides a controlled example of the command-obfuscation pattern described by T1027.010. It does not demonstrate that a security control was bypassed. [Source: MITRE T1027.010](https://attack.mitre.org/techniques/T1027/010/).

### 3.2 Process discovery

**Command executed:**

```powershell
Get-Process
```

**Expected result:** PowerShell lists running processes.  
**Observed result:** The console displayed a process table with columns including `Handles`, `NPM(K)`, `PM(K)`, `WS(K)`, `CPU(s)`, `Id`, `SI`, and `ProcessName`. Visible examples include `ACCSvc`, `AggregatorHost`, and `backgroundTaskHost`.

![Figure 2. Get-Process command and a visible portion of its output.](images/02_process_discovery.png)

*Figure 2. Process enumeration. The screenshot captures a portion of the list; it does not establish the total process count.*

MITRE explicitly identifies PowerShell `Get-Process` as an example of **T1057 — Process Discovery**, under Discovery. [Source: MITRE T1057](https://attack.mitre.org/techniques/T1057/).

### 3.3 Current-user discovery

**Command executed:**

```powershell
whoami
```

**Expected result:** The command displays the account associated with the current execution context.  
**Observed result:** The console displayed:

```text
acerswift3\ернар имаханов
```

The command then returned to the PowerShell prompt.

![Figure 3. whoami command and the returned account name.](images/03_user_discovery.png)

*Figure 3. Identification of the account running the command.*

MITRE lists `whoami` as a utility used for **T1033 — System Owner/User Discovery**, under Discovery. This output identifies the execution account; it does not establish account privileges or identify every logged-in user. [Source: MITRE T1033](https://attack.mitre.org/techniques/T1033/).

**Overall result:** The encoded command printed `T1059.001 test`, `Get-Process` displayed running processes, and `whoami` returned `acerswift3\ернар имаханов`.

## 4. Mapping observed results to ATT&CK

| Evidence | Observed behavior | ATT&CK tactic | Technique / sub-technique | Interpretation |
|---|---|---|---|---|
| Figure 1 | PowerShell executed an encoded command and printed the test message | Execution (TA0002) | T1059.001 — PowerShell | Confirms the tested command executed |
| Figure 1 | The command body was supplied as a Base64 argument | Defense Evasion (TA0005), conceptual mapping | T1027.010 — Command Obfuscation | Demonstrates an encoding pattern; successful evasion was not tested |
| Figure 2 | Running processes were enumerated | Discovery (TA0007) | T1057 — Process Discovery | Confirms process information was displayed |
| Figure 3 | The current execution account was queried | Discovery (TA0007) | T1033 — System Owner/User Discovery | Confirms the account name was displayed |

The mappings describe behaviors that can occur in adversary activity. The commands in this exercise were authorized and benign; matching a technique does not make an action malicious.

## 5. Connection to Week 5 and detection considerations

According to the supplied Week 5 context, hunt **H1** concerned encoded PowerShell execution. Figure 1 reproduces the relevant command-line feature: `powershell` started with `-EncodedCommand`.

A defender could investigate process-creation telemetry containing the executable, command line, parent process, user, host, and timestamp. PowerShell script-block logging, when enabled and collected, can provide additional script context. These are investigation opportunities, not collected evidence in this exercise.

A detection should account for legitimate administrative automation and variations of PowerShell arguments. The exact Week 5 query was not revalidated here. No claim is made that H1 matched these events or that a SIEM alert was generated. Figures 2 and 3 provide additional Discovery behavior, but their detection coverage was not tested.

## 6. Limitations

- The exercise covers three harmless commands on one Windows laptop, not a complete intrusion or insider-threat scenario.
- No download, persistence, credential theft, privilege escalation, or exfiltration was performed by these commands.
- Screenshots show console commands and output. They do not establish event-log collection, SIEM ingestion, parent-process lineage, or alert generation.
- Command encoding was demonstrated; malicious intent and successful defense evasion were not demonstrated.
- This report covers Week 6. CAR analytics implementation and SIEM validation belong to Week 7 and are outside the evidence presented here.

## 7. Conclusion

The exercise demonstrated PowerShell execution through a harmless encoded command and two discovery actions. The observed results were mapped to T1059.001, T1057, and T1033. The Base64 argument was additionally linked to T1027.010 as an example of an encoding pattern, with no claim of successful evasion. This connects the practical activity to the Week 5 encoded-PowerShell hunting hypothesis while keeping execution evidence separate from untested detection coverage.

## 8. References

MITRE technique pages checked on 23 October 2026:

1. [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
2. [T1027.010 — Obfuscated Files or Information: Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)
3. [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057/)
4. [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)

The Week 5 H1 connection is based on the supplied project description. Primary practical evidence is provided in Figures 1–3.
