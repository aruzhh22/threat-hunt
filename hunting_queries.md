# Week 10 — Hunting Queries (KQL)

These queries turn the APT29 / insider TTP overlap into hunts we could run in **Microsoft Sentinel / Defender XDR**.
Standard tables: `SigninLogs`, `AuditLogs`, `DeviceEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `CloudAppEvents`.
Badge data is assumed to be ingested as a custom table `PhysicalAccess_CL` (fields: `BadgeId_s`, `Direction_s`, `TimeGenerated`), plus a watchlist `EmployeeMap` (`BadgeId`, `UPN`).

> The same logic is implemented offline in Python in `hunt_insider.py` on synthetic data.

---

## H1 — Remote sign-in while badge says "inside" (T1078 Valid Accounts)

**Hypothesis:** if a user is physically in the office but a VPN / cloud login for the same account comes from an external IP, the credentials are shared or stolen (APT29 heavily relies on stolen valid accounts).

```kql
let badge = PhysicalAccess_CL
    | join kind=inner (_GetWatchlist('EmployeeMap')) on $left.BadgeId_s == $right.BadgeId
    | project BadgeTime = TimeGenerated, UPN, Direction_s;
SigninLogs
| where ResultType == 0
| where not(ipv4_is_private(IPAddress))
| join kind=inner badge on $left.UserPrincipalName == $right.UPN
| where BadgeTime < TimeGenerated and TimeGenerated - BadgeTime < 10h
| summarize arg_max(BadgeTime, Direction_s) by UserPrincipalName, TimeGenerated, IPAddress
| where Direction_s == "IN"
| project TimeGenerated, UserPrincipalName, IPAddress, LastBadge = BadgeTime
```

## H2 — Office workstation logon without badge entry (tailgating / shared account)

```kql
let badged = PhysicalAccess_CL
    | where Direction_s == "IN"
    | join kind=inner (_GetWatchlist('EmployeeMap')) on $left.BadgeId_s == $right.BadgeId
    | summarize by UPN, Day = startofday(TimeGenerated);
DeviceLogonEvents
| where LogonType == "Interactive" and DeviceName startswith "WS-"
| extend UPN = tolower(AccountUpn), Day = startofday(Timestamp)
| join kind=leftanti badged on UPN, Day
| project Timestamp, DeviceName, UPN
```

## H3 — After-hours archive → USB (T1560.001 + T1052.001 + T1070.004)

```kql
let window = 1h;
let archives = DeviceProcessEvents
    | where FileName in~ ("7z.exe","rar.exe","winrar.exe","zip.exe")
    | where hourofday(Timestamp) >= 20 or hourofday(Timestamp) < 6
    | project ArchiveTime = Timestamp, DeviceId, AccountName, ProcessCommandLine;
DeviceEvents
| where ActionType == "UsbDriveMounted"
| join kind=inner archives on DeviceId
| where Timestamp between (ArchiveTime .. ArchiveTime + window)
| project ArchiveTime, UsbTime = Timestamp, DeviceName, AccountName, ProcessCommandLine,
          UsbInfo = AdditionalFields
```

## H4 — Leaver data grab (T1213.002 + T1098.005)

Needs an HR watchlist `Leavers` (`UPN`, `NoticeDate`).

```kql
let leavers = _GetWatchlist('Leavers') | project UPN = tolower(UPN), NoticeDate = todatetime(NoticeDate);
let downloads = CloudAppEvents
    | where ActionType in ("FileDownloaded","FileSyncDownloadedFull")
    | summarize Files = count() by UPN = tolower(AccountDisplayName), Day = startofday(Timestamp)
    | where Files > 200;
let devices = AuditLogs
    | where OperationName == "Register device"
    | extend UPN = tolower(tostring(InitiatedBy.user.userPrincipalName))
    | project DeviceTime = TimeGenerated, UPN;
leavers
| join kind=inner downloads on UPN
| join kind=inner devices on UPN
| where Day between (NoticeDate - 14d .. NoticeDate + 30d)
| project UPN, NoticeDate, Day, Files, DeviceTime
```

## H5 — Laptop-farm pattern (T1200 + T1219 + T1090.002)

**Hypothesis:** several "different" remote employees connecting from the same residential IP, with KVM-over-IP hardware or remote-access tools, indicates a laptop farm used by fake IT workers (DPRK scheme).

```kql
let sharedIps = SigninLogs
    | where ResultType == 0
    | summarize Users = make_set(UserPrincipalName), UserCount = dcount(UserPrincipalName) by IPAddress
    | where UserCount > 1;
let tools = union
    (DeviceEvents | where ActionType == "PnpDeviceConnected"
        | where AdditionalFields has_any ("KVM","PiKVM","TinyPilot","ATEN")),
    (DeviceProcessEvents | where FileName in~ ("AnyDesk.exe","TeamViewer.exe","rustdesk.exe"))
    | summarize ToolEvents = count() by AccountName;
sharedIps
| mv-expand User = Users to typeof(string)
| extend AccountName = tostring(split(User, "@")[0])
| join kind=leftouter tools on AccountName
| project IPAddress, UserCount, User, ToolEvents
```

## H6 — APT29-style persistence: new mailbox delegate / OAuth credential (T1098.002, T1098.001)

```kql
AuditLogs
| where OperationName in ("Add delegated permission grant",
                          "Update application – Certificates and secrets management",
                          "Add-MailboxPermission")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, Actor, TargetResources
```

---

### Tuning notes
- H1 false positives: users with mobile phones on cellular data while in the office → exclude known mobile ASNs or only check VPN / desktop clients.
- H2 false positives: broken badge readers, visitors escorted in → cross-check with reception logs.
- H5 false positives: couples / roommates working for the same company → confirm with HR (identity verification, shipping address).
