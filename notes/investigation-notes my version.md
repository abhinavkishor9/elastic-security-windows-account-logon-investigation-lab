# Investigation Notes 

## Account Enumeration

The following command was used:

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

Observed accounts included:

```text
Administrator
CompromiseTest
DefaultAccount
Dell
DormantUser
Guest
lab-reset-user
TempSupport
WDAGUtilityAccount
```

Enabled accounts included:

```text
CompromiseTest
Dell
DormantUser
lab-reset-user
TempSupport
```

The current account was:

```text
desktop-9mmm37v\dell
```

## Current User Context

The following commands were used:

```powershell
whoami
```

```powershell
whoami /user
```

```powershell
whoami /groups
```

Observed user:

```text
desktop-9mmm37v\dell
```

Observed SID:

```text
S-1-5-21-51198790-337801975-3228388354-1001
```

The account belonged to the local Administrators group and was operating at a high integrity level.

## Initial Security Log Check

The initial command:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

first returned:

```text
No events were found that match the specified selection criteria.
```

This result was not treated as evidence that Windows authentication logging was disabled or absent.

The Security log and auditing state were investigated further.

## Local Successful Logons

After further validation, the local Security log returned multiple `4624` events.

Examples included:

```text
28-09-2026 06:18:36
4624
Microsoft-Windows-Security-Auditing
```

```text
28-09-2026 06:18:25
4624
Microsoft-Windows-Security-Auditing
```

```text
28-09-2026 06:16:43
4624
Microsoft-Windows-Security-Auditing
```

These events confirmed that successful logon auditing was active and generating records.

## Elastic 4624 Query

The following query was used:

```esql
FROM logs-*
| WHERE event.code == "4624"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName
| SORT @timestamp DESC
```

Elastic returned:

```text
38 documents processed
```

## `Dell` Logon

A focused query was used:

```esql
FROM logs-*
| WHERE event.code IN ("4624", "4625")
| WHERE user.name == "Dell"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName
| SORT @timestamp DESC
```

Result:

```text
2 documents processed
```

Observed:

```text
Sep 28, 2026 @ 06:24:55.739
Host: desktop-9mmm37v
User: Dell
Event: 4624
Logon Type: 2
```

The event also showed:

```text
TargetUserName: Dell
TargetDomainName: DESKTOP-9MMM37V
```

No source IP was populated in the returned fields.

## SYSTEM Logons

Elastic also showed:

```text
SYSTEM
Event: 4624
Logon Type: 5
TargetUserName: SYSTEM
TargetDomainName: NT AUTHORITY
```

These events represented service-related authentication context rather than user interactive logon.

## Machine Account Activity

The endpoint also produced 4624 activity associated with:

```text
DESKTOP-9MMM37V$
```

These records demonstrated that authentication telemetry may contain machine-account events in addition to user logons.

## Failed Logon Hunt

The following query was executed:

```esql
FROM logs-*
| WHERE event.code == "4625"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No failed-logon events were returned.

## Special Privilege Hunt

The following query was executed:

```esql
FROM logs-*
| WHERE event.code == "4672"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.SubjectUserName
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No Event ID `4672` records were returned in the investigated window.

## Remote Interactive Hunt

The following query was used:

```esql
FROM logs-*
| WHERE event.code == "4624"
| WHERE winlog.event_data.LogonType == "10"
| KEEP @timestamp, host.name, user.name, winlog.event_data.TargetUserName, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.LogonType
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No Logon Type `10` events were returned.

## Controlled Workstation Lock

A normal workstation lock was generated with:

```powershell
rundll32.exe user32.dll,LockWorkStation
```

The workstation was subsequently unlocked normally.

This activity was used to generate normal authentication-related activity without creating an artificial password attack.

## Authentication Context

The main observed contexts were:

```text
Dell
    |
    +-- 4624
        Logon Type 2
```

and:

```text
SYSTEM
    |
    +-- 4624
        Logon Type 5
```

These demonstrate why a SOC analyst must distinguish account identity and logon type rather than treating every 4624 event equally.

## Analyst Assessment

### Observed

- Successful logon events.
- Interactive Logon Type `2`.
- Service-related Logon Type `5`.
- User `Dell`.
- `SYSTEM`.
- Machine account `DESKTOP-9MMM37V$`.
- No failed-logon events in the queried range.
- No special-privilege events in the queried range.
- No Remote Interactive Logon Type `10` events.

### Confirmed

- Windows Security logging was generating successful logon events.
- Elastic received Event ID `4624` telemetry.
- `Dell` appeared in an interactive logon context.
- `SYSTEM` appeared in a service logon context.
- No failed authentication attack was demonstrated.

### Unknown

- Whether other authentication events existed outside the selected time window.
- The reason the initial Security-log query returned no events before the subsequent validation activity.
- Whether source information was unavailable because the corresponding fields were not populated for these events.

