# Elastic Security Lab 09 — Windows Account & Logon Investigation

## Overview

This lab investigates **Windows account and logon activity** using local Windows Security logs and Elastic endpoint telemetry.

The investigation focuses on identifying successful and failed logons, understanding Windows Logon Types, validating account context, examining source information when available, and distinguishing normal authentication activity from events that may require additional investigation.

The lab also demonstrates an important SOC workflow: validate the underlying Windows Security events locally before assuming that corresponding authentication telemetry is available in Elastic.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |
| Time Range | Last 15 minutes |

## Objectives

- Investigate Windows successful and failed logon activity.
- Validate local Windows Security event availability.
- Identify Event ID 4624 successful-logon activity.
- Investigate Event ID 4625 failed-logon activity.
- Examine Windows Logon Types and associated account context.
- Correlate local Windows events with Elastic telemetry.
- Distinguish user logons from system and service authentication activity.
- Investigate account information and local-user configuration.
- Examine special-privilege Event ID 4672 telemetry.
- Investigate Remote Interactive Logon Type 10 activity.
- Document zero-result queries and telemetry limitations.
- Build an evidence-based authentication timeline.

## Scenario

A SOC analyst is reviewing a Windows endpoint for unusual account and authentication activity.

The analyst first checks the local Security event log for Event IDs `4624` and `4625`. The initial query produces no results, so the analyst validates the Security log and auditing state before continuing.

Subsequent local inspection confirms that successful logon events are being recorded. Elastic is then queried for Event ID `4624` activity, and multiple successful logons are identified.

The investigation focuses on understanding what those events represent rather than treating every successful authentication event as suspicious.

## Account Baseline

The local account inventory showed:

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

Several accounts were enabled, including:

```text
CompromiseTest
Dell
DormantUser
lab-reset-user
TempSupport
```

The current user was confirmed as:

```text
desktop-9mmm37v\dell
```

with SID:

```text
S-1-5-21-51198790-337801975-3228388354-1001
```

## Local Security Log Validation

The following command was initially used:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

The initial query returned no events.

After further validation and normal logon activity, the local Security log showed multiple successful logon events.

Examples included:

```text
28-09-2026 06:18:36 4624
28-09-2026 06:18:25 4624
28-09-2026 06:16:43 4624
28-09-2026 06:16:00 4624
```

The provider was:

```text
Microsoft-Windows-Security-Auditing
```

## Elastic Successful Logon Investigation

The following ES|QL query was used:

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

Observed examples included:

```text
Sep 28, 2026 @ 06:18:36.429
SYSTEM
4624
Logon Type: 5
Authentication Package: Negotiate
```

and:

```text
Sep 28, 2026 @ 06:24:55.739
Dell
4624
Logon Type: 2
```

## Logon Type Analysis

Observed Logon Type examples included:

```text
Type 2
Type 5
```

The `Dell` event showed:

```text
Logon Type: 2
Target User: Dell
Target Domain: DESKTOP-9MMM37V
```

This represented an interactive logon context.

The `SYSTEM` events showed:

```text
Logon Type: 5
Target User: SYSTEM
Target Domain: NT AUTHORITY
```

These events represented service-related authentication context.

## Successful Logon Correlation

A focused query for `Dell` returned:

```text
2 documents processed
```

Observed:

```text
Sep 28, 2026 @ 06:24:55.739
Dell
4624
Logon Type: 2
```

The related workstation field showed:

```text
DESKTOP-9MMM37V
```

No source IP was populated in the returned fields.

## Failed Logon Investigation

The following query was used:

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

No failed-logon events were returned in the investigated window.

This does not prove that failed logons never occurred on the endpoint. It only establishes that the queried Elastic dataset returned no matching `4625` events in the selected range.

## Special Privilege Investigation

The following query was used:

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

No `4672` events were returned in the queried time range.

## Remote Interactive Investigation

A Logon Type 10 hunt was performed:

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

No Remote Interactive Logon Type 10 events were returned in the queried window.

## Controlled Workstation Lock

A benign workstation lock was generated with:

```powershell
rundll32.exe user32.dll,LockWorkStation
```

The workstation was then unlocked normally using the existing account credentials.

The purpose was to create normal authentication-related activity without generating repeated failed logons or changing account configuration.

## Key Findings

### Observed

- Local Windows Security auditing was verified.
- Event ID `4624` successful-logon activity was available.
- Elastic returned 38 `4624` documents in the investigated query.
- `Dell` was observed with Logon Type `2`.
- `SYSTEM` was observed with Logon Type `5`.
- `DESKTOP-9MMM37V$` machine-account events were also visible.
- No `4625` events were returned in the queried window.
- No `4672` events were returned in the queried window.
- No Logon Type `10` events were returned in the queried window.
- The current account and local-user inventory were validated.
- The Elastic Agent remained Healthy.

### Confirmed

- Successful Windows authentication telemetry was available in Elastic.
- The local account `Dell` was associated with Logon Type `2` events.
- `SYSTEM` Logon Type `5` activity was present.
- The controlled workstation lock/unlock activity was performed.
- No failed-logon event was demonstrated in the investigated Elastic time window.

### Not Demonstrated

- Password spraying
- Brute-force attack
- Remote Interactive logon
- Account takeover
- Credential theft
- Malicious authentication activity
- Confirmed compromise

## Telemetry Limitations

The investigation encountered several important telemetry considerations:

- The initial local Security query returned no results before further validation.
- Elastic contained successful logon events after the investigation window was populated.
- No `4625` events were returned in the queried range.
- No `4672` events were returned in the queried range.
- No Logon Type `10` events were returned.
- Several authentication fields such as source IP were not populated in the observed `4624` events.

A zero-result authentication query should therefore be interpreted within the selected time range and available telemetry.

## Investigation Principle

The authentication investigation model was:

```text
Account
    |
    v
Logon Event
    |
    v
Success / Failure
    |
    v
Logon Type
    |
    v
Source / Workstation
    |
    v
Authentication Details
    |
    v
Related Events
    |
    v
Assessment
```

## MITRE ATT&CK

Authentication events can support investigations related to several ATT&CK techniques, depending on the actual behavior observed.

This lab primarily focuses on understanding Windows authentication telemetry rather than demonstrating an attack technique.

## Final Assessment

The investigation confirmed normal successful-logon telemetry for the Windows endpoint, including interactive activity associated with `Dell` and service-related activity associated with `SYSTEM`.

The absence of `4625`, `4672`, and Logon Type `10` events in the queried window limited the scope of additional authentication findings.

No password attack, malicious remote logon, account takeover, credential theft, or confirmed compromise was demonstrated.
