# elastic-security-windows-account-logon-investigation-lab
## Overview
A SOC analyst investigating account activity should answer:

Which account?
    ↓
Which logon event?
    ↓
Successful or failed?
    ↓
When?
    ↓
From where?
    ↓
Logon Type?
    ↓
Authentication details?
    ↓
Expected or unusual?

Important Windows Security events commonly associated with this investigation include:

4624 — Successful logon
4625 — Failed logon
4634 — Logoff
4647 — User initiated logoff
4672 — Special privileges assigned to new logon

A successful logon is not automatically benign, and a failed logon is not automatically malicious. The analyst needs to examine the account, source information, logon type, authentication package, process context, and surrounding events.

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

## Lab Objectives

- Verify the availability of Windows authentication telemetry on the endpoint before beginning the investigation.
- Identify the local user accounts present on the Windows system and review their enabled state and recent logon information.
- Confirm the current user's identity, SID, and security-group context.
- Investigate successful Windows logon events represented by Event ID `4624`.
- Examine the different Logon Types observed in the collected authentication telemetry.
- Distinguish interactive user logons from service and machine-account authentication activity.
- Investigate failed logon activity using Event ID `4625` and document the absence of matching events when applicable.
- Examine Event ID `4672` for special-privilege logons and determine whether supporting telemetry is available.
- Investigate Remote Interactive Logon Type `10` activity without assuming that its absence proves no remote access occurred.
- Correlate account names, target-user information, workstation names, logon types, and timestamps where the required fields are populated.
- Compare locally observed Windows Security events with the corresponding Elastic authentication telemetry.
- Investigate missing or unpopulated authentication fields such as source IP and document them as unknowns.
- Use controlled workstation lock and unlock activity to validate normal authentication-related telemetry without generating repeated failed logons.
- Distinguish normal authentication events from activity that would require additional investigation.
- Document zero-result queries according to the selected time range, available dataset, and telemetry coverage.
- Build an evidence-based authentication timeline using only events directly supported by the collected telemetry.

## Lab Scenario

A SOC analyst is investigating Windows account and logon activity on an endpoint after noticing multiple successful authentication events. The analyst needs to determine which accounts are involved, what type of logon occurred, and whether the available evidence indicates normal user or system activity.

The investigation begins by reviewing the local Windows Security log and validating whether authentication events such as `4624` and `4625` are being generated. The analyst then compares the local results with Elastic telemetry to determine how much authentication information is available for investigation.

The analyst focuses on:

- User and machine account identities
- Successful and failed logon events
- Windows Logon Types
- Target usernames and domains
- Workstation information
- Source IP availability
- Service-related authentication activity
- Special-privilege logons
- Remote Interactive Logon Type `10`
- Differences between local Windows events and Elastic telemetry

The investigation identifies successful `4624` events associated with the local user `Dell`, including a Logon Type `2` interactive logon, as well as `SYSTEM` Logon Type `5` activity. Machine-account authentication events are also present.

Additional searches for `4625`, `4672`, and Logon Type `10` return no matching events within the investigated time range. The analyst treats these results as time- and telemetry-dependent findings rather than assuming that such activity has never occurred on the endpoint.

A controlled workstation lock and normal unlock are also performed to generate legitimate authentication-related activity without intentionally creating repeated failed logons or account-lockout conditions.

The scenario is designed to demonstrate how a SOC analyst investigates Windows authentication by correlating **account identity, logon type, timestamps, source information, and related events**, while clearly distinguishing observed authentication activity from suspicious or confirmed malicious behavior.

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

## MITRE ATT&CK

Authentication events can support investigations related to several ATT&CK techniques, depending on the actual behavior observed.

This lab primarily focuses on understanding Windows authentication telemetry rather than demonstrating an attack technique.

