# Troubleshooting Notes — Windows Account & Logon Investigation

## Issue 1 — Initial 4624/4625 Query Returned No Events

### Query

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Initial Result

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Investigation

The result was not immediately interpreted as proof that Windows was not generating authentication events.

Further validation of the Security log and auditing state was performed.

Subsequent local inspection showed multiple successful `4624` events.

### Lesson

A zero-result local event query can result from:

```text
Time range
Event availability
Audit configuration
Timing of the activity
```

The result must be investigated before drawing a conclusion.

---

## Issue 2 — Elastic 4624 Data Was Available After Validation

The Elastic query:

```esql
FROM logs-*
| WHERE event.code == "4624"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName
| SORT @timestamp DESC
```

returned:

```text
38 documents processed
```

### Lesson

Local Security-log validation and Elastic telemetry validation should be treated as separate checks.

```text
Windows generates event
        ↓
Elastic receives event
        ↓
Elastic fields are searchable
```

Each stage can have different visibility.

---

## Issue 3 — 4625 Query Returned 0 Results

### Query

```esql
FROM logs-*
| WHERE event.code == "4625"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.AuthenticationPackageName, winlog.event_data.SubStatus
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Interpretation

No failed-logon events were returned in the investigated time window.

This does not establish that the endpoint has never experienced a failed logon.

### Lesson

A zero-result authentication hunt should always be interpreted relative to:

```text
Time Range
Dataset
Available Fields
```

---

## Issue 4 — 4672 Query Returned 0 Results

### Query

```esql
FROM logs-*
| WHERE event.code == "4672"
| KEEP @timestamp, host.name, user.name, event.code, winlog.event_data.SubjectUserName
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

No Event ID `4672` activity was returned.

### Lesson

Absence of a `4672` result limits the available evidence for special-privilege correlation but does not prove that such events never occurred on the host.

---

## Issue 5 — Logon Type 10 Query Returned No Results

### Query

```esql
FROM logs-*
| WHERE event.code == "4624"
| WHERE winlog.event_data.LogonType == "10"
| KEEP @timestamp, host.name, user.name, winlog.event_data.TargetUserName, winlog.event_data.IpAddress, winlog.event_data.WorkstationName, winlog.event_data.LogonType
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Interpretation

No Remote Interactive Logon Type `10` events were observed in the investigated time range.

### Lesson

Do not describe the endpoint as having no RDP activity unless the available telemetry fully supports that conclusion.

---

## Issue 6 — Source IP Field Was Empty

The `Dell` 4624 event showed:

```text
Logon Type: 2
```

but:

```text
IpAddress: -
```

### Handling

The missing IP was documented as unavailable in the returned event.

No source location was inferred.

### Lesson

Missing authentication fields must remain unknown rather than being reconstructed through assumption.

---

## Issue 7 — Different Accounts Appeared in 4624 Telemetry

The Elastic results included:

```text
Dell
SYSTEM
DESKTOP-9MMM37V$
```

### Investigation

These were not treated as equivalent accounts.

The investigator considered:

```text
Dell
```

as the interactive user context observed with Logon Type `2`.

`SYSTEM` with Logon Type `5` was treated as service-related authentication context.

The machine account was documented separately.

### Lesson

Account identity and Logon Type must be analyzed together.

---

## Issue 8 — Workstation Lock Was Used Instead of Failed Password Attempts

The controlled authentication-related activity used:

```powershell
rundll32.exe user32.dll,LockWorkStation
```

The workstation was then unlocked normally.

No repeated incorrect passwords were generated.

### Lesson

Controlled SOC labs should generate useful telemetry without unnecessarily creating brute-force or account-lockout conditions.

---

## Issue 9 — Time Range

The primary investigation window was:

```text
Last 15 minutes
```

This was appropriate for the controlled activity.

When authentication events were unexpectedly absent, the investigation considered the event timestamps and validated the underlying Windows Security log before concluding anything about telemetry availability.

### Lesson

Authentication investigations are strongly dependent on accurate time correlation.

---

## Investigation Lessons

### Validate the Source Before Hunting

Before relying on Elastic authentication data, establish that Windows is generating the relevant Security events.

### 4624 Is Not Automatically Suspicious

A successful logon can represent:

```text
Interactive user activity
Service activity
System activity
Machine-account activity
```

Context matters.

### Logon Type Is Important

The same Event ID can represent very different authentication contexts.

### Missing Fields Stay Missing

An empty IP address or workstation field should not be replaced with assumptions.

### Zero Results Are Evidence of a Query Result

A zero-result query means:

```text
No matching documents returned
```

within the selected dataset and time range.

It does not automatically mean:

```text
The activity never happened
```

### Evidence Must Drive the Assessment

The investigation followed:

```text
Local Security Log
      ↓
Elastic Authentication Telemetry
      ↓
Account Context
      ↓
Logon Type
      ↓
Source / Workstation
      ↓
Related Events
      ↓
Assessment
```
