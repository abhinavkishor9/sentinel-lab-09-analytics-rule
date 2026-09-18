# Sentinel Lab 09 — Build an Analytics Rule

## Overview

This lab focuses on converting a validated KQL detection into a **Microsoft Sentinel Scheduled Analytics Rule**.

The detection identifies repeated authentication failures from a single source IP against multiple user accounts, followed by a successful authentication from the same IP.

For this lab, synthetic authentication telemetry is created using `datatable()` and dynamically generated timestamps with `now()`. This allows the detection to be tested inside the analytics-rule workflow even though the workspace does not currently contain suitable persistent authentication telemetry.

> **Note:** This is a controlled detection-engineering lab using synthetic data. The rule is not a production detection based on real authentication logs.

---

## Detection Scenario

The synthetic activity represents the following pattern:

```text
198.51.100.25
      |
      +---- user1 → Failed
      |
      +---- user2 → Failed
      |
      +---- user3 → Failed
      |
      +---- user4 → Failed
      |
      +---- user1 → Success
```

The detection looks for:

- Multiple failed authentication attempts
- Multiple targeted user accounts
- A common source IP
- A successful authentication from the same IP
- Activity occurring within a short time window

The training thresholds are:

```text
FailedAttempts >= 4
TargetedUsers >= 4
```

These thresholds are specific to the synthetic dataset and are not intended as production recommendations.

---

## Lab Objectives

- Create synthetic authentication telemetry using `datatable()`.
- Generate dynamic event timestamps using `now()`.
- Build KQL detection logic around authentication activity.
- Aggregate authentication activity by source IP.
- Identify repeated failures against multiple users.
- Validate the detection query in Microsoft Sentinel Logs.
- Convert the KQL query into a Scheduled Analytics Rule.
- Configure query frequency and lookback.
- Configure the alert trigger condition.
- Configure IP entity mapping.
- Add useful custom alert details.
- Configure incident creation.
- Verify the completed analytics rule.
- Document limitations associated with synthetic telemetry.

---

## Lab Environment

| Component | Value |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Rule Type | Scheduled query rule |
| Query Language | KQL |
| Data Source | Synthetic `datatable()` |
| Query Frequency | 5 minutes |
| Query Lookback | 5 minutes |
| Trigger | Number of results greater than 0 |
| Severity | Medium |
| Primary Entity | IP Address |
| Source IP | `198.51.100.25` |

---

## Synthetic Data

The following five events are generated:

| User | Result Type | Result | Source IP |
|---|---:|---|---|
| `user1@sentinellab.local` | `50126` | Failed | `198.51.100.25` |
| `user2@sentinellab.local` | `50126` | Failed | `198.51.100.25` |
| `user3@sentinellab.local` | `50126` | Failed | `198.51.100.25` |
| `user4@sentinellab.local` | `50126` | Failed | `198.51.100.25` |
| `user1@sentinellab.local` | `0` | Success | `198.51.100.25` |

The timestamps are generated relative to `now()`:

```kusto
extend TimeGenerated = now() - EventOffset
```

This keeps the synthetic events within the five-minute lookback period during testing.

---

## KQL Detection

The detection aggregates activity by source IP and calculates:

- Total authentication attempts
- Failed authentication attempts
- Successful authentication attempts
- Number of targeted users
- Targeted user list
- Observed locations

The detection logic is:

```kusto
datatable(
    EventOffset:timespan,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    Location:string
)
[
    4m, "user1@sentinellab.local", "198.51.100.25", 50126, "Invalid username or password", "Unknown",
    3m, "user2@sentinellab.local", "198.51.100.25", 50126, "Invalid username or password", "Unknown",
    2m, "user3@sentinellab.local", "198.51.100.25", 50126, "Invalid username or password", "Unknown",
    1m, "user4@sentinellab.local", "198.51.100.25", 50126, "Invalid username or password", "Unknown",
    30s, "user1@sentinellab.local", "198.51.100.25", 0, "Success", "New York"
]
| extend TimeGenerated = now() - EventOffset
| where TimeGenerated > ago(5m)
| summarize
    TotalAttempts = count(),
    FailedAttempts = countif(ResultType != 0),
    SuccessfulAttempts = countif(ResultType == 0),
    TargetedUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName),
    Locations = make_set(Location)
    by IPAddress
| where FailedAttempts >= 4
| where TargetedUsers >= 4
| project
    TimeGenerated = now(),
    IPAddress,
    TotalAttempts,
    FailedAttempts,
    SuccessfulAttempts,
    TargetedUsers,
    Users,
    Locations
```

---

## Expected Detection Result

The query should return a result similar to:

| Field | Value |
|---|---:|
| `IPAddress` | `198.51.100.25` |
| `TotalAttempts` | `5` |
| `FailedAttempts` | `4` |
| `SuccessfulAttempts` | `1` |
| `TargetedUsers` | `4` |

The successful query result confirms that the detection logic is able to identify the intended synthetic pattern.

---

## Analytics Rule Configuration

The KQL detection was converted into a Scheduled Analytics Rule.

### General

**Name**

`Multiple Failed Authentications From One IP`

**Description**

`Detects repeated authentication failures against multiple synthetic user accounts from the same source IP within a short time window.`

**Severity**

`Medium`

**Status**

`Enabled`

---

## Query Scheduling

The rule uses the following training configuration:

| Setting | Value |
|---|---|
| Run query every | 5 minutes |
| Lookup data from the last | 5 minutes |
| Trigger condition | Number of results greater than 0 |

The frequency and lookback are intentionally aligned with the synthetic event timestamps.

---

## Entity Mapping

The query returns:

```text
IPAddress
```

This field is mapped to:

```text
IP Address
```

The source IP is the primary investigation entity because the detection aggregates activity from multiple users into a single result.

---

## Custom Details

The following fields are surfaced as custom alert details:

```text
FailedAttempts
SuccessfulAttempts
TargetedUsers
TotalAttempts
```

This allows an analyst to see useful detection context directly from the generated alert.

---

## Incident Creation

The rule is configured to create or contribute to an incident when the detection produces a result.

The intended workflow is:

```text
Synthetic Authentication Data
            |
            v
        KQL Query
            |
            v
     Detection Result
            |
            v
   Scheduled Analytics Rule
            |
            v
           Alert
            |
            v
         Incident
            |
            v
       Investigation
```

---

## MITRE ATT&CK Context

The activity pattern may be relevant to:

**T1110 — Brute Force**

The multi-account nature of the activity may also resemble:

**T1110.003 — Password Spraying**

However, the synthetic events alone do not prove that a real password-spraying attack occurred.

The ATT&CK mapping is therefore treated as contextual detection mapping rather than confirmation of attacker behavior.

---

## Validation

The detection was validated by executing the KQL query in Microsoft Sentinel Logs.

Observed result:

```text
IPAddress: 198.51.100.25
TotalAttempts: 5
FailedAttempts: 4
SuccessfulAttempts: 1
TargetedUsers: 4
```

The analytics-rule wizard was then configured with:

```text
Frequency: 5 minutes
Lookback: 5 minutes
Trigger: Results greater than 0
Severity: Medium
```

---

## Important Limitation

This lab uses:

```kusto
datatable()
```

rather than a persistent authentication table.

Therefore, the lab demonstrates the **analytics-rule workflow and detection engineering process**, but it does not demonstrate detection against real authentication telemetry.

The following are synthetic:

- Authentication events
- User accounts
- Source IP
- Authentication results
- Location
- Detection thresholds

The rule should therefore be described as a **training implementation**, not a production security control.

---

## Key SOC Takeaways

### Detection Logic Must Be Tested First

The KQL query was validated before being placed into the analytics-rule wizard.

### Time Windows Matter

Synthetic events were generated relative to `now()` so that they remained inside the scheduled rule's lookback window.

### Entity Mapping Improves Alert Context

Mapping `IPAddress` to the IP Address entity provides a clear investigation pivot.

### Detection Does Not Equal Confirmation

The authentication pattern may resemble password spraying, but additional telemetry would be required to determine whether the activity was actually malicious.

### Detection Engineering Is More Than Writing KQL

The workflow demonstrated in this lab is:

```text
Detection Idea
      |
      v
KQL Development
      |
      v
Query Validation
      |
      v
Analytics Rule
      |
      v
Alert
      |
      v
Incident
      |
      v
Investigation
```

---

