# Investigation Notes 

## Initial Detection Pattern

The synthetic activity was generated from:

```text
198.51.100.25
```

The source IP produced the following sequence:

| Sequence | Account | Result | Result Type |
|---:|---|---|---:|
| 1 | `user1@sentinellab.local` | Failed | `50126` |
| 2 | `user2@sentinellab.local` | Failed | `50126` |
| 3 | `user3@sentinellab.local` | Failed | `50126` |
| 4 | `user4@sentinellab.local` | Failed | `50126` |
| 5 | `user1@sentinellab.local` | Success | `0` |

The timestamps were generated dynamically using:

```kusto
extend TimeGenerated = now() - EventOffset
```

This allowed the synthetic events to remain within the analytics rule's five-minute lookback window.

---

## Investigation Hypothesis

The detection hypothesis was:

> A single source IP generating repeated authentication failures against multiple accounts within a short time window may warrant investigation, particularly when a successful authentication follows the failures.

This pattern can be relevant to brute-force or password-spraying activity.

The detection itself does not establish malicious intent.

---

## Evidence Review

The first four events were failed authentication attempts.

```text
user1 → Failed
user2 → Failed
user3 → Failed
user4 → Failed
```

All four failures originated from:

```text
198.51.100.25
```

The activity therefore demonstrated:

```text
One IP
  |
  +---- Multiple Accounts
  |
  +---- Multiple Failed Attempts
```

A successful authentication was then observed:

```text
user1@sentinellab.local
        |
        +---- Success
```

The success originated from the same synthetic IP.

---

## Detection Logic

The query aggregated the authentication activity by `IPAddress`.

The following values were calculated:

```text
TotalAttempts
FailedAttempts
SuccessfulAttempts
TargetedUsers
Users
Locations
```

The detection threshold was:

```kusto
where FailedAttempts >= 4
| where TargetedUsers >= 4
```

This produced the expected result:

```text
IPAddress: 198.51.100.25
TotalAttempts: 5
FailedAttempts: 4
SuccessfulAttempts: 1
TargetedUsers: 4
```

---

## Detection Assessment

### Observed

A single source IP generated four failed authentication attempts against four different synthetic users.

### Observed

The same source IP subsequently generated one successful authentication.

### Confirmed

The KQL query successfully identified the synthetic activity pattern.

### Plausible

The pattern is compatible with a multi-account brute-force or password-spraying scenario.

### Unknown

The synthetic dataset cannot establish:

- Whether an actual attack occurred
- Whether credentials were compromised
- Whether the successful authentication was malicious
- Whether the source IP represents a real attacker
- Whether the accounts were actually targeted
- Whether the observed location represents real geolocation

---

## Analytics Rule Implementation

After validating the KQL, the detection was moved into the Microsoft Sentinel Scheduled Analytics Rule workflow.

The rule was configured as:

```text
Name:
Multiple Failed Authentications From One IP

Severity:
Medium

Frequency:
5 minutes

Lookback:
5 minutes

Trigger:
Number of results greater than 0
```

The rule was enabled for scheduled execution.

---

## Entity Mapping

The final detection query returned:

```text
IPAddress
```

This field was mapped to the Sentinel:

```text
IP Address
```

entity type.

The IP address was selected as the primary entity because the detection aggregates activity from multiple accounts into a single result.

---

## Custom Alert Details

The following fields were configured as useful custom details:

```text
FailedAttempts
SuccessfulAttempts
TargetedUsers
TotalAttempts
```

These values provide immediate context during alert triage.

For the synthetic detection:

```text
FailedAttempts: 4
SuccessfulAttempts: 1
TargetedUsers: 4
TotalAttempts: 5
```

---

## Incident Workflow

The analytics rule is intended to move the detection through the Sentinel incident workflow:

```text
Authentication Activity
        |
        v
Detection Query
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
SOC Investigation
```

This is the primary operational concept demonstrated by the lab.

---

## MITRE ATT&CK Context

The observed pattern may be associated with:

```text
T1110 — Brute Force
```

The activity may also resemble:

```text
T1110.003 — Password Spraying
```

The mapping should not be interpreted as proof of the technique because the dataset is synthetic and contains insufficient context for confirming attacker behavior.

---

## False Positive Considerations

In a real environment, similar authentication patterns could result from:

- Users repeatedly entering incorrect credentials
- Applications using expired passwords
- Automated authentication retries
- Misconfigured services
- Shared network infrastructure
- Authentication testing
- Legitimate administrative activity

The thresholds used in this lab were selected to trigger against the synthetic dataset.

They should not be treated as production thresholds.

---

## Additional Investigation Required in Production

If the same pattern were detected using real authentication telemetry, additional investigation would include:

```text
Authentication source
        |
        v
User context
        |
        v
Device information
        |
        v
Authentication location
        |
        v
MFA / Conditional Access
        |
        v
Sign-in risk
        |
        v
Post-authentication activity
```

Useful supporting telemetry could include:

- User sign-in history
- Device information
- User-agent information
- MFA results
- Conditional Access results
- Authentication risk
- Endpoint activity
- Network activity
- Privilege changes
- Post-authentication processes

---

## Evidence Classification

| Finding | Classification |
|---|---|
| Four failed authentications | Confirmed in synthetic dataset |
| Four targeted users | Confirmed in synthetic dataset |
| Common source IP | Confirmed in synthetic dataset |
| Successful authentication | Confirmed in synthetic dataset |
| Password spraying | Plausible pattern |
| Account compromise | Unknown |
| Malicious source | Unknown |
| Real-world attack | Not established |

---
