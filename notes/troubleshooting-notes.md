# Troubleshooting Notes — Sentinel Lab 09

## 1. Synthetic Events Not Returning Results

### Problem

The KQL query returns zero records even though the `datatable()` contains authentication events.

### Cause

The synthetic events may have timestamps outside the five-minute lookback period.

### Resolution

Generate timestamps dynamically:

```kusto
extend TimeGenerated = now() - EventOffset
```

Then restrict the query:

```kusto
where TimeGenerated > ago(5m)
```

### Lesson

Scheduled analytics rules evaluate data within their configured lookback period. Synthetic data must therefore use timestamps compatible with that window.

---

## 2. Static Timestamps Stop Triggering the Rule

### Problem

The query worked initially but stops returning results later.

### Cause

The original timestamps were fixed in the past.

As time moves forward, those events eventually fall outside:

```text
5-minute lookback
```

### Resolution

Use relative offsets instead of fixed historical timestamps:

```text
4m
3m
2m
1m
30s
```

and calculate:

```kusto
now() - EventOffset
```

### Lesson

For continuously tested synthetic scheduled rules, dynamic timestamps are important.

---

## 3. `TimeGenerated` Missing

### Problem

The synthetic data does not initially contain `TimeGenerated`.

### Cause

`datatable()` only creates the fields defined in its schema.

### Resolution

Create the field explicitly:

```kusto
| extend TimeGenerated = now() - EventOffset
```

The final query should retain the field where required.

---

## 4. Detection Threshold Not Reached

### Problem

The query executes but does not produce a detection result.

### Expected Conditions

The synthetic source IP must satisfy:

```text
FailedAttempts >= 4
```

and:

```text
TargetedUsers >= 4
```

### Resolution

Check the aggregation result before applying the threshold.

Expected values:

```text
FailedAttempts: 4
TargetedUsers: 4
```

If either value is lower, the detection condition will not be satisfied.

---

## 5. Query Returns Multiple Results

### Problem

The analytics-rule trigger is based on the number of returned rows, but the query produces unexpected multiple results.

### Cause

The query may be grouping by additional fields instead of only the source IP.

For example:

```kusto
by IPAddress, UserPrincipalName
```

would create separate results for each user.

### Resolution

For this lab, aggregate by:

```kusto
by IPAddress
```

This produces one detection result for the source IP when the threshold is met.

---

## 6. Entity Mapping Does Not Work

### Problem

The generated alert does not show the source IP as an entity.

### Checks

Confirm that the final query returns:

```text
IPAddress
```

Then map:

```text
IPAddress → IP Address
```

### Lesson

Entity mapping should use fields that are actually returned by the final detection query.

---

## 7. Account Entity Mapping Consideration

### Problem

The detection contains four users but the final result does not contain a single `Account` field.

### Cause

The query aggregates multiple accounts:

```kusto
Users = make_set(UserPrincipalName)
```

This produces an array of users rather than one account value.

### Resolution

Use the source IP as the primary entity.

Retain the affected users as custom detection context:

```text
Users
```

This better represents the structure of the aggregated detection.

---

## 8. Custom Details Not Available

### Problem

Detection values such as failed attempts are not available in the alert.

### Cause

The required field may not exist in the final query output.

### Resolution

Ensure the final `project` includes:

```text
FailedAttempts
SuccessfulAttempts
TargetedUsers
TotalAttempts
```

These can then be configured as custom details.

---

## 9. Alert Does Not Generate Immediately

### Problem

The analytics rule is created successfully but an alert is not immediately visible.

### Possible Reasons

- The rule has not executed yet.
- The rule is disabled.
- The query returns zero results during the scheduled execution.
- The trigger condition is not satisfied.
- The synthetic timestamps have moved outside the lookback period.
- The rule is still being validated or initialized.

### Validation

First run the KQL manually in Logs.

Expected result:

```text
IPAddress: 198.51.100.25
FailedAttempts: 4
TargetedUsers: 4
```

If the query works manually, review the analytics-rule configuration and execution timing.

---

## 10. Frequency and Lookback Mismatch

### Problem

The query frequency and lookback are configured differently.

### Lab Configuration

```text
Frequency: 5 minutes
Lookback: 5 minutes
```

### Consideration

The lookback must provide enough coverage for the intended detection window.

For this synthetic lab, both values are intentionally aligned.

Production detections may require different values based on:

- Event ingestion delay
- Attack duration
- Detection urgency
- Data volume
- Query performance
- Duplicate alert risk

---

## 11. Validation Takes Time

### Problem

The analytics-rule wizard remains on:

```text
Validating...
```

### Checks

Review:

- KQL syntax
- Query output
- Time field
- Entity mappings
- Custom details
- Scheduling
- Trigger configuration

Do not assume that the detection logic is invalid simply because validation takes time.

---

## 12. `datatable()` Is Not Persistent Telemetry

### Problem

The rule appears similar to a production analytics rule even though the underlying data is synthetic.

### Important Distinction

`datatable()` creates temporary data for the query.

It does not create a persistent authentication table.

Therefore, this lab demonstrates:

```text
KQL Development
      +
Analytics Rule Configuration
      +
Alert Workflow
```

but not:

```text
Production Authentication Monitoring
```

---

## 13. Source IP Is Synthetic

The source IP used by the lab is:

```text
198.51.100.25
```

It is part of the synthetic dataset and should not be treated as a real malicious IP.

The same applies to:

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

These are synthetic lab accounts.

---

## 14. Successful Authentication Should Not Automatically Be Treated as Compromise

### Problem

The detection contains four failures followed by a success.

### Incorrect Interpretation

```text
Success = Account Compromised
```

### Better Interpretation

```text
Success = Additional Investigation Required
```

In real telemetry, additional context would be required to determine whether the successful authentication was legitimate or suspicious.

---

## 15. MITRE Mapping Caution

The pattern resembles:

```text
T1110.003 — Password Spraying
```

However:

```text
Detection Pattern ≠ Confirmed Technique
```

The lab contains only synthetic authentication events.

Therefore, the ATT&CK technique should be documented as contextual mapping rather than confirmed attacker behavior.

---

## 16. Recommended Troubleshooting Sequence

When the analytics rule does not behave as expected, follow this order:

```text
1. Validate synthetic events
          |
          v
2. Validate TimeGenerated
          |
          v
3. Run KQL manually
          |
          v
4. Validate aggregation
          |
          v
5. Validate detection threshold
          |
          v
6. Validate query output fields
          |
          v
7. Validate entity mapping
          |
          v
8. Validate scheduling
          |
          v
9. Validate trigger condition
          |
          v
10. Check alert / incident
```

This prevents troubleshooting the Sentinel rule before confirming that the underlying detection query actually works.
