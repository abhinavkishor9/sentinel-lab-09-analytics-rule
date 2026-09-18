# Timeline 

| Relative Time | User | Source IP | Result | Result Type | Location |
|---|---|---|---|---:|---|
| T-4m | `user1@sentinellab.local` | `198.51.100.25` | Failed | `50126` | Unknown |
| T-3m | `user2@sentinellab.local` | `198.51.100.25` | Failed | `50126` | Unknown |
| T-2m | `user3@sentinellab.local` | `198.51.100.25` | Failed | `50126` | Unknown |
| T-1m | `user4@sentinellab.local` | `198.51.100.25` | Failed | `50126` | Unknown |
| T-30s | `user1@sentinellab.local` | `198.51.100.25` | Success | `0` | New York |

---

## T-4 Minutes

The source IP:

```text
198.51.100.25
```

generates a failed authentication attempt against:

```text
user1@sentinellab.local
```

Result:

```text
50126 — Invalid username or password
```

At this stage, the activity represents a single failed authentication.

---

## T-3 Minutes

A second failed authentication occurs against:

```text
user2@sentinellab.local
```

The source IP remains:

```text
198.51.100.25
```

The activity now involves two different accounts.

---

## T-2 Minutes

A third failed authentication occurs against:

```text
user3@sentinellab.local
```

The same source IP continues generating failed authentication attempts.

---

## T-1 Minute

A fourth failed authentication occurs against:

```text
user4@sentinellab.local
```

The synthetic dataset now contains:

```text
FailedAttempts: 4
TargetedUsers: 4
Source IP: 198.51.100.25
```

The configured detection thresholds are satisfied:

```text
FailedAttempts >= 4
TargetedUsers >= 4
```

---

## T-30 Seconds

A successful authentication occurs against:

```text
user1@sentinellab.local
```

Result:

```text
0 — Success
```

The synthetic event specifies:

```text
Location: New York
```

This increases the investigation value of the sequence but does not establish that the account was compromised.

---

## Detection Aggregation

The KQL detection aggregates the events by:

```text
IPAddress
```

The resulting detection contains:

```text
IPAddress: 198.51.100.25
TotalAttempts: 5
FailedAttempts: 4
SuccessfulAttempts: 1
TargetedUsers: 4
```

---

## Detection Sequence

```text
T-4m
  |
  +---- user1 → Failed
  |
T-3m
  |
  +---- user2 → Failed
  |
T-2m
  |
  +---- user3 → Failed
  |
T-1m
  |
  +---- user4 → Failed
  |
T-30s
  |
  +---- user1 → Success
```

---

## Analytics Rule Timeline

```text
Synthetic authentication events
            |
            v
       KQL development
            |
            v
       Query validation
            |
            v
    Scheduled rule creation
            |
            v
    Frequency: 5 minutes
            |
            v
    Lookback: 5 minutes
            |
            v
      Trigger: > 0
            |
            v
       IP entity mapping
            |
            v
      Custom alert details
            |
            v
      Incident creation
```

---

## Detection Threshold Timeline

The detection becomes eligible when the following state is reached:

```text
4 failed attempts
        +
4 targeted users
        |
        v
Detection condition satisfied
```

The later successful authentication adds additional investigation context.

---

