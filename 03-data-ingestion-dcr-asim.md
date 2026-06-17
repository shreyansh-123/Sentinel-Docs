# 01 — KQL for Detection Engineers

> Kusto Query Language is where a SIEM engineer lives. This doc takes you from data model to production detections and performance tuning.

## 1. The data model

- Data lives in a **Log Analytics workspace** as **tables** (schemas). Sentinel queries these via KQL.
- Core security tables you must know:
  - `SecurityEvent` (Windows events via MMA/AMA), `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` (Entra), `OfficeActivity` (M365), `DeviceEvents` / `DeviceProcessEvents` / `DeviceNetworkEvents` (Defender XDR), `SecurityAlert`, `SecurityIncident`, `ThreatIntelligenceIndicator`, `Heartbeat`, `CommonSecurityLog` (CEF/syslog).
- Every row has a `TimeGenerated` (UTC). Time filtering first is the #1 performance rule.

## 2. Query structure and operators

KQL is a piped language: `Table | operator | operator ...`.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)            // filter early
| where ResultType != 0                      // failed sign-ins
| summarize FailedCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailedCount > 20
| order by FailedCount desc
```

**Operators you use daily:**

- `where` (filter), `project` / `project-away` (select columns), `extend` (add computed columns), `summarize` (aggregate), `order by` / `sort`, `take` / `top`, `distinct`, `count`.
- `join` — know the **kinds**: `inner`, `innerunique` (default!), `leftouter`, `rightouter`, `fullouter`, `leftsemi`, `leftanti` (great for "present in A but not B"), `rightsemi`, `rightanti`. The default `innerunique` surprises people — it dedupes the left key.
- `union` — combine tables (`union withsource=SourceTable T1, T2`).
- `mv-expand` / `mv-apply` — expand dynamic arrays into rows.
- `parse` / `parse_json` / `extract` / `extract_all` — pull fields from strings.
- `make-series` — time-series for anomaly detection; pair with `series_decompose_anomalies`.
- `materialize()` — cache a subquery used multiple times.
- `lookup`, `evaluate` (plugins like `bag_unpack`, `pivot`, `narrow`).

## 3. Aggregations and time

```kusto
// Aggregations
| summarize count(), dcount(IPAddress), min(TimeGenerated), max(TimeGenerated),
            make_set(IPAddress, 100), arg_max(TimeGenerated, *) by UserPrincipalName

// bin() buckets time; ago()/now() for relative time
| summarize Events = count() by bin(TimeGenerated, 5m)
```

- `arg_max(TimeGenerated, *)` = the most recent full row per group (essential for "latest state").
- `make_set` / `make_list` build arrays you can `mv-expand` later.

## 4. Joins: a worked example (sign-in then privileged action)

```kusto
let window = 1h;
let signins =
    SigninLogs
    | where ResultType == 0
    | project UserPrincipalName, IPAddress, SigninTime = TimeGenerated;
let privileged =
    AuditLogs
    | where OperationName has "Add member to role"
    | project UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName),
              ActionTime = TimeGenerated, OperationName;
signins
| join kind=inner privileged on UserPrincipalName
| where ActionTime between (SigninTime .. (SigninTime + window))
| project UserPrincipalName, IPAddress, SigninTime, ActionTime, OperationName
```

## 5. Detection patterns

- **Threshold / brute force:** `summarize count()` over `bin()` and filter.
- **Rare/anomalous:** `make-series` + `series_decompose_anomalies`, or compare to a baseline with `join`.
- **Impossible travel:** geo-IP per sign-in, `prev()` over ordered rows, distance/time check.
- **First-seen:** `leftanti` join against a watchlist of known-good, or `arg_min(TimeGenerated, *)`.
- **Enrichment:** `join`/`lookup` against `ThreatIntelligenceIndicator` or a watchlist.

## 6. Performance and cost tuning

1. **Filter on `TimeGenerated` first**, then on indexed/string columns.
2. `project` only the columns you need, early.
3. Prefer `has` over `contains` (term-indexed, faster); avoid leading-wildcard `contains`.
4. Avoid `join` on huge unfiltered tables — filter both sides first; put the smaller table on the left.
5. Use `materialize()` for repeated subqueries.
6. Watch the default `innerunique` join kind — use explicit `kind=inner` when you mean it.
7. For scheduled rules, keep the query window tight and aligned to the rule frequency.

## 7. Functions and reuse

- Save queries as **functions** (`.create function` in the workspace, or saved functions in Sentinel) to reuse parsing/normalization.
- **ASIM** parsers (see ingestion doc) expose normalized functions like `imSignin`, `_Im_NetworkSession` so detections work across sources.

## 8. Practice prompts

- Top 10 source IPs by failed sign-ins in 24h, only for accounts that *also* had a success.
- Processes spawned by Office apps (`DeviceProcessEvents` where `InitiatingProcessFileName` in winword/excel/outlook).
- New external IPs talking to a host not seen in the prior 14 days (`leftanti`).
