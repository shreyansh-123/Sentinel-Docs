# Microsoft Sentinel: Beginner to Advanced Guide

Microsoft Sentinel is a cloud-native **Security Information and Event Management (SIEM)** and **Security Orchestration, Automated Response (SOAR)** solution built on Azure. It collects, detects, investigates, and responds to threats across your enterprise.

---

## 1. Foundations

### Core Concepts to Master

- **SIEM vs SOAR** - SIEM collects/analyzes logs; SOAR automates responses
- **Log Analytics Workspace (LAW)** - the backbone where all data lives in Sentinel
- **Data Connectors** - how logs flow into Sentinel (Azure AD, Office 365, CEF, Syslog, etc.)
- **Tables** - each data source populates specific tables (e.g., `SigninLogs`, `SecurityEvent`, `AuditLogs`)
- **Retention Policies** - hot (interactive) vs cold (archive) tiers, cost implications

### Key Azure Prerequisites

- Azure RBAC roles: `Microsoft Sentinel Reader`, `Contributor`, `Responder`
- Resource Groups, Subscriptions, and Tenant concepts
- Azure Monitor and its relationship with Sentinel

---

## 2. KQL - Kusto Query Language

KQL is the **most critical skill** in Sentinel. Master it deeply.

### Basic Operators

```kql
// Filter, project, summarize
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| project TimeGenerated, Account, Computer, IpAddress
| summarize FailedLogins = count() by Account
| order by FailedLogins desc
```

### Intermediate KQL

```kql
// Joins, unions, let statements
let threshold = 10;
let failedLogins = SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by Account, IpAddress;
let successLogins = SecurityEvent
| where EventID == 4624
| summarize Successes = count() by Account;
failedLogins
| join kind=inner successLogins on Account
| where Attempts > threshold
| extend RiskScore = Attempts * 1.5
```

### Advanced KQL

```kql
// Time series, anomaly detection, machine learning functions
let timeframe = 14d;
let threshold = 2.5;
SigninLogs
| where TimeGenerated > ago(timeframe)
| make-series LoginCount = count() on TimeGenerated
    from ago(timeframe) to now() step 1h by UserPrincipalName
| extend (anomalies, score, baseline) =
    series_decompose_anomalies(LoginCount, threshold)
| mv-expand TimeGenerated, LoginCount, anomalies, score, baseline
| where anomalies == 1
```

### Expert KQL Techniques

- `series_decompose_anomalies()` for behavioral baselining
- `bag_unpack()` for dynamic JSON fields
- `parse_json()` and `parse_url()` for enrichment
- `geo_point_to_s2cell()` for geolocation clustering
- `ipv4_is_private()` for IP classification
- Materialized views for performance optimization
- Functions and saved queries as reusable components

---

## 3. Analytics Rules

### Rule Types

| Type | Use Case |
|------|----------|
| **Scheduled** | KQL queries run on a schedule |
| **NRT (Near Real-Time)** | Sub-minute detection latency |
| **Fusion** | ML-based multi-stage attack correlation |
| **Microsoft Security** | Auto-create from Defender alerts |
| **Anomaly** | UEBA-based behavioral detection |
| **Threat Intelligence** | TI indicator matching |

### Writing Production-Grade Detection Rules

```kql
// Detecting impossible travel
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0  // Successful logins
| project TimeGenerated, UserPrincipalName,
    Location, IPAddress, Latitude, Longitude
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevLocation = prev(Location, 1),
         PrevTime = prev(TimeGenerated, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where Location != PrevLocation and TimeDiff < 60
```

### Rule Tuning Best Practices

- Set appropriate **lookback periods** and **query frequency**
- Use **entity mapping** (Account, Host, IP, URL, FileHash)
- Configure **alert grouping** to reduce noise
- Implement **suppression** for known false positives
- Use **custom details** to surface key fields in alerts

---

## 4. Incidents & Investigation

### Incident Lifecycle

Triage → Investigation → Containment → Eradication → Recovery → Lessons Learned

### Investigation Graph

- Entity relationships visualization
- Pivot from IP → User → Host → Process
- Timeline reconstruction across multiple tables

### Advanced Investigation Queries

```kql
// Full attack chain reconstruction
let suspiciousIP = "185.220.101.45";
let timeWindow = 48h;
union
(SigninLogs | where IPAddress == suspiciousIP),
(AuditLogs | where InitiatedBy has suspiciousIP),
(OfficeActivity | where ClientIP == suspiciousIP),
(SecurityAlert | where Entities has suspiciousIP)
| where TimeGenerated > ago(timeWindow)
| project TimeGenerated, Type, OperationName,
    UserPrincipalName, ResultDescription
| sort by TimeGenerated asc
```

### UEBA (User and Entity Behavior Analytics)

- Peer group analysis
- Activity baselines per user/entity
- Anomaly scores and investigation priorities
- `BehaviorAnalytics` table queries
- `IdentityInfo` table for HR/AD enrichment

---

## 5. SOAR & Automation

### Automation Rules

- Trigger on incident creation/update
- Auto-assign, auto-tag, auto-close
- Run playbooks conditionally
- Order of execution matters (priority-based)

### Playbooks (Logic Apps)

Built on Azure Logic Apps, triggered by Sentinel incidents/alerts/entities. Common patterns:

- **Enrichment**: VirusTotal, WHOIS, GeoIP lookups
- **Notification**: Teams, Slack, PagerDuty, email
- **Containment**: Block IP in firewall, disable AD user, isolate host via Defender
- **Ticketing**: Create JIRA/ServiceNow tickets

### Advanced Playbook - Auto Block Malicious IP

```json
{
  "trigger": "Sentinel Incident",
  "condition": "TacticName == 'InitialAccess' AND ConfidenceScore > 80",
  "actions": [
    "Extract IP entities from incident",
    "Check IP reputation via VirusTotal API",
    "If malicious score > 70: Add to Named Locations (Conditional Access)",
    "Update incident with enrichment",
    "Post to SOC Teams channel",
    "Create ServiceNow ticket"
  ]
}
```

### Watchlists

- Static/dynamic reference data (VIP users, known IPs, asset inventory)
- Used in KQL with `_GetWatchlist('WatchlistName')`
- Automate watchlist updates via Logic Apps or API

---

## 6. Threat Intelligence

### TI Integration

- Native TAXII/STIX feed ingestion
- Microsoft Defender TI (MDTI) integration
- Third-party: MISP, Anomali, Recorded Future
- `ThreatIntelligenceIndicator` table

### TI Matching at Scale

```kql
// Match network traffic against TI IOCs
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(7d)
| where Active == true and ConfidenceScore > 70
| where isnotempty(NetworkIP)
| project NetworkIP, ThreatType, Description;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| join kind=inner TI_IPs on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP,
    ThreatType, Description, DeviceVendor
```

### Diamond Model & MITRE ATT&CK Mapping

- Map every detection rule to ATT&CK tactics/techniques
- Use ATT&CK Navigator for coverage visualization
- Identify detection gaps per tactic
- Build detections for each kill chain phase

---

## 7. Advanced Detection Engineering

### Sigma Rules → Sentinel

- Convert community Sigma rules to KQL using `sigma-cli`
- Maintain rule versioning in Git
- CI/CD pipeline for rule deployment

### Detection-as-Code (DaC)

```yaml
# Example Sigma rule converted to Sentinel
title: Suspicious PowerShell Encoded Command
status: production
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - '-enc '
      - 'FromBase64String'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### Behavioral Detection Patterns

- **Stacking/Long-tail analysis** - find rare events
- **Frequency analysis** - detect beaconing C2
- **Sequence detection** - ordered event chains
- **Clustering** - group similar anomalies

```kql
// Beaconing detection via frequency analysis
let timeframe = 24h;
let minConnections = 50;
let jitterThreshold = 0.1;
CommonSecurityLog
| where TimeGenerated > ago(timeframe)
| where DeviceAction !in ("deny", "drop")
| summarize
    ConnectionTimes = make_list(TimeGenerated),
    Count = count()
    by SourceIP, DestinationIP, DestinationPort
| where Count > minConnections
| extend Intervals = array_sort_asc(ConnectionTimes)
| extend IntervalDiffs = series_subtract(
    array_slice(Intervals, 1, -1),
    array_slice(Intervals, 0, -2))
| extend StdDev = series_stats(IntervalDiffs).stdev
| extend Mean = series_stats(IntervalDiffs).avg
| extend Jitter = StdDev / Mean
| where Jitter < jitterThreshold  // Low jitter = beaconing
```

---

## 8. Multi-Workspace & Multi-Tenant Architecture

### Workspace Design Patterns

- Single workspace (simple, cost-effective)
- Multi-workspace (compliance, data sovereignty, team separation)
- Centralized vs federated SOC models

### Cross-Workspace Queries

```kql
// Query across multiple workspaces
union
workspace("workspace-1").SecurityEvent,
workspace("workspace-2").SecurityEvent,
workspace("workspace-3").SecurityEvent
| where EventID == 4625
| summarize count() by Computer, workspace_id
```

### Azure Lighthouse

- Manage multiple customer tenants from a single pane
- MSSP use case - delegate Sentinel access without full tenant access
- Cross-tenant incident management

### Content Hub & MSSP Considerations

- Centralized content deployment via ARM templates
- Sentinel Repositories (Git-based content sync)
- Custom solutions packaging

---

## 9. Cost Optimization & Performance

### Pricing Models

| Model | Description |
|-------|-------------|
| **Pay-as-you-go** | Per GB ingested |
| **Commitment tiers** | 100GB/day to 5000GB/day (significant discounts) |
| **Basic Logs** | Cheap storage for verbose/low-value logs |
| **Auxiliary Logs** | Ultra-cheap for compliance/archival |

### Cost Reduction Strategies

- Data Collection Rules (DCR) for filtering at ingestion
- Transformation rules to drop/mask fields before storage
- Archive tier for data older than 90 days
- Workspace-level data caps (use carefully)
- Identify top ingestion sources:

```kql
// Top tables by ingestion volume
Usage
| where TimeGenerated > ago(30d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType
| order by TotalGB desc
| take 20
```

### Performance Optimization

- Use `summarize` before `join` to reduce dataset size
- Avoid `contains` - use `has` for token-based search (10x faster)
- Use time filters early in queries
- Leverage materialized views for frequently-run aggregations
- Use `hint.strategy=broadcast` for small table joins

---

## 10. Compliance, Governance & Advanced Operations

### Regulatory Frameworks

- Map Sentinel detections to NIST CSF, ISO 27001, SOC 2, PCI-DSS
- Use Sentinel's built-in compliance workbooks
- Evidence collection for audits via Log Analytics

### Custom Workbooks (Advanced)

- Build executive dashboards with KQL + Azure Workbooks
- SOC metrics: MTTD (Mean Time to Detect), MTTR (Mean Time to Respond)
- Threat landscape visualization
- Capacity planning dashboards

### Advanced Threat Hunting

```kql
// Hunt for LSASS credential dumping
SecurityEvent
| where EventID == 10  // Process access
| where TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x147a", "0x143a")
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "unknown")
| project TimeGenerated, Computer, SourceImage,
    TargetImage, GrantedAccess, CallTrace
```

### Sentinel Ninja Program

- Microsoft's official learning path (L100 → L400)
- Practice labs via Microsoft Learn
- SC-200 certification (Microsoft Security Operations Analyst)

---

## Learning Roadmap Summary

| Phase | Timeline | Focus |
|-------|----------|-------|
| Foundations | Week 1-2 | Azure basics, Sentinel architecture |
| KQL Mastery | Week 2-4 | Query language, all operators |
| Detection Engineering | Week 4-8 | Analytics rules, tuning |
| Investigation & SOAR | Week 8-12 | Incidents, playbooks, automation |
| Advanced Topics | Month 3-4 | TI, UEBA, DaC, Sigma |
| Architecture & Scale | Month 4-6 | Multi-tenant, cost, performance |
| Expert Level | Month 6+ | Threat hunting, compliance, custom solutions |

---

## Recommended Resources

- **Microsoft Learn** - SC-200 learning path (free)
- **Sentinel GitHub** - `Azure/Azure-Sentinel` repo (thousands of community rules)
- **KQL Café** - community KQL learning sessions
- **MITRE ATT&CK** - `attack.mitre.org` for technique mapping
- **Reprise Security** - Sentinel-specific blog content
- **Rod Trent's** "Must Learn KQL" series
- **Microsoft Sentinel Ninja Training** - official L100-L400 content
