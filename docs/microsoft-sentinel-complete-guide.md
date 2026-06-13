# Microsoft Sentinel: The Complete Beginner-to-Expert Guide

> **Who this is for:** Anyone from a total beginner to a seasoned SOC engineer. By the end you should be able to crack interviews, pass the **SC-200** exam, and confidently operate Sentinel in a real production environment. Concepts are explained in plain language first, then backed by real, copy-paste-ready examples.

> **How to read this:** Each section starts with a friendly "What & Why" explanation (no jargon), then goes deeper. Don't skip the **"In plain English"** boxes, they're where the intuition lives. Look for the **Gotcha** notes, those are the small details that separate juniors from 10-year veterans.

---

## Table of Contents

1. [What is Microsoft Sentinel? (Start Here)](#1-what-is-microsoft-sentinel-start-here)
2. [Foundations & Architecture](#2-foundations--architecture)
3. [Getting Data In: Connectors, DCRs & Normalization](#3-getting-data-in-connectors-dcrs--normalization)
4. [KQL: The Kusto Query Language](#4-kql-the-kusto-query-language)
5. [Analytics Rules & Detection Engineering](#5-analytics-rules--detection-engineering)
6. [Incidents & Investigation](#6-incidents--investigation)
7. [SOAR & Automation](#7-soar--automation)
8. [Threat Intelligence](#8-threat-intelligence)
9. [Threat Hunting](#9-threat-hunting)
10. [UEBA & Behavioral Analytics](#10-ueba--behavioral-analytics)
11. [Multi-Workspace & Multi-Tenant Architecture](#11-multi-workspace--multi-tenant-architecture)
12. [Cost Optimization & Performance](#12-cost-optimization--performance)
13. [Compliance, Governance & SOC Operations](#13-compliance-governance--soc-operations)
14. [Detection-as-Code & DevOps for Sentinel](#14-detection-as-code--devops-for-sentinel)
15. [Troubleshooting & Day-2 Operations](#15-troubleshooting--day-2-operations)
16. [Interview Prep & Exam Cheat Sheet](#16-interview-prep--exam-cheat-sheet)
17. [Glossary](#17-glossary)
18. [Learning Roadmap & Resources](#18-learning-roadmap--resources)

---

## 1. What is Microsoft Sentinel? (Start Here)

Microsoft Sentinel is a cloud-native **SIEM** (Security Information and Event Management) and **SOAR** (Security Orchestration, Automation and Response) platform built on Azure.

> **In plain English:** Imagine your company has hundreds of computers, servers, cloud apps, and firewalls. Each of them constantly writes down what is happening ("User Bob logged in", "File deleted", "Connection blocked"). These notes are called **logs**. Sentinel is like a giant, super-smart security guard that:
> - **Collects** all those notes into one place (the SIEM part),
> - **Reads** them looking for signs of an attacker,
> - **Reacts** automatically when it spots danger, like locking a door before the burglar gets in (the SOAR part).

### Why "cloud-native" matters

Traditional SIEMs (Splunk, QRadar, ArcSight) often run on servers you have to buy, size, and maintain. Sentinel runs entirely in Azure, so:

- **No infrastructure to manage** - Microsoft runs the servers.
- **Scales instantly** - ingest 1 GB or 50 TB a day without re-architecting.
- **Pay for what you use** - billing is mostly based on how much data you ingest.
- **Deep Microsoft integration** - native hooks into Entra ID (Azure AD), Microsoft 365, Defender, and Azure.

### SIEM vs SOAR vs XDR (a common interview question)

| Term | What it does | Simple analogy |
|------|--------------|----------------|
| **SIEM** | Collects and analyzes logs to detect threats | The detective who reads all the clues |
| **SOAR** | Automates the response to threats | The rapid-response team that acts on the detective's findings |
| **XDR** | Deep detection/response across endpoints, identity, email, cloud (e.g., Microsoft Defender XDR) | The specialist who knows one neighborhood (your endpoints) intimately |
| **Sentinel** | A SIEM + SOAR that ingests signals from XDR and everything else | The headquarters that coordinates all of the above |

> **Gotcha:** Sentinel and Microsoft Defender XDR are now tightly integrated through the **unified security operations platform** in the Defender portal. In interviews, mention that Sentinel is no longer "just a standalone portal", Microsoft is consolidating the SOC experience into `security.microsoft.com`.

---

## 2. Foundations & Architecture

### The building blocks

```
         Data Sources                       Sentinel (on top of Log Analytics)
  ┌──────────────────────┐          ┌────────────────────────────────────────┐
  │ Entra ID / M365      │          │  Analytics Rules  →  Incidents          │
  │ Azure resources      │  logs    │       ↑                  ↓              │
  │ On-prem (Syslog/CEF) │ ───────► │  Log Analytics      Automation/SOAR     │
  │ Firewalls / Network  │          │  Workspace (LAW)    (Playbooks)         │
  │ AWS / GCP / SaaS     │          │  = the database         ↓              │
  └──────────────────────┘          │  Workbooks · Hunting · Threat Intel     │
                                     └────────────────────────────────────────┘
```

### Core concepts you MUST master

- **Log Analytics Workspace (LAW)** - The database where every log lives. Sentinel is essentially a security "layer" enabled on top of one LAW. *If you understand nothing else, understand this: no workspace = no Sentinel.*
- **Tables** - Logs are stored in named tables. Examples:
  - `SigninLogs` - Entra ID sign-ins
  - `SecurityEvent` - Windows security events
  - `AuditLogs` - Entra ID directory changes
  - `CommonSecurityLog` - CEF/firewall data
  - `OfficeActivity` - Microsoft 365 activity
  - `SecurityAlert` / `SecurityIncident` - alerts and incidents
- **Data Connectors** - Pre-built "pipes" that bring data from a source into a table.
- **Schema** - The columns of a table (column name + data type). Knowing schemas is half of writing good KQL.
- **Retention** - How long data stays queryable.
  - **Analytics (hot) tier** - fast, interactive, default up to 90 days free, then billed.
  - **Basic/Auxiliary tier** - cheap storage for high-volume, low-value logs (limited query features).
  - **Archive (cold) tier** - very cheap long-term storage; requires a "search job" or "restore" to query.

> **In plain English:** Hot data is like papers on your desk, instantly readable. Archive data is like boxes in the basement, cheap to keep but you have to go fetch the box before you can read it.

### Azure prerequisites & RBAC

Sentinel-specific built-in roles (least-privilege matters in interviews):

| Role | Can do |
|------|--------|
| **Sentinel Reader** | View data, incidents, workbooks (read-only) |
| **Sentinel Responder** | Reader + manage incidents (assign, change status, add comments) |
| **Sentinel Contributor** | Responder + create/edit analytics rules, workbooks |
| **Sentinel Automation Contributor** | Allows automation rules to run playbooks |
| **Sentinel Playbook Operator** | Run (but not edit) playbooks |

> **Gotcha:** Sentinel roles only control Sentinel features. To *read the actual log data*, the user also needs read access to the underlying Log Analytics workspace. A classic "why can't my analyst see the logs?" troubleshooting question. Also remember RBAC is layered: **Management group → Subscription → Resource group → Resource**, and roles inherit downward.

### Where Sentinel sits in Azure

- **Tenant** = your whole organization in Microsoft cloud (one Entra ID directory).
- **Subscription** = a billing/management container inside the tenant.
- **Resource Group** = a folder for related resources.
- **Workspace** lives inside a resource group, inside a subscription, inside the tenant.

---

## 3. Getting Data In: Connectors, DCRs & Normalization

Garbage in, garbage out. Detection quality depends entirely on data quality.

### Data Connectors

Connectors come in several flavors. Knowing the difference is an interview favorite:

| Connector type | How it works | Example |
|----------------|--------------|---------|
| **Service-to-service (native)** | Azure-internal, click to connect | Entra ID, Activity, M365, Defender |
| **API-based** | Sentinel polls a vendor API | AWS CloudTrail, GCP, Okta |
| **Agent-based (AMA)** | Azure Monitor Agent collects from VMs | Windows/Linux servers |
| **Syslog / CEF** | Logs forwarded to a Linux collector → AMA | Firewalls, network gear |
| **Codeless Connector Platform (CCP)** | Config-only connectors, no code | Many newer SaaS sources |
| **Logstash / custom / Logs Ingestion API** | Push anything via API | Custom apps |

> **Gotcha:** The old **Log Analytics Agent (MMA/OMS)** is **retired**. Production deployments must use the **Azure Monitor Agent (AMA)** with **Data Collection Rules (DCRs)**. If an interviewer mentions MMA, the correct answer is "migrate to AMA."

### Data Collection Rules (DCRs): filter & transform at ingestion

DCRs let you decide *what* to collect and *transform it before it's stored*, this saves money and improves quality.

```kql
// Example KQL transformation inside a DCR:
// drop noisy informational events and mask a sensitive field
source
| where EventID != 5145                     // drop high-volume noise
| extend AccountCustomEntity = Account
| project-away SensitiveColumn               // remove PII before storage
```

> **In plain English:** A DCR is a bouncer at the door of your database. It decides which logs get in, and can edit them (mask passwords, drop junk) on the way through, so you don't pay to store useless data.

### ASIM: Advanced Security Information Model (normalization)

Every vendor names fields differently (`src_ip`, `SourceIP`, `ClientIP`...). **ASIM** normalizes them into a common schema so one detection rule works across many sources.

```kql
// Query normalized network data regardless of vendor using an ASIM parser
_Im_NetworkSession(starttime=ago(1h))
| where DstPortNumber == 4444
| summarize count() by SrcIpAddr, DstIpAddr, DstPortNumber
```

- ASIM parsers start with `_Im_` (built-in, parametrized) or `Im` (versioned).
- Schemas include: NetworkSession, Authentication, ProcessEvent, FileEvent, DNS, WebSession, Registry.

> **Gotcha:** Writing detections against ASIM = write once, detect everywhere. Many "senior" candidates have never heard of ASIM; knowing it signals real depth.

---

## 4. KQL: The Kusto Query Language

KQL is the **single most important skill** in Sentinel. If you master one thing, master this.

> **In plain English:** KQL is how you ask questions of your data. It reads like a sentence flowing through a pipe `|`: "Take this table → keep only these rows → show me these columns → group and count them." Data flows top-to-bottom, left-to-right.

### The mental model: data flows through pipes

```kql
TableName              // 1. start with a table
| where ...            // 2. filter rows
| project ...          // 3. choose columns
| summarize ...        // 4. aggregate
| order by ...         // 5. sort
| take 10              // 6. limit
```

### Beginner: the essential operators

```kql
SecurityEvent
| where TimeGenerated > ago(24h)     // time filter FIRST (performance!)
| where EventID == 4625              // 4625 = failed logon
| project TimeGenerated, Account, Computer, IpAddress  // pick columns
| summarize FailedLogins = count() by Account          // group & count
| sort by FailedLogins desc          // biggest offenders first
| take 10                            // top 10
```

Must-know operators and what they do, in plain words:

| Operator | Plain-English meaning |
|----------|----------------------|
| `where` | Keep only rows that match |
| `project` / `project-away` | Keep / drop specific columns |
| `extend` | Add a new calculated column |
| `summarize` | Group rows and calculate (count, sum, avg, max) |
| `count` | How many rows |
| `distinct` | Unique values only |
| `sort` / `order by` | Order the results |
| `take` / `limit` | Return only N rows (no order guarantee) |
| `top` | Sort + limit in one step |
| `render` | Draw a chart |

> **Gotcha (performance #1 rule):** Always filter by **time first**, then by the most selective `where` clauses. `has` is faster than `contains` because it matches whole tokens using the index; `contains` scans every character. Avoid leading-wildcard `*` searches.

### Intermediate: joins, unions, let, parsing

```kql
// let = define a variable/subquery for reuse and readability
let threshold = 10;
let failed = SecurityEvent
    | where EventID == 4625
    | summarize Attempts = count() by Account, IpAddress;
let success = SecurityEvent
    | where EventID == 4624
    | summarize Successes = count() by Account;
failed
| join kind=inner success on Account     // combine two result sets
| where Attempts > threshold
| extend RiskScore = Attempts * 1.5      // add a derived column
```

**Join kinds explained simply:**

| `kind=` | Returns |
|---------|---------|
| `inner` | Only matching rows from both sides |
| `leftouter` | All left rows + matches from right (nulls if none) |
| `leftsemi` | Left rows that *have* a match (left columns only) |
| `leftanti` | Left rows that have **no** match, perfect for "find what's missing" |
| `fullouter` | Everything from both sides |

> **Gotcha:** `leftanti` is a hunting superpower, e.g., "show me hosts that logged in but were **never** seen in our asset inventory." Put the smaller table on the **left** of a join, and `summarize` before joining to shrink the data.

**union** stacks tables on top of each other (good for searching across sources):

```kql
union SigninLogs, AuditLogs, OfficeActivity
| where TimeGenerated > ago(1h)
| where * has "185.220.101.45"
```

**Parsing dynamic/JSON data:**

```kql
AuditLogs
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)  // dot into JSON
| extend TargetName = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, OperationName, TargetName
```

### Advanced: time series, anomalies, and ML functions

```kql
// Detect unusual login spikes per user using built-in anomaly detection
let timeframe = 14d;
let sensitivity = 2.5;   // higher = fewer, stronger anomalies
SigninLogs
| where TimeGenerated > ago(timeframe)
| make-series LoginCount = count()
    on TimeGenerated from ago(timeframe) to now() step 1h
    by UserPrincipalName
| extend (anomalies, score, baseline) =
    series_decompose_anomalies(LoginCount, sensitivity)
| mv-expand TimeGenerated, LoginCount, anomalies, score, baseline
| where toint(anomalies) == 1     // 1 = positive spike anomaly
| project TimeGenerated, UserPrincipalName, LoginCount, score
```

> **In plain English:** `make-series` turns events into a smooth timeline (a heartbeat). `series_decompose_anomalies` learns the normal rhythm, then flags the beats that are abnormally high or low, automatic baselining without you guessing thresholds.

### Expert techniques toolbox

- `series_decompose_anomalies()` - behavioral baselining (above).
- `bag_unpack()` / `mv-expand` - flatten dynamic JSON into columns/rows.
- `parse_json()`, `parse_url()`, `parse_path()` - structured extraction.
- `geo_info_from_ip_address()` - enrich IPs with country/city.
- `ipv4_is_private()`, `ipv4_is_in_range()` - classify/segment IPs.
- `materialize()` - cache a subquery used multiple times in one query.
- `iff()` / `case()` - conditional columns.
- `arg_max()` / `arg_min()` - get the latest/earliest row per group (great for "most recent state").
- **Saved functions** - turn a query into a reusable function (e.g., `MyMaliciousIPs()`).

```kql
// arg_max pattern: latest device info per machine
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceId
```

> **Gotcha:** `take`/`limit` does **not** guarantee order, use `top N by Column` when you need the actual highest values. And `count()` counts rows; `dcount()` counts *distinct* values (approximate but fast); use `count_distinct()` when you need exactness.

---

## 5. Analytics Rules & Detection Engineering

Analytics rules are the queries that run on a schedule and create **alerts/incidents** when something matches.

### Rule types

| Type | Use case | Latency |
|------|----------|---------|
| **Scheduled** | Custom KQL on a timer (most common) | Minutes |
| **NRT (Near-Real-Time)** | High-priority, sub-minute detection | ~1 min |
| **Fusion** | ML correlates multiple low-fidelity signals into one high-fidelity incident | Variable |
| **Microsoft Security** | Auto-create Sentinel incidents from Defender alerts | Real-time |
| **Anomaly** | Customizable UEBA/ML anomaly templates | Continuous |
| **Threat Intelligence** | Match logs against TI indicators | Scheduled |

> **Gotcha:** **Fusion** is unique, it stitches together events that look harmless alone (one failed login here, one mailbox rule there) into a single multi-stage attack incident. You can't write Fusion logic yourself; you enable it and tune which detections feed it. NRT rules have constraints (single table, no unions/joins in some cases) in exchange for speed.

### Anatomy of a great scheduled rule

1. **Query** - the KQL detection logic.
2. **Query scheduling** - how often it runs + how far back it looks.
3. **Alert threshold** - generate alert when results exceed N.
4. **Entity mapping** - tell Sentinel which columns are Accounts, Hosts, IPs, URLs, FileHashes. *This powers the investigation graph.*
5. **Custom details** - surface key fields directly on the alert.
6. **MITRE ATT&CK mapping** - tactic/technique for coverage tracking.
7. **Incident settings** - grouping & suppression.
8. **Automated response** - attach automation rules/playbooks.

```kql
// Production example: impossible travel (login from two far places too fast)
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0                  // 0 = success
| project TimeGenerated, UserPrincipalName, Location, IPAddress,
          Latitude = todouble(LocationDetails.geoCoordinates.latitude),
          Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize                              // required before prev()/next()
| extend PrevUser = prev(UserPrincipalName),
         PrevLoc  = prev(Location),
         PrevTime = prev(TimeGenerated),
         PrevLat  = prev(Latitude),
         PrevLon  = prev(Longitude)
| where UserPrincipalName == PrevUser and Location != PrevLoc
| extend MinutesApart = datetime_diff('minute', TimeGenerated, PrevTime)
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
| extend ImpliedSpeedKmh = DistanceKm / (todouble(MinutesApart) / 60)
| where ImpliedSpeedKmh > 900            // faster than a commercial jet
```

> **In plain English:** If the same person "logs in" from London and then from Tokyo 20 minutes later, no human can travel that fast, so the account is likely compromised. `serialize` + `prev()` lets us compare each row to the one before it.

### Detection tuning: the art that takes years

- **Lookback vs frequency:** lookback should be ≥ frequency, and add buffer for **ingestion delay** (logs arrive late!). A rule running every 5 min with a 5-min lookback will miss late data, use a longer lookback and dedupe.
- **Entity mapping** is mandatory for good investigations, never skip it.
- **Alert grouping:** group related alerts into one incident to fight alert fatigue.
- **Suppression:** temporarily silence a noisy known-good pattern.
- **False-positive handling:** maintain an exclusion **watchlist** rather than hardcoding exceptions in the query.
- **Tune for fidelity:** a rule that fires 500 times a day will be ignored. Aim for high signal, low noise.

> **Gotcha:** "Ingestion delay" is the silent killer of detections. Veterans always account for the gap between when an event happens and when it lands in the table (can be minutes to an hour). Use `ingestion_time()` to diagnose it.

### Detection quality metrics

- **True Positive (TP):** real threat, correctly alerted.
- **False Positive (FP):** benign activity that alerted, tune it down.
- **False Negative (FN):** real threat that was missed, the dangerous one.
- **Precision** = TP / (TP + FP), how trustworthy your alerts are.
- **Recall** = TP / (TP + FN), how much you actually catch.

---

## 6. Incidents & Investigation

An **incident** is a container that groups one or more **alerts** that likely belong to the same attack.

### Incident lifecycle

```
Triage → Investigate → Contain → Eradicate → Recover → Lessons Learned
```

> **In plain English:** Triage = "is this real and how bad?" Investigate = "what exactly happened and how far did it spread?" Contain = "stop the bleeding." Eradicate = "remove the attacker." Recover = "restore to normal." Lessons Learned = "make sure it never happens the same way again."

### The investigation graph

A visual map of entities (users, hosts, IPs, files) and how they connect. You **pivot**: start at a suspicious IP → see which user used it → which host → which processes ran. This is how you reconstruct the full story.

### Reconstructing an attack chain

```kql
// Pull everything related to one suspicious IP across all sources
let suspiciousIP = "185.220.101.45";
let window = 48h;
union isfuzzy=true
  (SigninLogs       | where IPAddress == suspiciousIP        | extend Src="SigninLogs"),
  (AuditLogs        | where tostring(InitiatedBy) has suspiciousIP | extend Src="AuditLogs"),
  (OfficeActivity   | where ClientIP == suspiciousIP         | extend Src="OfficeActivity"),
  (CommonSecurityLog| where SourceIP == suspiciousIP or DestinationIP == suspiciousIP | extend Src="Firewall"),
  (SecurityAlert    | where Entities has suspiciousIP        | extend Src="Alert")
| where TimeGenerated > ago(window)
| project TimeGenerated, Src, OperationName, UserPrincipalName, ResultDescription
| sort by TimeGenerated asc
```

> **Gotcha:** `isfuzzy=true` lets the `union` succeed even if one of the tables doesn't exist in your workspace, very handy when a connector isn't enabled. Without it, a missing table throws an error and the whole query fails.

### Triage questions a senior analyst always asks

1. Is this a known **false positive** pattern?
2. What is the **blast radius** (how many users/hosts/data)?
3. Is the activity **still ongoing**?
4. What **MITRE tactic/technique** does this map to?
5. Is there **lateral movement** or **privilege escalation**?
6. What's the **earliest** sign (patient zero / initial access)?

---

## 7. SOAR & Automation

This is the part that lets a small team respond like a big one.

### Automation Rules vs Playbooks (know the difference!)

| | **Automation Rule** | **Playbook** |
|---|---|---|
| What | Lightweight, native Sentinel logic | A full workflow built on Azure Logic Apps |
| Triggers | Incident/alert created or updated | Called by automation rule, or manually |
| Typical use | Auto-assign, auto-tag, change severity, suppress, run a playbook | Enrich, notify, contain, create tickets |
| Power | Simple if/then | Hundreds of connectors, API calls, approvals |

> **In plain English:** An **automation rule** is the manager that says "when a high-severity incident appears, assign it to the on-call analyst and run the enrichment playbook." A **playbook** is the worker that actually does the heavy lifting (calls VirusTotal, posts to Teams, disables the user).

### Common playbook patterns

- **Enrichment:** VirusTotal, AbuseIPDB, WHOIS, GeoIP, MDTI lookups.
- **Notification:** Teams, Slack, email, PagerDuty, ServiceNow.
- **Containment:** disable Entra ID user, revoke sessions, isolate device via Defender, block IP via firewall/Conditional Access Named Location.
- **Ticketing:** create/update Jira or ServiceNow tickets, two-way sync.
- **Human-in-the-loop:** post an approval card in Teams before taking destructive action.

```text
Auto-respond to a confirmed malicious sign-in (conceptual flow):
  Trigger:   Sentinel incident created
  Condition: Tactic == InitialAccess AND Severity == High
  Steps:
    1. Extract Account + IP entities from the incident
    2. Look up IP reputation (VirusTotal / MDTI)
    3. IF reputation is malicious:
         - Revoke the user's Entra ID sessions
         - Add IP to a blocked Named Location (Conditional Access)
         - Post an alert card to the SOC Teams channel
         - Create a ServiceNow incident
    4. Write all enrichment back as an incident comment
    5. Re-assign incident to Tier-2 for review
```

> **Gotcha:** Always put **destructive actions** (disabling users, isolating hosts) behind an **approval step** or a high-confidence condition. An over-eager playbook that disables the CEO's account at 2 a.m. because of a false positive is a career-defining mistake. This is why "human-in-the-loop" exists.

### Watchlists

Reference data you can join against in KQL (VIP users, terminated employees, approved admin IPs, asset inventory).

```kql
let vips = _GetWatchlist('VIP_Users') | project UserPrincipalName;
SigninLogs
| where ResultType != 0                       // failed logins
| join kind=inner vips on UserPrincipalName   // only alert on VIPs
```

---

## 8. Threat Intelligence

Threat Intelligence (TI) = knowledge about known-bad things (malicious IPs, domains, file hashes, URLs), called **IOCs** (Indicators of Compromise).

### How TI gets into Sentinel

- **TAXII** feeds (the transport) carrying **STIX** objects (the data format).
- **Microsoft Defender Threat Intelligence (MDTI)**.
- **Threat Intelligence Upload API** for custom indicators.
- Third-party platforms: MISP, Anomali, Recorded Future, OpenCTI.
- Indicators land in the `ThreatIntelligenceIndicator` table.

> **In plain English:** STIX is the *language* threat intel is written in; TAXII is the *delivery truck* that brings it to you. IOCs are the actual "wanted posters" (this IP is bad, this hash is malware).

### Matching logs against TI at scale

```kql
let TI = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(7d)
    | where Active == true and ConfidenceScore > 70
    | where isnotempty(NetworkIP)
    | project NetworkIP, ThreatType, Description;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| join kind=inner TI on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, Description, DeviceVendor
```

### MITRE ATT&CK & the kill chain

- **ATT&CK** is the industry-standard catalog of attacker **tactics** (the *why*: Initial Access, Persistence, Exfiltration) and **techniques** (the *how*: T1059 Command & Scripting).
- Map every detection to ATT&CK, then use the **ATT&CK Navigator** to see your coverage and find gaps.
- The **Cyber Kill Chain** (Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions) is the older, higher-level model, good for explaining the attack story to non-technical stakeholders.
- The **Diamond Model** (Adversary, Capability, Infrastructure, Victim) helps structure attribution.

> **Gotcha:** Interviewers love "what's the difference between a tactic and a technique?" Answer: a **tactic** is the attacker's goal (e.g., Persistence); a **technique** is the specific method to achieve it (e.g., T1547 Boot/Logon Autostart). **Procedures** are the exact tool/command used.

---

## 9. Threat Hunting

**Detection** is automated and waits for known patterns. **Hunting** is a human proactively searching for the unknown, assuming the attacker is already inside.

> **In plain English:** Detections are mousetraps you set and forget. Hunting is you walking through the house with a flashlight at midnight looking for the mouse the traps missed.

### Hypothesis-driven hunting

A good hunt starts with a hypothesis: *"If an attacker is dumping credentials, I should see suspicious access to lsass.exe."*

```kql
// Hunt: LSASS credential dumping (Mimikatz-style)
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","taskmgr.exe")  // trim known-good
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
```

### Behavioral hunting patterns (the "senior" toolkit)

- **Long-tail / stacking analysis** - rare is suspicious. Count how often each value appears; the rarest are worth a look.
- **Frequency analysis (beaconing)** - malware "phones home" on a regular interval. Low timing variation (jitter) = likely C2.
- **Sequence detection** - specific events in a specific order.
- **Clustering** - group similar anomalies to spot campaigns.

```kql
// Beaconing: regular, low-jitter outbound connections suggest C2
let lookback = 24h;
let minConns = 50;
let maxJitter = 0.15;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DeviceAction !in ("deny","drop")
| summarize Times = make_list(TimeGenerated), Count = count()
    by SourceIP, DestinationIP, DestinationPort
| where Count > minConns
| extend Sorted = array_sort_asc(Times)
| extend Diffs = series_subtract(array_slice(Sorted,1,-1), array_slice(Sorted,0,-2))
| extend Stats = series_stats_dynamic(Diffs)
| extend Jitter = todouble(Stats.stdev) / todouble(Stats.avg)
| where Jitter < maxJitter           // very regular timing = beaconing
| project SourceIP, DestinationIP, DestinationPort, Count, Jitter
```

> **In plain English:** Humans browse the web randomly; malware checks in like clockwork. If connections to one address are almost perfectly evenly spaced (tiny jitter), that regularity itself is the giveaway.

### Long-tail (stacking) example

```kql
// Rare parent-child process relationships are worth investigating
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| summarize Count = count() by InitiatingProcessFileName, FileName
| where Count < 5                    // the long tail = rare = suspicious
| sort by Count asc
```

> **Gotcha:** Sentinel has a dedicated **Hunting** experience with built-in queries, **bookmarks** (save interesting findings), and **livestream** (run a hunting query continuously in near-real-time). Bookmarks can be promoted into incidents, mention this to show you know the workflow, not just the KQL.

---

## 10. UEBA & Behavioral Analytics

**UEBA** (User and Entity Behavior Analytics) learns what is *normal* for each user/host and flags deviations.

> **In plain English:** Instead of fixed rules ("alert if >10 failed logins"), UEBA learns *your* habits. If you always log in from one city between 9-5 and suddenly authenticate from another country at 3 a.m. to a server you've never touched, that's anomalous *for you*, even if the raw action isn't inherently "bad."

### Key tables

- `BehaviorAnalytics` - enriched activity with anomaly scores, blast radius, and investigation priority.
- `IdentityInfo` - identity context (department, manager, group membership) synced from Entra ID.
- `UserPeerAnalytics` - who behaves similarly (peer groups).

```kql
BehaviorAnalytics
| where TimeGenerated > ago(7d)
| where ActivityInsights has "FirstTime"      // never-before-seen behavior
| where InvestigationPriority > 5
| project TimeGenerated, UserName, ActivityType,
          ActivityInsights, InvestigationPriority
| sort by InvestigationPriority desc
```

> **Gotcha:** UEBA needs **time to learn** (a baseline period, typically a week+) before scores are meaningful. Don't expect useful anomalies the day you turn it on. It also has a separate enablement step and consumes ingestion, factor that into cost.

---

## 11. Multi-Workspace & Multi-Tenant Architecture

### Workspace design choices

| Pattern | When to use | Trade-off |
|---------|-------------|-----------|
| **Single workspace** | Most orgs, simplicity, easy correlation | Less data isolation |
| **Multi-workspace** | Data sovereignty, regulatory, business-unit separation | Cross-workspace queries, more overhead |
| **Centralized SOC** | One team watches everything | Needs cross-workspace access |
| **Federated SOC** | Regional/BU teams operate independently | Harder global view |

> **In plain English:** One big workspace is like keeping all files in one cabinet, easy to search, but everyone sees everything. Multiple workspaces are like separate locked cabinets per department, more private and compliant, but you need a master key and extra steps to search across them.

### Cross-workspace queries

```kql
union
  workspace("law-prod").SecurityEvent,
  workspace("law-emea").SecurityEvent,
  workspace("law-apac").SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Computer, _ResourceId
```

### Azure Lighthouse (for MSSPs / multi-tenant)

- Lets a service provider manage **many customer tenants** from their own tenant.
- **Delegated** access, no need to be a guest in each customer directory.
- Enables cross-tenant incident management for MSSP SOCs.

### Content management at scale

- **Content Hub** - install ready-made solutions (connectors, rules, workbooks) per product.
- **Repositories** - connect a GitHub/Azure DevOps repo to sync content (this is Detection-as-Code, see §14).
- **ARM/Bicep templates** - deploy consistent content across many workspaces.

---

## 12. Cost Optimization & Performance

Sentinel cost is driven mostly by **data ingestion (GB/day)** and retention. Controlling this is a core senior-engineer responsibility.

### Pricing models

| Model | Description |
|-------|-------------|
| **Pay-as-you-go** | Per GB ingested; simple, good for small/variable volumes |
| **Commitment (Simplified) tiers** | Pre-commit GB/day (100 → 5000+) for big discounts |
| **Basic Logs** | Cheap ingestion for verbose, low-value logs; limited query/retention |
| **Auxiliary Logs** | Even cheaper, for compliance/archival data |
| **Archive tier** | Very cheap long-term retention; query via search job/restore |

> **In plain English:** Pay-as-you-go is like paying per grocery item. Commitment tiers are a Costco membership, you promise to buy a lot, so each unit is cheaper. Basic/Auxiliary logs are the bulk-bin discount shelf for stuff you rarely need but must keep.

### Cost reduction strategies (in priority order)

1. **Filter at ingestion with DCRs** - don't pay to store noise (e.g., drop verbose firewall "allow" events).
2. **Route low-value, high-volume data to Basic/Auxiliary logs**.
3. **Use transformation rules** to trim/mask fields before storage.
4. **Tier old data to Archive** instead of keeping it hot.
5. **Find your top spenders** and challenge each one:

```kql
// Which tables cost the most? Start your cost review here.
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize TotalGB = sum(Quantity) / 1024 by DataType
| sort by TotalGB desc
| take 20
```

6. **Daily cap** - emergency brake to prevent runaway bills (use carefully, capping can drop security data!).
7. **Free data sources** - many Microsoft 365/Entra/Defender data types are free to ingest; know which.

> **Gotcha:** A daily cap stops *all* ingestion once hit, including your most critical security logs. It's a budget safety net, not a tuning tool. Veterans prefer DCR filtering + Basic logs over caps.

### Query performance rules

- **Time filter first**, then most selective filters.
- Prefer `has` over `contains`; avoid `* startswith` / leading wildcards.
- `summarize` *before* `join`; put the **smaller** table on the left.
- Use `project` early to carry fewer columns.
- Use **functions** and (where supported) **materialized views** for repeated aggregations.
- Use `hint.strategy=broadcast` when joining a small table to a huge one.
- Use `arg_max()` instead of sorting + `take 1` for "latest per key."

---

## 13. Compliance, Governance & SOC Operations

### Mapping to frameworks

- Align detections and reports to **NIST CSF**, **ISO 27001**, **SOC 2**, **PCI-DSS**, **HIPAA**.
- Use built-in compliance workbooks and the **Content Hub** solutions for specific standards.
- Log Analytics retention + immutability supports **audit evidence**.

### SOC metrics that matter (and show up in interviews)

| Metric | Meaning | Why it matters |
|--------|---------|----------------|
| **MTTD** | Mean Time To Detect | How fast you notice an attack |
| **MTTA** | Mean Time To Acknowledge | How fast someone picks up the incident |
| **MTTR** | Mean Time To Respond/Remediate | How fast you stop it |
| **Dwell time** | How long the attacker was inside undetected | The number boards care about |
| **FP rate** | Share of alerts that are false | Drives analyst burnout |

```kql
// Rough MTTR from Sentinel incidents
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend Hours = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize MTTR_Hours = avg(Hours), Incidents = count() by Severity
```

### Custom Workbooks

Interactive dashboards (KQL + visualizations) for executives and the SOC: threat landscape, ingestion/cost trends, detection coverage, analyst workload, capacity planning.

### Advanced hunting example (kept for reference)

```kql
// LSASS access via classic Windows Security events
SecurityEvent
| where EventID == 4656 or EventID == 4663
| where ObjectName endswith "lsass.exe"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, AccessMask
```

---

## 14. Detection-as-Code & DevOps for Sentinel

Treat detections like software: versioned, reviewed, tested, and deployed through CI/CD.

> **In plain English:** Instead of clicking buttons in the portal to create rules (which no one remembers later), you store rules as files in Git. Changes go through pull requests and pipelines, so you get history, peer review, and the ability to roll back, exactly like real code.

### The DaC workflow

```
Write rule (YAML/ARM) → Git PR → automated tests/lint → CI/CD pipeline → deploy to Sentinel
```

- **Sentinel Repositories** natively connect a GitHub/Azure DevOps repo to a workspace.
- Store **analytics rules, hunting queries, workbooks, playbooks, parsers** as code.
- Promote content from **dev → test → prod** workspaces with the same pipeline.

### Sigma: write once, deploy anywhere

**Sigma** is a vendor-neutral detection format. Convert community Sigma rules to KQL with `sigma-cli`, then commit them.

```yaml
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
  - Legitimate admin automation scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

> **Gotcha:** The hard part of DaC isn't the pipeline, it's **testing**. Senior teams maintain sample/unit-test data so a rule's logic is validated before it ever reaches production. Mentioning rule testing and version-controlled tuning signals real maturity.

---

## 15. Troubleshooting & Day-2 Operations

The questions you'll actually face once Sentinel is live.

### "My logs aren't showing up"

1. Is the **connector** connected and the agent (AMA) healthy?
2. Check the **Heartbeat** table, is the source even reporting?
3. Is a **DCR** filtering the data out before storage?
4. **Ingestion delay**, give it time and check `ingestion_time()`.
5. Permissions, can your account read the workspace?

```kql
// Are my agents alive? (no heartbeat = no data)
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| extend MinutesAgo = datetime_diff('minute', now(), LastSeen)
| where MinutesAgo > 15           // silent for 15+ min = investigate
| sort by MinutesAgo desc
```

### "My rule isn't firing / firing too much"

- Run the rule's KQL manually in Logs, does it return rows?
- Check **query period vs frequency** and ingestion delay.
- Verify the **alert threshold** and **grouping/suppression** settings.
- Too noisy? Add a benign-activity **watchlist** exclusion and tune.

### "Costs spiked overnight"

- Run the `Usage` query (§12) to find the table that jumped.
- Identify the source (new connector? misconfigured verbose logging?).
- Apply a DCR filter or move it to Basic logs.

### Measuring ingestion latency

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| extend LatencySeconds = datetime_diff('second', ingestion_time(), TimeGenerated)
| summarize avg(LatencySeconds), max(LatencySeconds), percentile(LatencySeconds, 95)
```

> **Gotcha:** `TimeGenerated` = when the event *happened*. `ingestion_time()` = when it *arrived* in Sentinel. The gap between them is **ingestion latency**, the root cause of countless "the rule missed it" mysteries.

---

## 16. Interview Prep & Exam Cheat Sheet

### Rapid-fire questions you should be able to answer

- **SIEM vs SOAR?** SIEM detects (collect/analyze); SOAR responds (automate).
- **What underpins Sentinel?** A Log Analytics Workspace.
- **MMA vs AMA?** MMA is retired; use AMA + DCRs.
- **`has` vs `contains`?** `has` is token/indexed (fast); `contains` is substring (slow).
- **Tactic vs technique (ATT&CK)?** Goal vs method (e.g., Persistence vs T1547).
- **Fusion rule?** ML correlation of multiple low-fidelity signals into one incident; you can't author its logic.
- **NRT rule limits?** Near-real-time but constrained (single source, no joins/unions in some cases).
- **Automation rule vs playbook?** Native lightweight logic vs Logic Apps workflow.
- **Alert vs incident?** Alert = single detection; incident = grouped alerts (the case).
- **STIX vs TAXII?** Data format vs transport protocol.
- **Reduce cost?** DCR filtering, Basic/Auxiliary logs, archive tier, commitment tiers, find top tables via `Usage`.
- **Ingestion delay impact?** Rules can miss late data; lookback must exceed frequency + buffer.
- **`serialize` why?** Required before windowing functions like `prev()`/`next()`/`row_number()`.
- **`leftanti` join use?** Find rows with **no** match ("what's missing / never seen").

### SC-200 exam focus areas

1. Mitigate threats using **Microsoft Defender XDR** (endpoint, identity, email, cloud apps).
2. Mitigate threats using **Microsoft Defender for Cloud**.
3. Mitigate threats using **Microsoft Sentinel** (connectors, analytics, incidents, automation, hunting, workbooks, KQL).
4. Heavy emphasis on **KQL**, know it cold.

### A simple study order

KQL → connectors/DCR → analytics rules → incidents/investigation → automation → hunting → UEBA/TI → architecture/cost.

---

## 17. Glossary

- **SIEM** - Security Information and Event Management; collects and analyzes logs.
- **SOAR** - Security Orchestration, Automation and Response; automates reactions.
- **XDR** - Extended Detection and Response; deep cross-signal detection (Defender).
- **LAW** - Log Analytics Workspace; the underlying data store.
- **KQL** - Kusto Query Language; how you query data.
- **DCR** - Data Collection Rule; filters/transforms data at ingestion.
- **AMA** - Azure Monitor Agent; the supported log collection agent.
- **ASIM** - Advanced Security Information Model; normalizes schemas across sources.
- **IOC** - Indicator of Compromise; a known-bad artifact (IP, hash, domain).
- **TI** - Threat Intelligence; knowledge about adversaries and IOCs.
- **STIX/TAXII** - The format/transport for sharing threat intel.
- **UEBA** - User and Entity Behavior Analytics; anomaly detection by behavior.
- **MITRE ATT&CK** - Catalog of adversary tactics and techniques.
- **Fusion** - ML-based multi-stage attack correlation in Sentinel.
- **NRT** - Near-Real-Time analytics rule.
- **Playbook** - Automated workflow built on Azure Logic Apps.
- **Watchlist** - Reference data you join against in KQL.
- **MTTD/MTTR** - Mean Time To Detect / Respond.
- **Dwell time** - How long an attacker stays undetected.
- **DaC** - Detection-as-Code; managing detections like software in Git.

---

## 18. Learning Roadmap & Resources

### Roadmap

| Phase | Timeline | Focus |
|-------|----------|-------|
| Foundations | Week 1-2 | Azure basics, Sentinel architecture, workspace concepts |
| KQL Mastery | Week 2-4 | All operators, joins, summarize, time series |
| Data & Connectors | Week 3-4 | Connectors, AMA, DCRs, ASIM normalization |
| Detection Engineering | Week 4-8 | Analytics rules, entity mapping, tuning, MITRE mapping |
| Investigation & SOAR | Week 8-12 | Incidents, investigation graph, automation, playbooks |
| Hunting, UEBA & TI | Month 3-4 | Proactive hunting, behavioral analytics, threat intel |
| Architecture & Cost | Month 4-6 | Multi-tenant, Lighthouse, cost optimization, performance |
| Expert / DaC | Month 6+ | Detection-as-Code, Sigma, CI/CD, compliance, custom solutions |

### Resources

- **Microsoft Learn** - SC-200 learning path (free, official).
- **Microsoft Sentinel Ninja Training** - structured L100 → L400 content.
- **`Azure/Azure-Sentinel` GitHub repo** - thousands of community rules, hunting queries, playbooks.
- **MITRE ATT&CK** - `attack.mitre.org` and the ATT&CK Navigator.
- **Rod Trent's "Must Learn KQL"** series - the friendliest KQL on-ramp.
- **KQL Café / KQL playground** - hands-on practice.
- **SigmaHQ** - community detection rules in Sigma format.
- **MITRE D3FEND** - defensive countermeasures companion to ATT&CK.

---

> **Final advice:** Reading this guide builds knowledge; **doing** builds skill. Spin up a free Azure/Sentinel trial, ingest some logs, break things, write KQL daily, and reconstruct a few attack scenarios end-to-end. The engineers who look like they have "10 years of experience" are simply the ones who have investigated the most incidents and written the most queries. Now go build.
