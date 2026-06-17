# 02 — Microsoft Sentinel Detection Engineering

> Turning data into high-fidelity detections: rule types, entity mapping, MITRE alignment, grouping, and tuning.

## 1. Analytics rule types

| Type | Description | When to use |
|---|---|---|
| **Scheduled** | KQL run on a schedule (e.g., every 5 min over last 1h) | The workhorse; most custom detections |
| **Near-real-time (NRT)** | Runs ~every minute, low latency | Time-critical detections; limited (one table, constraints) |
| **Microsoft Security** | Auto-create incidents from MS product alerts (Defender, MDCA) | Bring 1st-party alerts into Sentinel |
| **Fusion** | ML correlation of multi-stage attacks across signals | Enable; low FP, high value, little tuning |
| **ML Behavior Analytics / Anomaly** | Built-in ML (e.g., anomalous SSH/RDP) | Baseline-driven detections |
| **Threat Intelligence** | Match logs to TI indicators | IoC matching |

## 2. Scheduled rule anatomy

- **Query** (KQL) + **frequency** + **lookback period** (keep aligned; e.g., run every 5m over 1h with dedupe logic).
- **Alert threshold** (e.g., results > 0).
- **Entity mapping** — map query columns to entities (Account, IP, Host, URL, FileHash). *Critical:* entities power investigation graph, playbook inputs, and grouping. A detection with no entity mapping is half-built.
- **Custom details** — surface key fields directly on the alert.
- **Alert details** — dynamic alert name/severity from query output.
- **MITRE ATT&CK** tactics & techniques tagging.
- **Incident settings** — create incident, **alert grouping** (group alerts into one incident by entities/details within a window to fight alert fatigue).
- **Suppression** — stop re-firing for N hours after a match.

## 3. Entity mapping example

For a brute-force query producing `UserPrincipalName`, `IPAddress`:

```
Account  -> FullName  = UserPrincipalName
IP       -> Address   = IPAddress
```

Now playbooks receive these entities, and grouping by Account+IP collapses noise into one incident.

## 4. Detection-as-code

- Store rules as **ARM/Bicep** or YAML (Sentinel repositories / GitHub-GitLab integration) and deploy via pipeline.
- Benefits: version history, peer review, environment promotion, rollback, and bulk management.
- Sentinel's **Repositories** feature connects a git repo and deploys analytics rules, hunting queries, playbooks, and workbooks automatically.

## 5. MITRE ATT&CK alignment

- Tag every detection with tactics/techniques. Use the **MITRE ATT&CK** blade in Sentinel to visualize **coverage** and find gaps.
- Aim for breadth across tactics (Initial Access → Impact), not 50 rules on one technique.

## 6. Tuning and false positives

- **Baseline before deploy:** run the query historically; if it returns hundreds of hits, it will be noisy.
- **Allow-lists / watchlists:** exclude known scanners, service accounts, break-glass accounts via `leftanti` join to a watchlist.
- **Dynamic thresholds:** compare to per-entity baselines rather than a global constant.
- **Grouping + suppression** to reduce duplicate incidents.
- **Measure:** track true-positive rate per rule; retire or fix rules with chronic FPs. A rule that's always closed as benign is worse than no rule (it erodes trust).

## 7. Hunting and notebooks

- **Hunting queries** — proactive KQL not tied to alerts; promote good ones to scheduled rules.
- **Livestream** — watch a hunting query in near-real-time during an investigation.
- **Bookmarks** — save interesting hunting results to an incident.
- **Jupyter notebooks** (via Azure ML) for advanced/large-scale hunting and ML.

## 8. UEBA

- User and Entity Behavior Analytics enriches entities with behavioral baselines, peer comparisons, and a `BehaviorAnalytics` table you can query and join into detections (e.g., "action by a user with an unusually high investigation priority score").
