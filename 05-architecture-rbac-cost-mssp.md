# 03 — Data Ingestion, DCRs, Normalization (ASIM) & Cost

> Detections are only as good as the data feeding them. This is the plumbing a SIEM engineer owns.

## 1. Getting data in

- **Data connectors** — 1st-party (Entra, Defender XDR, Activity logs, M365) are mostly point-and-click. 3rd-party via **AMA** (Azure Monitor Agent), **CEF/Syslog** (via an AMA forwarder), **Logstash**, **Codeless Connector Platform**, or the **Logs Ingestion API**.
- **Azure Monitor Agent (AMA)** replaced the legacy MMA/Log Analytics agent. AMA collects via **Data Collection Rules**.

## 2. Data Collection Rules (DCR)

- A **DCR** defines *what* to collect, *how to transform* it, and *where* to send it.
- **Ingestion-time transformations** (KQL `transformKql`) let you filter noise, drop columns, mask PII, enrich, or route before billing/storage — this is a major cost and quality lever.
- **DCE** (Data Collection Endpoint) is the ingestion endpoint some scenarios require (custom logs, private link).

Example transform (drop noisy informational events at ingestion):

```kusto
source
| where EventID !in (4662, 5156)
| project-away DescriptionRaw
```

## 3. Normalization with ASIM

- **ASIM** (Advanced Security Information Model) is Sentinel's normalized schema (like a vendor-neutral CIM). Sources are normalized to schemas: `Network Session`, `Authentication`, `Process Event`, `DNS`, `Web Session`, etc.
- Use **ASIM parsers** (`_Im_*` functions) so a single detection works across many sources (e.g., one network-session rule covers firewall + proxy + cloud).
- Write detections against ASIM where possible for portability and source-agnostic coverage.

## 4. Table plans, retention and archive

- **Analytics tier** — full query/alerting, default retention (configurable). Most security tables.
- **Basic / Auxiliary logs** — cheaper ingestion for high-volume, low-value-per-row logs; limited query, no scheduled alerting (KQL-restricted), short interactive retention.
- **Archive** — cheap long-term retention; **search jobs** and **restore** bring archived data back for investigation/compliance.
- Set **per-table retention** to balance cost vs investigation/compliance needs.

## 5. Cost management

Ingestion is the dominant Sentinel cost. Levers:

1. **Filter at ingestion** with DCR transforms (drop noise before billing).
2. **Right-tier tables** (Basic/Auxiliary for verbose, low-signal data).
3. **Commitment/Simplified pricing tiers** — commit to daily GB for a discount over pay-as-you-go.
4. **Retention policy** per table; archive instead of keeping in Analytics.
5. **Avoid duplicate ingestion** (e.g., don't ingest Defender data you can query via XDR advanced hunting if it's not needed in-workspace).
6. **Monitor** with the `Usage` table and the Workspace usage workbook.

```kusto
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize BillableGB = sum(Quantity)/1000 by DataType
| order by BillableGB desc
```

## 6. Watchlists & Threat Intelligence

- **Watchlists** — import CSV reference data (VIP users, asset criticality, allow-lists) and `join`/`lookup` in detections.
- **Threat Intelligence** — ingest indicators via **TAXII** feeds or the **TI upload API** (STIX). Stored in `ThreatIntelligenceIndicator`; matched by TI analytics rules and used for enrichment.
