# 05 — Architecture, RBAC at Scale, Cost Governance & MSSP/Multi-Tenant

> How to design Sentinel for an enterprise or MSSP, not just a single workspace.

## 1. Workspace design

Key decision: **single workspace vs multiple**.

- **Single workspace** — simplest, best correlation, cheapest to operate. Default unless you have a hard reason not to.
- **Multiple workspaces** — driven by: data residency/sovereignty, regulatory separation, separate billing/ownership, or RBAC isolation.
- **Workspace = Sentinel instance.** One Sentinel per workspace.
- Use **resource-context / table-level RBAC** to scope what teams see within one workspace before splitting workspaces.

## 2. Multi-tenant & MSSP

- **Azure Lighthouse** — manage many customer tenants from your MSSP tenant with delegated RBAC, without switching directories. The standard MSSP pattern.
- **Cross-workspace queries** — `workspace("name").Table` and `union` across workspaces for centralized hunting/detection.
- **Multi-workspace view** in Sentinel for SOC analysts spanning tenants.
- Keep detections/playbooks as code and deploy to each tenant via pipeline (consistency at scale).

## 3. RBAC at scale

| Role | Grants |
|---|---|
| Microsoft Sentinel **Reader** | View data, incidents, workbooks |
| Microsoft Sentinel **Responder** | + triage incidents, run playbooks, change incident state |
| Microsoft Sentinel **Contributor** | + create/edit rules, workbooks, playbooks |
| Microsoft Sentinel **Playbook Operator** | Run/attach playbooks (without broad Logic App rights) |
| Microsoft Sentinel **Automation Contributor** | Used by automation rules to run playbooks |
| Logic App **Contributor** | Author/manage the Logic App itself |

- Apply roles at **resource group / workspace** scope; avoid subscription-wide grants.
- Separate **author** (Contributor) from **operator** (Responder/Playbook Operator) duties.
- The playbook's **managed identity** gets only the downstream permissions it needs (e.g., one Graph application permission).

## 4. Cost governance

- Primary cost = **ingestion (GB/day)** + Logic Apps action executions + (optional) UEBA/ML.
- Levers (detailed in doc 03): ingestion-time DCR filtering, table tiering (Basic/Aux), commitment tiers, retention/archive, dedup.
- Govern with budgets/alerts, the Usage workbook, and a monthly review of top `DataType` consumers.
- Push routing/decisions into **automation rules** (free) instead of always invoking (billed) playbook actions.

## 5. Resilience & operations

- **Region/BCDR:** workspace is regional; plan for region selection, retention, and export of critical data; understand that Sentinel content (rules/playbooks) should be redeployable from code.
- **Health monitoring:** `Heartbeat` and `SentinelHealth` tables to confirm agents/connectors/playbooks are healthy; alert on silent connectors (data gaps are blind spots).
- **Onboarding/offboarding** customers or business units via repeatable IaC.

## 6. Reference architecture (enterprise)

```
Data sources (Entra, M365, Defender XDR, firewalls, cloud) 
   -> AMA / connectors / Logs Ingestion API (+ DCR transforms)
   -> Log Analytics workspace (ASIM-normalized)
   -> Sentinel: analytics rules (as code) -> incidents
   -> Automation rules (route/triage)
   -> Playbooks (Logic Apps, managed identity, Key Vault)
   -> Response (Entra/Defender/firewall/ITSM/Teams) + incident comments
   -> Monitoring (diagnostics, workbooks, SentinelHealth)
All content deployed via git + pipeline (detection-as-code).
```
