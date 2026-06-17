# 04 — SOAR with Logic Apps & Sentinel Playbooks (Engineer Track)

> This refines the SOAR concepts for the engineer track. For the full deep dive see `../soar-logic-apps-and-playbooks-expert-guide.md`. This doc focuses on the production-engineering angle.

## 1. Quick recap

- A **playbook** = an Azure **Logic App** triggered by Sentinel (incident / alert / entity).
- **Automation rules** route incidents to playbooks and handle native actions (assign, tag, severity, close, run multiple playbooks in order).
- Prefer **managed identity** for auth; **Key Vault** for any secret.

## 2. Trigger selection (engineer cheat sheet)

- **Incident trigger** → full context, most response/enrichment playbooks. Run automatically (via automation rule) or manually.
- **Alert trigger** → per-alert enrichment before/independent of grouping.
- **Entity trigger** → analyst-initiated on a single entity (right-click).

## 3. Production design rules

1. One playbook, one job; compose via automation rules.
2. **Idempotent** — guard against duplicate side effects on re-run.
3. **Parameterize** workspace IDs, recipients, thresholds, resource IDs.
4. **Try/Catch/Finally** via `Scope` + `runAfter`.
5. **Retry policy** tuned for throttling (honor `Retry-After`, handle Graph 429).
6. **Bounded** approvals/`Until` loops with timeouts and a defined timeout path.
7. **Document** start/end in the incident comment; fail loud on error.
8. **Human-in-the-loop** for high blast-radius actions (disable user, isolate host, perimeter block).

## 4. Operational layer (often missing, interview gold)

- **Testing:** trigger playbooks against a **synthetic incident** in a test workspace; assert side effects; keep a regression set.
- **Change management:** edit in source control, not the portal; PR review; promote dev→test→prod; tag releases; keep a changelog.
- **Monitoring:** diagnostics → Log Analytics; alert on failed runs; workbook of success/failure/duration per playbook.
- **Runbook/SLA:** define which playbooks gate which incident severities, on-call ownership, and a documented **kill switch** (disable automation rule) for runaway automation.
- **Least privilege:** user-assigned managed identity with only the exact Graph/RBAC permissions; reviewed periodically.

## 5. Containment building blocks (Graph/Defender)

| Action | API |
|---|---|
| Revoke sessions | `POST /users/{id}/revokeSignInSessions` |
| Disable account | `PATCH /users/{id}` `{ accountEnabled: false }` |
| Confirm risky user | `POST /identityProtection/riskyUsers/confirmCompromised` |
| Isolate device | Defender `machineActions` / connector `isolateMachine` |
| Block IoC | Defender `tiIndicators` / connector |
| Soft-delete mail | Defender for Office / Security & Compliance search action |

## 6. Senior nuance

`revokeSignInSessions` invalidates tokens but **does not reset the password** — full account containment pairs it with a password reset, `accountEnabled=false`, and/or a Conditional Access block. State this explicitly in the playbook and the incident comment.
