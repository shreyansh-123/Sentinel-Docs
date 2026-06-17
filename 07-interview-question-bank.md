# 06 — Deployable Examples

Production-style, parameterized examples you can adapt and deploy via pipeline.

## Contents
- `revoke-sessions-playbook.logicapp.json` — Logic App (Consumption) workflow definition for the manual user-session-revoke playbook: revoke sessions via Graph (managed identity), email the SOC team, and add a Sentinel incident comment, with try/catch.
- `analytics-rule-bruteforce.bicep` — a scheduled analytics rule (brute-force sign-ins) as code, with entity mapping and MITRE tagging.

> Replace placeholder values (`<...>`), connection resource IDs, and recipients with your environment's parameters. Authorize the managed identity and grant least-privilege Graph permission (`User.RevokeSessions.All`) and Sentinel Responder before use.
