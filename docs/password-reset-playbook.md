# Microsoft Sentinel: Password Reset Playbook

> **Disclaimer:** This document is generic, best-effort guidance based on common
> Microsoft Sentinel / Azure Logic Apps practice. Verify every step, resource name,
> and RBAC role against the official Microsoft documentation before using in
> production: https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks

## Overview

A Sentinel password reset playbook automates the response to an alert/incident
(for example, a compromised-account or suspicious-sign-in detection) by forcing a
password reset and revoking active sessions for the affected user in Microsoft
Entra ID (formerly Azure AD).

Playbooks in Sentinel are built on **Azure Logic Apps**. The playbook is triggered
by a Sentinel **automation rule** (incident/alert trigger) and runs a sequence of
Logic App actions.

## Prerequisites

- An active Azure subscription.
- Microsoft Sentinel enabled on a Log Analytics workspace.
- Microsoft Entra ID (Azure AD) tenant with the target users.
- A managed identity or service principal for the Logic App to authenticate to
  Microsoft Graph.
- Microsoft Graph API permissions to reset passwords and revoke sessions.

## Roles and Permissions Required

### To build / deploy the playbook

| Task | Role (Azure RBAC / Entra ID) | Scope |
| --- | --- | --- |
| Create / edit the Logic App (playbook) | **Logic App Contributor** | Resource group |
| Attach the playbook to Sentinel & create automation rules | **Microsoft Sentinel Contributor** | Workspace / resource group |
| Grant the Logic App managed identity to Sentinel | **Microsoft Sentinel Automation Contributor** | Resource group |
| Assign roles / consent to Graph permissions | **Global Administrator** or **Privileged Role Administrator** | Entra ID tenant |

### To run the password reset action (Logic App identity / Graph)

The Logic App's managed identity (or service principal) needs Microsoft Graph
application permissions:

| Capability | Microsoft Graph permission |
| --- | --- |
| Reset user password | `User-PasswordProfile.ReadWrite.All` (or `Directory.ReadWrite.All`) |
| Revoke active sessions / sign-ins | `User.RevokeSessions.All` (or `Directory.ReadWrite.All`) |
| Read user details | `User.Read.All` |

To actually reset passwords, the identity typically also needs an Entra ID
directory role such as **Password Administrator**, **User Administrator**, or
**Authentication Administrator** (Privileged Authentication Administrator for
admin accounts).

### To operate / trigger the playbook (analysts)

| Task | Role |
| --- | --- |
| View incidents and run playbooks manually | **Microsoft Sentinel Responder** |
| Read-only investigation | **Microsoft Sentinel Reader** |

## Step-by-Step: Create the Playbook

1. **Plan the trigger.** Decide whether the playbook runs on an *incident*
   trigger (recommended, via automation rule) or an *alert* trigger.

2. **Create the Logic App (playbook):**
   - In the Azure portal go to **Microsoft Sentinel > Configuration > Automation > Create > Playbook with incident trigger**.
   - Select the subscription, resource group, region, and a playbook name
     (e.g., `PR-Reset-Compromised-User`).
   - Enable a **system-assigned managed identity** for the Logic App.

3. **Add the Sentinel trigger** (`Microsoft Sentinel incident` trigger) as the
   first step so the playbook receives the incident/entity context.

4. **Extract the user entity:**
   - Use the *Entities - Get Accounts* action to pull the affected account(s)
     from the incident.
   - Loop over the returned accounts.

5. **Add an approval step (optional but recommended):**
   - Add an *Office 365 Outlook - Send approval email* (or Teams adaptive card)
     so a SOC analyst approves before the reset is forced.

6. **Reset the password (Microsoft Graph):**
   - Add an *HTTP* action calling Microsoft Graph, e.g.
     `POST https://graph.microsoft.com/v1.0/users/{id}/authentication/methods/.../resetPassword`
     or update the user's `passwordProfile` with `forceChangePasswordNextSignIn = true`.
   - Authenticate with the Logic App managed identity.

7. **Revoke active sessions:**
   - Add an *HTTP* action calling
     `POST https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions`.

8. **Notify and document:**
   - Add a Sentinel *Add comment to incident* action recording the action taken.
   - Send a notification (email/Teams) to the affected user and the SOC.

9. **Grant permissions:**
   - In Entra ID, grant the Logic App managed identity the required Graph
     application permissions and admin-consent them.
   - Assign the appropriate directory role (e.g., Password Administrator).

10. **Connect the playbook to Sentinel:**
    - Give Sentinel permission to run the playbook (Sentinel Automation
      Contributor on the resource group).
    - Create an **automation rule** that triggers the playbook for the relevant
      analytics rule / incident condition.

11. **Test:**
    - Run the playbook manually against a test incident with a non-privileged
      test user.
    - Verify the password reset, session revocation, and incident comment.

12. **Monitor:**
    - Review Logic App run history for failures.
    - Audit actions in the Entra ID audit log.

## Flowchart

See [`password-reset-playbook-flowchart.md`](./password-reset-playbook-flowchart.md)
for a Mermaid flowchart of this playbook. GitLab renders Mermaid diagrams natively.

## References

- Automate threat response with playbooks: https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Roles and permissions in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/roles
- Microsoft Graph user resetPassword / revokeSignInSessions: https://learn.microsoft.com/graph/api/resources/users
