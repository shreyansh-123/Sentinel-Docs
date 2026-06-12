# Microsoft Sentinel: Password Reset Playbook

> **Disclaimer:** This is best-effort guidance based on common Microsoft Sentinel /
> Azure Logic Apps practice. Microsoft occasionally changes portal navigation, role
> names, and API details. Validate every step in a test tenant against the official
> docs before production use:
> https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks

## 1. What this playbook does

When Sentinel raises an incident for a compromised or suspicious account, this
playbook automatically:

1. Reads the affected user from the incident.
2. (Optionally) asks a SOC analyst to approve.
3. Forces a password reset in Microsoft Entra ID (Azure AD).
4. Revokes the user's active sign-in sessions.
5. Notifies the user and the SOC, and logs the action on the incident.

Playbooks run on **Azure Logic Apps** and are triggered by a Sentinel
**automation rule**.

## 2. Prerequisites (checklist)

- [ ] Active Azure subscription.
- [ ] Microsoft Sentinel enabled on a Log Analytics workspace.
- [ ] Microsoft Entra ID tenant with the target users.
- [ ] Permission to create resources and assign roles (see section 4).

## 3. Roles and permissions required

### People building / running the playbook

| Who / what | Role | Scope |
| --- | --- | --- |
| Person creating the Logic App | **Logic App Contributor** | Resource group |
| Person wiring it into Sentinel | **Microsoft Sentinel Contributor** | Workspace |
| Letting Sentinel run the playbook | **Microsoft Sentinel Automation Contributor** | Resource group |
| Person assigning Graph permissions | **Global Administrator** or **Privileged Role Administrator** | Tenant |
| Analysts running it manually | **Microsoft Sentinel Responder** | Workspace |

### The playbook's identity (managed identity) needs Microsoft Graph permissions

| Capability | Microsoft Graph application permission |
| --- | --- |
| Reset user password | `User-PasswordProfile.ReadWrite.All` |
| Revoke sessions | `User.RevokeSessions.All` |
| Read user details | `User.Read.All` |

It usually also needs an Entra ID directory role such as **Password
Administrator** or **User Administrator** (Privileged Authentication
Administrator to reset admin accounts).

## 4. Create the managed identity

A **managed identity** lets the playbook authenticate to Microsoft Graph without
storing any secret. The simplest option is a **system-assigned managed identity**
on the Logic App itself (created in step 5). If you prefer, you can create a
**user-assigned managed identity** first:

### Option A - System-assigned (recommended, easiest)

You enable this when you create the Logic App (see step 5.4). Nothing to do here.

### Option B - User-assigned managed identity

**Portal:**
1. Go to **Azure portal > Managed Identities > Create**.
2. Pick the subscription, resource group, region, and a name
   (e.g., `mi-sentinel-password-reset`).
3. Click **Review + create > Create**.

**Azure CLI:**
```bash
az identity create \
  --name mi-sentinel-password-reset \
  --resource-group rg-sentinel \
  --location eastus
```
Note the returned `principalId` (the object ID) and `clientId` - you need them to
assign permissions.

## 5. Create the playbook (Logic App), step by step

1. In the Azure portal, open **Microsoft Sentinel** and select your workspace.
2. Go to **Configuration > Automation**.
3. Click **Create > Playbook with incident trigger**.
4. On the **Basics** tab: choose subscription, resource group, region, and a
   name (e.g., `pb-password-reset`). On the next tab enable **System-assigned
   managed identity** (or attach your user-assigned one). Click
   **Review + create > Create**.
5. The Logic App opens in the **Logic App Designer**. Build the steps below.

### 5.1 Trigger
The **Microsoft Sentinel incident** trigger is already the first step. It gives
the playbook the incident and its entities.

### 5.2 Get the affected user
- Click **+ New step > Microsoft Sentinel > Entities - Get Accounts**.
- In **Entities list**, select the dynamic field `Entities` from the trigger.
- Add a **For each** loop over the returned accounts (the designer adds this
  automatically when you reference an account property).

### 5.3 (Optional) Approval step
- Inside the loop, add **+ New step > Office 365 Outlook > Send approval email**
  (or a Teams adaptive card).
- Add a **Condition**: continue only if the response equals **Approve**.

### 5.4 Reset the password (HTTP call to Microsoft Graph)
Inside the loop (or the approved branch), add **+ New step > HTTP** with:

- **Method:** `PATCH`
- **URI:** `https://graph.microsoft.com/v1.0/users/<userId>`
  (use the account's object ID / UPN dynamic value instead of `<userId>`)
- **Headers:** `Content-Type: application/json`
- **Body:**
```json
{
  "passwordProfile": {
    "forceChangePasswordNextSignIn": true,
    "password": "<generate-a-strong-temporary-password>"
  }
}
```
- **Authentication:** choose **Managed identity**, audience
  `https://graph.microsoft.com`.

### 5.5 Revoke active sessions
Add another **HTTP** step:
- **Method:** `POST`
- **URI:** `https://graph.microsoft.com/v1.0/users/<userId>/revokeSignInSessions`
- **Authentication:** **Managed identity**, audience `https://graph.microsoft.com`.

### 5.6 Notify and log
- Add **Microsoft Sentinel > Add comment to incident** describing the action.
- Add an email/Teams notification to the user and SOC.

Click **Save**.

## 6. Assign Microsoft Graph permissions to the managed identity

Graph **application** permissions cannot be granted in the portal UI for managed
identities - you assign them with PowerShell (or Graph). Get the managed
identity's **object ID** (principalId) first.

### PowerShell (Microsoft Graph module)
```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

# Object ID of your playbook's managed identity
$managedIdentityId = "<principalId-of-managed-identity>"

# Microsoft Graph service principal in your tenant
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Permissions to grant
$permissions = @(
  "User-PasswordProfile.ReadWrite.All",
  "User.RevokeSessions.All",
  "User.Read.All"
)

foreach ($p in $permissions) {
  $appRole = $graph.AppRoles | Where-Object { $_.Value -eq $p -and $_.AllowedMemberTypes -contains "Application" }
  New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $managedIdentityId `
    -PrincipalId $managedIdentityId `
    -ResourceId $graph.Id `
    -AppRoleId $appRole.Id
}
```

### Assign the directory role (so it can actually reset passwords)
```powershell
# Example: Password Administrator (roleTemplateId 966707d0-3269-4727-9be2-8c3a10f19b9d)
$role = Get-MgDirectoryRole -Filter "displayName eq 'Password Administrator'"
if (-not $role) {
  $template = Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Password Administrator'"
  $role = New-MgDirectoryRole -RoleTemplateId $template.Id
}
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id `
  -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$managedIdentityId"
```

After assignment, allow a few minutes for replication.

## 7. Connect the playbook to Sentinel

1. Ensure Sentinel can run playbooks: assign **Microsoft Sentinel Automation
   Contributor** on the resource group.
2. In Sentinel go to **Configuration > Automation > Create > Automation rule**.
3. Set the trigger (e.g., *When incident is created*) and conditions (e.g.,
   analytics rule name = your compromised-account rule).
4. Under **Actions**, choose **Run playbook** and select `pb-password-reset`.
5. Save.

## 8. Test

1. Use a dedicated **test user** (never an admin).
2. In Sentinel, open a test incident and run the playbook manually
   (**Incident > Actions > Run playbook**).
3. Confirm: password reset worked, sessions were revoked, and the incident has a
   comment.
4. Check the Logic App **Run history** for errors.

## 9. Operate and monitor

- Review Logic App run history regularly.
- Audit every reset in the Entra ID **Audit log**.
- Keep an **exclusion list** of admin / break-glass / service accounts.

## Challenges and Considerations

Key challenges to plan for when building and operating this playbook:

- **Privileged permissions risk.** The Logic App identity needs powerful Graph
  permissions (password reset, session revocation). If compromised, it becomes a
  high-value target. Use least privilege, scope tightly, and monitor its usage.
- **Resetting privileged / admin accounts.** Standard roles cannot reset
  passwords for admins. Resetting an admin requires Privileged Authentication
  Administrator, and automating this is risky. Consider excluding admin accounts
  or routing them to manual handling.
- **False positives.** Automatically resetting passwords on a false-positive
  alert disrupts legitimate users. An approval step (human-in-the-loop) is
  strongly recommended before forcing resets.
- **Account lockout / business disruption.** Forced resets plus session
  revocation can lock users out mid-work, including service or break-glass
  accounts. Maintain an exclusion list for critical accounts.
- **Entity resolution.** The incident may not cleanly map to a single Entra ID
  user (UPN vs. SID vs. display name mismatches). Handle missing or ambiguous
  account entities gracefully.
- **Authentication & token expiry.** Managed identity tokens, admin consent, and
  Graph permission changes can break the playbook silently. Build error handling
  and alert on Logic App run failures.
- **API throttling & limits.** Microsoft Graph enforces rate limits; bulk
  incidents can trigger throttling. Add retry/backoff logic.
- **Communicating the new password.** Securely delivering a temporary password or
  reset link to the (possibly compromised) user is non-trivial. Prefer
  self-service reset flows or out-of-band channels.
- **Auditability & compliance.** Every automated reset must be logged for audit
  and compliance. Ensure incident comments and Entra ID audit logs capture who/
  what/when.
- **Testing safely.** Testing against real users is dangerous. Use dedicated test
  accounts and a non-production tenant where possible.
- **Cost.** Logic Apps bill per action/execution; high incident volume increases
  cost.

## Flowchart

See [`password-reset-playbook-flowchart.md`](./password-reset-playbook-flowchart.md)
for a Mermaid flowchart of this playbook. GitLab renders Mermaid diagrams natively.

## References

- Automate threat response with playbooks: https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Roles and permissions in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/roles
- Assign Graph permissions to a managed identity: https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-assign-app-role-managed-identity
- Microsoft Graph user resource (passwordProfile, revokeSignInSessions): https://learn.microsoft.com/graph/api/resources/users
