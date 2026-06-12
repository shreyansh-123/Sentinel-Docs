# Password Reset Playbook - Flowchart

This Mermaid diagram renders natively in GitLab. To use it in diagrams.net
(draw.io), open https://app.diagrams.net/ and choose **Arrange > Insert > Advanced > Mermaid**,
then paste the diagram code below.

```mermaid
flowchart TD
    A([Incident / Alert raised in Sentinel]) --> B{Automation rule\nmatches condition?}
    B -- No --> Z([No action])
    B -- Yes --> C[Trigger playbook\nLogic App incident trigger]
    C --> D[Get affected account entities]
    D --> E{For each user}
    E --> F{Approval required?}
    F -- Yes --> G[Send approval request\nto SOC analyst]
    G --> H{Approved?}
    H -- No --> I[Add incident comment:\naction declined]
    I --> E
    H -- Yes --> J
    F -- No --> J[Reset password via Microsoft Graph\nforceChangePasswordNextSignIn]
    J --> K[Revoke active sign-in sessions\nvia Microsoft Graph]
    K --> L[Notify affected user\n+ SOC team]
    L --> M[Add comment to Sentinel incident]
    M --> E
    E -- All users processed --> N([Playbook complete])
```
