// Scheduled analytics rule: failed sign-in brute force, as code.
// Deploy at the Sentinel (Log Analytics) workspace scope.

param workspaceName string
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource bruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-12-01-preview' = {
  scope: workspace
  name: guid(workspaceName, 'bruteforce-signins')
  kind: 'Scheduled'
  properties: {
    displayName: 'Brute force: excessive failed sign-ins from single IP'
    description: 'More than 20 failed Entra sign-ins for an account from one IP within 1 hour.'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
SigninLogs
| where ResultType != 0
| summarize FailedCount = count(), Accounts = make_set(UserPrincipalName, 50)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailedCount > 20
| mv-expand Accounts
| extend UserPrincipalName = tostring(Accounts)
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'Selected'
        groupByEntities: [ 'Account', 'IP' ]
      }
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [ { identifier: 'FullName', columnName: 'UserPrincipalName' } ]
      }
      {
        entityType: 'IP'
        fieldMappings: [ { identifier: 'Address', columnName: 'IPAddress' } ]
      }
    ]
  }
}
