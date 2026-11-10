@description('Name of the Logic App.')
param logicAppName string = 'nightwatch-finding-to-defender-alert'

@description('Azure region for the Logic App.')
param location string = resourceGroup().location

@description('detections.ai API host.')
param apiHost string = 'detections.ai'

@secure()
@description('A detections.ai API key for the Team whose findings raise alerts.')
param apiKey string

@description('Only findings at this severity or higher raise an alert.')
@allowed([
  'critical'
  'high'
  'medium'
  'low'
])
param minSeverity string = 'medium'

@description('MITRE ATT&CK tactic recorded as the alert category.')
param alertCategory string = 'Execution'

var apiBase = 'https://${apiHost}/api/v1-beta'
var newline = 'decodeUriComponent(\'%0A\')'

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    parameters: {
      apiKey: {
        value: apiKey
      }
    }
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        apiKey: {
          type: 'SecureString'
        }
      }
      triggers: {
        When_a_new_Nightwatch_finding_is_published: {
          type: 'HttpWebhook'
          inputs: {
            subscribe: {
              method: 'POST'
              uri: '${apiBase}/webhooks/event-types/nightwatch.finding.new/subscribe'
              headers: {
                'X-API-Key': '@parameters(\'apiKey\')'
              }
              body: {
                url: '@{listCallbackUrl()}'
                name: 'Logic App ${logicAppName}'
                min_severity: minSeverity
              }
            }
            // The unsubscribe call cannot read the subscribe response, so it deletes by callback URL.
            unsubscribe: {
              method: 'POST'
              uri: '${apiBase}/webhooks/unsubscribe'
              headers: {
                'X-API-Key': '@parameters(\'apiKey\')'
              }
              body: {
                url: '@{listCallbackUrl()}'
              }
            }
          }
        }
      }
      actions: {
        Map_severity: {
          type: 'Compose'
          runAfter: {}
          inputs: '@if(or(equals(triggerBody()?[\'severity\'], \'critical\'), equals(triggerBody()?[\'severity\'], \'high\')), \'high\', if(equals(triggerBody()?[\'severity\'], \'medium\'), \'medium\', if(equals(triggerBody()?[\'severity\'], \'low\'), \'low\', \'unknown\')))'
        }
        Map_hosts: {
          type: 'Select'
          runAfter: {}
          inputs: {
            from: '@coalesce(triggerBody()?[\'hosts\'], json(\'[]\'))'
            select: {
              entityType: 'device'
              entityIdentifier: 'deviceName'
              identifierValue: '@item()'
              role: 'impacted'
            }
          }
        }
        Map_accounts: {
          type: 'Select'
          runAfter: {}
          inputs: {
            from: '@coalesce(triggerBody()?[\'accounts\'], json(\'[]\'))'
            select: {
              entityType: 'user'
              entityIdentifier: 'userPrincipalName'
              identifierValue: '@item()'
              role: 'impacted'
            }
          }
        }
        Map_calls_to_action: {
          type: 'Select'
          runAfter: {}
          inputs: {
            from: '@coalesce(triggerBody()?[\'calls_to_action\'], json(\'[]\'))'
            select: '@item()?[\'title\']'
          }
        }
        Map_report_urls: {
          type: 'Select'
          runAfter: {}
          inputs: {
            from: '@coalesce(triggerBody()?[\'reports\'], json(\'[]\'))'
            select: '@item()?[\'url\']'
          }
        }
        // Expression functions evaluate every argument, so an if() guarding reports[0] would still fail on an empty list.
        Report_url: {
          type: 'Compose'
          runAfter: {
            Map_report_urls: [
              'Succeeded'
            ]
          }
          inputs: '@{join(take(body(\'Map_report_urls\'), 1), \'\')}'
        }
        Create_Defender_alert: {
          type: 'Http'
          runAfter: {
            Map_severity: [
              'Succeeded'
            ]
            Map_hosts: [
              'Succeeded'
            ]
            Map_accounts: [
              'Succeeded'
            ]
            Map_calls_to_action: [
              'Succeeded'
            ]
            Report_url: [
              'Succeeded'
            ]
          }
          inputs: {
            method: 'POST'
            uri: 'https://graph.microsoft.com/beta/security/alerts_v2/createAlert'
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://graph.microsoft.com'
            }
            body: {
              createAlertInput: {
                title: '@{if(equals(triggerBody()?[\'test\'], true), \'[Test] \', \'\')}@{if(empty(triggerBody()?[\'title\']), \'detections.ai Nightwatch finding\', triggerBody()?[\'title\'])}'
                description: '@{concat(if(empty(triggerBody()?[\'summary\']), \'detections.ai Nightwatch finding.\', triggerBody()?[\'summary\']), ${newline}, ${newline}, \'Finding ID: \', coalesce(triggerBody()?[\'finding_id\'], \'none\'), ${newline}, \'Affected hosts: \', string(coalesce(triggerBody()?[\'hosts_count\'], 0)), \', accounts: \', string(coalesce(triggerBody()?[\'accounts_count\'], 0)), if(empty(outputs(\'Report_url\')), \'\', concat(${newline}, \'Report: \', outputs(\'Report_url\'))))}'
                severity: '@{outputs(\'Map_severity\')}'
                category: alertCategory
                recommendedActions: '@{join(body(\'Map_calls_to_action\'), ${newline})}'
                entityDefinitions: '@union(body(\'Map_accounts\'), body(\'Map_hosts\'))'
                mitreTechniques: []
                isExcludedFromCorrelation: true
              }
            }
          }
        }
      }
      outputs: {}
    }
  }
}

@description('Object (principal) ID of the Logic App\'s managed identity. Pass it to grant-graph-permission.ps1.')
output principalId string = workflow.identity.principalId

output logicAppName string = workflow.name
