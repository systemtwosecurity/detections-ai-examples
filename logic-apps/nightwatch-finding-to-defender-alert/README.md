# Nightwatch finding to Microsoft Defender alert

An Azure Logic App that raises a Microsoft Defender XDR alert for each new Nightwatch finding. It subscribes to the
`nightwatch.finding.new` webhook with your detections.ai API key. It then creates the alert through the Microsoft Graph
[createAlert](https://learn.microsoft.com/en-us/graph/api/security-alert-createalert?view=graph-rest-beta) API, signed
in as the Logic App's own managed identity, so no client secret is stored.

| File                         | What it is                                                                    |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `main.bicep`                 | The Logic App, with its system-assigned managed identity turned on.           |
| `azuredeploy.json`           | The same template as ARM JSON, built from `main.bicep` with `az bicep build`. |
| `grant-graph-permission.ps1` | Grants the managed identity the Graph permission createAlert needs.           |

If you change `main.bicep`, rebuild `azuredeploy.json` with
`az bicep build --file main.bicep --outfile azuredeploy.json` before deploying it from the portal.

## Before you start

- A detections.ai API key for the Team whose findings should raise alerts. A Team Admin creates one under **Team
  settings > API Keys**.
- An Azure subscription and a resource group you can deploy to.
- Someone who can run the permission script as a **Global Administrator** or **Privileged Role Administrator** in the
  Microsoft Entra tenant that holds Defender. Granting a Microsoft Graph application permission needs one of these
  roles. If the role is eligible through Privileged Identity Management, activate it before running the script.

## 1. Deploy the Logic App

In Azure Cloud Shell, or anywhere the Azure CLI is signed in:

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file main.bicep \
  --parameters apiKey='<your detections.ai API key>' minSeverity=medium
```

Without the CLI, open **Deploy a custom template** in the Azure portal, choose **Build your own template in the
editor**, load `azuredeploy.json`, and fill in the parameters.

| Parameter       | Default                                | Meaning                                                            |
| --------------- | -------------------------------------- | ------------------------------------------------------------------ |
| `apiKey`        | required                               | The detections.ai API key. Stored as a secure workflow parameter.  |
| `minSeverity`   | `medium`                               | Only findings at this severity or higher raise an alert.           |
| `logicAppName`  | `nightwatch-finding-to-defender-alert` | Name of the Logic App.                                             |
| `alertCategory` | `Execution`                            | MITRE ATT&CK tactic recorded as the category of every alert.       |
| `apiHost`       | `detections.ai`                        | The detections.ai API host. Change it only if support tells you to |

Deploying turns the workflow on, and Logic Apps registers its webhook with detections.ai. The webhook appears under
**Team settings > Notifications > Webhooks** as `Logic App <logicAppName>`. The deployment outputs `principalId`, the
managed identity's object ID, which the next step uses.

## 2. Managed identity

The template turns on the Logic App's system-assigned managed identity, so a deployed Logic App needs nothing more here.

If you built the Logic App by hand instead, turn it on yourself:

1. Open the Logic App in the Azure portal.
2. Go to **Settings > Identity > System assigned**.
3. Set **Status** to **On** and select **Save**.
4. Copy the **Object (principal) ID** for the next step.

The HTTP action that calls Graph must use **Authentication type: Managed identity**, **System-assigned managed
identity**, audience `https://graph.microsoft.com`.

## 3. Grant the Graph permission

createAlert needs the Microsoft Graph application permission `SecurityAlert.Create.All`. A managed identity has no **API
permissions** page in the portal, and the Azure CLI's sign-in cannot request the scope this grant needs, so grant it
with Microsoft Graph PowerShell:

1. Open [Azure Cloud Shell](https://shell.azure.com) and choose **PowerShell**.
2. Upload `grant-graph-permission.ps1` with **Manage files > Upload**.
3. Run it with the Logic App's resource group and name:

   ```powershell
   ./grant-graph-permission.ps1 -ResourceGroupName <your-resource-group> -LogicAppName nightwatch-finding-to-defender-alert
   ```

   Or pass the object ID from step 1 or 2:

   ```powershell
   ./grant-graph-permission.ps1 -PrincipalId <principalId>
   ```

4. Sign in when `Connect-MgGraph` asks, with the administrator account, and consent to `Application.Read.All` and
   `AppRoleAssignment.ReadWrite.All`.

The script does nothing if the permission is already there. Without the script, the same grant is these commands:

```powershell
Connect-MgGraph -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'
$principalId = '<principalId>'
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$appRole = $graph.AppRoles | Where-Object { $_.Value -eq 'SecurityAlert.Create.All' -and $_.AllowedMemberTypes -contains 'Application' }
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -PrincipalId $principalId -ResourceId $graph.Id -AppRoleId $appRole.Id
```

`SecurityAlert.ReadWrite.All` also works, but it can read and change every alert in the tenant, and this workflow only
creates them.

Azure caches a managed identity's token for up to 24 hours. If a run asked for a token before you granted the
permission, its later runs can still get 403 from Graph until that token expires.

## 4. Test it

1. In detections.ai, open **Team settings > Notifications > Webhooks**, find `Logic App <logicAppName>`, and select
   **Send test**. The test is built from your Team's newest published finding.
2. In the Logic App's **Run history**, open the new run. **Create_Defender_alert** should show status 201.
3. In the [Microsoft Defender portal](https://security.microsoft.com), open **Incidents & alerts > Alerts**. The alert's
   title starts with `[Test]`.

A test event raises a real Defender alert. Resolve it when you are done.

## How a finding maps to the alert

| Alert field          | From the finding                                                              |
| -------------------- | ----------------------------------------------------------------------------- |
| `title`              | `title`, with `[Test] ` in front for a test event                             |
| `description`        | `summary`, the `finding_id`, the host and account counts, and the report link |
| `severity`           | `critical` and `high` become `high`; `medium` and `low` keep their value      |
| `recommendedActions` | The first 10 `calls_to_action` titles, one per line                           |
| `entityDefinitions`  | The first 10 hosts as impacted `device`s, the first 10 accounts as `user`s    |
| `category`           | The `alertCategory` parameter                                                 |

Notes:

- Accounts go in with the identifier `userPrincipalName`. Nightwatch reports an account the way the logs named it, which
  can be `DOMAIN\name` or a bare name rather than a UPN. If Graph rejects a value, the run fails and no alert is raised:
  check **Run history** after the first real findings arrive.
- The webhook carries the first 10 hosts, accounts and calls to action. The description gives the full host and account
  counts, and the report link shows the rest.
- If Graph times out or returns a server error, Logic Apps retries the call, which can raise the same alert twice. Set
  `retryPolicy` to `none` on `Create_Defender_alert` if you prefer a missed alert to a duplicate.
- Alerts are created with `isExcludedFromCorrelation: true`, so Defender does not correlate them with other alerts. Set
  it to `false` in `main.bicep` to let Defender group them with related alerts into incidents.
- createAlert is a Microsoft Graph beta API. Microsoft can change beta APIs, and does not support them for production
  use.
- To mark the finding back in detections.ai from the same workflow, call
  `POST https://detections.ai/api/v1-beta/nightwatch/findings/{finding_id}/mark` with the `X-API-Key` header. See the
  [API guide](https://detections.ai/api/v1-beta/docs).

## Remove it

Delete the Logic App. Logic Apps unsubscribes the webhook when the workflow is deleted or disabled. If the webhook is
still listed under **Team settings > Notifications > Webhooks**, delete it there.
