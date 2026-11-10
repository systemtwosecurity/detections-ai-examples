<#
.SYNOPSIS
Grants a Logic App's managed identity the Microsoft Graph application permission it needs to create Defender alerts.

.DESCRIPTION
Run in Azure Cloud Shell (PowerShell), signed in as a Global Administrator or Privileged Role Administrator.
Running it again is safe: it does nothing when the permission is already granted.

.EXAMPLE
./grant-graph-permission.ps1 -ResourceGroupName my-rg -LogicAppName nightwatch-finding-to-defender-alert

.EXAMPLE
./grant-graph-permission.ps1 -PrincipalId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string] $ResourceGroupName,

    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string] $LogicAppName,

    [Parameter(Mandatory, ParameterSetName = 'ById')]
    [string] $PrincipalId,

    [string] $Permission = 'SecurityAlert.Create.All'
)

$ErrorActionPreference = 'Stop'
$microsoftGraphAppId = '00000003-0000-0000-c000-000000000000'

if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    $logicApp = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Logic/workflows' -Name $LogicAppName
    if (-not $logicApp) {
        $subscription = (Get-AzContext).Subscription.Name
        throw "No Logic App '$LogicAppName' in resource group '$ResourceGroupName' of subscription '$subscription'. Check the names, or switch subscription with Set-AzContext."
    }
    $PrincipalId = $logicApp.Identity.PrincipalId
    if (-not $PrincipalId) {
        throw "Logic App '$LogicAppName' has no system-assigned managed identity. Turn it on under Settings > Identity, then run this script again."
    }
}

# The Microsoft Graph cmdlets ignore $ErrorActionPreference, so each call below sets -ErrorAction Stop itself.
Connect-MgGraph -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome -ErrorAction Stop

$graph = Get-MgServicePrincipal -Filter "appId eq '$microsoftGraphAppId'" -ErrorAction Stop
if (-not $graph) {
    throw "Could not read the Microsoft Graph service principal. Check that your Global Administrator or Privileged Role Administrator role is active."
}
$appRole = $graph.AppRoles | Where-Object { $_.Value -eq $Permission -and $_.AllowedMemberTypes -contains 'Application' }
if (-not $appRole) {
    throw "Microsoft Graph has no application permission named '$Permission'."
}

$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All -ErrorAction Stop |
    Where-Object { $_.ResourceId -eq $graph.Id -and $_.AppRoleId -eq $appRole.Id }
if ($existing) {
    Write-Host "Managed identity $PrincipalId already has Microsoft Graph $Permission."
    return
}

$assignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -PrincipalId $PrincipalId -ResourceId $graph.Id -AppRoleId $appRole.Id -ErrorAction Stop
if (-not $assignment) {
    throw "Microsoft Graph did not grant $Permission. Check that your Global Administrator or Privileged Role Administrator role is active."
}
Write-Host "Granted Microsoft Graph $Permission to managed identity $PrincipalId."
