<#
.SYNOPSIS
  Grants and verifies the managed identity's core Microsoft Graph application roles.
.EXAMPLE
  ./grant_graph_roles.ps1 -ManagedIdentityObjectId <PRINCIPAL_ID>
.NOTES
  Requires Microsoft.Graph PowerShell and Privileged Role Administrator /
  Global Administrator or an appropriately scoped custom role.
  Cloud Application Administrator cannot grant Microsoft Graph application roles.
#>
param([Parameter(Mandatory = $true)][string]$ManagedIdentityObjectId)
$ErrorActionPreference = "Stop"
. "$PSScriptRoot\permission_helpers.ps1"
# Mail.Send is for the optional weekly digest; restrict its mailbox access in Exchange.
Grant-MgGraphRoles -PrincipalId $ManagedIdentityObjectId `
  -RequiredRoles @("Directory.Read.All", "Application.Read.All", "AuditLog.Read.All", "Mail.Send") `
  -OptionalRoles @()
