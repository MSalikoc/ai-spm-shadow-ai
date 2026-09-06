<#
.SYNOPSIS
  Grants and verifies read-only Microsoft AI Data Sources application permissions.
.EXAMPLE
  ./grant_connector_roles.ps1 -ManagedIdentityObjectId <PRINCIPAL_ID>
.NOTES
  Requires Microsoft.Graph PowerShell and Privileged Role Administrator /
  Global Administrator or an appropriately scoped custom role.
  Cloud Application Administrator cannot grant Microsoft Graph application roles.
  Missing optional roles are NOT granted; role availability does not prove licensing.
  Agent 365 requires Microsoft Agent 365 licensing. MDCA requires ingested discovery data.
#>
param([Parameter(Mandatory = $true)][string]$ManagedIdentityObjectId)
$ErrorActionPreference = "Stop"
. "$PSScriptRoot\permission_helpers.ps1"
# Sponsor listing currently documents a write permission; never auto-grant it.
Grant-MgGraphRoles -PrincipalId $ManagedIdentityObjectId `
  -RequiredRoles @("Application.Read.All", "Directory.Read.All") `
  -OptionalRoles @("AgentIdentity.Read.All", "AgentIdentityBlueprint.Read.All", `
    "CopilotPackages.Read.All", "CloudApp-Discovery.Read.All", "AuditLogsQuery.Read.All")
