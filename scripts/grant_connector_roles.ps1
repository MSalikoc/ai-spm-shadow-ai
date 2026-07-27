<#
.SYNOPSIS
  Managed Identity'ye Microsoft AI Data Sources connector'ları (Agent 365, Entra Agent ID,
  Defender for Cloud Apps, Purview Audit) için gereken Graph *application* rollerini atar.

  Bu, temel AI-SPM deploy'unun bir PARÇASI DEĞİL — grant_graph_roles.ps1'i (temel scan)
  DEĞİŞTİRMEZ; opsiyonel, idempotent bir ek script'tir.

.EXAMPLE
  ./grant_connector_roles.ps1 -ManagedIdentityObjectId <PRINCIPAL_ID>

.NOTES
  Gerekli: Microsoft.Graph PowerShell modülü + rol atayabilen bir yönetici
  (Privileged Role Administrator / Global Administrator).
#>
param(
  [Parameter(Mandatory = $true)][string]$ManagedIdentityObjectId
)

$ErrorActionPreference = "Stop"
$GraphAppId = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph
$Roles = @(
  "CopilotPackages.Read.All",        # Agent 365
  "Application.Read.All",            # Entra Agent ID
  "Directory.Read.All",              # Entra Agent ID (owner/sponsor/grup)
  "CloudApp-Discovery.Read.All",     # Defender for Cloud Apps (PREVIEW)
  "AuditLogsQuery.Read.All"          # Purview Audit
)

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All" | Out-Null

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
Write-Host "Microsoft Graph SP: $($graphSp.Id)"

foreach ($role in $Roles) {
  $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $role -and $_.AllowedMemberTypes -contains "Application" }
  if (-not $appRole) {
    Write-Warning "'$role' bu tenant'ta bulunamadı (lisans/preview eksik olabilir), atlanıyor."
    continue
  }
  try {
    New-MgServicePrincipalAppRoleAssignment `
      -ServicePrincipalId $ManagedIdentityObjectId `
      -PrincipalId $ManagedIdentityObjectId `
      -ResourceId $graphSp.Id `
      -AppRoleId $appRole.Id | Out-Null
    Write-Host "  ✓ $role atandı"
  } catch {
    Write-Host "  ($role zaten atanmış olabilir)"
  }
}

Write-Host "Bitti. Rol atamalarının yayılması birkaç dakika sürebilir."
Write-Host "Not: 'CloudApp-Discovery.Read.All' PREVIEW — Defender for Cloud Apps lisansı yoksa"
Write-Host "bu connector LICENSE_MISSING/PERMISSION_MISSING gösterir (dürüstçe, uydurma yok)."
