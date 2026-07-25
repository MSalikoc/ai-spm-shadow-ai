<#
.SYNOPSIS
  AI-SPM Managed Identity'sine gereken Microsoft Graph *application* rollerini atar.
  Bu adım ARM/portal ile yapılamaz — deploy sonrası bir kez çalıştırılır.

.EXAMPLE
  ./grant_graph_roles.ps1 -ManagedIdentityObjectId <PRINCIPAL_ID>

  PrincipalId, ARM deployment çıktısındaki "managedIdentityPrincipalId" değeridir.
  Ayrıca: az functionapp identity show -g <RG> -n <FUNC> --query principalId -o tsv

.NOTES
  Gerekli: Microsoft.Graph PowerShell modülü + rol atayabilen bir yönetici
  (Privileged Role Administrator / Global Administrator).
#>
param(
  [Parameter(Mandatory = $true)][string]$ManagedIdentityObjectId
)

$ErrorActionPreference = "Stop"
$GraphAppId = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph
$Roles = @("Directory.Read.All", "Application.Read.All", "AuditLog.Read.All")

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All" | Out-Null

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
Write-Host "Microsoft Graph SP: $($graphSp.Id)"

foreach ($role in $Roles) {
  $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $role -and $_.AllowedMemberTypes -contains "Application" }
  if (-not $appRole) { Write-Warning "'$role' bulunamadı, atlanıyor."; continue }

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
