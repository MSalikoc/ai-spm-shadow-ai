<#
.SYNOPSIS
  Creates an app registration that can read EVERY AI-SPM data source, and grants it the
  Graph APPLICATION permissions. PowerShell twin of create_app_registration.sh.

.DESCRIPTION
  An `az login` sign-in produces a DELEGATED token, which can only carry Graph scopes the
  Azure CLI application itself is authorized for. That covers directory reads — so Entra
  discovery works — but never CloudApp-Discovery.Read.All, AuditLogsQuery.Read.All or
  CopilotPackages.Read.All. No directory role fixes that, because the limit is on the
  client application. Application permissions on your own registration do fix it, and
  need no Azure resources.

  Uses the Azure CLI rather than the Microsoft.Graph module, so there is nothing extra to
  install: if you can run `az login`, you can run this.

  100% read-only permissions. Nothing here can change your tenant.

.EXAMPLE
  ./scripts/create_app_registration.ps1

.EXAMPLE
  ./scripts/create_app_registration.ps1 -AppName "AI-SPM Scanner (Prod)"

.NOTES
  Requires a role that can grant application permissions — Privileged Role Administrator
  or Global Administrator — the same requirement postdeploy.sh has.
#>
param(
  [string]$AppName = "AI-SPM Scanner"
)

$ErrorActionPreference = "Stop"
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Read-only Graph application permissions. Names are resolved live against the tenant's
# own Graph service principal, so a role this tenant does not expose fails loudly
# instead of being silently skipped.
$Roles = @(
  "Application.Read.All"        # enterprise app + service principal inventory
  "Directory.Read.All"          # OAuth grants, owners, directory context
  "AuditLog.Read.All"           # sign-in activity (also needs Entra ID P1)
  "CopilotPackages.Read.All"    # Agent 365 catalogue
  "CloudApp-Discovery.Read.All" # Defender for Cloud Apps — Shadow AI web usage
  "AuditLogsQuery.Read.All"     # Purview Audit — sensitive AI interactions
)

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw "Azure CLI not found. Install it from https://aka.ms/InstallAzureCLI, then run 'az login'."
}
try { az account show -o none 2>$null } catch { throw "Run 'az login' first." }
if ($LASTEXITCODE -ne 0) { throw "Run 'az login' first." }

$TenantId = az account show --query tenantId -o tsv
Write-Host "==> Tenant: $TenantId"

Write-Host "==> 1/4 Creating app registration: $AppName"
$AppId = az ad app list --display-name $AppName --query "[0].appId" -o tsv 2>$null
if ($AppId -and $AppId -ne "None") {
  Write-Host "    Already exists, reusing: $AppId"
} else {
  $AppId = az ad app create --display-name $AppName --sign-in-audience AzureADMyOrg `
           --query appId -o tsv
  Write-Host "    Created: $AppId"
}

# The service principal is what actually holds the app roles.
az ad sp show --id $AppId -o none 2>$null
if ($LASTEXITCODE -ne 0) { az ad sp create --id $AppId -o none }
Start-Sleep -Seconds 5   # directory replication

Write-Host "==> 2/4 Requesting Graph application permissions..."
$GraphSpId = az ad sp show --id $GraphAppId --query id -o tsv
$SpObjectId = az ad sp show --id $AppId --query id -o tsv
$Missing = @()
$RoleIds = @{}

foreach ($role in $Roles) {
  $roleId = az ad sp show --id $GraphAppId `
    --query "appRoles[?value=='$role' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv
  if (-not $roleId -or $roleId -eq "None") {
    # A role this tenant's Graph does not expose (preview or licence gated). Reported
    # rather than pretended to be granted.
    $Missing += $role
    continue
  }
  $RoleIds[$role] = $roleId
  az ad app permission add --id $AppId --api $GraphAppId --api-permissions "$roleId=Role" -o none 2>$null
  Write-Host "    + $role"
}

Write-Host "==> 3/4 Granting admin consent..."
# `az ad app permission admin-consent` is flaky on freshly created apps; assigning the
# app role directly is the reliable equivalent and is idempotent. The body goes through a
# temp file because inline JSON quoting differs between PowerShell and cmd.
foreach ($role in $RoleIds.Keys) {
  $body = @{ principalId = $SpObjectId; resourceId = $GraphSpId; appRoleId = $RoleIds[$role] } |
          ConvertTo-Json -Compress
  $tmp = New-TemporaryFile
  Set-Content -Path $tmp -Value $body -Encoding utf8
  az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/appRoleAssignments" `
    --headers "Content-Type=application/json" --body "@$tmp" -o none 2>$null
  Remove-Item $tmp -Force
}

Write-Host "==> 4/4 Creating a client secret (2 years)..."
$Secret = az ad app credential reset --id $AppId --append `
          --display-name "aispm-cli" --years 2 --query password -o tsv

# Print the interpreter that will actually work here: a venv holds the dependencies when
# one exists, and Windows has no bare `python3`.
$Root = Split-Path -Parent $PSScriptRoot
if (Test-Path (Join-Path $Root ".venv\Scripts\python.exe")) { $Py = ".venv\Scripts\python.exe" }
elseif (Test-Path (Join-Path $Root ".venv/bin/python"))     { $Py = ".venv/bin/python" }
elseif (Get-Command python -ErrorAction SilentlyContinue)   { $Py = "python" }
else                                                        { $Py = "python3" }

Write-Host ""
Write-Host "============================================================"
Write-Host "Ready. Paste these three lines first:"
Write-Host ""
Write-Host "`$env:AISPM_TENANT_ID = `"$TenantId`""
Write-Host "`$env:AISPM_CLIENT_ID = `"$AppId`""
Write-Host "`$env:AISPM_CLIENT_SECRET = `"$Secret`""
Write-Host ""
Write-Host "Then, in order:"
Write-Host ""
Write-Host "  $Py aispm.py doctor --auth app"
Write-Host "  $Py aispm.py scan  --auth app --scope consented --open"
Write-Host ""
Write-Host "Save the secret in a password manager now — Azure will not show it again."
Write-Host "The env vars last for this PowerShell session only."
Write-Host "Role assignment can take 1-2 minutes to propagate; a 403 right away is normal."
Write-Host ""
Write-Host "To roll the secret later:"
Write-Host "  az ad app credential reset --id `"$AppId`" --append --display-name aispm-cli --years 2"
Write-Host "============================================================"

if ($Missing.Count -gt 0) {
  Write-Host ""
  Write-Host "NOTE: these permissions were not found in your tenant's Graph and were skipped:"
  Write-Host "  $($Missing -join ', ')"
  Write-Host "That usually means the Microsoft feature is not provisioned at all (no"
  Write-Host "Microsoft 365 Copilot licence hides CopilotPackages.Read.All, for example)."
  Write-Host "doctor will report them as NOT_AVAILABLE — it never fabricates."
}
