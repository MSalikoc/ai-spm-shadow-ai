<#
.SYNOPSIS
  Creates an app registration for AI-SPM endpoint access checks, and grants it the
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

  Requests read-only data permissions. Setup itself creates registrations, grants and credentials.

.EXAMPLE
  ./scripts/create_app_registration.ps1

.EXAMPLE
  ./scripts/create_app_registration.ps1 -AppName "AI-SPM Scanner (Prod)"

.NOTES
  Requires a role that can grant application permissions — Privileged Role Administrator,
  Global Administrator or an appropriately scoped custom role. Cloud Application
  Administrator cannot grant Microsoft Graph application roles.

  Global Reader is NOT enough. It is read-only, so it can neither create the registration
  nor consent the permissions, and the attempt fails partway through. Note that an
  `az login` token may still *list* scopes like Application.ReadWrite.All: those describe
  what the Azure CLI is allowed to ask for on your behalf, not what your directory role
  permits. If you are a Global Reader, hand this script to an admin — they run it once,
  and the values it prints are all you need afterwards.
#>
param(
  [string]$AppName = "AI-SPM Scanner"
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\permission_helpers.ps1"
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Read-only Graph application permissions. Names are resolved live against the tenant's
# own Graph service principal, so a role this tenant does not expose fails loudly
# instead of being silently skipped.
$Roles = @(
  "Application.Read.All"        # enterprise app + service principal inventory
  "Directory.Read.All"          # OAuth grants, owners, directory context
  "AuditLog.Read.All"           # sign-in activity (also needs Entra ID P1)
  "AgentIdentity.Read.All"      # agent identity inventory
  "AgentIdentityBlueprint.Read.All" # agent blueprint inventory
  "CopilotPackages.Read.All"    # Agent 365 catalogue
  "CloudApp-Discovery.Read.All" # Defender for Cloud Apps — Shadow AI web usage
  "AuditLogsQuery.Read.All"     # Purview Audit — sensitive AI interactions
)

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw "Azure CLI not found. Install it from https://aka.ms/InstallAzureCLI, then run 'az login'."
}
Invoke-Az account show -o none | Out-Null

$TenantId = Invoke-Az account show --query tenantId -o tsv
$SignedInAs = Invoke-Az account show --query user.name -o tsv
Write-Host "==> Tenant: $TenantId"
Write-Host "==> Signed in as: $SignedInAs"
Write-Host "    This needs a role that can grant application permissions (Privileged Role"
Write-Host "    Administrator, Global Administrator or appropriately scoped custom role)."
Write-Host "    Global Reader is read-only and cannot complete it."

Write-Host "==> 1/4 Creating app registration: $AppName"
$AppId = Invoke-Az ad app list --display-name $AppName --query "[0].appId" -o tsv
if ($AppId -and $AppId -ne "None") {
  Write-Host "    Already exists, reusing: $AppId"
} else {
  $AppId = Invoke-Az ad app create --display-name $AppName --sign-in-audience AzureADMyOrg `
           --query appId -o tsv
  Write-Host "    Created: $AppId"
}

# The service principal is what actually holds the app roles.
if (-not $AppId -or $AppId -eq "None") { throw "App registration returned no application ID." }
$SpObjectId = Invoke-Az ad sp list --filter "appId eq '$AppId'" --query "[0].id" -o tsv
if (-not $SpObjectId -or $SpObjectId -eq "None") {
  $SpObjectId = Invoke-Az ad sp create --id $AppId --query id -o tsv
}
if (-not $SpObjectId -or $SpObjectId -eq "None") { throw "No service principal ID returned." }

Write-Host "==> 2/4 Requesting Graph application permissions..."
$GraphSpId = Invoke-Az ad sp show --id $GraphAppId --query id -o tsv
if (-not $GraphSpId -or $GraphSpId -eq "None") { throw "Microsoft Graph service principal was not found." }
$Missing = @()
$RoleIds = @{}

foreach ($role in $Roles) {
  $roleId = Invoke-Az ad sp show --id $GraphAppId `
    --query "appRoles[?value=='$role' && isEnabled && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv
  if (-not $roleId -or $roleId -eq "None") {
    if ($role -in @("Application.Read.All", "Directory.Read.All", "AuditLog.Read.All")) {
      throw "Required Graph application role '$role' is unavailable."
    }
    $Missing += $role
    continue
  }
  $RoleIds[$role] = $roleId
}

foreach ($role in $RoleIds.Keys) {
  Invoke-Az ad app permission add --id $AppId --api $GraphAppId `
    --api-permissions "$($RoleIds[$role])=Role" -o none | Out-Null
}
Write-Host "==> 3/4 Granting admin consent..."
# `az ad app permission admin-consent` is flaky on freshly created apps; assigning the
# app role directly is the reliable equivalent and is idempotent. The body goes through a
# temp file because inline JSON quoting differs between PowerShell and cmd.
foreach ($role in $RoleIds.Keys) {
  Grant-AzGraphRole $SpObjectId $GraphSpId $RoleIds[$role]
  Write-Host "    Verified grant: $role"
}

Write-Host "==> 4/4 Creating a client secret (2 years)..."
$Secret = Invoke-Az ad app credential reset --id $AppId --append `
          --display-name "aispm-cli" --years 2 --query password -o tsv
if (-not $Secret -or $Secret -eq "None") { throw "Credential creation returned no secret." }

# Print the interpreter that will actually work here: a venv holds the dependencies when
# one exists, and Windows has no bare `python3`.
$Root = Split-Path -Parent $PSScriptRoot
if (Test-Path (Join-Path $Root ".venv\Scripts\python.exe")) { $Py = ".venv\Scripts\python.exe" }
elseif (Test-Path (Join-Path $Root ".venv/bin/python"))     { $Py = ".venv/bin/python" }
elseif (Get-Command python -ErrorAction SilentlyContinue)   { $Py = "python" }
else                                                        { $Py = "python3" }

Write-Host ""
Write-Host "============================================================"
Write-Host "Available grants verified; endpoint access and licensing still need doctor/scan checks."
Write-Host "Paste these three lines first:"
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
  # Joined into a variable first: Windows PowerShell 5.1's parser mis-reads a
  # single-quoted string nested inside $() inside a double-quoted string and dies with
  # "The string is missing the terminator". 5.1 is still the default shell on Windows.
  $MissingList = $Missing -join ", "
  Write-Host "  $MissingList"
  Write-Host "These roles were NOT GRANTED. Role availability does not establish license status."
  Write-Host "Agent 365 requires Microsoft Agent 365 licensing; MDCA also needs discovery ingestion."
}
