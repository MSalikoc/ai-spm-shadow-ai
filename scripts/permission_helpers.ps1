$ErrorActionPreference = "Stop"

function Invoke-Az {
  $output = & az @args
  if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI failed (exit $LASTEXITCODE). No successful setup is reported."
  }
  return $output
}

function Get-AzGraphAssignments([string]$PrincipalId) {
  $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments"
  while ($uri) {
    $page = Invoke-Az rest --method GET --uri $uri -o json | ConvertFrom-Json
    $page.value
    $uri = $page.'@odata.nextLink'
  }
}

function Grant-AzGraphRole([string]$PrincipalId, [string]$ResourceId, [string]$RoleId) {
  $existing = @(Get-AzGraphAssignments $PrincipalId)
  if ($existing | Where-Object { $_.resourceId -eq $ResourceId -and $_.appRoleId -eq $RoleId }) {
    return
  }
  # Use a project-local file to avoid platform-specific native JSON quoting.
  $bodyPath = Join-Path (Get-Location) (".aispm-role-" + [guid]::NewGuid() + ".json")
  try {
    @{ principalId = $PrincipalId; resourceId = $ResourceId; appRoleId = $RoleId } |
      ConvertTo-Json -Compress | Set-Content -Path $bodyPath -Encoding utf8
    Invoke-Az rest --method POST `
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
      --headers "Content-Type=application/json" --body "@$bodyPath" -o none | Out-Null
  } finally {
    Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
  }
  for ($attempt = 0; $attempt -lt 3; $attempt++) {
    $existing = @(Get-AzGraphAssignments $PrincipalId)
    if ($existing | Where-Object { $_.resourceId -eq $ResourceId -and $_.appRoleId -eq $RoleId }) {
      return
    }
    if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
  }
  throw "Graph role $RoleId was not visible after assignment. Retry setup before creating credentials."
}

function Grant-MgGraphRoles([string]$PrincipalId, [string[]]$RequiredRoles, [string[]]$OptionalRoles) {
  Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All" -ErrorAction Stop | Out-Null
  $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
  if (-not $graphSp.Id) { throw "Microsoft Graph service principal was not found." }
  $resolved = @{}
  foreach ($role in @($RequiredRoles) + @($OptionalRoles)) {
    $appRole = $graphSp.AppRoles | Where-Object {
      $_.Value -eq $role -and $_.IsEnabled -and $_.AllowedMemberTypes -contains "Application"
    }
    if (-not $appRole) {
      if ($role -in $RequiredRoles) { throw "Required Graph application role '$role' is unavailable." }
      Write-Warning "Optional role '$role' is unavailable and NOT GRANTED. This does not establish license status."
      continue
    }
    $resolved[$role] = $appRole.Id
  }
  $existing = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All -ErrorAction Stop)
  foreach ($role in $resolved.Keys) {
    $roleId = $resolved[$role]
    if ($existing | Where-Object { $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $roleId }) {
      Write-Host "  Verified existing grant: $role"
      continue
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId `
      -PrincipalId $PrincipalId -ResourceId $graphSp.Id -AppRoleId $roleId -ErrorAction Stop | Out-Null
    $verified = $false
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
      $existing = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All -ErrorAction Stop)
      if ($existing | Where-Object { $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $roleId }) {
        $verified = $true
        break
      }
      if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
    }
    if (-not $verified) { throw "Graph grant '$role' could not be verified. Retry after propagation." }
    Write-Host "  Verified grant: $role"
  }
  Write-Host "Available grants verified; unavailable optional roles were NOT granted."
  Write-Host "Run doctor and scan to check endpoint access, licensing and data ingestion prerequisites."
}
