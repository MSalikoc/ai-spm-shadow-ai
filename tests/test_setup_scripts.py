"""Offline setup contracts. Azure and Graph commands are always replaced by stubs."""
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


@pytest.fixture
def work():
    path = ROOT / (".setup-test-" + uuid.uuid4().hex)
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def shell(name, source, work):
    executable = shutil.which(name)
    if not executable:
        pytest.skip(f"{name} is not installed")
    args = ["-NoProfile", "-NonInteractive", "-Command"] if name == "pwsh" else ["-c"]
    return subprocess.run([executable, *args, source], cwd=work, capture_output=True,
                          text=True, timeout=30)


def ps_path(path):
    return "'" + str(path).replace("'", "''") + "'"


def bash_path(path):
    # Git Bash accepts Windows drive paths using slashes.
    return "'" + str(path).replace("\\", "/").replace("'", "'\\''") + "'"


def test_powershell_checks_real_native_exit_status(work):
    source = f"""
    . {ps_path(SCRIPTS / 'permission_helpers.ps1')}
    function az {{ & {ps_path(Path(sys.executable))} -c 'raise SystemExit(23)' }}
    Invoke-Az account show
    """
    result = shell("pwsh", source, work)
    assert result.returncode != 0
    assert "exit 23" in result.stderr


PS_AZ = r"""
function Start-Sleep {}
function az {
  $global:LASTEXITCODE = 0
  $cmd = $args -join ' '
  Add-Content calls.log $cmd
  if ($fail -and $cmd.Contains($fail)) { $global:LASTEXITCODE = 23; return }
  if ($cmd -like 'account show*tenantId*') { return 'tenant-id' }
  if ($cmd -like 'account show*user.name*') { return 'test-user' }
  if ($cmd -like 'ad app list*') { if (-not $new) { return 'app-id' }; return }
  if ($cmd -like 'ad app create*') { return 'app-id' }
  if ($cmd -like 'ad sp list*') { if (-not $new) { return 'principal-id' }; return }
  if ($cmd -like 'ad sp create*') { return 'principal-id' }
  if ($cmd -like 'ad sp show*appRoles*') {
    if ($global:mockMissing -and $cmd.Contains("value=='$global:mockMissing'")) { return }
    return 'role-id'
  }
  if ($cmd -like 'ad sp show*') { return 'graph-id' }
  if ($cmd -like 'rest --method POST*') { Set-Content assigned yes; return }
  if ($cmd -like 'rest --method GET*') {
    if ((Test-Path assigned) -and -not $invisible) {
      return '{"value":[{"resourceId":"graph-id","appRoleId":"role-id"}]}'
    }
    return '{"value":[]}'
  }
  if ($cmd -like 'ad app credential reset*') { return 'offline-placeholder' }
}
"""


@pytest.mark.parametrize("failure", [
    "account show", "ad app list", "ad sp list", "ad sp show",
    "ad app permission add", "rest --method GET", "rest --method POST",
    "ad app credential reset",
])
def test_registration_native_failures_never_report_success(work, failure):
    source = f"$fail = '{failure}'\n" + PS_AZ + f"\n& {ps_path(SCRIPTS / 'create_app_registration.ps1')}"
    result = shell("pwsh", source, work)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "Paste these three lines" not in result.stdout
    calls = (work / "calls.log").read_text(encoding="utf-8-sig")
    if failure != "ad app credential reset":
        assert "credential reset" not in calls


@pytest.mark.parametrize("existing", [True, False])
def test_az_grants_are_idempotent_and_verified(work, existing):
    if existing:
        (work / "assigned").write_text("yes")
    source = PS_AZ + f"""
    . {ps_path(SCRIPTS / 'permission_helpers.ps1')}
    Grant-AzGraphRole principal-id graph-id role-id
    Grant-AzGraphRole principal-id graph-id role-id
    """
    result = shell("pwsh", source, work)
    assert result.returncode == 0, result.stderr
    calls = (work / "calls.log").read_text(encoding="utf-8-sig")
    assert calls.count("rest --method POST") == (0 if existing else 1)
    assert calls.count("rest --method GET") >= 2


def test_unverified_registration_grants_never_create_secret(work):
    source = "$invisible = $true\n" + PS_AZ + f"\n& {ps_path(SCRIPTS / 'create_app_registration.ps1')}"
    result = shell("pwsh", source, work)
    assert result.returncode != 0
    assert "credential reset" not in (work / "calls.log").read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("failure", ["ad app create", "ad sp create"])
def test_registration_creation_failure_never_reaches_credentials(work, failure):
    source = f"$new=$true; $fail='{failure}'\n" + PS_AZ
    source += f"\n& {ps_path(SCRIPTS / 'create_app_registration.ps1')}"
    result = shell("pwsh", source, work)
    assert result.returncode != 0
    assert "credential reset" not in (work / "calls.log").read_text(encoding="utf-8-sig")


def test_registration_missing_required_role_aborts_before_any_grant(work):
    source = "$global:mockMissing='Directory.Read.All'\n" + PS_AZ
    source += f"\n& {ps_path(SCRIPTS / 'create_app_registration.ps1')}"
    result = shell("pwsh", source, work)
    assert result.returncode != 0
    assert "Required Graph application role" in result.stderr
    calls = (work / "calls.log").read_text(encoding="utf-8-sig")
    assert "rest --method POST" not in calls and "credential reset" not in calls


PS_MG = r"""
function Connect-MgGraph {}
function Start-Sleep {}
function Get-MgServicePrincipal {
  $roles = @('Directory.Read.All', 'Application.Read.All', 'AuditLog.Read.All', 'Mail.Send',
    'AgentIdentity.Read.All', 'AgentIdentityBlueprint.Read.All', 'CopilotPackages.Read.All',
    'CloudApp-Discovery.Read.All', 'AuditLogsQuery.Read.All')
  return [pscustomobject]@{Id='graph-id';AppRoles=@($roles | Where-Object {$_ -ne $missing} |
    ForEach-Object {[pscustomobject]@{Id=$_;Value=$_;IsEnabled=$true;AllowedMemberTypes=@('Application')}})}
}
$global:mockAssignments = @()
function Get-MgServicePrincipalAppRoleAssignment {
  if ($readFailure) { throw 'offline read failure' }
  return $global:mockAssignments
}
function New-MgServicePrincipalAppRoleAssignment {
  param($ServicePrincipalId, $PrincipalId, $ResourceId, $AppRoleId, $ErrorAction)
  Add-Content posts.log $AppRoleId
  if ($writeFailure) { throw 'offline write failure' }
  if (-not $invisible) {
    $global:mockAssignments += [pscustomobject]@{ResourceId=$ResourceId;AppRoleId=$AppRoleId}
  }
}
"""


@pytest.mark.parametrize("script, count", [("grant_graph_roles.ps1", 4), ("grant_connector_roles.ps1", 7)])
def test_mg_grants_skip_existing_verified_assignments(work, script, count):
    source = PS_MG + f"""
    & {ps_path(SCRIPTS / script)} -ManagedIdentityObjectId principal-id
    & {ps_path(SCRIPTS / script)} -ManagedIdentityObjectId principal-id
    """
    result = shell("pwsh", source, work)
    assert result.returncode == 0, result.stderr
    assert len((work / "posts.log").read_text(encoding="utf-8-sig").splitlines()) == count
    assert "Verified existing grant" in result.stdout


@pytest.mark.parametrize("condition", ["$readFailure=$true", "$writeFailure=$true",
                                      "$invisible=$true", "$missing='Directory.Read.All'"])
def test_mg_grant_failures_are_not_duplicate_success(work, condition):
    source = condition + "\n" + PS_MG + f"\n& {ps_path(SCRIPTS / 'grant_graph_roles.ps1')} principal-id"
    result = shell("pwsh", source, work)
    assert result.returncode != 0
    assert "Available grants verified" not in result.stdout


def test_mg_missing_optional_role_is_reported_not_granted(work):
    source = "$missing='AgentIdentity.Read.All'\n" + PS_MG + f"\n& {ps_path(SCRIPTS / 'grant_connector_roles.ps1')} principal-id"
    result = shell("pwsh", source, work)
    assert result.returncode == 0, result.stderr
    assert "NOT GRANTED" in result.stdout
    assert "AgentIdentity.Read.All" not in (work / "posts.log").read_text(encoding="utf-8-sig")


BASH_AZ = r"""
sleep() { :; }
az() {
  printf '%s\n' "$*" >> calls.log
  if [[ -n "$FAIL" && "$*" == *"$FAIL"* ]]; then return 23; fi
  case "$*" in
    "account show"*"tenantId"*) echo tenant-id ;;
    "ad app list"*) echo app-id ;;
    "ad sp list"*) echo principal-id ;;
    "ad sp show"*"appRoles"*)
      if [[ -z "${MISSING:-}" || "$*" != *"value=='$MISSING'"* ]]; then echo role-id; fi ;;
    "ad sp show"*) echo graph-id ;;
    "rest --method POST"*) echo yes > assigned ;;
    "rest --method GET"*'@odata.nextLink'*) : ;;
    "rest --method GET"*) if [[ -f assigned && "$INVISIBLE" != true ]]; then echo assignment-id; fi ;;
    "ad app credential reset"*) echo offline-placeholder ;;
  esac
  return 0
}
"""


@pytest.mark.parametrize("failure", ["account show", "ad app list", "ad sp list", "ad sp show",
                                    "ad app permission add", "rest --method GET",
                                    "rest --method POST", "ad app credential reset"])
def test_bash_registration_stops_on_native_failure(work, failure):
    source = f"FAIL='{failure}'; INVISIBLE=false\n" + BASH_AZ
    source += f"\nexport -f az sleep; export FAIL INVISIBLE\nbash {bash_path(SCRIPTS / 'create_app_registration.sh')}"
    result = shell("bash", source, work)
    assert result.returncode != 0, result.stdout + result.stderr
    calls = (work / "calls.log").read_text()
    if failure != "ad app credential reset":
        assert "credential reset" not in calls
    assert "Available grants verified" not in result.stdout


@pytest.mark.parametrize("existing", [True, False])
def test_bash_role_idempotency(work, existing):
    if existing:
        (work / "assigned").write_text("yes")
    source = "set -euo pipefail\nFAIL=''; INVISIBLE=false\n" + BASH_AZ + f"""
    source {bash_path(SCRIPTS / 'permission_helpers.sh')}
    grant_graph_role principal-id graph-id role-id
    grant_graph_role principal-id graph-id role-id
    """
    result = shell("bash", source, work)
    assert result.returncode == 0, result.stderr
    calls = (work / "calls.log").read_text()
    assert calls.count("rest --method POST") == (0 if existing else 1)


def test_bash_unverified_grant_fails(work):
    source = "set -euo pipefail\nFAIL=''; INVISIBLE=true\n" + BASH_AZ + f"""
    source {bash_path(SCRIPTS / 'permission_helpers.sh')}
    grant_graph_role principal-id graph-id role-id
    """
    result = shell("bash", source, work)
    assert result.returncode != 0
    assert "not visible after assignment" in result.stderr


@pytest.mark.parametrize("script", ["grant_graph_roles.sh", "grant_connector_roles.sh"])
@pytest.mark.parametrize("failure", ["ad sp show", "rest --method GET", "rest --method POST"])
def test_bash_grant_script_errors_never_report_success(work, script, failure):
    source = f"FAIL='{failure}'; INVISIBLE=false\n" + BASH_AZ
    source += f"\nexport -f az sleep; export FAIL INVISIBLE\nbash {bash_path(SCRIPTS / script)} principal-id"
    result = shell("bash", source, work)
    assert result.returncode != 0
    assert "Available grants verified" not in result.stdout


@pytest.mark.parametrize("missing, succeeds", [("Directory.Read.All", False),
                                             ("AgentIdentity.Read.All", True)])
def test_bash_required_and_optional_role_availability(work, missing, succeeds):
    source = f"FAIL=''; INVISIBLE=false; MISSING='{missing}'\n" + BASH_AZ
    source += f"\nexport -f az sleep; export FAIL INVISIBLE MISSING\nbash {bash_path(SCRIPTS / 'grant_connector_roles.sh')} principal-id"
    result = shell("bash", source, work)
    assert (result.returncode == 0) == succeeds, result.stderr
    if succeeds:
        assert "NOT GRANTED" in result.stderr
        assert "This does not establish license status" in result.stderr
    else:
        assert "required Graph application role" in result.stderr
        assert "rest --method POST" not in (work / "calls.log").read_text()


def test_bash_script_syntax(work):
    paths = [bash_path(path) for path in SCRIPTS.glob("*.sh")]
    result = shell("bash", "set -e; " + "; ".join(f"bash -n {path}" for path in paths), work)
    assert result.returncode == 0, result.stderr
