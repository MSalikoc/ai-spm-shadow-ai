"""The local CLI and its preflight — the path that needs no Azure deployment."""
import json
import os

import pytest

import aispm
import auth
import preflight
from graph_client import GraphError


class FakeTenant:
    """
    A Graph stand-in whose endpoints can each be set to allow, deny, or not exist —
    which is the whole point of preflight: telling those three apart.
    """

    def __init__(self, denied=(), missing=()):
        self.denied = set(denied)
        self.missing = set(missing)

    def _check(self, path):
        for frag in self.denied:
            if frag in path:
                raise GraphError(403, path, "Authorization_RequestDenied")
        for frag in self.missing:
            if frag in path:
                raise GraphError(404, path, "Resource not found")

    def get_all(self, path, params=None, max_items=None, beta=False):
        self._check(path)
        if path == "/servicePrincipals":
            if "appId eq" in (params or {}).get("$filter", ""):
                return [{"id": "graph-sp"}]
            return [{"id": "sp1", "appId": "app1", "displayName": "ChatGPT Connector",
                     "appOwnerOrganizationId": "ext", "publisherName": "OpenAI",
                     "verifiedPublisher": {"displayName": "OpenAI"}},
                    {"id": "sp2", "appId": "app2", "displayName": "Ledger Sync",
                     "appOwnerOrganizationId": "ext2", "publisherName": "Contoso"}]
        if path == "/oauth2PermissionGrants":
            return [{"clientId": "sp1", "resourceId": "res", "scope": "Mail.Read offline_access",
                     "consentType": "AllPrincipals", "principalId": "u1"},
                    {"clientId": "sp2", "resourceId": "res", "scope": "Files.Read.All",
                     "consentType": "Principal", "principalId": "u2"}]
        return []

    def get(self, path, params=None, beta=False):
        try:
            self._check(path)
        except GraphError:
            return {}
        return {"displayName": "Microsoft Graph", "appRoles": [], "accountEnabled": True}

    def get_checked(self, path, params=None, beta=False):
        self._check(path)
        return {}

    def post(self, path, body, beta=False):
        self._check(path)
        return {"id": "q1", "status": "succeeded"}

    def batch_collection(self, spec, beta=False):
        return {r["id"]: [] for r in spec}

    def telemetry(self):
        return {"requests": 12, "batch_calls": 2, "throttled": 0, "errors": 0,
                "retries": 0, "batched_requests": 4}


# --- preflight tells the three failure modes apart --------------------------
def test_preflight_reports_every_source():
    rows = preflight.run(FakeTenant())
    assert len(rows) == len(preflight.PROBES)
    assert all(r["status"] == preflight.OK for r in rows)
    assert not preflight.blocking(rows)


def test_missing_permission_is_not_reported_as_missing_data():
    rows = preflight.run(FakeTenant(denied=["/auditLogs/signIns"]))
    signin = next(r for r in rows if r["key"] == "signin_logs")
    assert signin["status"] == preflight.DENIED
    assert "lacks this permission" in signin["note"]
    assert "AuditLog.Read.All" in signin["permission"]


def test_unlicensed_feature_is_distinguished_from_a_denied_one():
    rows = preflight.run(FakeTenant(missing=["/copilot/"], denied=["/security/auditLog"]))
    by_key = {r["key"]: r for r in rows}
    assert by_key["agent365"]["status"] == preflight.UNAVAILABLE
    assert by_key["purview_audit"]["status"] == preflight.DENIED


def test_core_permission_loss_is_blocking_but_an_optional_one_is_not():
    assert preflight.blocking(preflight.run(FakeTenant(denied=["/servicePrincipals"])))
    assert not preflight.blocking(preflight.run(FakeTenant(denied=["/copilot/"])))


def test_connector_flags_follow_what_is_actually_readable():
    rows = preflight.run(FakeTenant(denied=["/copilot/"], missing=["cloudAppDiscovery"]))
    flags = preflight.connector_flags(rows)
    assert flags["ENABLE_AGENT365"] is False
    assert flags["ENABLE_DEFENDER_CLOUD_APPS"] is False
    assert flags["ENABLE_PREVIEW_CONNECTORS"] is False
    assert flags["ENABLE_ENTRA_AGENT_ID"] is True


def test_preflight_text_names_the_permission_to_grant():
    text = preflight.format_text(preflight.run(FakeTenant(denied=["/auditLogs/signIns"])))
    assert "AuditLog.Read.All" in text
    assert "Ready to scan" in text            # an optional gap does not block


def test_preflight_text_says_when_a_scan_cannot_run():
    text = preflight.format_text(preflight.run(FakeTenant(denied=["/oauth2PermissionGrants"])))
    assert "Cannot run a useful scan" in text


# --- the CLI ---------------------------------------------------------------
@pytest.fixture
def cli(monkeypatch):
    """
    Points the CLI at a fake tenant. `cmd_scan` deliberately writes ENABLE_*/AISPM_*
    into the real environment (that is how it hands the preflight result to the
    collectors), so the fixture snapshots and restores them — otherwise a scan here
    leaks connector flags into every test that runs afterwards.
    """
    touched = [k for k in os.environ if k.startswith(("ENABLE_", "AISPM_"))]
    saved = {k: os.environ[k] for k in touched}

    def _run(argv, tenant=None, scopes=("Directory.Read.All",), kind="application"):
        graph = tenant or FakeTenant()
        monkeypatch.setattr(aispm, "_graph", lambda _a: (graph, "tenant-abc"))
        monkeypatch.setattr(aispm, "_graph_and_scopes",
                            lambda _a: (graph, "tenant-abc", set(scopes), kind))
        return aispm.main(argv)

    yield _run

    for k in [k for k in os.environ if k.startswith(("ENABLE_", "AISPM_"))]:
        del os.environ[k]
    os.environ.update(saved)


def test_doctor_exits_clean_when_everything_is_readable(cli, capsys):
    assert cli(["doctor"]) == 0
    assert "Ready to scan" in capsys.readouterr().out


def test_doctor_exits_nonzero_when_the_core_scan_is_blocked(cli):
    assert cli(["doctor"], FakeTenant(denied=["/servicePrincipals"])) == 1


def test_scan_writes_the_two_pages(cli, tmp_path, capsys):
    """Two pages, not four: the assessment to start on, the detail behind it."""
    out = tmp_path / "run"
    assert cli(["scan", "--out", str(out)]) == 0

    assess = (out / "assessment.html").read_text(encoding="utf-8")
    assert "Assessment results" in assess and "AI estate" in assess
    assert 'href="detail.html"' in assess

    detail = (out / "detail.html").read_text(encoding="utf-8")
    assert "ChatGPT Connector" in detail
    assert 'data-tab="apps"' in detail and 'data-tab="coverage"' in detail
    assert 'href="assessment.html"' in detail

    # The pages people used to bookmark are gone, not silently rewritten.
    assert not (out / "report.html").exists()
    assert not (out / "portal.html").exists()
    assert not (out / "connectors.html").exists()

    payload = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert payload["findings"][0]["risk_score"] >= 0
    assert payload["generated"]
    assert json.loads((out / "assessment.json").read_text(encoding="utf-8"))["tests"]
    assert "applications assessed" in capsys.readouterr().out


def test_scan_refuses_to_run_without_the_core_permissions(cli, tmp_path, capsys):
    out = tmp_path / "run"
    assert cli(["scan", "--out", str(out)], FakeTenant(denied=["/oauth2PermissionGrants"])) == 1
    assert not (out / "assessment.html").exists()
    assert "Stopping" in capsys.readouterr().out


def test_scan_scope_reaches_the_collector(cli, tmp_path):
    """`--scope consented` has to actually widen discovery, not just print a word."""
    out = tmp_path / "run"
    cli(["scan", "--out", str(out), "--scope", "ai"])
    ai_only = json.loads((out / "report.json").read_text(encoding="utf-8"))["findings"]

    cli(["scan", "--out", str(out), "--scope", "consented"])
    consented = json.loads((out / "report.json").read_text(encoding="utf-8"))["findings"]

    assert {a["display_name"] for a in ai_only} == {"ChatGPT Connector"}
    assert {a["display_name"] for a in consented} == {"ChatGPT Connector", "Ledger Sync"}
    assert os.environ["AISPM_SCAN_SCOPE"] == "consented"


def test_scan_only_enables_connectors_the_identity_can_read(cli, tmp_path):
    cli(["scan", "--out", str(tmp_path / "r")],
        FakeTenant(denied=["/copilot/"], missing=["cloudAppDiscovery"]))
    assert os.environ["ENABLE_AGENT365"] == "false"
    assert os.environ["ENABLE_DEFENDER_CLOUD_APPS"] == "false"
    assert os.environ["ENABLE_ENTRA_AGENT_ID"] == "true"


def test_no_connectors_flag_skips_the_data_sources_step(cli, tmp_path):
    out = tmp_path / "run"
    assert cli(["scan", "--out", str(out), "--no-connectors"]) == 0
    assert (out / "assessment.html").exists()
    assert not (out / "connectors.json").exists()
    # The data-source tabs say why they are empty rather than rendering empty tables.
    assert "No AI data sources are connected" in (out / "detail.html").read_text(encoding="utf-8")


def test_activity_window_flag_reaches_the_collector(cli, tmp_path):
    cli(["scan", "--out", str(tmp_path / "r"), "--activity-days", "14"])
    assert os.environ["AISPM_ACTIVITY_DAYS"] == "14"


def test_unknown_command_is_rejected():
    with pytest.raises(SystemExit):
        aispm.main(["nonsense"])


def test_device_code_mode_requires_its_arguments(monkeypatch):
    args = aispm.build_parser().parse_args(["scan", "--auth", "device-code"])
    with pytest.raises(SystemExit, match="device-code"):
        aispm._graph(args)


def test_missing_azure_cli_login_gets_an_actionable_message():
    hint = aispm._auth_hint(Exception("AzureCliCredential: Please run az login"))
    assert "az login" in hint


def test_missing_azure_cli_tells_you_how_to_install_it():
    """The very first thing a new user hits — it must name the fix, not the SDK error."""
    hint = aispm._auth_hint(Exception("Azure CLI not found on path"))
    assert "brew install azure-cli" in hint
    assert "aka.ms/InstallAzureCLI" in hint
    assert "--auth app" in hint          # the no-CLI alternative is offered too


def test_not_signed_in_is_distinguished_from_not_installed():
    hint = aispm._auth_hint(Exception("AzureCliCredential: Please run 'az login'"))
    assert "az login" in hint
    assert "brew install" not in hint    # they already have it; don't send them installing
    assert "Global Reader" in hint       # says which role is enough


# --- the deployed Function exposes the same preflight ----------------------
def test_function_app_serves_doctor(monkeypatch):
    import function_app

    monkeypatch.setenv("AISPM_TENANT_ID", "tenant-abc")
    monkeypatch.setattr(function_app.auth, "get_token_managed_identity", lambda: "tok")
    monkeypatch.setattr(function_app, "GraphClient",
                        lambda _t: FakeTenant(denied=["/auditLogs/signIns"]))

    class Req:
        params = {}

    body = function_app.doctor_view(Req()).get_body().decode()
    assert "Sign-in logs" in body and "AuditLog.Read.All" in body
    assert "Scan scope: ai" in body


def test_function_app_doctor_json_names_blocking_sources(monkeypatch):
    import function_app

    monkeypatch.setenv("AISPM_TENANT_ID", "tenant-abc")
    monkeypatch.setattr(function_app.auth, "get_token_managed_identity", lambda: "tok")
    monkeypatch.setattr(function_app, "GraphClient",
                        lambda _t: FakeTenant(denied=["/servicePrincipals"]))

    class Req:
        params = {"format": "json"}

    payload = json.loads(function_app.doctor_view(Req()).get_body().decode())
    assert "service_principals" in payload["blocking"]
    assert payload["tenant"] == "tenant-abc"


def test_function_app_doctor_reports_a_missing_tenant_id(monkeypatch):
    import function_app

    monkeypatch.delenv("AISPM_TENANT_ID", raising=False)

    class Req:
        params = {}

    resp = function_app.doctor_view(Req())
    assert resp.status_code == 500
    assert "AISPM_TENANT_ID" in resp.get_body().decode()


# --- credentials come from the environment, not the command line -----------
def test_credentials_fall_back_to_environment(monkeypatch):
    """Keeps the secret out of shell history and out of `ps` output."""
    monkeypatch.setenv("AISPM_TENANT_ID", "tenant-env")
    monkeypatch.setenv("AISPM_CLIENT_ID", "client-env")
    monkeypatch.setenv("AISPM_CLIENT_SECRET", "secret-env")

    args = aispm.build_parser().parse_args(["scan", "--auth", "app"])
    assert (args.tenant, args.client_id, args.client_secret) == (
        "tenant-env", "client-env", "secret-env")


def test_explicit_flags_still_beat_the_environment(monkeypatch):
    monkeypatch.setenv("AISPM_TENANT_ID", "tenant-env")
    args = aispm.build_parser().parse_args(["scan", "--tenant", "tenant-flag"])
    assert args.tenant == "tenant-flag"


def test_an_unsubstituted_placeholder_is_named_rather_than_sent_to_graph():
    """
    `--tenant <T>` pasted into zsh dies with "no such file or directory: T", naming
    neither the flag nor the fix. Quoted, it reaches us — so say what to do.
    """
    for argv in (["scan", "--tenant", "<T>"],
                 ["scan", "--client-id", "<C>"],
                 ["scan", "--client-secret", "<SECRET>"],
                 ["doctor", "--tenant", "<TENANT_ID>"]):
        with pytest.raises(SystemExit) as e:
            aispm.main(argv)
        message = str(e.value)
        assert "placeholder" in message
        assert "AISPM_TENANT_ID" in message      # points at the export route


def test_a_real_value_that_merely_looks_odd_is_not_rejected(monkeypatch):
    args = aispm.build_parser().parse_args(
        ["scan", "--tenant", "af80ebe6-b601-49c4-89b9-381499b97ba6"])
    aispm._reject_placeholders(args)             # does not raise


def test_sample_needs_no_tenant_flags_to_parse():
    """
    `sample` takes no --tenant/--client-id, so its Namespace has neither. Reading
    args.tenant directly in the placeholder guard crashed the one command the README
    tells people to run to regenerate the published samples.
    """
    args = aispm.build_parser().parse_args(["sample"])
    assert not hasattr(args, "tenant")
    aispm._reject_placeholders(args)              # must not raise


def test_the_placeholder_guard_still_fires_on_commands_that_do_take_flags():
    import pytest as _pytest
    with _pytest.raises(SystemExit, match="placeholder"):
        aispm.main(["scan", "--tenant", "<T>"])


# --- Windows: `az` is a .cmd, which changes how it must be launched --------
def _jwt(payload):
    import base64
    import json
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"h.{body}.s"


def test_az_is_resolved_before_launching_it(monkeypatch):
    """
    On Windows `az` is az.cmd and CreateProcess does not apply PATHEXT, so
    subprocess.run(["az", ...]) raises FileNotFoundError there. Resolving the path
    first is what makes the shell-out work on all three platforms.
    """
    import subprocess as sp
    seen = {}
    monkeypatch.setattr("shutil.which",
                        lambda name: r"C:\Program Files\az.cmd" if name == "az" else None)

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return sp.CompletedProcess(cmd, 0, stdout='{"tenantId":"t-1"}', stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert auth.tenant_id_from_cli() == "t-1"
    assert seen["cmd"][0].endswith("az.cmd"), "must launch the resolved path, not 'az'"


def test_no_az_on_path_degrades_quietly(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert auth.az_json("account", "show") is None
    assert auth.tenant_id_from_cli() is None


def test_the_tenant_falls_back_to_the_token_when_az_cannot_be_shelled_out(monkeypatch):
    """
    The symptom this fixes: signed in with az, yet told to run `az login`. The token
    already names its tenant in `tid`, so the shell-out is not the only source.
    """
    monkeypatch.setattr(auth, "tenant_id_from_cli", lambda: None)
    monkeypatch.setattr(auth, "get_token_azure_cli",
                        lambda tenant=None: _jwt({"tid": "tenant-from-token",
                                                  "scp": "Directory.Read.All"}))
    args = aispm.build_parser().parse_args(["doctor"])
    tenant, _token = aispm._token(args)
    assert tenant == "tenant-from-token"


def test_an_explicit_tenant_still_wins(monkeypatch):
    monkeypatch.setattr(auth, "tenant_id_from_cli", lambda: "from-cli")
    monkeypatch.setattr(auth, "get_token_azure_cli", lambda tenant=None: _jwt({"tid": "from-token"}))
    args = aispm.build_parser().parse_args(["doctor", "--tenant", "explicit"])
    assert aispm._token(args)[0] == "explicit"


# --- probes must not mistake their own bad request for a missing feature ---
def test_a_collection_that_rejects_a_page_size_is_still_readable(monkeypatch):
    """
    /directoryRoles answers 400 "This resource does not support custom page sizes".
    Reading that as "not provisioned in this tenant" was the probe blaming the tenant
    for its own query.
    """
    class PageSizeFussy(FakeTenant):
        def get_all(self, path, params=None, max_items=None, beta=False):
            if path == "/directoryRoles":
                if params and "$top" in params:
                    raise GraphError(400, path,
                                     '{"error":{"code":"Request_UnsupportedQuery",'
                                     '"message":"This resource does not support custom '
                                     'page sizes. Please retry without a page size."}}')
                return [{"id": "role-1"}]
            return super().get_all(path, params, max_items, beta)

    rows = {r["key"]: r for r in preflight.run(PageSizeFussy())}
    assert rows["directory_roles"]["status"] == preflight.OK


def test_a_real_400_is_still_reported_as_unavailable(monkeypatch):
    """The retry must not paper over an endpoint that genuinely is not there."""
    rows = {r["key"]: r for r in preflight.run(FakeTenant(missing=["/copilot/"]))}
    assert rows["agent365"]["status"] == preflight.UNAVAILABLE


def test_the_remedy_names_the_script_for_the_shell_you_are_in(monkeypatch):
    denied = ["/security/", "/copilot/"]
    scopes = {"Directory.Read.All", "Application.Read.All"}

    monkeypatch.setattr(preflight.os, "name", "posix")
    posix = preflight.format_text(preflight.run(FakeTenant(denied=denied), scopes, "delegated"))
    assert "./scripts/create_app_registration.sh" in posix
    assert "python3 aispm.py doctor --auth app" in posix

    monkeypatch.setattr(preflight.os, "name", "nt")
    win = preflight.format_text(preflight.run(FakeTenant(denied=denied), scopes, "delegated"))
    assert r".\scripts\create_app_registration.ps1" in win
    assert "$env:AISPM_TENANT_ID" in win
    assert "Cloud Shell Bash" in win          # postdeploy.sh has no PowerShell twin
    assert ".sh" not in win.split("1. An app registration")[1].split("2. Deploy")[0]
