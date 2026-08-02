"""The local CLI and its preflight — the path that needs no Azure deployment."""
import json
import os

import pytest

import aispm
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

    def _run(argv, tenant=None):
        graph = tenant or FakeTenant()
        monkeypatch.setattr(aispm, "_graph", lambda _a: (graph, "tenant-abc"))
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


def test_scan_writes_both_dashboards(cli, tmp_path, capsys):
    out = tmp_path / "run"
    assert cli(["scan", "--out", str(out)]) == 0

    report_html = out / "report.html"
    assert report_html.exists()
    doc = report_html.read_text(encoding="utf-8")
    assert "AI-SPM" in doc and "Where to start" in doc
    assert "ChatGPT Connector" in doc

    payload = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert payload["findings"][0]["risk_score"] >= 0
    assert payload["generated"]
    assert "applications assessed" in capsys.readouterr().out


def test_scan_refuses_to_run_without_the_core_permissions(cli, tmp_path, capsys):
    out = tmp_path / "run"
    assert cli(["scan", "--out", str(out)], FakeTenant(denied=["/oauth2PermissionGrants"])) == 1
    assert not (out / "report.html").exists()
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
    assert (out / "report.html").exists()
    assert not (out / "connectors.html").exists()


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
