"""
Telling "the scope was never in the token" apart from "the tenant said no".

An `az login` sign-in produces a delegated token limited to what the Azure CLI
application is authorized for. That is why Entra discovery works while the connector
sources come back 403 — and no directory role changes it. Preflight has to say so,
because "grant CloudApp-Discovery.Read.All" is useless advice when the problem is that
the client can never carry it.
"""
import base64
import json

import auth
import preflight
from graph_client import GraphError
from test_cli import FakeTenant


def _jwt(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


# --- token introspection ---------------------------------------------------
def test_delegated_token_scopes_come_from_scp():
    token = _jwt({"scp": "Directory.Read.All Application.Read.All User.Read"})
    scopes, kind = auth.token_scopes(token)
    assert kind == "delegated"
    assert "directory.read.all" in scopes and "user.read" in scopes


def test_application_token_scopes_come_from_roles():
    token = _jwt({"roles": ["Directory.Read.All", "CloudApp-Discovery.Read.All"]})
    scopes, kind = auth.token_scopes(token)
    assert kind == "application"
    assert "cloudapp-discovery.read.all" in scopes


def test_a_malformed_token_yields_nothing_rather_than_raising():
    for junk in ("", "not-a-jwt", "a.b", "a.!!!!.c"):
        assert auth.token_scopes(junk) == (set(), "unknown")
    assert auth.decode_token_claims("garbage") == {}


def test_claims_are_read_without_needing_the_signature():
    """Display only — Graph still validates the real token on every call."""
    token = _jwt({"scp": "Directory.Read.All", "upn": "admin@contoso.com"})
    assert auth.decode_token_claims(token)["upn"] == "admin@contoso.com"


# --- the az-login story ----------------------------------------------------
AZ_CLI_SCOPES = {"Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"}


def test_az_login_denial_is_explained_as_a_client_limit_not_a_role_problem():
    denied = ["/security/dataDiscovery", "/security/auditLog", "/copilot/"]
    rows = preflight.run(FakeTenant(denied=denied), AZ_CLI_SCOPES, "delegated")
    by_key = {r["key"]: r for r in rows}

    for key in ("defender_cloud_apps", "purview_audit", "agent365"):
        assert by_key[key]["status"] == preflight.DENIED
        assert by_key[key]["scope_in_token"] is False
        assert by_key[key]["note"] == preflight.NOT_IN_TOKEN

    # Entra sources are fine, which is exactly what makes the failure confusing.
    assert by_key["service_principals"]["status"] == preflight.OK
    assert by_key["entra_agent_id"]["status"] == preflight.OK


def test_a_denial_despite_holding_the_scope_is_not_blamed_on_the_client():
    held = AZ_CLI_SCOPES | {"CloudApp-Discovery.Read.All"}
    rows = preflight.run(FakeTenant(denied=["/security/dataDiscovery"]), held, "application")
    row = next(r for r in rows if r["key"] == "defender_cloud_apps")
    assert row["scope_in_token"] is True
    assert row["note"] != preflight.NOT_IN_TOKEN


def test_missing_scopes_lists_what_would_actually_unlock_things():
    rows = preflight.run(FakeTenant(denied=["/security/", "/copilot/"]),
                         AZ_CLI_SCOPES, "delegated")
    absent = preflight.missing_scopes(rows)
    assert set(absent) == {"CloudApp-Discovery.Read.All", "AuditLogsQuery.Read.All",
                           "CopilotPackages.Read.All"}
    assert len(absent) == len(set(absent))       # deduplicated


def test_report_offers_both_routes_out_of_the_delegated_limit(monkeypatch):
    """
    The script name is platform-aware by design (see preflight._remedy_text): Windows
    readers get create_app_registration.ps1, everyone else gets the .sh twin. Pin the
    platform here so the assertion — and this test's result — doesn't depend on which
    OS happens to run the suite.
    """
    monkeypatch.setattr(preflight.os, "name", "posix")
    rows = preflight.run(FakeTenant(denied=["/security/", "/copilot/"]),
                         AZ_CLI_SCOPES, "delegated")
    text = preflight.format_text(rows)
    assert "DELEGATED token" in text
    assert "create_app_registration.sh" in text
    assert "postdeploy.sh" in text
    assert "Global Administrator does not change this" in text
    assert "CloudApp-Discovery.Read.All" in text


def test_no_delegated_lecture_when_running_as_an_application():
    """The advice is wrong for an app identity — it already uses application permissions."""
    rows = preflight.run(FakeTenant(missing=["/copilot/"]),
                         {"Directory.Read.All"}, "application")
    text = preflight.format_text(rows)
    assert "DELEGATED token" not in text
    assert "application token" in text


def test_an_unavailable_endpoint_is_not_blindly_blamed_on_scopes():
    """404 alone establishes neither license status nor a missing token role."""
    rows = preflight.run(FakeTenant(missing=["/copilot/"]), AZ_CLI_SCOPES, "delegated")
    row = next(r for r in rows if r["key"] == "agent365")
    assert row["status"] == preflight.UNAVAILABLE
    assert row["note"] != preflight.NOT_IN_TOKEN
    assert preflight.missing_scopes(rows) == []


def test_preflight_still_works_without_token_scopes():
    """The Function endpoint and older callers pass no scopes at all."""
    rows = preflight.run(FakeTenant(denied=["/copilot/"]))
    row = next(r for r in rows if r["key"] == "agent365")
    assert row["scope_in_token"] is None
    assert row["note"] == "the identity lacks this permission"
    assert "DELEGATED token" not in preflight.format_text(rows)


def test_agent_inventory_requires_specialized_read_roles():
    rows = {r["key"]: r for r in preflight.run(
        FakeTenant(denied=["microsoft.graph.agent"]), AZ_CLI_SCOPES, "application")}
    assert rows["entra_agent_id"]["scopes"] == ["AgentIdentity.Read.All"]
    assert rows["entra_agent_blueprints"]["scopes"] == ["AgentIdentityBlueprint.Read.All"]
    assert rows["entra_agent_id"]["scope_in_token"] is False
    assert rows["entra_agent_blueprints"]["scope_in_token"] is False
    assert "ReadWrite" not in str(preflight.PROBES)


def test_empty_known_token_has_no_roles_not_unknown_roles():
    rows = preflight.run(FakeTenant(denied=["/copilot/"]), set(), "application")
    row = next(r for r in rows if r["key"] == "agent365")
    assert row["scope_in_token"] is False
    assert row["note"] == "the application token lacks this role"


def test_invalid_query_is_error_not_missing_license():
    class InvalidQuery(FakeTenant):
        def get_all(self, path, params=None, max_items=None, beta=False):
            raise GraphError(400, path, "Request_UnsupportedQuery")

    rows = preflight.run(InvalidQuery())
    assert all(row["status"] == preflight.FAILED for row in rows)
    assert all("licensed" not in row["note"] for row in rows)


def test_explicit_graph_license_error_is_distinct_from_query_failure():
    class LicenseRequired(FakeTenant):
        def get_all(self, path, params=None, max_items=None, beta=False):
            if path == "/auditLogs/signIns":
                raise GraphError(403, path, json.dumps({"error": {
                    "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant"}}))
            return super().get_all(path, params, max_items, beta)

    row = next(r for r in preflight.run(LicenseRequired()) if r["key"] == "signin_logs")
    assert row["status"] == preflight.LICENSE_MISSING
    assert "explicitly" in row["note"]


def test_probe_limits_and_sampled_relationship_failures():
    class CheckedTenant(FakeTenant):
        def get_all(self, path, params=None, max_items=None, beta=False):
            assert max_items == 1
            assert int((params or {}).get("$top", 1)) <= 100
            if path.endswith(("/appRoleAssignments", "/owners")):
                raise GraphError(403, path, "Authorization_RequestDenied")
            return super().get_all(path, params, max_items, beta)

    rows = {r["key"]: r for r in preflight.run(CheckedTenant())}
    assert rows["app_role_assignments"]["status"] == preflight.DENIED
    assert rows["service_principal_owners"]["status"] == preflight.DENIED
    assert rows["service_principals"]["status"] == preflight.OK


def test_absent_sample_does_not_claim_relationship_readable():
    class EmptyTenant(FakeTenant):
        def get_all(self, path, params=None, max_items=None, beta=False):
            return []

    rows = {r["key"]: r for r in preflight.run(EmptyTenant())}
    assert rows["app_role_assignments"]["status"] == preflight.NOT_TESTED
    assert rows["service_principal_owners"]["status"] == preflight.NOT_TESTED


def test_discovery_success_is_not_every_source_access():
    rows = preflight.run(FakeTenant())
    text = preflight.format_text(rows)
    assert "Every source is readable" not in text
    assert "full source access is not verified" in text
    assert "Purview audit queries" in text and "MDCA ingestion" in text
    assert "Microsoft Agent 365" in next(r for r in rows if r["key"] == "agent365")["permission"]
    remedy = preflight._remedy_text()
    assert "Administrator is not sufficient" in remedy


def test_blueprint_only_access_still_enables_partial_agent_collection():
    rows = preflight.run(FakeTenant(denied=["microsoft.graph.agentIdentity/"]))
    for row in rows:
        if row["key"] == "entra_agent_id":
            row["status"] = preflight.DENIED
    assert preflight.connector_flags(rows)["ENABLE_ENTRA_AGENT_ID"]
