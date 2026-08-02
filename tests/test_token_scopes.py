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


def test_report_offers_both_routes_out_of_the_delegated_limit():
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


def test_a_not_provisioned_source_is_never_blamed_on_scopes():
    """404 means the tenant does not have the feature; granting a scope will not help."""
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
