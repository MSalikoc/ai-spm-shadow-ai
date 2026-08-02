"""Application (app-only) permission discovery tests."""
import collectors
import report
import scoring


class FakeGraph:
    def __init__(self, grants=None, assignments=None, resources=None):
        self._grants = grants or []
        self._assignments = assignments or {}
        self._resources = resources or {}

    def get_all(self, path, params=None):
        if path == "/oauth2PermissionGrants":
            return self._grants
        if path.endswith("/appRoleAssignments"):
            sp_id = path.split("/")[2]
            return self._assignments.get(sp_id, [])
        return []

    def get(self, path, params=None):
        rid = path.split("/")[2]
        return self._resources.get(rid, {})


ZERO = "00000000-0000-0000-0000-000000000000"


def test_app_permission_resolution_and_fallback():
    graph = FakeGraph(
        assignments={"app1": [
            {"appRoleId": "r-known", "resourceId": "graph", "resourceDisplayName": "Microsoft Graph"},
            {"appRoleId": "r-unknown", "resourceId": "custom", "resourceDisplayName": "Contoso HR API"},
            {"appRoleId": ZERO, "resourceId": "graph"},  # no role → skipped
        ]},
        resources={
            "graph": {"displayName": "Microsoft Graph",
                      "appRoles": [{"id": "r-known", "value": "Sites.ReadWrite.All"}]},
            "custom": {"displayName": "Contoso HR API", "appRoles": []},  # can't be resolved
        })
    apps = [{"sp_id": "app1"}]
    collectors.enrich_with_app_role_assignments(graph, apps)
    perms = apps[0]["application_permissions"]

    assert apps[0]["has_app_only_access"] is True
    assert len(perms) == 2  # zero-guid skipped
    # GUID → resolved to a readable name
    assert {"resource": "Microsoft Graph", "permission": "Sites.ReadWrite.All",
            "permission_id": "r-known"} in perms
    # The unresolved custom API permission GUID was NOT lost
    custom = [p for p in perms if p["resource"] == "Contoso HR API"][0]
    assert custom["permission"] == "r-unknown" and custom["permission_id"] == "r-unknown"


def test_app_only_app_has_no_delegated():
    graph = FakeGraph(assignments={"app1": [
        {"appRoleId": "r1", "resourceId": "graph", "resourceDisplayName": "Microsoft Graph"}]},
        resources={"graph": {"displayName": "Microsoft Graph",
                             "appRoles": [{"id": "r1", "value": "Mail.Read"}]}})
    apps = [{"sp_id": "app1", "scopes": [], "delegated_permissions": []}]
    collectors.enrich_with_oauth_grants(FakeGraph(), apps)   # no delegated
    collectors.enrich_with_app_role_assignments(graph, apps)
    assert apps[0]["has_app_only_access"] is True
    assert apps[0]["delegated_permissions"] == []
    assert report._perm_type(apps[0]) == "apponly"


def test_delegated_permissions_structured():
    graph = FakeGraph(
        grants=[{"clientId": "app2", "resourceId": "graph", "scope": "User.Read Files.Read.All",
                 "consentType": "Principal", "principalId": "u1"}],
        resources={"graph": {"displayName": "Microsoft Graph", "appRoles": []}})
    apps = [{"sp_id": "app2"}]
    collectors.enrich_with_oauth_grants(graph, apps)
    dp = apps[0]["delegated_permissions"]
    assert {"resource": "Microsoft Graph", "permission": "User.Read",
            "consent_type": "Principal"} in dp
    assert "files.read.all" in apps[0]["scopes"]  # legacy output preserved


def test_scoring_counts_app_only_permissions():
    app = {"scopes": [], "consent_type": None, "user_count": 0, "verified_publisher": True,
           "third_party": True, "confidence": "high",
           "application_permissions": [{"permission": "Sites.ReadWrite.All",
                                        "resource": "Microsoft Graph", "permission_id": "x"}]}
    scoring.score_app(app)
    assert app["risk_score"] > 0                       # used to be 0 — blind spot closed
    assert any("App-only" in r for r in app["reasons"])


def test_report_renders_app_only_cards_and_filter():
    apps = [{"display_name": "AppOnlyBot", "vendor": "X", "first_party_microsoft": False,
             "third_party": True, "verified_publisher": True, "scopes": [], "consent_type": None,
             "user_count": 0, "risk_score": 40, "risk_level": "Medium", "reasons": ["r"],
             "remediation": ["m"], "delegated_permissions": [], "has_app_only_access": True,
             "application_permissions": [{"permission": "Directory.ReadWrite.All",
                                          "resource": "Microsoft Graph", "permission_id": "g"}]}]
    doc = report.html_string(apps, "t")
    assert "App-only permissions (unattended)" in doc      # finding block
    assert 'data-group="perm" data-value="apponly"' in doc  # filter button
    assert "Directory.ReadWrite.All" in doc             # app perm shown in the finding
    assert 'data-perm="apponly"' in doc                 # row tag
