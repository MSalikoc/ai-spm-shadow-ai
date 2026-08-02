"""
Scan scope — which service principals get assessed.

`ai` is precise but only sees vendors the catalog already knows. `consented` widens the
view to every app that actually holds a grant, which is what makes an unknown AI tool
visible instead of silently dropped.
"""
import collectors

HOME = "home-tenant"
GRAPH_SP = "graph-sp-id"

SPS = [
    {"id": "sp-openai", "appId": "app-openai", "displayName": "ChatGPT Enterprise",
     "appOwnerOrganizationId": "ext-1", "publisherName": "OpenAI"},
    {"id": "sp-unknown", "appId": "app-unknown", "displayName": "Zephyr Workspace",
     "appOwnerOrganizationId": "ext-2", "publisherName": "Zephyr Labs"},
    {"id": "sp-quiet", "appId": "app-quiet", "displayName": "Legacy Timesheets",
     "appOwnerOrganizationId": "ext-3", "publisherName": "Contoso Partners"},
    {"id": "sp-ms", "appId": "app-ms", "displayName": "Microsoft Teams",
     "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
     "publisherName": "Microsoft"},
    {"id": "sp-internal", "appId": "app-internal", "displayName": "Our Own Tool",
     "appOwnerOrganizationId": HOME, "publisherName": "IT"},
]


class ScopeGraph:
    """
    Serves the SP list plus the two bulk calls `consented` scope relies on:
    the tenant's delegated grants and everything assigned an app role on Graph.
    """

    def __init__(self, grant_clients=(), app_role_principals=()):
        self._grants = [{"clientId": c, "resourceId": "res", "scope": "User.Read"}
                        for c in grant_clients]
        self._roles = [{"principalId": p, "appRoleId": "role-1"} for p in app_role_principals]

    def get_all(self, path, params=None, max_items=None):
        if path == "/servicePrincipals":
            if "appId eq" in (params or {}).get("$filter", ""):
                return [{"id": GRAPH_SP}]
            return SPS
        if path == "/oauth2PermissionGrants":
            return self._grants
        if path == f"/servicePrincipals/{GRAPH_SP}/appRoleAssignedTo":
            return self._roles
        return []

    def get(self, path, params=None):
        return {}


def _names(found):
    return {a["display_name"] for a in found}


def test_ai_scope_keeps_only_catalog_matches():
    graph = ScopeGraph(grant_clients=["sp-unknown", "sp-quiet"])
    found = collectors.collect_service_principals(graph, HOME)
    assert _names(found) == {"ChatGPT Enterprise"}


def test_consented_scope_surfaces_an_ai_tool_the_catalog_never_heard_of(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "consented")
    graph = ScopeGraph(grant_clients=["sp-unknown"])
    found = collectors.collect_service_principals(graph, HOME)

    assert _names(found) == {"ChatGPT Enterprise", "Zephyr Workspace"}
    zephyr = next(a for a in found if a["display_name"] == "Zephyr Workspace")
    # Surfaced because it holds a grant — not because we claim it is AI.
    assert zephyr["ai_match"] is False
    assert zephyr["match_signal"] == "scope"
    assert zephyr["vendor"] == "Not an AI catalog match"

    chatgpt = next(a for a in found if a["display_name"] == "ChatGPT Enterprise")
    assert chatgpt["ai_match"] is True and chatgpt["confidence"] == "high"


def test_consented_scope_finds_app_only_holders_with_no_delegated_grant(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "consented")
    graph = ScopeGraph(app_role_principals=["sp-quiet"])
    assert "Legacy Timesheets" in _names(collectors.collect_service_principals(graph, HOME))


def test_consented_scope_skips_apps_holding_nothing(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "consented")
    graph = ScopeGraph()          # nobody has consented to anything
    assert _names(collectors.collect_service_principals(graph, HOME)) == {"ChatGPT Enterprise"}


def test_consented_scope_never_pulls_in_microsoft_first_party(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "consented")
    graph = ScopeGraph(grant_clients=["sp-ms"])
    assert "Microsoft Teams" not in _names(collectors.collect_service_principals(graph, HOME))


def test_all_scope_takes_every_third_party_app(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "all")
    found = collectors.collect_service_principals(ScopeGraph(), HOME)
    assert _names(found) == {"ChatGPT Enterprise", "Zephyr Workspace", "Legacy Timesheets"}
    # Our own tenant's app and Microsoft's are not third-party, so neither appears.
    assert "Our Own Tool" not in _names(found)


def test_unrecognised_scope_falls_back_to_the_safe_default(monkeypatch):
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "everything-please")
    assert collectors.scan_scope() == "ai"


def test_scope_lookup_survives_a_failing_bulk_call(monkeypatch):
    """A denied appRoleAssignedTo must not sink the whole discovery step."""
    monkeypatch.setenv("AISPM_SCAN_SCOPE", "consented")

    class Broken(ScopeGraph):
        def get_all(self, path, params=None, max_items=None):
            if "appRoleAssignedTo" in path:
                raise RuntimeError("Graph 403 Authorization_RequestDenied")
            return super().get_all(path, params, max_items)

    found = collectors.collect_service_principals(Broken(grant_clients=["sp-unknown"]), HOME)
    assert _names(found) == {"ChatGPT Enterprise", "Zephyr Workspace"}
