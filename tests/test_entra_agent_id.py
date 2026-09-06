"""Step 3 — Microsoft Entra Agent ID collector tests (offline mock)."""
import json
import os

import connectors
from connectors import correlation, model
from connectors.agent365 import Agent365Collector
from connectors.base import ConnectorStatus, EntityType, Source
from connectors.entra_agent_id import EntraAgentIdCollector, metrics

FX = os.path.join(os.path.dirname(connectors.__file__), "fixtures", "entra_agent_identities.json")
A365_FX = os.path.join(os.path.dirname(connectors.__file__), "fixtures", "agent365_packages.json")


class FakeGraph:
    """Routes the agentIdentity/blueprint lists + per-SP owner/sponsor/perm/group."""

    def __init__(self, data, fail=None, blueprint_fail=None, sub_fail=False):
        self._identities = data.get("identities", [])
        self._blueprints = data.get("blueprints", [])
        self._fail = fail                    # main identity list error
        self._blueprint_fail = blueprint_fail
        self._sub_fail = sub_fail            # make all sub-resources fail (PARTIAL test)

    def _by_oid(self, path):
        # /servicePrincipals/{oid}/... → extract the oid
        parts = path.split("/")
        return parts[2] if len(parts) > 2 else None

    def get_all(self, path, params=None, max_items=None):
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            if self._fail:
                raise RuntimeError(self._fail)
            return [rec["sp"] for rec in self._identities]
        if path == "/applications/microsoft.graph.agentIdentityBlueprint":
            if self._blueprint_fail:
                raise RuntimeError(self._blueprint_fail)
            return self._blueprints
        # sub-resources
        if self._sub_fail:
            raise RuntimeError("Graph 403 Forbidden on sub-resource")
        oid = self._by_oid(path)
        rec = next((r for r in self._identities if r["sp"]["id"] == oid), None)
        if rec is None:
            return []
        if path.endswith("/owners"):
            return rec.get("owners", [])
        if path.endswith("/sponsors"):
            return rec.get("sponsors", [])
        if path.endswith("/appRoleAssignments"):
            return rec.get("appRoleAssignments", [])
        if path.endswith("/oauth2PermissionGrants"):
            return rec.get("oauth2PermissionGrants", [])
        if path.endswith("/memberOf"):
            return rec.get("memberOf", [])
        return []

    def get(self, path, params=None):
        return {}


def _data():
    with open(FX, encoding="utf-8") as f:
        return json.load(f)


def test_lists_and_normalizes_identities(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_SPONSORS", "true")
    c = EntraAgentIdCollector(FakeGraph(_data()))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED
    # 2 identity + 2 blueprint
    assert len(assets) == 4

    fin = next(a for a in assets if a["display_name"] == "Finance Agent Identity")
    assert fin["asset_type"] == EntityType.AGENT_IDENTITY
    assert fin["external_ids"]["entra_app_id"] == "APP-FIN-1"       # ready for Agent365 correlation
    assert fin["external_ids"]["agent_identity_id"] == "OID-1"
    assert fin["external_ids"]["agent_blueprint_id"] == "APP-BP-FIN"
    ai = fin["agent_identity"]
    assert ai["account_enabled"] is True
    assert ai["owners"][0]["upn"] == "alice@contoso.com"
    assert ai["sponsors"][0]["display_name"] == "Bob Sponsor"
    # app-only vs delegated are separate
    assert ai["application_permissions"][0]["resource_display_name"] == "Microsoft Graph"
    assert ai["delegated_permissions"][0]["scopes"] == ["User.Read", "Mail.Read"]
    assert ai["group_memberships"][0]["display_name"] == "Finance-Agents"
    assert ai["raw_reference"]["source"] == "ENTRA_AGENT_ID"


def test_blueprint_normalized_separately(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    assets = EntraAgentIdCollector(FakeGraph(_data())).safe_run()
    bp = next(a for a in assets if a["display_name"] == "Unused Agent Blueprint")
    assert bp["asset_type"] == EntityType.AGENT_BLUEPRINT
    assert bp["external_ids"]["agent_blueprint_id"] == "APP-BP-UNUSED"
    assert bp["agent_blueprint"]["publisher_domain"] == "contoso.com"


def test_metrics(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_SPONSORS", "true")
    assets = EntraAgentIdCollector(FakeGraph(_data())).safe_run()
    m = metrics(assets)
    assert m["total_identities"] == 2
    assert m["enabled"] == 1 and m["disabled"] == 1
    assert m["without_owner"] == 1 and m["without_sponsor"] == 1
    assert m["without_blueprint"] == 1          # only Orphan
    assert m["with_app_only_permissions"] == 1
    assert m["with_delegated_permissions"] == 1
    assert m["uncorrelated"] == 0               # agent appId falls back to its object ID
    assert m["total_blueprints"] == 2


def test_permission_missing_does_not_stop(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(
        _data(), fail="Graph 403 Forbidden: Authorization_RequestDenied",
        blueprint_fail="Graph 403 Forbidden: Authorization_RequestDenied"))
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_sub_resource_failure_is_partial(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), sub_fail=True))
    assets = c.safe_run()                       # identities still come through
    assert len(assets) == 4
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    fin = next(a for a in assets if a["display_name"] == "Finance Agent Identity")
    assert fin["agent_identity"]["owners"] is None
    assert metrics(assets)["without_owner"] == 0
    assert metrics(assets)["owner_unknown"] == 2


def test_blueprint_list_failure_keeps_identities(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), blueprint_fail="Graph 400 preview not enabled"))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    assert len([a for a in assets if a["asset_type"] == EntityType.AGENT_IDENTITY]) == 2
    assert len([a for a in assets if a["asset_type"] == EntityType.AGENT_BLUEPRINT]) == 0


def test_identity_list_failure_keeps_blueprints(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), fail="Graph 403 Forbidden"))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    assert len(assets) == 2
    assert all(a["asset_type"] == EntityType.AGENT_BLUEPRINT for a in assets)


def test_not_configured_without_env():
    c = EntraAgentIdCollector(FakeGraph(_data()))   # no ENABLE_ENTRA_AGENT_ID
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.NOT_CONFIGURED


def test_identity_correlates_with_agent365_via_appid(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    entra = EntraAgentIdCollector(FakeGraph(_data())).safe_run()
    with open(A365_FX, encoding="utf-8") as f:
        pkgs = json.load(f)

    class _FG:
        def get_all(self, path, params=None, max_items=None):
            return pkgs if path == "/copilot/admin/catalog/packages" else []

        def get(self, path, params=None):
            pid = path.rsplit("/", 1)[-1]
            return next((p for p in pkgs if p.get("id") == pid), {})

    a365 = Agent365Collector(_FG()).safe_run()
    merged = correlation.correlate(entra + a365)
    fin = [a for a in merged if a["external_ids"].get("entra_app_id") == "APP-FIN-1"]
    assert len(fin) == 1
    assert set(fin[0]["sources"]) == {"AGENT_365", "ENTRA_AGENT_ID"}
    assert fin[0]["correlation_confidence"] == 98         # correlated via entra_app_id
    # the identity side's data is preserved (agent_identity), and the package side too (agent365)
    assert fin[0].get("agent_identity") and fin[0].get("agent365")


def test_default_sponsor_gate_is_unknown_not_orphan(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    monkeypatch.delenv("ENABLE_ENTRA_AGENT_SPONSORS", raising=False)

    class Graph(FakeGraph):
        def get_all(self, path, params=None, max_items=None):
            assert not path.endswith("/sponsors")
            if path.endswith(("agentIdentity", "agentIdentityBlueprint")):
                assert params == {"$top": "100"}
            return super().get_all(path, params, max_items)

    collector = EntraAgentIdCollector(Graph(_data()))
    assets = collector.safe_run()
    assert collector.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    assert metrics(assets)["without_sponsor"] == 0
    assert metrics(assets)["sponsor_unknown"] == 2
    assert all(a["agent_identity"]["collection_status"]["sponsors"] == "NOT_COLLECTED"
               for a in assets if a.get("agent_identity"))
    assert "AgentIdentity.ReadWrite.All" not in collector.required_read_roles
    assert {"AgentIdentity.Read.All", "AgentIdentityBlueprint.Read.All"} <= set(collector.required_read_roles)


def test_documented_identity_default_response_links_blueprint_by_client_id():
    agent_id = "1b7313c4-05d0-4a08-88e3-7b76c003a0a2"
    blueprint_id = "00001111-aaaa-2222-bbbb-3333cccc4444"
    collector = EntraAgentIdCollector()
    assets = collector.normalize([
        {"_kind": "identity", "sp": {
            "id": agent_id, "displayName": "My Agent Identity",
            "agentIdentityBlueprintId": blueprint_id, "servicePrincipalType": "ServiceIdentity"}},
        {"_kind": "blueprint", "app": {
            "id": "55556666-aaaa-2222-bbbb-3333cccc4444", "appId": blueprint_id,
            "displayName": "Blueprint"}},
    ])
    agent, blueprint = correlation.correlate(assets)
    assert agent["external_ids"]["entra_app_id"] == agent_id
    assert agent["related"]["blueprint_asset_id"] == blueprint["asset_id"]
    assert blueprint["agent_blueprint"]["object_id"] != blueprint["agent_blueprint"]["blueprint_id"]
