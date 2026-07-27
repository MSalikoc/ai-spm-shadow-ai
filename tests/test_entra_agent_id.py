"""Adım 3 — Microsoft Entra Agent ID collector testleri (offline mock)."""
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
    """agentIdentity/blueprint listeleri + SP başına owner/sponsor/perm/grup yönlendirir."""

    def __init__(self, data, fail=None, blueprint_fail=None, sub_fail=False):
        self._identities = data.get("identities", [])
        self._blueprints = data.get("blueprints", [])
        self._fail = fail                    # ana identity listesi hatası
        self._blueprint_fail = blueprint_fail
        self._sub_fail = sub_fail            # tüm alt-kaynaklar patlasın (PARTIAL testi)

    def _by_oid(self, path):
        # /servicePrincipals/{oid}/... → oid'yi çıkar
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
        # alt-kaynaklar
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
    c = EntraAgentIdCollector(FakeGraph(_data()))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED
    # 2 identity + 2 blueprint
    assert len(assets) == 4

    fin = next(a for a in assets if a["display_name"] == "Finance Agent Identity")
    assert fin["asset_type"] == EntityType.AGENT_IDENTITY
    assert fin["external_ids"]["entra_app_id"] == "APP-FIN-1"       # Agent365 korelasyonuna hazır
    assert fin["external_ids"]["agent_identity_id"] == "OID-1"
    assert fin["external_ids"]["agent_blueprint_id"] == "BP-1"
    ai = fin["agent_identity"]
    assert ai["account_enabled"] is True
    assert ai["owners"][0]["upn"] == "alice@contoso.com"
    assert ai["sponsors"][0]["display_name"] == "Bob Sponsor"
    # app-only vs delege ayrı
    assert ai["application_permissions"][0]["resource_display_name"] == "Microsoft Graph"
    assert ai["delegated_permissions"][0]["scopes"] == ["User.Read", "Mail.Read"]
    assert ai["group_memberships"][0]["display_name"] == "Finance-Agents"
    assert ai["raw_reference"]["source"] == "ENTRA_AGENT_ID"


def test_blueprint_normalized_separately(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    assets = EntraAgentIdCollector(FakeGraph(_data())).safe_run()
    bp = next(a for a in assets if a["display_name"] == "Unused Agent Blueprint")
    assert bp["asset_type"] == EntityType.AGENT_BLUEPRINT
    assert bp["external_ids"]["agent_blueprint_id"] == "BP-2"
    assert bp["agent_blueprint"]["publisher_domain"] == "contoso.com"


def test_metrics(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    assets = EntraAgentIdCollector(FakeGraph(_data())).safe_run()
    m = metrics(assets)
    assert m["total_identities"] == 2
    assert m["enabled"] == 1 and m["disabled"] == 1
    assert m["without_owner"] == 1 and m["without_sponsor"] == 1
    assert m["without_blueprint"] == 1          # sadece Orphan
    assert m["with_app_only_permissions"] == 1
    assert m["with_delegated_permissions"] == 1
    assert m["uncorrelated"] == 1               # Orphan'ın appId'si yok
    assert m["total_blueprints"] == 2


def test_permission_missing_does_not_stop(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), fail="Graph 403 Forbidden: Authorization_RequestDenied"))
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_sub_resource_failure_is_partial(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), sub_fail=True))
    assets = c.safe_run()                       # identity'ler yine gelir
    assert len(assets) == 4
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    fin = next(a for a in assets if a["display_name"] == "Finance Agent Identity")
    assert fin["agent_identity"]["owners"] == []   # owner alınamadı ama identity kayboldı değil


def test_blueprint_list_failure_keeps_identities(monkeypatch):
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    c = EntraAgentIdCollector(FakeGraph(_data(), blueprint_fail="Graph 400 preview not enabled"))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    assert len([a for a in assets if a["asset_type"] == EntityType.AGENT_IDENTITY]) == 2
    assert len([a for a in assets if a["asset_type"] == EntityType.AGENT_BLUEPRINT]) == 0


def test_not_configured_without_env():
    c = EntraAgentIdCollector(FakeGraph(_data()))   # ENABLE_ENTRA_AGENT_ID yok
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
    assert fin[0]["correlation_confidence"] == 98         # entra_app_id ile korele
    # identity tarafının verisi korundu (agent_identity), package tarafı da (agent365)
    assert fin[0].get("agent_identity") and fin[0].get("agent365")
