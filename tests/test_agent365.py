"""Adım 2 — Microsoft Agent 365 collector testleri (offline mock)."""
import json
import os
from datetime import datetime, timezone

import connectors
from connectors import correlation, model, registry
from connectors.agent365 import Agent365Collector, metrics
from connectors.base import ConnectorStatus, EntityType, Source

NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)
FX = os.path.join(os.path.dirname(connectors.__file__), "fixtures", "agent365_packages.json")


class FakeGraph:
    def __init__(self, packages, fail=None):
        self._packages = packages
        self._fail = fail

    def get_all(self, path, params=None, max_items=None):
        if self._fail:
            raise RuntimeError(self._fail)
        if path == "/copilot/admin/catalog/packages":
            return self._packages
        return []

    def get(self, path, params=None):
        pid = path.rsplit("/", 1)[-1]
        for p in self._packages:
            if p.get("id") == pid:
                return p     # detay = liste kaydının aynısı (mock)
        return {}


def _packages():
    with open(FX, encoding="utf-8") as f:
        return json.load(f)


def test_lists_and_normalizes_packages(monkeypatch):
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    c = Agent365Collector(FakeGraph(_packages()))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED
    assert len(assets) == 2
    fin = next(a for a in assets if a["display_name"] == "Finance Assistant")
    assert fin["asset_type"] == EntityType.AI_AGENT
    assert fin["external_ids"]["agent365_package_id"] == "pkg-finance-001"
    assert fin["external_ids"]["entra_app_id"] == "APP-FIN-1"      # korelasyona hazır
    assert fin["agent365"]["package_type"] == "declarativeAgent"
    assert fin["agent365"]["build_type"] == "partner"
    assert fin["agent365"]["available_to"] == "everyone"
    # elementDetails parse edildi
    el = fin["agent365"]["elements"][0]
    assert el["declarative_agent_id"] == "da-fin-1" and el["file_support"] is True
    assert el["raw_reference"]["source"] == "AGENT_365"           # kayıp yok


def test_build_type_and_blocked(monkeypatch):
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    assets = Agent365Collector(FakeGraph(_packages())).safe_run()
    ms = next(a for a in assets if a["display_name"] == "Microsoft 365 Copilot Agent")
    assert ms["agent365"]["build_type"] == "microsoft"
    assert ms["agent365"]["blocked"] is True
    assert ms["agent365"]["elements"][0]["bot_id"] == "bot-2"


def test_metrics(monkeypatch):
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    assets = Agent365Collector(FakeGraph(_packages())).safe_run()
    m = metrics(assets, now=NOW)
    assert m["total_registered"] == 2
    assert m["microsoft_built"] == 1 and m["partner_built"] == 1
    assert m["blocked"] == 1
    assert m["deployed_to_everyone"] == 1        # sadece MS agent
    assert m["modified_last_30d"] == 1           # sadece Finance (07-20)
    assert m["without_correlated_identity"] == 1  # MS agent'ın appId'si yok


def test_permission_missing_does_not_stop(monkeypatch):
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    c = Agent365Collector(FakeGraph([], fail="Graph 403 Forbidden: Authorization_RequestDenied"))
    assets = c.safe_run()          # exception fırlatmaz
    assert assets == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_not_configured_without_env():
    c = Agent365Collector(FakeGraph(_packages()))   # ENABLE_AGENT365 yok
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.NOT_CONFIGURED


def test_package_correlates_with_entra_app(monkeypatch):
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    a365 = Agent365Collector(FakeGraph(_packages())).safe_run()
    # Entra tarafından aynı appId ile gelen bir uygulama (Adım 3'ün yapacağı gibi)
    entra = model.make_asset(EntityType.AI_AGENT, "Finance Agent Identity", Source.ENTRA_AGENT_ID,
                             external_ids={"entra_app_id": "APP-FIN-1", "agent_identity_id": "OID-1"})
    merged = correlation.correlate(a365 + [entra])
    fin = [a for a in merged if a["external_ids"].get("entra_app_id") == "APP-FIN-1"]
    assert len(fin) == 1
    assert set(fin[0]["sources"]) == {"AGENT_365", "ENTRA_AGENT_ID"}
    assert fin[0]["external_ids"]["agent_identity_id"] == "OID-1"
    assert fin[0]["correlation_confidence"] == 98
