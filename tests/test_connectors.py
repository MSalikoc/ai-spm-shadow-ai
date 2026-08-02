"""Step 1 — connector framework + unified model + correlation tests (offline)."""
import json
import os

import connectors
from connectors import correlation, model, registry
from connectors.base import BaseCollector, ConnectorStatus, EntityType, Source


# --- Mock connector'lar (offline) -------------------------------------------
class MockAgent365(BaseCollector):
    name, source = "agent365", Source.AGENT_365

    def is_configured(self):
        return True

    def collect(self, since=None):
        return [{"pkg": "pkg-123", "appId": "APP-1", "name": "Finance Agent"}]

    def normalize(self, raw):
        return [model.make_asset(EntityType.AI_AGENT, r["name"], self.source,
                external_ids={"agent365_package_id": r["pkg"], "entra_app_id": r["appId"]},
                first_seen="2026-07-01T00:00:00Z", last_seen="2026-07-20T00:00:00Z")
                for r in raw]


class MockEntraAgentId(BaseCollector):
    name, source = "entra_agent_id", Source.ENTRA_AGENT_ID

    def is_configured(self):
        return True

    def collect(self, since=None):
        return [{"oid": "OID-9", "appId": "APP-1", "name": "Finance Agent Identity"}]

    def normalize(self, raw):
        return [model.make_asset(EntityType.AI_AGENT, r["name"], self.source,
                external_ids={"agent_identity_id": r["oid"], "entra_app_id": r["appId"]},
                first_seen="2026-06-15T00:00:00Z", last_seen="2026-07-26T00:00:00Z")
                for r in raw]


class MockDefender(BaseCollector):
    name, source = "defender_cloud_apps", Source.DEFENDER_CLOUD_APPS

    def is_configured(self):
        return True

    def collect(self, since=None):
        return [{"mdca": "m1", "name": "ChatGPT"}]

    def normalize(self, raw):
        return [model.make_asset(EntityType.AI_APPLICATION, r["name"], self.source,
                external_ids={"mdca_app_id": r["mdca"]}) for r in raw]


class FailingCollector(BaseCollector):
    name, source = "boom", Source.PURVIEW_AUDIT

    def is_configured(self):
        return True

    def collect(self, since=None):
        raise RuntimeError("API down")

    def normalize(self, raw):
        return []


# --- Testler ----------------------------------------------------------------
def test_same_model_correlation_and_failure_isolation():
    res = registry.run([MockAgent365(), MockEntraAgentId(), MockDefender(), FailingCollector()])
    # Acceptance: a connector error doesn't stop the scan
    assert res["health"]["boom"]["status"] == ConnectorStatus.ERROR
    assert res["health"]["agent365"]["status"] == ConnectorStatus.CONNECTED
    assert res["health"]["defender_cloud_apps"]["status"] == ConnectorStatus.CONNECTED
    # Acceptance: same agent from two sources → one asset
    agents = [a for a in res["assets"] if a["asset_type"] == "AI_AGENT"]
    assert len(agents) == 1
    a = agents[0]
    assert set(a["sources"]) == {"AGENT_365", "ENTRA_AGENT_ID"}      # each record's source is visible
    assert a["correlation_confidence"] == 98                          # entra_app_id ile korele
    assert a["external_ids"]["agent_identity_id"] == "OID-9"          # external ids merged
    assert a["external_ids"]["agent365_package_id"] == "pkg-123"
    assert a["first_seen"] == "2026-06-15T00:00:00Z"                  # min
    assert a["last_seen"] == "2026-07-26T00:00:00Z"                   # max
    assert len(a["_correlated_from"]) == 2                            # izlenebilirlik
    # An application without a shared id stays separate
    apps = [x for x in res["assets"] if x["asset_type"] == "AI_APPLICATION"]
    assert len(apps) == 1 and apps[0]["sources"] == ["DEFENDER_CLOUD_APPS"]


def test_name_only_does_not_merge():
    a = model.make_asset(EntityType.AI_APPLICATION, "Claude", Source.AGENT_365,
                         external_ids={"agent365_package_id": "p-a"})
    b = model.make_asset(EntityType.AI_APPLICATION, "Claude", Source.DEFENDER_CLOUD_APPS,
                         external_ids={"mdca_app_id": "m-b"})
    merged = correlation.correlate([a, b])
    assert len(merged) == 2   # same name, no strong shared id → NO merge


def test_publisher_domain_correlation_confidence():
    def mk(src, **ext):
        a = model.make_asset(EntityType.AI_APPLICATION, "X", src, external_ids=ext)
        a["publisher"], a["domain"] = "openai", "openai.com"
        return a
    merged = correlation.correlate([mk(Source.AGENT_365, agent365_package_id="p1"),
                                    mk(Source.DEFENDER_CLOUD_APPS, mdca_app_id="m1")])
    assert len(merged) == 1 and merged[0]["correlation_confidence"] == 65


def test_default_skeletons_not_configured():
    res = registry.run(connectors.default_collectors())
    for name in ("agent365", "entra_agent_id", "defender_cloud_apps",
                 "purview_audit", "purview_dspm_import"):
        assert res["health"][name]["status"] == ConnectorStatus.NOT_CONFIGURED
    assert res["assets"] == []


def test_field_availability_wrapper():
    f = model.field(model.NOT_EXPOSED_BY_API)
    assert f["status"] == "NOT_EXPOSED_BY_API" and f["values"] == []


def test_offline_fixture_correlation():
    fx = os.path.join(os.path.dirname(connectors.__file__), "fixtures", "unified_sample.json")
    with open(fx, encoding="utf-8") as f:
        data = json.load(f)
    merged = correlation.correlate(data)
    assert len(merged) == 1                          # the fixture's 2 records become one asset
    assert merged[0]["correlation_confidence"] == 98
    assert set(merged[0]["sources"]) == {"AGENT_365", "ENTRA_AGENT_ID"}


def test_deterministic_asset_id():
    a1 = model.make_asset(EntityType.AI_AGENT, "X", Source.AGENT_365,
                          external_ids={"entra_app_id": "APP-9"})
    a2 = model.make_asset(EntityType.AI_AGENT, "Y different name", Source.ENTRA_AGENT_ID,
                          external_ids={"entra_app_id": "APP-9"})
    assert a1["asset_id"] == a2["asset_id"] == "entra_app_id:APP-9"   # deterministic
