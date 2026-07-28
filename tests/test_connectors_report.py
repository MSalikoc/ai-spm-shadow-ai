"""Adım 7 — connectors_report.py: 15-bölümlü assessment + standalone HTML/JSON."""
import json
import os

import connectors
import connectors_report
import pipeline
from connectors.base import ConnectorStatus

FXDIR = os.path.join(os.path.dirname(connectors.__file__), "fixtures")


class MegaFakeGraph:
    """Dört connector'ın hepsini tek sahte Graph istemcisiyle besler (fixture dosyalarından)."""

    def __init__(self):
        with open(os.path.join(FXDIR, "agent365_packages.json"), encoding="utf-8") as f:
            self.pkgs = json.load(f)
        with open(os.path.join(FXDIR, "entra_agent_identities.json"), encoding="utf-8") as f:
            self.entra = json.load(f)
        with open(os.path.join(FXDIR, "defender_cloud_apps.json"), encoding="utf-8") as f:
            self.defender = json.load(f)
        with open(os.path.join(FXDIR, "purview_audit_records.json"), encoding="utf-8") as f:
            self.audit_records = json.load(f)
        self._poll_done = False

    def get_all(self, path, params=None, max_items=None):
        if path == "/copilot/admin/catalog/packages":
            return self.pkgs
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            return [r["sp"] for r in self.entra["identities"]]
        if path == "/applications/microsoft.graph.agentIdentityBlueprint":
            return self.entra["blueprints"]
        if "/uploadedStreams" in path and "aggregatedAppsDetails" not in path:
            return self.defender["streams"]
        if "aggregatedAppsDetails" in path:
            sid = path.split("/uploadedStreams/", 1)[1].split("/aggregatedAppsDetails", 1)[0]
            return self.defender["apps_by_stream"].get(sid, [])
        if path.endswith("/records"):
            return self.audit_records
        for parts in ("/owners", "/sponsors", "/appRoleAssignments",
                      "/oauth2PermissionGrants", "/memberOf"):
            if path.endswith(parts):
                oid = path.split("/")[2]
                rec = next((r for r in self.entra["identities"] if r["sp"]["id"] == oid), None)
                if rec is None:
                    return []
                key = {"/owners": "owners", "/sponsors": "sponsors",
                       "/appRoleAssignments": "appRoleAssignments",
                       "/oauth2PermissionGrants": "oauth2PermissionGrants",
                       "/memberOf": "memberOf"}[parts]
                return rec.get(key, [])
        return []

    def get(self, path, params=None):
        if path.rsplit("/", 1)[-1] in {p["id"] for p in self.pkgs}:
            pid = path.rsplit("/", 1)[-1]
            return next((p for p in self.pkgs if p["id"] == pid), {})
        if "/auditLog/queries/" in path:
            self._poll_done = True
            return {"id": "query-1", "status": "succeeded"}
        return {}

    def post(self, path, body):
        return {"id": "query-1", "status": "notStarted"}


def _enable_all(monkeypatch):
    for f in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS",
              "ENABLE_PURVIEW_AUDIT", "ENABLE_PREVIEW_CONNECTORS"):
        monkeypatch.setenv(f, "true")
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)


def test_full_pipeline_to_assessment(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    assert result is not None
    assert result["health"]["agent365"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["entra_agent_id"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["defender_cloud_apps"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["purview_audit"]["status"] == ConnectorStatus.CONNECTED

    a = connectors_report.assessment(result)
    assert set(a) >= {
        "executive", "data_source_coverage", "sensitive_exposure", "agent_identities",
        "agent365_packages", "shadow_ai_usage", "sensitive_interactions", "findings",
        "direction_analysis", "correlation_quality", "application_detail", "agent_detail",
        "sit_distribution", "users_and_groups", "known_gaps",
    }
    assert a["executive"]["connectors_connected"] == 4
    assert len(a["agent_identities"]["identities"]) == 2
    assert len(a["agent365_packages"]["packages"]) == 2
    assert len(a["shadow_ai_usage"]["applications"]) >= 1
    # Purview audit'teki hassas etkileşim -> ChatGPT / Finance Assistant gibi app'lerle korele
    assert isinstance(a["sensitive_interactions"]["sample"], list)
    assert a["known_gaps"]                                  # dürüst boşluklar her zaman var


def test_agent_detail_shows_blueprint_relation(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    # Bu identity Agent365 paketiyle entra_app_id üzerinden korele olduğu için
    # display_name Agent365'ten gelir ("Finance Assistant") — owner/blueprint verisi
    # yine de agent_identity alt-dict'inden taşınır (korelasyon veri kaybetmez).
    fin = next(x for x in a["agent_detail"] if x["owners"])
    assert fin["owners"][0]["display_name"] == "Alice Admin"
    assert fin["blueprint"]["display_name"] == "Finance Agent Blueprint"


def test_application_detail_matches_sensitive_exposure_count(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    exposed = [p for p in a["application_detail"]
              if p["sensitive_data_summary"]["window_30d"]["sensitive"] > 0]
    assert len(exposed) == len(a["sensitive_exposure"])


def test_json_and_html_render_without_error(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    js = connectors_report.json_string(result)
    parsed = json.loads(js)
    assert "executive" in parsed

    doc = connectors_report.html_string(result, tenant_id="contoso.onmicrosoft.com")
    assert "<html>" in doc and "AI Data Sources" in doc
    assert "contoso.onmicrosoft.com" in doc
    assert "Applications with Sensitive Data Exposure" in doc
    # Adım 7 HTML'i keşif/trafik/inceleme bölümlerini de basıyor (yalnızca 4 bölümle
    # sınırlı kalmasın diye) — agent envanteri, shadow AI trafiği, Purview etkileşim
    # log'u ve "assessment results" tablosu + tıklanınca açılan slide-over detay paneli
    # (Microsoft Zero Trust Assessment deseni: Risk/Status rozetleri, facts, Result,
    # What was checked, Remediation action).
    assert "Finance Assistant" in doc                    # Agent 365 paket tablosu
    assert "Orphan Agent Identity" in doc                # Entra Agent Identity tablosu
    assert "ChatGPT" in doc                              # Shadow AI trafik tablosu
    assert 'class="zt-row"' in doc                       # tıklanabilir assessment satırları
    assert 'id="zt-panel"' in doc and "What was checked" in doc and "Remediation action" in doc
    assert "data-detail=" in doc                         # her satırın detay verisi gömülü
    assert "alice@contoso.com" in doc                    # agent detail owner (JSON içinde) görünür


def test_html_tables_render_even_with_only_partial_data(monkeypatch):
    """Bazı connector'lar boşken (ör. entra_agent_id) sayfa çökmemeli, dürüst 'yok' mesajı basmalı."""
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    for f in ("ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"):
        monkeypatch.delenv(f, raising=False)
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)

    class _FG:
        def get_all(self, path, params=None, max_items=None):
            if path == "/copilot/admin/catalog/packages":
                return [{"id": "p1", "displayName": "Solo Agent", "applicationId": "APP-1"}]
            return []

        def get(self, path, params=None):
            return {}

    result = pipeline.run_connectors(_FG())
    doc = connectors_report.html_string(result)
    assert "Solo Agent" in doc
    assert "Entra Agent Identity keşfedilmedi" in doc
    assert "Shadow AI uygulaması keşfedilmedi" in doc


def test_coverage_section_reports_not_configured_when_all_off():
    result = {"assets": [], "coverage": {}, "health": {}, "counts": {"raw": 0, "merged": 0}}
    a = connectors_report.assessment(result)
    statuses = {r["status"] for r in a["data_source_coverage"]}
    assert statuses == {ConnectorStatus.NOT_CONFIGURED}
    assert a["sensitive_exposure"] == []
    assert a["executive"]["connectors_connected"] == 0
