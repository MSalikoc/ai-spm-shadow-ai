"""pipeline.connectors_enabled()/run_connectors() — flag-off no-op garantisi."""
import pipeline


def test_disabled_by_default(monkeypatch):
    for f in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID",
              "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT",
              "PURVIEW_DSPM_IMPORT_PATH"):
        monkeypatch.delenv(f, raising=False)
    assert pipeline.connectors_enabled() is False
    assert pipeline.run_connectors(graph=None) is None    # zero impact on the existing pipeline


def test_enabled_when_any_flag_true(monkeypatch):
    monkeypatch.delenv("ENABLE_AGENT365", raising=False)
    monkeypatch.setenv("ENABLE_ENTRA_AGENT_ID", "true")
    assert pipeline.connectors_enabled() is True


def test_enabled_when_dspm_path_set(monkeypatch):
    for f in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID",
              "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"):
        monkeypatch.delenv(f, raising=False)
    monkeypatch.setenv("PURVIEW_DSPM_IMPORT_PATH", "/some/path.json")
    assert pipeline.connectors_enabled() is True


def test_run_connectors_end_to_end(monkeypatch):
    """All connectors run with fake data; the registry+correlation+profile chain doesn't break."""
    import connectors
    from connectors.agent365 import Agent365Collector
    from connectors.base import Source

    class _FG:
        def get_all(self, path, params=None, max_items=None, headers=None):
            if path == "/copilot/admin/catalog/packages":
                return [{"id": "p1", "displayName": "Finance Assistant",
                         "applicationId": "APP-1", "publisher": "Contoso"}]
            return []

        def get(self, path, params=None):
            return {}

    monkeypatch.setenv("ENABLE_AGENT365", "true")
    for f in ("ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"):
        monkeypatch.delenv(f, raising=False)
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)

    result = pipeline.run_connectors(_FG())
    assert result is not None
    assert result["counts"]["raw"] == 1
    assert "profiles" in result and "portfolio" in result
    assert result["health"]["agent365"]["status"] == "PARTIALLY_CONNECTED"


def test_synthetic_tenant_uses_documented_shapes_and_explicit_sample_clock(monkeypatch):
    import connectors_report
    import portal
    import scoring
    from scripts.make_sample import build_fleet
    from scripts.sample_tenant import NOW, SampleGraph
    for flag in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS",
                 "ENABLE_PREVIEW_CONNECTORS", "ENABLE_PURVIEW_AUDIT"):
        monkeypatch.setenv(flag, "true")
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)
    graph = SampleGraph()
    result = pipeline.run_connectors(graph, now=NOW)
    assert result["health"]["defender_cloud_apps"]["status"] == "CONNECTED"
    assert result["coverage"]["purview_audit"]["checkpoint_status"] == "DISABLED_NO_VERIFIED_TENANT"
    section = connectors_report.assessment(result, now=NOW)["sensitive_interactions"]
    assert len(section["records"]) == len(graph.records)
    assert section["event_metrics"]["window_30d"]["sensitive_allowed_count"] > 0
    assert section["event_metrics"]["window_30d"]["sensitive_blocked_count"] > 0
    mdca = next(a["mdca"] for a in result["assets"] if a.get("mdca"))
    assert mdca["devices"] is None
    assert mdca["traffic_bytes"] == mdca["uploaded_bytes"] + mdca["downloaded_bytes"]
    estate = portal.build_estate(scoring.score_all(build_fleet()), result, now=NOW)
    assert sum({"oauth", "web"} <= set(v["evidence"]) for v in estate["vendors"]) >= 9
    assert all(a["agent365"]["detail_status"] == "COLLECTED"
               for a in result["assets"] if a.get("agent365"))
