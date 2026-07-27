"""pipeline.connectors_enabled()/run_connectors() — flag-off no-op garantisi."""
import pipeline


def test_disabled_by_default(monkeypatch):
    for f in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID",
              "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT",
              "PURVIEW_DSPM_IMPORT_PATH"):
        monkeypatch.delenv(f, raising=False)
    assert pipeline.connectors_enabled() is False
    assert pipeline.run_connectors(graph=None) is None    # mevcut pipeline'a sıfır etki


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
    """Tüm connector'lar sahte veriyle çalışır; registry+correlation+profil zinciri kırılmaz."""
    import connectors
    from connectors.agent365 import Agent365Collector
    from connectors.base import Source

    class _FG:
        def get_all(self, path, params=None, max_items=None):
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
    assert result["health"]["agent365"]["status"] == "CONNECTED"
