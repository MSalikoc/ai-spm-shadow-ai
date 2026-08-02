"""Step 4 — Microsoft Defender for Cloud Apps (Shadow AI) collector tests (offline mock)."""
import json
import os

import connectors
from connectors.base import ConnectorStatus, EntityType
from connectors.defender_cloud_apps import DefenderCloudAppsCollector, metrics

FX = os.path.join(os.path.dirname(connectors.__file__), "fixtures", "defender_cloud_apps.json")


class FakeGraph:
    """Routes the uploadedStreams list + per-stream aggregatedAppsDetails."""

    def __init__(self, data, fail=None, stream_fail=None):
        self._streams = data["streams"]
        self._apps = data["apps_by_stream"]
        self._fail = fail                # stream list error
        self._stream_fail = stream_fail  # make this stream_id's agg call fail

    def get_all(self, path, params=None, max_items=None):
        if path.endswith("/uploadedStreams"):
            if self._fail:
                raise RuntimeError(self._fail)
            return self._streams
        if "aggregatedAppsDetails" in path:
            sid = path.split("/uploadedStreams/", 1)[1].split("/aggregatedAppsDetails", 1)[0]
            if self._stream_fail and sid == self._stream_fail:
                raise RuntimeError("Graph 500 stream error")
            return self._apps.get(sid, [])
        return []

    def get(self, path, params=None):
        return {}


def _data():
    with open(FX, encoding="utf-8") as f:
        return json.load(f)


def _enable(monkeypatch):
    monkeypatch.setenv("ENABLE_DEFENDER_CLOUD_APPS", "true")
    monkeypatch.setenv("ENABLE_PREVIEW_CONNECTORS", "true")


def test_filters_to_ai_and_aggregates(monkeypatch):
    _enable(monkeypatch)
    c = DefenderCloudAppsCollector(FakeGraph(_data()))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED

    apps = [a for a in assets if a["asset_type"] == EntityType.AI_APPLICATION]
    names = {a["display_name"] for a in apps}
    # ChatGPT (category), SomeAI (category), Claude (catalog domain — category isn't AI) → AI
    # Salesforce (CRM, not in the catalog) → filtered out
    assert names == {"ChatGPT", "SomeAI Writer", "Claude"}
    assert "Salesforce" not in names

    chatgpt = next(a for a in apps if a["display_name"] == "ChatGPT")
    # two-stream aggregate: traffic additive, users conservative max
    assert chatgpt["mdca"]["uploaded_bytes"] == 3000000
    assert chatgpt["mdca"]["transactions"] == 8000
    assert chatgpt["mdca"]["users"] == 40
    assert chatgpt["mdca"]["stream_count"] == 2
    assert chatgpt["external_ids"]["mdca_app_id"] == "mdca-chatgpt"
    assert chatgpt["first_seen"] == "2026-06-20T00:00:00Z"
    assert chatgpt["last_seen"] == "2026-07-26T00:00:00Z"


def test_claude_matched_by_catalog_domain(monkeypatch):
    _enable(monkeypatch)
    assets = DefenderCloudAppsCollector(FakeGraph(_data())).safe_run()
    claude = next(a for a in assets if a.get("display_name") == "Claude")
    # even though its category is "Collaboration", it was counted as AI via the catalog domain (claude.ai)
    assert claude["mdca"]["category"] == "Collaboration"
    assert claude["domain"] == "claude.ai"


def test_usage_observations_emitted(monkeypatch):
    _enable(monkeypatch)
    assets = DefenderCloudAppsCollector(FakeGraph(_data())).safe_run()
    obs = [a for a in assets if a["asset_type"] == EntityType.USAGE_OBSERVATION]
    # ChatGPT x2 streams + SomeAI + Claude = 4 observations (no Salesforce)
    assert len(obs) == 4
    o = next(x for x in obs if x["usage_observation"]["app_name"] == "ChatGPT"
             and x["usage_observation"]["stream_id"] == "stream-fw-1")
    assert o["usage_observation"]["direction"] == "UPLOADED"
    assert o["usage_observation"]["data_sensitivity"] == "UNDETERMINED_REQUIRES_PURVIEW"
    # observations do NOT put mdca_app_id in external_ids (avoids id collision with the app asset)
    assert o["external_ids"]["mdca_app_id"] is None


def test_upload_volume_not_marked_sensitive(monkeypatch):
    _enable(monkeypatch)
    assets = DefenderCloudAppsCollector(FakeGraph(_data())).safe_run()
    chatgpt = next(a for a in assets if a.get("display_name") == "ChatGPT" and a.get("mdca"))
    # high upload volume ALONE doesn't count as sensitive sharing
    assert chatgpt["mdca"]["data_sensitivity"] == "UNDETERMINED_REQUIRES_PURVIEW"
    assert chatgpt["mdca"]["sensitive_data_types"]["status"] == "NOT_EXPOSED_BY_API"


def test_metrics(monkeypatch):
    _enable(monkeypatch)
    assets = DefenderCloudAppsCollector(FakeGraph(_data())).safe_run()
    m = metrics(assets)
    assert m["total_ai_apps"] == 3
    assert m["sanctioned"] == 1 and m["unsanctioned"] == 1 and m["unreviewed"] == 1
    assert m["total_users_observed"] == 55          # 40 + 5 + 10 (no dedupe)
    assert m["total_uploaded_bytes"] == 3500100     # 3M + 100 + 500K
    assert m["high_risk_apps"] == 1                 # SomeAI riskScore 2 (<=3)
    assert m["usage_observations"] == 4
    assert m["uncorrelated"] == 3                   # none carry an entra_app_id


def test_permission_missing_does_not_stop(monkeypatch):
    _enable(monkeypatch)
    c = DefenderCloudAppsCollector(FakeGraph(_data(), fail="Graph 403 Forbidden: Authorization_RequestDenied"))
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_partial_when_one_stream_fails(monkeypatch):
    _enable(monkeypatch)
    c = DefenderCloudAppsCollector(FakeGraph(_data(), stream_fail="stream-fw-1"))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    # stream-proxy-2 still comes through → ChatGPT/SomeAI/Claude with proxy data
    apps = [a for a in assets if a["asset_type"] == EntityType.AI_APPLICATION]
    chatgpt = next(a for a in apps if a["display_name"] == "ChatGPT")
    assert chatgpt["mdca"]["stream_count"] == 1     # only the proxy stream was counted


def test_not_configured_without_preview_flag(monkeypatch):
    monkeypatch.setenv("ENABLE_DEFENDER_CLOUD_APPS", "true")   # no PREVIEW flag
    monkeypatch.delenv("ENABLE_PREVIEW_CONNECTORS", raising=False)
    c = DefenderCloudAppsCollector(FakeGraph(_data()))
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.NOT_CONFIGURED


# --- traffic volume: the schema does not use the names we guessed ----------
def _one(app):
    c = DefenderCloudAppsCollector(graph=None)
    return c._metrics_of(app)


def test_traffic_is_found_under_whatever_the_schema_calls_it():
    """
    A fixed guess list matched none of the real field names, so every application
    reported 0 bytes while the portal showed gigabytes.
    """
    for upload_key in ("uploadedBytes", "uploadVolume", "bytesUploaded",
                       "totalUploadedVolumeInBytes", "uploadedDataVolume"):
        m = _one({upload_key: 12 * 1024**3, "displayName": "ChatGPT"})
        assert m["uploaded_bytes"] == 12 * 1024**3, upload_key


def test_upload_and_download_are_never_confused():
    m = _one({"downloadedBytes": 500, "uploadedBytes": 100})
    assert m["uploaded_bytes"] == 100
    assert m["downloaded_bytes"] == 500

    # Only a download field present: upload must stay 0, not borrow the download value.
    only_down = _one({"totalDownloadedVolume": 900})
    assert only_down["uploaded_bytes"] == 0
    assert only_down["downloaded_bytes"] == 900


def test_total_traffic_is_kept_when_the_split_is_not_reported():
    m = _one({"trafficBytes": 7 * 1024**3})
    assert m["traffic_bytes"] == 7 * 1024**3
    assert m["uploaded_bytes"] == 0        # not invented from the total


def test_traffic_search_ignores_upload_and_download_fields():
    m = _one({"uploadedBytes": 10, "downloadedBytes": 20, "totalTrafficVolume": 30})
    assert m["traffic_bytes"] == 30


def test_booleans_are_never_read_as_a_count():
    m = _one({"isUploadBlocked": True, "uploadedBytes": 42})
    assert m["uploaded_bytes"] == 42


def test_exact_names_still_win_over_the_pattern_search():
    m = _one({"uploadedBytes": 5, "someOtherUploadThing": 999})
    assert m["uploaded_bytes"] == 5


def test_users_and_transactions_survive_a_renamed_field():
    m = _one({"distinctUserCount": 486, "totalTransactions": 570})
    assert m["users"] == 486
    assert m["transactions"] == 570
