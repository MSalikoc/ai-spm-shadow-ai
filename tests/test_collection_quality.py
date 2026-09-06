"""Collection gaps must not become negative security evidence."""
from datetime import datetime, timezone

import assessment
import assessment_report
import collectors
import drift
import report
from graph_client import GraphError


def test_failed_metadata_is_unknown_in_control_and_report():
    class Graph:
        def get_all(self, *args, **kwargs):
            return []

        def get_checked(self, *args, **kwargs):
            raise GraphError(403, "fixture", "denied")

    app = {"sp_id": "fixture", "display_name": "AI", "publisher": "Unknown"}
    collectors.enrich_with_ownership(Graph(), [app])
    assert app["technical_inventory"]["credential_count"] is None
    assert assessment.t_credentials({"apps": [app]})[0] == assessment.NOT_ASSESSED
    assert "Credential metadata unavailable" in report._governance_block(app)
    assert collectors.core_health([app])["status"] == "PARTIALLY_CONNECTED"


def test_partial_usage_never_passes_usage_controls():
    apps = [{"display_name": "Known", "usage": {"available": True, "active_users_30d": 2}},
            {"display_name": "Unknown", "usage": {"available": False}}]
    ctx = assessment.context(apps)
    for control in (assessment.t_blocked_in_use, assessment.t_unused_privileged,
                    assessment.t_never_used, assessment.t_growth, assessment.t_signin_visibility):
        assert control(ctx)[0] == assessment.NOT_ASSESSED


def test_short_usage_window_does_not_pass_thirty_day_control():
    ctx = assessment.context([{"usage": {"available": True, "window_days": 7}}])
    assert assessment.t_unused_privileged(ctx)[0] == assessment.NOT_ASSESSED


def test_incomplete_source_cannot_assert_a_clean_control():
    results = assessment.run([], health={
        "defender_cloud_apps": {"status": "PARTIALLY_CONNECTED", "count": 1}})
    reviewed = next(r for r in results if r["id"] == "AISPM-2004")
    assert reviewed["status"] == assessment.NOT_ASSESSED
    assert reviewed["evidence_complete"] is False


def test_known_failure_survives_partial_source_but_not_as_complete_coverage():
    results = assessment.run([], estate={
        "vendors": [{"vendor": "AI", "evidence": {"web"}, "sanctioned": False}],
        "unattached_agents": []}, health={
            "defender_cloud_apps": {"status": "PARTIALLY_CONNECTED", "count": 1}})
    result = next(r for r in results if r["id"] == "AISPM-2004")
    assert result["status"] == assessment.FAILED
    assert assessment.summary([result])["assessable"] == 0


def test_failed_owner_read_is_not_a_drift_removal():
    original = {"app_id": "a", "ownership": {"service_principal_owners": [{"id": "owner"}]}}
    failed = {"app_id": "a", "ownership": {"service_principal_owners": []},
              "collection_errors": {"owners": "403"}}
    changes = drift.diff(drift.snapshot([original]), drift.snapshot([failed]),
                         now=datetime(2026, 9, 6, tzinfo=timezone.utc))
    assert not any(c["change_type"] == "OWNER_REMOVED" for c in changes)


def test_core_partial_collection_reduces_dashboard_completeness():
    source = {"status": "CONNECTED", "count": 1}
    health = {key: source for key in ("agent365", "entra_agent_id",
                                     "defender_cloud_apps", "purview_audit")}
    coverage = assessment_report._coverage_confidence([], health, [{"usage": None}])
    assert coverage["connected"] == 4
    assert "Partial" in coverage["rows"]


def test_one_block_does_not_hide_a_separate_allowed_sensitive_transfer():
    vendor = {"vendor": "AI", "sensitive_types": {"SSN"}, "blocked": 1,
              "sensitive_allowed": 1, "sensitive_unknown": 0}
    ctx = assessment.context([], {"vendors": [vendor]}, {
        "purview_audit": {"status": "CONNECTED", "count": 1}})
    assert assessment.t_dlp_block(ctx)[0] == assessment.FAILED
    vendor.update(sensitive_allowed=0, sensitive_unknown=1)
    assert assessment.t_dlp_block(ctx)[0] == assessment.NOT_ASSESSED


def test_actual_defender_sanction_state_is_used():
    vendor = {"vendor": "AI", "evidence": {"web"}, "web": {"sanctioned": "sanctioned"}}
    ctx = assessment.context([], {"vendors": [vendor]}, {
        "defender_cloud_apps": {"status": "CONNECTED", "count": 1}})
    assert assessment.t_shadow_discovery(ctx)[0] == assessment.PASSED


def test_connector_checkpoint_tenant_and_profile_clock_are_explicit(monkeypatch):
    import connectors
    import pipeline

    captured = {}
    instant = datetime(2026, 8, 1, tzinfo=timezone.utc)

    def collectors_for(graph, tenant_id=None):
        captured["tenant"] = tenant_id
        return []

    def profiles_for(assets, now=None):
        captured["clock"] = now
        return []

    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    monkeypatch.setenv("AISPM_TENANT_ID", "must-not-be-inferred")
    monkeypatch.setattr(connectors, "default_collectors", collectors_for)
    monkeypatch.setattr(connectors.registry, "run", lambda _: {"assets": []})
    monkeypatch.setattr(connectors.sensitive_data, "build_app_profiles", profiles_for)
    pipeline.run_connectors(None, tenant_id="authenticated-tenant", now=instant)
    assert captured == {"tenant": "authenticated-tenant", "clock": instant}
    pipeline.run_connectors(None)
    assert captured["tenant"] is None


def test_connector_unknown_ownership_is_not_a_change():
    import connectors_drift

    known = {"asset_id": "agent", "agent_identity": {
        "owners": [{"id": "owner"}], "sponsors": [{"id": "sponsor"}]}}
    unknown = {"asset_id": "agent", "agent_identity": {"owners": None, "sponsors": None}}
    previous = connectors_drift.snapshot({"assets": [known]})
    current = connectors_drift.snapshot({"assets": [unknown]})
    assert current["identities"]["agent"]["owners"] is None
    assert connectors_drift.diff(previous, current) == []
