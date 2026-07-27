"""Adım 8 — connector kaynaklı change-tracking (connectors_drift.py) testleri."""
from datetime import datetime, timezone

import connectors_drift as cd
from connectors import model
from connectors.base import ConnectorStatus, EntityType, Source

NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


def _pkg(name, pkg_id, blocked=False):
    a = model.make_asset(EntityType.AI_AGENT, name, Source.AGENT_365,
                         external_ids={"agent365_package_id": pkg_id})
    a["agent365"] = {"blocked": blocked, "build_type": "partner"}
    return a


def _identity(name, oid, enabled=True, owners=None, sponsors=None):
    a = model.make_asset(EntityType.AGENT_IDENTITY, name, Source.ENTRA_AGENT_ID,
                         external_ids={"agent_identity_id": oid})
    a["agent_identity"] = {"account_enabled": enabled,
                           "owners": [{"upn": o} for o in (owners or [])],
                           "sponsors": [{"upn": s} for s in (sponsors or [])]}
    return a


def _mdca_app(name, mdca_id, sanctioned):
    a = model.make_asset(EntityType.AI_APPLICATION, name, Source.DEFENDER_CLOUD_APPS,
                         external_ids={"mdca_app_id": mdca_id})
    a["mdca"] = {"sanctioned_state": sanctioned}
    return a


def _interaction(rec_id, app_host, user, direction, sits=None, label=None):
    a = model.make_asset(EntityType.SENSITIVE_INTERACTION, f"{app_host}-{user}", Source.PURVIEW_AUDIT,
                         external_ids={"purview_record_id": rec_id})
    a["interaction"] = {"interaction_id": rec_id, "app_host": app_host, "user": user,
                        "direction": direction,
                        "sensitive_info_types": [{"name": s} for s in (sits or [])],
                        "sensitivity_label_id": label}
    return a


def _result(assets, health=None):
    return {"assets": assets, "coverage": {}, "health": health or {}}


# ---------- Agent 365 paket ----------
def test_new_and_blocked_package():
    prev = cd.snapshot(_result([_pkg("Finance Assistant", "pkg-1")]))
    cur = cd.snapshot(_result([_pkg("Finance Assistant", "pkg-1", blocked=True),
                              _pkg("New Bot", "pkg-2")]))
    events = cd.diff(prev, cur, NOW)
    types = {e["change_type"] for e in events}
    assert "NEW_AGENT_365_PACKAGE" in types
    assert "AGENT_365_PACKAGE_BLOCKED" in types


def test_package_unblocked():
    prev = cd.snapshot(_result([_pkg("Finance Assistant", "pkg-1", blocked=True)]))
    cur = cd.snapshot(_result([_pkg("Finance Assistant", "pkg-1", blocked=False)]))
    events = cd.diff(prev, cur, NOW)
    assert any(e["change_type"] == "AGENT_365_PACKAGE_UNBLOCKED" for e in events)


# ---------- Entra Agent Identity ----------
def test_new_identity_and_owner_sponsor_changed():
    prev = cd.snapshot(_result([_identity("Agent 1", "OID-1", owners=["alice@x.com"])]))
    cur = cd.snapshot(_result([
        _identity("Agent 1", "OID-1", owners=["bob@x.com"], sponsors=["carol@x.com"]),
        _identity("Agent 2", "OID-2"),
    ]))
    events = cd.diff(prev, cur, NOW)
    types = {e["change_type"] for e in events}
    assert "NEW_AGENT_IDENTITY" in types
    assert "AGENT_OWNER_CHANGED" in types
    assert "AGENT_SPONSOR_CHANGED" in types


def test_identity_disabled_and_enabled():
    prev = cd.snapshot(_result([_identity("Agent 1", "OID-1", enabled=True)]))
    cur = cd.snapshot(_result([_identity("Agent 1", "OID-1", enabled=False)]))
    events = cd.diff(prev, cur, NOW)
    assert any(e["change_type"] == "AGENT_IDENTITY_DISABLED" for e in events)


# ---------- Defender/MDCA sanctioned state ----------
def test_new_unsanctioned_app_and_transition():
    prev = cd.snapshot(_result([_mdca_app("ChatGPT", "m1", "unreviewed")]))
    cur = cd.snapshot(_result([_mdca_app("ChatGPT", "m1", "unsanctioned"),
                              _mdca_app("EvilAI", "m2", "unsanctioned")]))
    events = cd.diff(prev, cur, NOW)
    types_by_asset = {(e["change_type"], e["asset_id"]) for e in events}
    assert ("NEW_UNSANCTIONED_AI_APP", "mdca_app_id:m2") in types_by_asset  # yeni + doğrudan unsanctioned
    assert ("NEW_UNSANCTIONED_AI_APP", "mdca_app_id:m1") in types_by_asset  # unreviewed -> unsanctioned


def test_app_sanctioned_transition():
    prev = cd.snapshot(_result([_mdca_app("ChatGPT", "m1", "unreviewed")]))
    cur = cd.snapshot(_result([_mdca_app("ChatGPT", "m1", "sanctioned")]))
    events = cd.diff(prev, cur, NOW)
    assert any(e["change_type"] == "AI_APP_SANCTIONED" for e in events)


# ---------- Purview hassas etkileşimler ----------
def test_sensitive_interaction_blocked_allowed_and_generic():
    prev = cd.snapshot(_result([]))
    cur = cd.snapshot(_result([
        _interaction("i1", "ChatGPT", "alice@x.com", "BLOCKED", sits=["Credit Card Number"]),
        _interaction("i2", "ChatGPT", "bob@x.com", "ALLOWED", sits=["SSN"]),
        _interaction("i3", "Teams", "carol@x.com", "ACCESSED", label="Confidential"),
        _interaction("i4", "Teams", "dave@x.com", "ACCESSED"),   # hassas içerik yok -> event YOK
    ]))
    events = cd.diff(prev, cur, NOW)
    types_by_asset = {(e["change_type"], e["asset_id"]) for e in events}
    assert ("SENSITIVE_INTERACTION_BLOCKED", "i1") in types_by_asset
    assert ("SENSITIVE_INTERACTION_ALLOWED", "i2") in types_by_asset
    assert ("NEW_SENSITIVE_INTERACTION", "i3") in types_by_asset
    assert not any(e["asset_id"] == "i4" for e in events)


def test_interaction_not_renotified_once_seen():
    """Aynı interaction ikinci taramada tekrar 'yeni' sayılmamalı (30g pencere overlap)."""
    a = _interaction("i1", "ChatGPT", "alice@x.com", "BLOCKED", sits=["Credit Card Number"])
    snap1 = cd.snapshot(_result([a]))
    events1 = cd.diff({}, snap1, NOW)
    assert any(e["asset_id"] == "i1" for e in events1)
    snap2 = cd.snapshot(_result([a]))       # ikinci taramada hâlâ pencere içinde
    events2 = cd.diff(snap1, snap2, NOW)
    assert not any(e["asset_id"] == "i1" for e in events2)


def test_raw_content_never_persisted_in_snapshot():
    a = _interaction("i1", "ChatGPT", "alice@x.com", "SHARED", sits=["SSN"])
    a["interaction"]["raw_content_stored"] = True
    a["interaction"]["raw_content"] = {"prompt": "gizli müşteri verisi", "response": "..."}
    snap = cd.snapshot(_result([a]))
    assert "raw_content" not in snap["_interactions"]["i1"]
    assert "prompt" not in str(snap["_interactions"]["i1"])


# ---------- kaynak bağlantı durumu ----------
def test_purview_coverage_changed_and_generic_data_source_disconnected():
    prev = cd.snapshot(_result([], health={
        "purview_audit": {"status": ConnectorStatus.NOT_CONFIGURED},
        "agent365": {"status": ConnectorStatus.CONNECTED},
    }))
    cur = cd.snapshot(_result([], health={
        "purview_audit": {"status": ConnectorStatus.CONNECTED},
        "agent365": {"status": ConnectorStatus.PERMISSION_MISSING},
    }))
    events = cd.diff(prev, cur, NOW)
    types_by_asset = {(e["change_type"], e["asset_id"]) for e in events}
    assert ("PURVIEW_COVERAGE_CHANGED", "purview_audit") in types_by_asset
    assert ("DATA_SOURCE_DISCONNECTED", "agent365") in types_by_asset


# ---------- process() / storage kalıcılığı ----------
def test_process_none_result_is_noop(monkeypatch):
    calls = []
    monkeypatch.setattr("storage.read_json", lambda name: calls.append(("read", name)))
    monkeypatch.setattr("storage.write_json", lambda name, obj: calls.append(("write", name)))
    assert cd.process(None) == []
    assert calls == []                      # storage'a hiç dokunulmadı


def test_process_first_scan_is_baseline(monkeypatch):
    monkeypatch.setattr("storage.read_json", lambda name: None)
    written = {}
    monkeypatch.setattr("storage.write_json", lambda name, obj: written.setdefault(name, obj))
    events = cd.process(_result([_pkg("Finance Assistant", "pkg-1")]))
    assert events == []                     # baseline: değişiklik üretmez
    assert "connectors_snapshot.json" in written
    assert "connectors_changes.json" not in written


def test_process_second_scan_emits_and_persists(monkeypatch):
    prev_snap = cd.snapshot(_result([_pkg("Finance Assistant", "pkg-1")]))
    monkeypatch.setattr("storage.read_json",
                       lambda name: prev_snap if name == "connectors_snapshot.json" else None)
    written = {}
    monkeypatch.setattr("storage.write_json", lambda name, obj: written.setdefault(name, obj))
    events = cd.process(_result([_pkg("Finance Assistant", "pkg-1", blocked=True)]), now=NOW)
    assert any(e["change_type"] == "AGENT_365_PACKAGE_BLOCKED" for e in events)
    assert "connectors_changes.json" in written
    assert written["connectors_changes.json"]["events"][0]["change_type"] == "AGENT_365_PACKAGE_BLOCKED"


def test_recent_filters_by_window(monkeypatch):
    old = cd._ev(datetime(2026, 6, 1, tzinfo=timezone.utc), "NEW_AGENT_365_PACKAGE",
                "p1", "P1", None, "P1", "x")
    new = cd._ev(NOW, "NEW_AGENT_365_PACKAGE", "p2", "P2", None, "P2", "x")
    monkeypatch.setattr("storage.read_json", lambda name: {"events": [new, old]})
    out = cd.recent(days=14, now=NOW)
    assert [e["asset_id"] for e in out] == ["p2"]


def test_executive_summary_lines():
    events = [
        cd._ev(NOW, "NEW_UNSANCTIONED_AI_APP", "m1", "EvilAI", None, "unsanctioned", "x"),
        cd._ev(NOW, "SENSITIVE_INTERACTION_ALLOWED", "i1", "ChatGPT", None, "ALLOWED", "x"),
    ]
    lines = cd.executive_summary(events)
    assert any("onaysız" in l for l in lines)
    assert any("engellenmedi" in l for l in lines)
