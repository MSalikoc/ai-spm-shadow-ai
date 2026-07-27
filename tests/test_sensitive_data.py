"""Adım 6 — uygulama bazlı hassas veri korelasyonu + blueprint relate-not-merge testleri."""
from datetime import datetime, timezone

from connectors import correlation, model, sensitive_data
from connectors.base import EntityType, Source
from connectors.sensitive_data import (build_app_profiles, evaluate_findings,
                                        portfolio_summary)

NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


def _mdca_app(name, mdca_id, sanctioned, uploaded=0):
    a = model.make_asset(EntityType.AI_APPLICATION, name, Source.DEFENDER_CLOUD_APPS,
                         external_ids={"mdca_app_id": mdca_id})
    a["domain"] = name.lower() + ".example"
    a["mdca"] = {"sanctioned_state": sanctioned, "users": 30, "uploaded_bytes": uploaded,
                 "transactions": 100, "data_sensitivity": "UNDETERMINED_REQUIRES_PURVIEW"}
    return a


def _interaction(rec_id, user, app_host, direction, ts, sits=None, label=None):
    a = model.make_asset(EntityType.SENSITIVE_INTERACTION, f"{app_host}—{user}",
                         Source.PURVIEW_AUDIT,
                         external_ids={"purview_record_id": rec_id}, last_seen=ts)
    a["interaction"] = {
        "interaction_id": rec_id, "operation": "ConnectedAIAppInteraction",
        "user": user, "app_host": app_host, "app_id": None, "timestamp": ts,
        "direction": direction, "sensitivity_label_id": label,
        "sensitive_info_types": [{"name": s} for s in (sits or [])],
        "workload": "AIApp",
    }
    return a


def _observation(app_name, mdca_id, uploaded, ts):
    a = model.make_asset(EntityType.USAGE_OBSERVATION, f"{app_name} @ stream", Source.DEFENDER_CLOUD_APPS,
                         last_seen=ts)
    a["usage_observation"] = {"mdca_app_id": mdca_id, "app_name": app_name, "domain": None,
                              "direction": "UPLOADED", "users": 12, "uploaded_bytes": uploaded,
                              "transactions": 50}
    return a


def test_merges_usage_and_sensitivity_per_app():
    assets = [
        _mdca_app("ChatGPT", "mdca-chatgpt", "unsanctioned", uploaded=3000000),
        _interaction("i1", "alice@x.com", "ChatGPT", "SHARED", "2026-07-25T00:00:00Z",
                     sits=["Credit Card Number"]),
        _interaction("i2", "bob@x.com", "ChatGPT", "ALLOWED", "2026-07-20T00:00:00Z",
                     sits=["U.S. Social Security Number"], label="Confidential"),
        _observation("ChatGPT", "mdca-chatgpt", 3000000, "2026-07-24T00:00:00Z"),
    ]
    profiles = build_app_profiles(assets, now=NOW)
    chatgpt = next(p for p in profiles if p["display_name"] == "ChatGPT")
    # MDCA usage + Purview hassaslık aynı app altında birleşti
    assert chatgpt["matched_to_inventory"] is True
    assert chatgpt["sanctioned_state"] == "unsanctioned"
    assert chatgpt["affected_user_count"] == 2
    assert chatgpt["usage"]["uploaded_bytes"] == 3000000
    assert chatgpt["sensitive_data_summary"]["window_30d"]["sensitive"] == 2
    assert set(chatgpt["sit_distribution"]) == {"Credit Card Number", "U.S. Social Security Number"}
    assert {"AGENT_365"} != set(chatgpt["sources"])  # DEFENDER + PURVIEW kaynakları


def test_finding_shared_with_unsanctioned_ai():
    assets = [
        _mdca_app("ChatGPT", "mdca-chatgpt", "unsanctioned", uploaded=3000000),
        _interaction("i1", "alice@x.com", "ChatGPT", "SHARED", "2026-07-25T00:00:00Z",
                     sits=["Credit Card Number"]),
    ]
    profiles = build_app_profiles(assets, now=NOW)
    chatgpt = next(p for p in profiles if p["display_name"] == "ChatGPT")
    types = {f["type"] for f in chatgpt["findings"]}
    assert "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI" in types
    high = next(f for f in chatgpt["findings"] if f["type"] == "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI")
    assert high["severity"] == "high"


def test_access_is_not_sharing():
    # sadece ACCESSED (kurumsal veriye erişim) → paylaşım bulgusu ÜRETİLMEZ
    assets = [
        _mdca_app("SanctionedCopilot", "mdca-copilot", "sanctioned"),
        _interaction("i1", "alice@x.com", "SanctionedCopilot", "ACCESSED", "2026-07-25T00:00:00Z",
                     label="Confidential"),
    ]
    profiles = build_app_profiles(assets, now=NOW)
    p = next(pp for pp in profiles if pp["display_name"] == "SanctionedCopilot")
    types = {f["type"] for f in p["findings"]}
    assert "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI" not in types
    assert "AI_APP_ACCESSING_LABELED_DATA" in types      # erişim ayrı finding


def test_upload_volume_alone_is_undetermined():
    # MDCA upload var, Purview yok → BELİRSİZ (tek başına hassas paylaşım değil)
    assets = [_mdca_app("MysteryAI", "mdca-x", "unsanctioned", uploaded=5000000)]
    profiles = build_app_profiles(assets, now=NOW)
    p = profiles[0]
    types = {f["type"] for f in p["findings"]}
    assert "UNSANCTIONED_AI_UPLOAD_UNDETERMINED" in types
    assert "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI" not in types


def test_blocked_is_positive_control():
    assets = [
        _mdca_app("ChatGPT", "mdca-chatgpt", "unsanctioned"),
        _interaction("i1", "alice@x.com", "ChatGPT", "BLOCKED", "2026-07-25T00:00:00Z",
                     sits=["Credit Card Number"]),
    ]
    profiles = build_app_profiles(assets, now=NOW)
    p = next(pp for pp in profiles if pp["display_name"] == "ChatGPT")
    assert p["blocked"] == 1
    assert "SENSITIVE_DATA_BLOCKED_TO_AI" in {f["type"] for f in p["findings"]}
    # engellenen paylaşım "shared" sayılmaz → high finding yok
    assert "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI" not in {f["type"] for f in p["findings"]}


def test_unmatched_event_becomes_synthetic_app():
    # envanterde olmayan bir app (Copilot host) → sentetik profil, ayrı gösterilir
    assets = [_interaction("i1", "alice@x.com", "Microsoft Teams", "ACCESSED",
                           "2026-07-25T00:00:00Z", label="Confidential")]
    profiles = build_app_profiles(assets, now=NOW)
    teams = next(p for p in profiles if p["display_name"] == "Microsoft Teams")
    assert teams["matched_to_inventory"] is False


def test_portfolio_summary():
    assets = [
        _mdca_app("ChatGPT", "mdca-chatgpt", "unsanctioned", uploaded=3000000),
        _interaction("i1", "alice@x.com", "ChatGPT", "SHARED", "2026-07-25T00:00:00Z",
                     sits=["Credit Card Number"]),
        _interaction("i2", "bob@x.com", "ChatGPT", "BLOCKED", "2026-07-20T00:00:00Z",
                     sits=["U.S. Social Security Number"]),
    ]
    s = portfolio_summary(build_app_profiles(assets, now=NOW))
    assert s["apps_with_sensitive_data"] == 1
    assert s["unsanctioned_with_sensitive"] == 1
    assert s["total_affected_users"] == 2
    assert s["total_blocked"] == 1
    assert s["high_severity_findings"] >= 1


# ---------- blueprint relate-not-merge (Adım 3 açığının Adım 6 düzeltmesi) ----------

def test_blueprint_relates_not_merges():
    # Aynı blueprint'ten TÜREYEN iki identity + blueprint asset'i → COLLAPSE OLMAMALI
    id1 = model.make_asset(EntityType.AGENT_IDENTITY, "Agent Instance 1", Source.ENTRA_AGENT_ID,
                           external_ids={"agent_identity_id": "OID-1", "agent_blueprint_id": "BP-1"})
    id2 = model.make_asset(EntityType.AGENT_IDENTITY, "Agent Instance 2", Source.ENTRA_AGENT_ID,
                           external_ids={"agent_identity_id": "OID-2", "agent_blueprint_id": "BP-1"})
    bp = model.make_asset(EntityType.AGENT_BLUEPRINT, "Agent Blueprint", Source.ENTRA_AGENT_ID,
                          external_ids={"agent_blueprint_id": "BP-1"})
    merged = correlation.correlate([id1, id2, bp])
    identities = [a for a in merged if a["asset_type"] == EntityType.AGENT_IDENTITY]
    blueprints = [a for a in merged if a["asset_type"] == EntityType.AGENT_BLUEPRINT]
    assert len(identities) == 2          # iki identity AYRI kaldı (collapse yok)
    assert len(blueprints) == 1
    # relate ile bağlandılar (merge değil)
    for ident in identities:
        assert ident["related"]["blueprint_id"] == "BP-1"
        assert ident["related"]["blueprint_asset_id"] == blueprints[0]["asset_id"]
    assert set(blueprints[0]["related"]["identity_asset_ids"]) == {
        i["asset_id"] for i in identities}
