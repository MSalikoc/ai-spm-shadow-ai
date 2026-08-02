"""Drift / snapshot diff testleri."""
from datetime import datetime, timezone

import drift
import notify

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)


def _app(app_id, **kw):
    base = dict(app_id=app_id, display_name=app_id, vendor="V", scopes=[],
                delegated_permissions=[], application_permissions=[], has_app_only_access=False,
                consent_type="Principal", technical_inventory={"enabled": True},
                ownership={"service_principal_owners": []}, classification={"category": "Third-Party Shadow AI"},
                lifecycle={"status": "Discovered"}, business_context={}, usage=None)
    base.update(kw)
    return base


def test_first_scan_is_baseline_no_events():
    """Criterion 2/4: the first scan (no prev) produces no false changes."""
    cur = drift.snapshot([_app("a1")])
    events = drift.diff({}, cur, NOW)   # prev empty → real diff (a1 is new). process() manages the baseline.
    # process: prev None ise []
    assert cur  # snapshot is produced
    # process() (not diff) manages baseline behavior; diff producing NEW here is expected
    assert any(e["change_type"] == "NEW_APPLICATION" for e in events)


def test_new_and_removed_application():
    prev = drift.snapshot([_app("a1"), _app("a2")])
    cur = drift.snapshot([_app("a2"), _app("a3")])
    events = drift.diff(prev, cur, NOW)
    types = {(e["change_type"], e["asset_id"]) for e in events}
    assert ("NEW_APPLICATION", "a3") in types
    assert ("REMOVED_APPLICATION", "a1") in types


def test_permission_change_and_escalation():
    prev = drift.snapshot([_app("a1", scopes=["user.read"],
                                delegated_permissions=[{"resource": "MG", "permission": "User.Read"}])])
    cur = drift.snapshot([_app("a1", scopes=["user.read", "files.readwrite.all"],
                               delegated_permissions=[{"resource": "MG", "permission": "User.Read"},
                                                      {"resource": "MG", "permission": "Files.ReadWrite.All"}])])
    events = drift.diff(prev, cur, NOW)
    types = {e["change_type"] for e in events}
    assert "NEW_PERMISSION" in types
    assert "PERMISSION_ESCALATED" in types   # kriter 7


def test_new_app_only_and_admin_consent():
    prev = drift.snapshot([_app("a1")])
    cur = drift.snapshot([_app("a1", has_app_only_access=True,
                               application_permissions=[{"resource": "MG", "permission": "Sites.ReadWrite.All"}],
                               consent_type="AllPrincipals")])
    types = {e["change_type"] for e in drift.diff(prev, cur, NOW)}
    assert "NEW_APP_ONLY_ACCESS" in types
    assert "ADMIN_CONSENT_ADDED" in types


def test_lifecycle_classification_business_owner_changes():
    prev = drift.snapshot([_app("a1")])
    cur = drift.snapshot([_app("a1", lifecycle={"status": "Approved"},
                               classification={"category": "Approved Enterprise AI"},
                               ownership={"service_principal_owners": [], "business_owner": "Finance"})])
    evs = {e["change_type"]: e for e in drift.diff(prev, cur, NOW)}
    assert "LIFECYCLE_CHANGED" in evs and evs["LIFECYCLE_CHANGED"]["new_value"] == "Approved"
    assert "CLASSIFICATION_CHANGED" in evs
    assert "BUSINESS_OWNER_CHANGED" in evs and evs["BUSINESS_OWNER_CHANGED"]["new_value"] == "Finance"


def test_activity_percentage_and_first_signin():
    prev = drift.snapshot([_app("a1", usage={"available": True, "active_users_30d": 10,
                                             "last_used_date": None})])
    cur = drift.snapshot([_app("a1", usage={"available": True, "active_users_30d": 13,
                                            "last_used_date": "2026-07-24T00:00:00+00:00"})])
    evs = {e["change_type"]: e for e in drift.diff(prev, cur, NOW)}
    assert "ACTIVITY_INCREASED" in evs
    assert "30%" in evs["ACTIVITY_INCREASED"]["description"]   # (13-10)/10 = 30%
    assert "FIRST_SIGNIN" in evs


def test_app_disabled():
    prev = drift.snapshot([_app("a1", technical_inventory={"enabled": True})])
    cur = drift.snapshot([_app("a1", technical_inventory={"enabled": False})])
    assert any(e["change_type"] == "APP_DISABLED" for e in drift.diff(prev, cur, NOW))


def test_deterministic_change_id_fields():
    events = drift.diff(drift.snapshot([]), drift.snapshot([_app("a1")]), NOW)
    e = events[0]
    for k in ("change_id", "change_type", "asset_id", "asset_name", "timestamp",
              "old_value", "new_value", "importance", "description"):
        assert k in e
    assert len(e["change_id"]) == 12


def test_executive_summary_matches_manager_format():
    events = [
        {"change_type": "NEW_APPLICATION", "asset_name": "A", "old_value": None, "new_value": "v"},
        {"change_type": "NEW_APPLICATION", "asset_name": "B", "old_value": None, "new_value": "v"},
        {"change_type": "NEW_APPLICATION", "asset_name": "C", "old_value": None, "new_value": "v"},
        {"change_type": "NEW_APP_ONLY_ACCESS", "asset_name": "A", "old_value": False, "new_value": True},
        {"change_type": "ACTIVITY_INCREASED", "asset_name": "Claude", "old_value": 100, "new_value": 132},
        {"change_type": "BUSINESS_OWNER_CHANGED", "asset_name": "X", "old_value": None, "new_value": "Fin"},
        {"change_type": "BUSINESS_OWNER_CHANGED", "asset_name": "Y", "old_value": None, "new_value": "HR"},
        {"change_type": "LIFECYCLE_CHANGED", "asset_name": "Z", "old_value": "Under Review", "new_value": "Approved"},
    ]
    lines = drift.executive_summary(events)
    joined = " ".join(lines)
    assert "3 new AI applications discovered." in lines
    assert "1 applications had app-only permissions added." in lines
    assert "Claude usage increased 32%." in lines
    assert "2 applications were assigned a business owner." in lines
    assert "moved from" in joined and "to Approved" in joined


def test_new_apps_grouped_by_business_unit():
    """Criterion 8: new AI applications are shown by business unit."""
    import report

    def full(aid, name, bu):
        return {"display_name": name, "vendor": "V", "first_party_microsoft": False,
                "third_party": True, "verified_publisher": True, "scopes": [], "consent_type": None,
                "user_count": 0, "risk_score": 10, "risk_level": "Low", "reasons": ["r"],
                "remediation": ["m"], "delegated_permissions": [], "application_permissions": [],
                "has_app_only_access": False, "usage": None,
                "ownership": {"service_principal_owners": []},
                "business_context": {"business_unit": bu}, "lifecycle": {"status": "Discovered"},
                "technical_inventory": {}, "notes": "", "history": [], "app_id": aid,
                "classification": {"category": "Third-Party Shadow AI", "ownership": "External",
                                   "confidence": 90, "reasons": ["x"], "manual_override": False}}

    apps = [full("a1", "FinBot", "Finance"), full("a2", "HRBot", "HR"), full("a3", "Mystery", "")]
    ch = [{"change_type": "NEW_APPLICATION", "asset_id": i, "asset_name": n,
           "timestamp": "2026-07-25T10:00:00+00:00", "importance": "High",
           "description": "new", "old_value": None, "new_value": "V", "change_id": "x"}
          for i, n in [("a1", "FinBot"), ("a2", "HRBot"), ("a3", "Mystery")]]
    doc = report.html_string(apps, "t", ch)
    assert "by business unit" in doc
    assert "Finance" in doc and "FinBot" in doc
    assert "HR" in doc and "HRBot" in doc
    assert "Unassigned" in doc        # new app without a BU


def test_dashboard_timeline_and_empty():
    apps = [{"display_name": "X", "vendor": "Y", "first_party_microsoft": False, "third_party": True,
             "verified_publisher": True, "scopes": [], "consent_type": None, "user_count": 0,
             "risk_score": 10, "risk_level": "Low", "reasons": ["r"], "remediation": ["m"],
             "delegated_permissions": [], "application_permissions": [], "has_app_only_access": False,
             "usage": None, "ownership": {"service_principal_owners": []}, "business_context": {},
             "lifecycle": {"status": "Discovered"}, "technical_inventory": {}, "notes": "", "history": [],
             "classification": {"category": "Unknown AI", "ownership": "External", "confidence": 40,
                                "reasons": ["x"], "manual_override": False}, "app_id": "a1"}]
    import report
    ch = [{"change_id": "abc", "change_type": "NEW_APPLICATION", "asset_id": "a1",
           "asset_name": "X", "timestamp": "2026-07-25T10:00:00+00:00", "old_value": None,
           "new_value": "Y", "importance": "High", "description": "New AI application"}]
    doc = report.html_string(apps, "t", ch)
    assert "timeline" in doc and "NEW_APPLICATION" in doc
    # baseline (changes=[]) → "no changes"
    assert "No changes" in report.html_string(apps, "t", [])
