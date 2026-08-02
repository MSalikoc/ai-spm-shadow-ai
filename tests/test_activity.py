"""Real usage / sign-in activity tests."""
from datetime import datetime, timedelta, timezone

import collectors
import report

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class ActivityGraph:
    """
    In-memory signIns mock. Sign-ins are pulled in bulk with a chunked
    `appId eq '..' or ..` filter and grouped by each record's own appId, so the mock
    honours the filter and every record carries an appId, exactly like real Graph.
    """
    def __init__(self, user_signins=None, sp_signins=None, fail_probe=False):
        self._user = user_signins or []
        self._sp = sp_signins or []
        self._fail = fail_probe

    def get_all(self, path, params=None, max_items=None):
        if path == "/auditLogs/signIns":
            if self._fail:
                raise RuntimeError("Graph 403: sign-in logs require P1")
            flt = (params or {}).get("$filter", "")
            if params and params.get("$top") == "1":  # probe
                return self._user[:1]
            rows = self._sp if "servicePrincipal" in flt else self._user
            return [r for r in rows if f"appId eq '{r.get('appId')}'" in flt]
        return []

    def get(self, path, params=None):
        return {}


def test_usage_windows_and_last_used():
    users = [
        {"appId": "a1", "createdDateTime": _iso(2), "userId": "u1", "ipAddress": "1.1.1.1",
         "location": {"countryOrRegion": "TR"}, "status": {"errorCode": 0}},
        {"appId": "a1", "createdDateTime": _iso(5), "userId": "u2", "ipAddress": "2.2.2.2",
         "location": {"countryOrRegion": "DE"}, "status": {"errorCode": 0}},
        {"appId": "a1", "createdDateTime": _iso(20), "userId": "u3", "ipAddress": "1.1.1.1",
         "location": {"countryOrRegion": "TR"}, "status": {"errorCode": 50126}},
        {"appId": "a1", "createdDateTime": _iso(70), "userId": "u4", "ipAddress": "3.3.3.3",
         "location": {"countryOrRegion": "US"}, "status": {"errorCode": 0}},
    ]
    graph = ActivityGraph(user_signins=users)
    apps = [{"app_id": "a1", "user_count": 150}]
    collectors.enrich_with_signin_activity(graph, apps, now=NOW)
    u = apps[0]["usage"]

    assert u["available"] is True
    assert u["consent_user_count"] == 150
    assert u["active_users_7d"] == 2          # u1,u2
    assert u["active_users_30d"] == 3         # u1,u2,u3
    assert u["active_users_90d"] == 4         # +u4
    assert u["unique_user_count"] == 4
    assert u["unique_ip_count"] == 3
    assert u["country_count"] == 3
    assert u["successful_signins_30d"] == 2   # u1,u2 (u3 failed, u4 outside 30d)
    assert u["failed_signins_30d"] == 1       # u3
    assert u["never_used"] is False
    assert u["inactive_30d"] is False
    assert u["last_delegated_signin"].startswith("2026-07-23")  # 2 days ago
    assert len(u["daily_active_30d"]) == 30


def test_never_used_and_inactive():
    graph = ActivityGraph(user_signins=[])   # no sign-ins at all
    apps = [{"app_id": "a1", "user_count": 5}]
    collectors.enrich_with_signin_activity(graph, apps, now=NOW)
    u = apps[0]["usage"]
    assert u["never_used"] is True
    assert u["inactive_30d"] is True and u["inactive_90d"] is True
    assert report._usage_type(apps[0]) == "unused"


def test_app_only_service_principal_signin():
    graph = ActivityGraph(
        user_signins=[],
        sp_signins=[{"appId": "a1", "createdDateTime": _iso(3), "servicePrincipalId": "sp1"}])
    apps = [{"app_id": "a1", "user_count": 0, "has_app_only_access": True}]
    collectors.enrich_with_signin_activity(graph, apps, now=NOW)
    u = apps[0]["usage"]
    assert u["last_service_principal_signin"].startswith("2026-07-22")  # 3 days ago
    assert u["last_used_date"] is not None


def test_graceful_degradation_without_p1():
    graph = ActivityGraph(fail_probe=True)
    apps = [{"app_id": "a1", "user_count": 10}, {"app_id": "a2", "user_count": 3}]
    collectors.enrich_with_signin_activity(graph, apps, now=NOW)
    assert all(a["usage"] is None for a in apps)   # kesintisiz devam
    assert report._usage_type(apps[0]) == "unknown"


def test_dashboard_shows_usage_cards_and_trend():
    apps = [{"display_name": "ActiveBot", "vendor": "X", "first_party_microsoft": False,
             "third_party": True, "verified_publisher": True, "scopes": ["user.read"],
             "consent_type": "Principal", "user_count": 10, "risk_score": 20,
             "risk_level": "Low", "reasons": ["r"], "remediation": ["m"],
             "delegated_permissions": [], "application_permissions": [], "has_app_only_access": False,
             "usage": {"available": True, "consent_user_count": 10, "active_users_7d": 3,
                       "active_users_30d": 8, "active_users_90d": 9, "successful_signins_30d": 40,
                       "failed_signins_30d": 2, "unique_user_count": 9, "unique_ip_count": 5,
                       "country_count": 2, "last_used_date": "2026-07-24T10:00:00+00:00",
                       "last_delegated_signin": "2026-07-24T10:00:00+00:00",
                       "last_service_principal_signin": None, "never_used": False,
                       "inactive_30d": False, "inactive_90d": False, "growth_7d": 1,
                       "daily_active_30d": [1, 2, 0, 3, 2, 1, 4, 2] + [0] * 22}}]
    doc = report.html_string(apps, "t")
    assert "Usage & Activity" in doc
    assert "Active user trend" in doc
    assert 'data-group="usage"' in doc          # usage filter
    assert 'data-usage="active"' in doc         # row tag
    assert "<polyline" in doc                    # trend chart rendered


def test_dashboard_graceful_when_no_activity():
    apps = [{"display_name": "X", "vendor": "Y", "first_party_microsoft": False,
             "third_party": True, "verified_publisher": True, "scopes": ["user.read"],
             "consent_type": "Principal", "user_count": 1, "risk_score": 10,
             "risk_level": "Low", "reasons": ["r"], "remediation": ["m"],
             "delegated_permissions": [], "application_permissions": [],
             "has_app_only_access": False, "usage": None}]
    doc = report.html_string(apps, "t")
    assert "Entra ID P1" in doc                  # graceful message


def test_bulk_pull_routes_rows_to_the_right_app():
    """One chunked query returns rows for several apps; each app must get only its own."""
    users = [
        {"appId": "a1", "createdDateTime": _iso(1), "userId": "u1", "status": {"errorCode": 0}},
        {"appId": "a1", "createdDateTime": _iso(2), "userId": "u2", "status": {"errorCode": 0}},
        {"appId": "a2", "createdDateTime": _iso(3), "userId": "u9", "status": {"errorCode": 0}},
    ]
    apps = [{"app_id": "a1", "user_count": 0}, {"app_id": "a2", "user_count": 0},
            {"app_id": "a3", "user_count": 0}]
    collectors.enrich_with_signin_activity(ActivityGraph(user_signins=users), apps, now=NOW)

    assert apps[0]["usage"]["unique_user_count"] == 2
    assert apps[1]["usage"]["unique_user_count"] == 1
    assert apps[2]["usage"]["never_used"] is True     # no rows, still assessed


def test_signin_pull_is_chunked_not_one_query_per_app():
    """The whole point of the bulk pull: query count scales with chunks, not apps."""
    calls = []

    class Counting(ActivityGraph):
        def get_all(self, path, params=None, max_items=None):
            if path == "/auditLogs/signIns" and (params or {}).get("$top") != "1":
                calls.append((params or {}).get("$filter", ""))
            return super().get_all(path, params, max_items)

    apps = [{"app_id": f"a{i}", "user_count": 0} for i in range(30)]
    collectors.enrich_with_signin_activity(Counting(user_signins=[]), apps, now=NOW)

    # 30 apps over a 15-app chunk = 2 chunks, times 2 passes (user + servicePrincipal).
    assert len(calls) == 4
    assert all(f.count("appId eq") <= 15 for f in calls)
    assert sum(f.count("appId eq") for f in calls) == 60   # every app covered, twice


def test_activity_window_is_configurable(monkeypatch):
    monkeypatch.setenv("AISPM_ACTIVITY_DAYS", "30")
    assert collectors.activity_days() == 30
    monkeypatch.setenv("AISPM_ACTIVITY_DAYS", "999")   # clamped to the log retention max
    assert collectors.activity_days() == 90
    monkeypatch.setenv("AISPM_ACTIVITY_DAYS", "nonsense")
    assert collectors.activity_days() == 90
