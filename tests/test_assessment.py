"""The assessment catalogue and the page it renders."""
import json

import assessment
import assessment_report


def _app(**kw):
    base = {"app_id": "app-1", "sp_id": "sp-1", "display_name": "SomeAI",
            "vendor": "SomeAI", "publisher": "Some Corp", "verified_publisher": True,
            "third_party": True, "first_party_microsoft": False,
            "scopes": ["user.read"], "delegated_permissions": [],
            "application_permissions": [], "has_app_only_access": False,
            "consent_type": "Principal", "user_count": 4, "risk_score": 10,
            "risk_level": "Low", "reasons": [], "remediation": [],
            "asset_type": "application",
            "ownership": {"business_owner": "owner@contoso.com"},
            "business_context": {"purpose": "Testing"},
            "lifecycle": {"status": "Approved", "next_review_date": None},
            "classification": {"category": "Approved Enterprise AI", "confidence": 90},
            "technical_inventory": {"credential_count": 0},
            "usage": {"available": True, "active_users_30d": 4, "inactive_30d": False,
                      "never_used": False, "growth_7d": 0, "last_used_date": "2026-08-01"}}
    base.update(kw)
    return base


CONNECTED = {"defender_cloud_apps": {"status": "CONNECTED", "count": 3},
             "purview_audit": {"status": "CONNECTED", "count": 5},
             "agent365": {"status": "CONNECTED", "count": 2}}


# --- the catalogue itself ---------------------------------------------------

def test_catalogue_is_well_formed():
    ids = [t[0] for t in assessment.TESTS]
    assert len(ids) == len(set(ids)), "test IDs must be unique — they are the record key"
    for (tid, name, pillar, risk, impact, effort, req, fn,
         checked, recommendation, actions) in assessment.TESTS:
        assert pillar in assessment.PILLARS, tid
        assert risk in ("High", "Medium", "Low"), tid
        assert callable(fn), tid
        assert len(checked) >= 1 and all(len(p) > 40 for p in checked), tid
        assert recommendation and req, tid
        assert isinstance(actions, list), tid


def test_every_test_produces_a_verdict():
    results = assessment.run([_app()], health=CONNECTED)
    assert len(results) == len(assessment.TESTS)
    for t in results:
        assert t["status"] in assessment.STATUSES
        assert t["verdict"]


def test_failures_sort_above_gaps_and_passes():
    """A reader who stops after the first screen must have seen what needs them."""
    results = assessment.run([_app(consent_type="AllPrincipals",
                                   scopes=["files.read.all"])])
    seen = [t["status"] for t in results]
    order = [assessment.STATUS_ORDER[s] for s in seen]
    assert order == sorted(order)
    assert seen[0] == assessment.FAILED


def test_a_broken_test_does_not_blank_the_page(monkeypatch):
    def explode(ctx):
        raise RuntimeError("boom")

    patched = [(t[0], t[1], t[2], t[3], t[4], t[5], t[6], explode, t[8], t[9], t[10])
               if t[0] == "AISPM-1001" else t for t in assessment.TESTS]
    monkeypatch.setattr(assessment, "TESTS", patched)
    results = assessment.run([_app()])
    broken = [t for t in results if t["id"] == "AISPM-1001"][0]
    assert broken["status"] == assessment.SKIPPED
    assert "boom" in broken["verdict"]
    assert len(results) == len(assessment.TESTS)


# --- the honesty rule -------------------------------------------------------

def test_missing_connector_is_not_assessed_rather_than_passed():
    results = assessment.run([_app()], health={})           # nothing connected
    by_id = {t["id"]: t for t in results}
    for tid in ("AISPM-2001", "AISPM-2002", "AISPM-2004", "AISPM-5002"):
        assert by_id[tid]["status"] == assessment.NOT_ASSESSED, tid
        assert by_id[tid]["status"] != assessment.PASSED


def test_missing_signin_logs_downgrade_the_usage_tests():
    apps = [_app(usage={"available": False})]
    by_id = {t["id"]: t for t in assessment.run(apps, health=CONNECTED)}
    for tid in ("AISPM-3005", "AISPM-4001", "AISPM-4002", "AISPM-4004"):
        assert by_id[tid]["status"] == assessment.NOT_ASSESSED, tid
        assert "Entra ID P1" in by_id[tid]["verdict"]


def test_a_failure_names_the_assets():
    apps = [_app(display_name="LeakyAI", consent_type="AllPrincipals",
                 scopes=["files.read.all", "offline_access"])]
    t = [x for x in assessment.run(apps, health=CONNECTED) if x["id"] == "AISPM-1001"][0]
    assert t["status"] == assessment.FAILED
    assert t["assets"] and t["assets"][0][0] == "LeakyAI"
    assert "files.read.all" in t["assets"][0][1]


def test_clean_estate_passes_the_permission_tests():
    by_id = {t["id"]: t for t in assessment.run([_app()], health=CONNECTED)}
    for tid in ("AISPM-1001", "AISPM-1002", "AISPM-1003", "AISPM-1005"):
        assert by_id[tid]["status"] == assessment.PASSED, tid


def test_first_party_microsoft_is_not_assessed_as_shadow_ai():
    apps = [_app(first_party_microsoft=True, consent_type="AllPrincipals",
                 scopes=["files.read.all"])]
    t = [x for x in assessment.run(apps, health=CONNECTED) if x["id"] == "AISPM-1001"][0]
    assert t["status"] == assessment.PASSED


def test_review_overdue_reads_dates_it_cannot_parse_as_no_date():
    from datetime import datetime, timezone
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert assessment.review_overdue({"lifecycle": {"next_review_date": "nonsense"}}, now) is False
    assert assessment.review_overdue({"lifecycle": {"next_review_date": "2026-01-01"}}, now) is True
    assert assessment.review_overdue({}, now) is False


def test_summary_counts_by_status_and_pillar():
    s = assessment.summary(assessment.run([_app()], health=CONNECTED))
    assert s["total"] == len(assessment.TESTS)
    assert sum(s["by_status"].values()) == s["total"]
    assert sum(p["total"] for p in s["by_pillar"].values()) == s["total"]
    assert s["assessable"] == s["total"] - s["by_status"][assessment.NOT_ASSESSED]


# --- the page ---------------------------------------------------------------

def _estate():
    return {"vendors": [{"vendor": "SomeAI", "evidence": {"oauth"}, "users": 4,
                         "risk_score": 10, "risk_level": "Low", "oauth_apps": [],
                         "sensitive_types": set(), "interactions": 0, "blocked": 0}],
            "unattached_agents": []}


def test_page_renders_the_table_and_the_panel():
    apps = [_app()]
    results = assessment.run(apps, _estate(), CONNECTED)
    doc = assessment_report.html_string(results, apps, "tenant-1", estate=_estate(),
                                        health=CONNECTED)
    assert "<!doctype html>" in doc
    assert "Assessment results" in doc
    assert 'data-f="pillar"' in doc and 'data-f="status"' in doc
    assert "What was checked" in doc              # the panel payload rides on the row
    assert "AISPM-1001" in doc
    # Every test row carries its own panel; the estate rows on the third tab carry theirs.
    assert doc.count('data-panel="') == len(results) + len(_estate()["vendors"])


def test_page_shows_a_dash_not_a_zero_for_a_source_it_cannot_read():
    apps = [_app()]
    results = assessment.run(apps, _estate(), {})
    doc = assessment_report.html_string(results, apps, "t", estate=_estate(), health={})
    assert "not connected" in doc
    assert "How to make this test answerable" in doc


def test_page_drops_the_detail_link_it_was_not_given():
    apps = [_app()]
    results = assessment.run(apps, _estate(), CONNECTED)
    with_link = assessment_report.html_string(results, apps, "t", estate=_estate(),
                                              health=CONNECTED, detail_href="detail.html")
    assert 'href="detail.html"' in with_link

    alone = assessment_report.html_string(results, apps, "t", estate=_estate(),
                                          health=CONNECTED)
    assert 'class="out"' not in alone          # no href given → no dead nav button


def test_the_estate_tab_carries_the_vendors_and_their_arithmetic():
    apps = [_app()]
    est = _estate()
    est["vendors"][0]["breakdown"] = [(18, "424 people reached it"), (0, "no DLP block")]
    results = assessment.run(apps, est, CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", estate=est, health=CONNECTED)
    assert "AI estate" in doc and "1 vendors" in doc
    assert "424 people reached it" in doc       # the score shows its own sum
    assert 'id="t-estate"' in doc


def test_the_estate_tab_survives_a_tenant_with_no_vendors():
    results = assessment.run([], {"vendors": [], "unattached_agents": []}, {})
    doc = assessment_report.html_string(results, [], "t")
    assert "No AI vendors were found" in doc


def test_json_is_the_same_verdicts_as_data():
    results = assessment.run([_app()], health=CONNECTED)
    payload = json.loads(assessment_report.json_string(results))
    assert payload["summary"]["total"] == len(results)
    assert len(payload["tests"]) == len(results)
    assert {"id", "status", "verdict", "risk", "pillar"} <= set(payload["tests"][0])


def test_the_page_is_signed():
    """The author's name is on the page a customer is handed."""
    results = assessment.run([_app()], _estate(), CONNECTED)
    doc = assessment_report.html_string(results, [_app()], "t", estate=_estate(),
                                        health=CONNECTED,
                                        context={"finished": "05 August 2026, 09:16 UTC"})
    assert "Created by Ali Koc" in doc
    assert "05 August 2026, 09:16 UTC" in doc

    # and the separator does not strand itself when there is no timestamp to follow it
    bare = assessment_report.html_string(results, [_app()], "t", estate=_estate(),
                                         health=CONNECTED)
    assert "Created by Ali Koc" in bare
    assert "&middot; </div>" not in bare


def test_page_survives_an_empty_tenant():
    """No applications, no connectors, no divide-by-zero."""
    results = assessment.run([], {"vendors": [], "unattached_agents": []}, {})
    doc = assessment_report.html_string(results, [], "t")
    assert "<!doctype html>" in doc
    assert "Assessment results" in doc
    assert len(results) == len(assessment.TESTS)
