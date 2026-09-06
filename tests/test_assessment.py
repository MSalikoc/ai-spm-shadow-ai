"""The assessment catalogue and the page it renders."""
import json
from datetime import datetime, timezone

import pytest

import assessment
import assessment_report
import decisions


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
    assert s["assessable"] == (s["by_status"][assessment.PASSED]
                               + s["by_status"][assessment.FAILED])


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


def test_page_survives_an_empty_tenant():
    """No applications, no connectors, no divide-by-zero."""
    results = assessment.run([], {"vendors": [], "unattached_agents": []}, {})
    doc = assessment_report.html_string(results, [], "t")
    assert "<!doctype html>" in doc
    assert "Assessment results" in doc
    assert len(results) == len(assessment.TESTS)


# --- the decision cockpit ----------------------------------------------------

def _risky_app(**kw):
    """Fails across every risk band (High/Medium/Low) and several pillars at once —
    the asset a blast-radius ranking should put first."""
    base = _app(display_name="RiskyAI", vendor="RiskyAI", consent_type="AllPrincipals",
               scopes=["files.readwrite.all", "directory.read.all", "mail.send",
                      "offline_access"],
               application_permissions=[{"permission": "Files.ReadWrite.All"}],
               has_app_only_access=True, verified_publisher=False,
               user_count=300, risk_score=80, risk_level="Critical",
               ownership={"business_owner": ""},
               technical_inventory={"credential_count": 2})
    base.update(kw)
    return base


def _lonely_app(**kw):
    """Fails exactly one (Medium) test — the contrast case for concentration."""
    base = _app(display_name="LonelyAI", vendor="LonelyAI",
               ownership={"business_owner": ""})
    base.update(kw)
    return base


def test_cockpit_narrative_names_the_top_failing_control_and_its_reach():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert "Scan summary (immutable)" in doc
    assert "control failure(s) are consolidated into 3 executive decision(s)" in doc
    assert "Control privileged AI access and sensitive-data exposure" in doc
    assert "named evidence item(s)" in doc
    assert "people reached" not in doc.split("executive decisions")[0]


def test_cockpit_narrative_is_honest_when_nothing_failed():
    apps = [_app()]                                   # the clean fixture — passes everything
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert "No control in this catalogue failed this scan" in doc


def test_cockpit_posture_reuses_reports_scoring_formula():
    """The gauge is report._posture_score, not a second formula living on this page."""
    import report
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    shadow_apps = [a for a in apps if not a.get("first_party_microsoft")]
    counts = {lv: sum(1 for a in shadow_apps if a.get("risk_level") == lv)
             for lv in report.LEVELS}
    expected = report._posture_score(shadow_apps, counts)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert 'aria-label="Tenant AI posture: %d of 100' % expected in doc


def test_cockpit_coverage_confidence_never_lets_a_gap_read_as_a_pass():
    apps = [_app()]
    results = assessment.run(apps, health={})            # nothing connected
    doc = assessment_report.html_string(results, apps, "t", health={})
    summary = assessment.summary(results)
    answerable = (summary["by_status"][assessment.PASSED]
                  + summary["by_status"][assessment.FAILED])
    pct = round(100 * answerable / summary["total"])
    assert "Coverage confidence" in doc
    assert "Assessment coverage:" in doc and "(%d%%)" % pct in doc
    assert "Telemetry coverage:" in doc and "sources completed collection" in doc
    assert "fully informative" not in doc
    assert "roadmap sources are not in this denominator" in doc
    assert doc.count('class="bad">Gap</span>') >= 1     # at least one named source gap
    assert 'class="roadmap">Roadmap</span>' in doc


def test_cockpit_risk_concentration_ranks_the_asset_named_by_the_most_failures():
    apps = [_lonely_app(), _risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    risky_pos = doc.index("RiskyAI", doc.index("Risk concentration"))
    lonely_pos = doc.index("LonelyAI", doc.index("Risk concentration"))
    assert risky_pos < lonely_pos                        # more failing controls first
    assert "10 control(s) &middot; 1 matching inventory record(s)" in doc
    assert "1 control(s) &middot; 1 matching inventory record(s)" in doc


def test_cockpit_concentration_is_honest_when_risk_is_spread_not_concentrated():
    apps = [_app()]                                       # nothing fails
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert "risk is spread rather than concentrated" in doc


def test_cockpit_groups_failures_into_three_decisions_and_keeps_control_evidence():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert doc.count('<article class="decision"') == 3
    assert "IAM + Data Protection" in doc
    assert "Identity Security / SecOps" in doc
    assert "AI Governance Council" in doc
    assert "The complete 26-control evidence backlog remains below." in doc
    assert "Assessment results" in doc


def test_cockpit_says_no_executive_decision_is_required_when_clean():
    apps = [_app()]                                       # passes every test
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert "No remediation decision is required" in doc
    assert '<article class="decision"' not in doc


def test_decision_programs_expose_owner_sla_choice_and_measurable_effect():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    programs = assessment_report._decision_programs(results, apps)
    assert len(programs) == 3
    assert all(p["owner"] and p["sla"] and p["choice"] for p in programs)
    assert all(p["controls"] for p in programs)
    assert sum(len(p["controls"]) for p in programs) == sum(
        1 for t in results if t["status"] == assessment.FAILED)


def test_decision_scope_deduplicates_non_unique_labels_without_inventing_people():
    apps = [_risky_app(app_id="one", sp_id="sp-one", display_name="Same", user_count=100),
            _risky_app(app_id="two", sp_id="sp-two", display_name="Same", user_count=1)]
    results = assessment.run(apps, health=CONNECTED)
    programs = assessment_report._decision_programs(results, apps)
    access = next(p for p in programs if p["key"] == "sensitive-access")
    assert access["evidence_items"] == 1
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    decision_section = doc.split("executive decisions")[1].split("</article>")[0]
    assert "101 people" not in decision_section


def test_single_program_uses_a_singular_dynamic_heading():
    results = [{"id": "AISPM-3001", "name": "Owner", "pillar": assessment.P_GOV,
                "risk": "Medium", "impact": "Low", "effort": "Low", "requirement": "—",
                "status": assessment.FAILED, "verdict": "One app has no owner.",
                "assets": [("App", "Missing")], "checked": [], "recommendation": "Assign.",
                "actions": []}]
    doc = assessment_report.html_string(results, [_app()], "t", health=CONNECTED)
    assert "1 executive decision that moves the risk" in doc


def test_program_effect_does_not_claim_one_choice_closes_every_control():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    assert "retains its canonical verification criteria" in doc
    assert "move to verification if" not in doc


def test_decision_workflow_state_is_rendered_and_exported():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    states = {"sensitive-access": {
        "decision_key": "sensitive-access", "status": "In progress", "owner": "Alice",
        "due_date": "2026-09-01", "notes": "", "compensating_control": "",
        "acceptance": None, "updated_at": "2026-08-01T00:00:00+00:00", "history": []}}
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)
    doc = assessment_report.html_string(
        results, apps, "t", health=CONNECTED, context={"now": now},
        decision_states=states)
    assert '<span class="dstatus overdue">In progress</span>' in doc
    assert "<b>Alice</b>" in doc
    assert "2026-09-01" in doc
    payload = json.loads(assessment_report.json_string(results, states, now=now))
    assert payload["decision_workflow"]["sensitive-access"]["owner"] == "Alice"
    assert payload["decision_workflow"]["sensitive-access"]["overdue"] is True


def test_expiring_risk_acceptance_is_visible_on_decision_card():
    apps = [_risky_app()]
    results = assessment.run(apps, health=CONNECTED)
    states = {"governance": {
        "decision_key": "governance", "status": "Risk accepted", "owner": "CISO",
        "due_date": None, "notes": "", "compensating_control": "",
        "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                       "expires_at": "2026-10-01"},
        "updated_at": "2026-09-01T00:00:00+00:00", "history": []}}
    doc = assessment_report.html_string(
        results, apps, "t", health=CONNECTED,
        context={"now": datetime(2026, 9, 5, tzinfo=timezone.utc)},
        decision_states=states)
    assert "Risk accepted" in doc
    assert "Migration" in doc
    assert "expires 2026-10-01" in doc


@pytest.mark.parametrize("status", [
    "Decision required", "Approved", "In progress", "Deferred", "Compensating control",
    "Risk accepted",
])
def test_persisted_open_decisions_remain_visible_with_no_current_failures(status):
    apps = [_app()]
    results = assessment.run(apps, health=CONNECTED)
    assert not any(t["status"] == assessment.FAILED for t in results)
    state = {
        **decisions.default_state("governance"), "status": status, "owner": "CISO",
        "due_date": "2026-09-01", "notes": "Review this decision",
        "compensating_control": "Manual monitoring" if status == "Compensating control" else "",
        "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                       "expires_at": "2026-09-01"} if status == "Risk accepted" else None,
    }
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)
    programs = assessment_report._decision_programs(
        results, apps, {"governance": state}, now=now)
    assert len(programs) == 1 and programs[0]["controls"] == []
    assert not programs[0]["workflow"]["data_error"]
    doc = assessment_report.html_string(
        results, apps, "t", health=CONNECTED, context={"now": now},
        decision_states={"governance": state})
    assert doc.count('<article class="decision"') == 1
    assert "0 current failed control(s)" in doc
    assert "1 persisted decision program(s) still require governance attention" in doc
    assert "No remediation decision is required" not in doc
    assert "no current failed controls are being claimed" in doc
    assert "Unassigned" not in doc.split('<article class="decision"')[1].split("</article>")[0]
    if status == "Risk accepted":
        assert "Risk acceptance expired" in doc
    else:
        assert 'class="dstatus overdue"' in doc


def test_unexpired_acceptance_with_no_failures_stays_visible_for_review():
    state = {**decisions.default_state("governance"),
             "owner": "CISO", "status": "Risk accepted",
             "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                            "expires_at": "2026-10-01"}}
    programs = assessment_report._decision_programs(
        [], [], {"governance": state}, now=datetime(2026, 9, 5, tzinfo=timezone.utc))
    assert len(programs) == 1
    assert not programs[0]["workflow"]["acceptance_expired"]


@pytest.mark.parametrize("status", ["Verified", "False positive"])
def test_completed_decisions_without_failures_can_be_omitted_but_remain_in_json(status):
    state = {**decisions.default_state("governance"), "status": status,
             "owner": "CISO", "notes": "Evidence reviewed", "due_date": "2026-09-01"}
    states = {"governance": state}
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)
    assert assessment_report._decision_programs([], [], states, now=now) == []
    data = json.loads(assessment_report.json_string([], states, now=now))
    record = data["decision_workflow"]["governance"]
    assert record["status"] == status
    assert record["overdue"] is False and record["data_error"] is None


@pytest.mark.parametrize("field,value", [
    ("status", []), ("status", {}), ("owner", 123), ("owner", {}),
    ("notes", []), ("compensating_control", {}),
    ("acceptance", "not-an-object"), ("acceptance", []),
    ("acceptance", {"expires_at": [], "approved_by": {}, "rationale": 123}),
    ("due_date", []), ("due_date", {}), ("due_date", 0),
    ("updated_at", []), ("history", 123), ("_data_error", ["invalid"]),
])
def test_corrupt_persisted_fields_do_not_prevent_html_or_json_publication(field, value):
    results = assessment.run([_app()], health=CONNECTED)
    state = {**decisions.default_state("governance"), field: value}
    states = {"governance": state}
    doc = assessment_report.html_string(results, [_app()], "t", decision_states=states)
    payload = json.loads(assessment_report.json_string(results, states))
    assert "Workflow data invalid" in doc
    assert "No remediation decision is required" not in doc
    assert "0 current failed control(s)" in doc
    assert payload["decision_workflow"]["governance"]["data_error"]


def test_json_exports_all_derived_workflow_fields_even_without_current_failures():
    states = {
        "governance": {**decisions.default_state("governance"), "owner": "CISO",
                       "status": "Risk accepted",
                       "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                                      "expires_at": "2026-09-01"}},
        "sensitive-access": {**decisions.default_state("sensitive-access"), "owner": "IAM",
                             "status": "In progress", "due_date": "2026-09-01"},
        "identity-exposure": {**decisions.default_state("identity-exposure"), "status": []},
    }
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)
    payload = json.loads(assessment_report.json_string([], states, now=now))
    records = payload["decision_workflow"]
    assert records["governance"]["acceptance_expired"] is True
    assert records["governance"]["display_status"] == "Risk acceptance expired"
    assert records["sensitive-access"]["overdue"] is True
    assert records["identity-exposure"]["data_error"]
    assert records["identity-exposure"]["display_status"] == "Workflow data invalid"
    assert all({"overdue", "acceptance_expired", "data_error", "display_status"} <= set(record)
               for record in records.values())
    for results in ([], assessment.run([_risky_app()], health=CONNECTED)):
        assert len(assessment_report._decision_programs(results, [], states, now=now)) == 3


def test_cockpit_trend_is_never_fabricated_without_history():
    apps = [_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED, changes=None)
    assert "No comparison available" in doc


def test_cockpit_trend_reads_a_real_baseline_as_steady_not_blank():
    apps = [_app()]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED, changes=[])
    assert "No changes recorded against the previous scan" in doc


def test_cockpit_trend_counts_real_drift_events_by_direction():
    apps = [_app()]
    results = assessment.run(apps, health=CONNECTED)
    changes = [{"change_type": "NEW_APPLICATION", "asset_name": "X"},
              {"change_type": "ADMIN_CONSENT_ADDED", "asset_name": "Y"},
              {"change_type": "APP_DISABLED", "asset_name": "Z"}]
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED, changes=changes)
    assert "2 material change(s) in the last 14 days" in doc
    assert "1 deterioration, 1 improvement" in doc
    assert "1 other inventory or usage event(s)" in doc
    assert 'class="trend flat"' in doc


def test_cockpit_trend_does_not_treat_inventory_noise_as_risk_deterioration():
    apps = [_app()]
    results = assessment.run(apps, health=CONNECTED)
    changes = [{"change_type": "NEW_APPLICATION"}, {"change_type": "OWNER_CHANGED"},
               {"change_type": "ACTIVITY_INCREASED"}]
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED, changes=changes)
    assert "no material risk change" in doc
    assert 'class="trend flat"' in doc


def test_coverage_confidence_separates_operational_and_roadmap_sources():
    results = assessment.run([_app()], health=CONNECTED)
    coverage = assessment_report._coverage_confidence(results, CONNECTED)
    summary = assessment.summary(results)
    assert coverage["assessment_pct"] == round(
        100 * (summary["by_status"][assessment.PASSED]
               + summary["by_status"][assessment.FAILED]) / len(results))
    assert coverage["operational"] == 5
    assert coverage["connected"] == 4  # Graph plus three fixture connectors
    assert coverage["telemetry_pct"] == 80
    assert coverage["confidence"] == "Medium"


def test_skipped_control_reduces_assessment_coverage_and_empty_is_really_zero():
    result = {"id": "BROKEN", "status": assessment.SKIPPED, "pillar": assessment.P_MON,
              "risk": "High", "name": "Broken", "verdict": "Could not run", "assets": []}
    coverage = assessment_report._coverage_confidence([result], {
        key: {"status": "CONNECTED"} for key in
        ("agent365", "entra_agent_id", "defender_cloud_apps", "purview_audit")})
    assert coverage["assessment_pct"] == 0
    assert coverage["assessable"] == 0
    assert coverage["confidence"] == "Low"
    empty = assessment_report._coverage_confidence([], {})
    assert empty["total"] == 0 and empty["assessment_pct"] == 0


def test_partial_and_no_data_sources_are_not_presented_as_complete_telemetry():
    health = {"agent365": {"status": "PARTIALLY_CONNECTED"},
              "entra_agent_id": {"status": "NO_DATA"},
              "defender_cloud_apps": {"status": "CONNECTED"},
              "purview_audit": {"status": "CONNECTED"}}
    coverage = assessment_report._coverage_confidence(
        assessment.run([_app()], health=health), health)
    assert coverage["connected"] == 3  # Graph plus two fully informative connectors
    assert coverage["telemetry_pct"] == 60
    assert 'class="warn">Partial</span>' in coverage["rows"]
    assert 'class="warn">Reachable · no detected data</span>' in coverage["rows"]


def test_coverage_freshness_is_explicitly_unknown_or_uses_reported_source_time():
    assert "not reported" in assessment_report._source_freshness(CONNECTED)
    health = {**CONNECTED,
              "agent365": {**CONNECTED["agent365"],
                           "collected_at": "2026-09-05T12:00:00Z"}}
    text = assessment_report._source_freshness(health)
    assert "1 connector(s)" in text
    assert "2026-09-05T12:00:00+00:00" in text
    assert "not event freshness" in text


def test_cockpit_is_accessible_by_keyboard_and_screen_reader():
    apps = [_risky_app()]
    results = assessment.run(apps, _estate(), CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", estate=_estate(), health=CONNECTED)
    assert '<a class="skiplink" href="#main">Skip to content</a>' in doc
    assert '<main class="wrap" id="main">' in doc
    assert 'role="dialog" aria-hidden="true"' in doc
    assert "removeAttribute('inert')" in doc
    assert "e.key!=='Tab'" in doc
    # Rows and estate rows are keyboard-focusable, not click-only.
    assert 'tabindex="0" role="button" aria-haspopup="dialog"' in doc
    # Sortable headers expose their state to assistive tech.
    assert 'aria-sort="none"' in doc
    # Executive decisions are semantic articles; detailed controls remain keyboard-openable.
    assert '<article class="decision" aria-labelledby="decision-1">' in doc


def test_drift_control_distinguishes_baseline_from_steady_comparison():
    apps = [_app()]
    baseline = next(t for t in assessment.run(apps, health=CONNECTED, changes=None)
                    if t["id"] == "AISPM-5003")
    steady = next(t for t in assessment.run(apps, health=CONNECTED, changes=[])
                  if t["id"] == "AISPM-5003")
    assert baseline["status"] == assessment.NOT_ASSESSED
    assert steady["status"] == assessment.PASSED
    assert "held steady" in steady["verdict"]


def test_cockpit_groups_duplicate_names_without_double_counting_controls():
    apps = [_risky_app(display_name="Same", user_count=100),
            _risky_app(display_name="Same", user_count=1)]
    results = assessment.run(apps, _estate(), CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", estate=_estate(),
                                        health=CONNECTED)
    assert "Same (2 identities)" in doc
    assert "2 matching inventory record(s)" in doc
    assert "101 reached" not in doc


def test_page_drops_the_detail_link_it_was_not_given_and_keeps_the_cockpit():
    """The additive cockpit must not disturb the pre-existing detail-link contract."""
    apps = [_app()]
    results = assessment.run(apps, _estate(), CONNECTED)
    with_link = assessment_report.html_string(results, apps, "t", estate=_estate(),
                                              health=CONNECTED, detail_href="detail.html")
    assert 'href="detail.html"' in with_link
    assert "Scan summary (immutable)" in with_link


def test_verified_conflict_is_derived_consistently_without_rewriting_record():
    from copy import deepcopy
    states = {"sensitive-access": {
        **decisions.default_state("sensitive-access"), "status": "Verified", "owner": "IAM"}}
    original = deepcopy(states)
    results = assessment.run([_risky_app()], health=CONNECTED)
    doc = assessment_report.html_string(results, [], "t", decision_states=states)
    payload = json.loads(assessment_report.json_string(results, states))
    state = payload["decision_workflow"]["sensitive-access"]
    assert state["evidence_conflict"] is True
    assert state["status"] == "Verified"
    assert state["display_status"] == "Verification needs review"
    assert "Evidence conflict: manually" in doc
    assert payload["decision_attention"]["conflicting"] == 1
    assert states == original


def test_no_evidence_does_not_manufacture_active_decisions_but_all_can_be_reviewed():
    doc = assessment_report.html_string([], [], "t")
    payload = json.loads(assessment_report.json_string([]))
    assert '<article class="decision"' not in doc
    assert doc.count('class="workflow-review-row"') == 3
    assert all(not value["persisted"] for value in payload["decision_workflow"].values())
    assert set(payload["decision_attention"].values()) == {0}
    assert 'name="decision-context" content="snapshot"' in doc


def test_decisions_precede_expandable_detail_and_print_keeps_as_of():
    results = assessment.run([_risky_app()], health=CONNECTED)
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)
    doc = assessment_report.html_string(results, [], "t", context={"now": now})
    assert doc.index('class="executive-strip"') < doc.index('<article class="decision"')
    assert doc.index('<article class="decision"') < doc.index('Detailed coverage, exposure')
    assert 'id="print-brief"' in doc and now.isoformat() in doc
    assert 'id="control-AISPM-1001"' in doc
    assert 'data-evidence=' in doc
    assert "self-reported" in doc
    assert "expected_revision:editorRevision" in doc


def test_visual_dashboard_counts_inventory_not_people_and_keeps_unrated():
    apps = [_app(risk_level="Critical", has_app_only_access=True, asset_type="agent"),
            _app(risk_level="High"), _app(risk_level=None),
            _app(first_party_microsoft=True, risk_level="Critical")]
    results = assessment.run(apps, health=CONNECTED)
    doc = assessment_report.html_string(results, apps, "t", health=CONNECTED)
    visual = doc.split('<section class="dashboard-visuals"')[1].split("</section>")[0]
    assert 'Assessed inventory</span><strong>3</strong>' in visual
    assert 'Critical / High risk</span><strong>2</strong>' in visual
    assert 'Unattended access</span><strong>1</strong>' in visual
    assert "1 agent-labelled" in visual
    assert 'aria-label="inventory records: 3"' in visual
    assert "Unrated: 1 (33%)" in visual
    assert doc.index('class="dashboard-visuals"') < doc.index('<article class="decision"')
    assert "DEMO / SYNTHETIC DATA" not in doc


def test_visual_dashboard_shows_all_control_states_and_missing_measurements():
    results = assessment.run([_app()], health=CONNECTED)[:4]
    statuses = [assessment.FAILED, assessment.PASSED, assessment.NOT_ASSESSED, assessment.SKIPPED]
    for result, status in zip(results, statuses):
        result["status"] = status
        result["evidence_complete"] = True
    coverage = assessment_report._coverage_confidence(results, {})
    visual = assessment_report._visual_summary(results, [], {}, coverage, 0, "Low")
    for status in statuses:
        assert f'{status} <b>1</b>' in visual
    assert "Controls with complete evidence <b>2 / 4</b>" in visual
    assert "Not measured" in visual
    assert "Nothing to chart yet" in visual
    assert "Low exposure" not in visual
    assert "Tenant AI posture: 0" not in assessment_report.html_string([], [], "t")
    sample = assessment_report.html_string([], [], "t", context={"sample_data": True})
    assert "DEMO / SYNTHETIC DATA" in sample


def test_source_collection_times_compare_instants_not_lexical_offsets():
    text = assessment_report._source_freshness({
        "agent365": {"collected_at": "2026-09-05T09:30:00+03:00"},
        "purview_audit": {"checked_at": "2026-09-05T07:00:00Z"},
        "defender_cloud_apps": {"timestamp": "not-a-time"}})
    assert "oldest: 2026-09-05T06:30:00+00:00" in text
    assert "not event freshness" in text
    assert "1 invalid" in text


def test_skipped_controls_are_visible_in_overview_gaps_and_totals():
    results = assessment.run([_app()], health=CONNECTED)
    results[0]["status"] = assessment.SKIPPED
    results[0]["verdict"] = "Collector evaluation failed"
    doc = assessment_report.html_string(results, [], "t", health=CONNECTED)
    skipped = sum(t["status"] == assessment.SKIPPED for t in results)
    assert f'Skipped</div><div class="fn">{skipped}</div>' in doc
    summary = assessment.summary(results)
    assert summary["assessable"] == (summary["by_status"][assessment.PASSED]
                                    + summary["by_status"][assessment.FAILED])
    gaps = doc.split("<h2>Not assessed / skipped</h2>")[1].split("</details>")[0]
    assert "Skipped:" in gaps and "Collector evaluation failed" in gaps


def test_editor_seed_escapes_markup_and_theme_respects_explicit_light():
    states = {"governance": {**decisions.default_state("governance"),
                            "notes": "</script><img src=x onerror=alert(1)>"}}
    doc = assessment_report.html_string([], [], "t", decision_states=states)
    seed = doc.split('id="workflow-seed">')[1].split("</script>")[0]
    assert "<img" not in seed and "\\u003c" in seed
    assert json.loads(seed)["states"]["governance"]["notes"] == states["governance"]["notes"]
    assert '(param === "light" || param === "dark") ? param' in doc
    assert doc.index("const param") < doc.index("var $=")
    assert "--cp-accent: #b11f4b" in doc and "--cp-accent: #fd8ea1" in doc


def test_consent_footprint_verdict_does_not_infer_tenant_wide_reach():
    results = assessment.run([_app(user_count=0, risk_score=90)], health=CONNECTED)
    control = next(t for t in results if t["id"] == "AISPM-4003")
    assert control["status"] == assessment.PASSED
    assert "does not rule out tenant-wide access" in control["verdict"]
    results = assessment.run([_app(user_count=250, risk_score=60)], health=CONNECTED)
    control = next(t for t in results if t["id"] == "AISPM-4003")
    assert control["status"] == assessment.FAILED
    assert "consent-user count of at least 250" in control["verdict"]
    assert "reach" not in control["verdict"]
