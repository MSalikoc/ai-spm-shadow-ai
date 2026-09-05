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
    assert "Executive summary" in doc
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
    assert "Evidence confidence" in doc
    assert "Assessment coverage:" in doc and "(%d%%)" % pct in doc
    assert "Telemetry coverage:" in doc and "fully informative" in doc
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
    assert 'class="warn">No data</span>' in coverage["rows"]


def test_coverage_freshness_is_explicitly_unknown_or_uses_reported_source_time():
    assert "not reported" in assessment_report._source_freshness(CONNECTED)
    health = {**CONNECTED,
              "agent365": {**CONNECTED["agent365"],
                           "collected_at": "2026-09-05T12:00:00Z"}}
    text = assessment_report._source_freshness(health)
    assert "1 connector(s)" in text
    assert "2026-09-05T12:00:00Z" in text


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
    assert "Executive summary" in with_link
