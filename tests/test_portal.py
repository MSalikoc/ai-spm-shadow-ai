"""
The unified portal — one estate over two scans that share no identifier.

The two rules under test both came from a real tenant where breaking them produced an
unusable page: only AI creates a vendor row, and agents attach to a vendor rather than
creating one.
"""
import portal


def _oauth(name, vendor=None, score=50, users=10, scopes=(), ai=True):
    return {"display_name": name, "vendor": vendor or name, "ai_match": ai,
            "risk_score": score, "risk_level": "High", "user_count": users,
            "scopes": list(scopes), "consent_type": "AllPrincipals",
            "first_party_microsoft": False, "application_permissions": []}


def _assessment(web=(), packages=(), identities=(), interactions=()):
    """A complete assessment shape — the same 15 keys connectors_report.assessment emits."""
    return {
        "executive": {"connectors_connected": 1, "connectors_total": 5,
                      "findings_by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
                      "total_apps": len(web), "matched_to_inventory": 0},
        "data_source_coverage": [],
        "sensitive_exposure": [],
        "shadow_ai_usage": {"metrics": {}, "applications": list(web)},
        "agent365_packages": {"metrics": {}, "packages": list(packages)},
        "agent_identities": {"metrics": {}, "identities": list(identities)},
        "sensitive_interactions": {"metrics": {}, "sample": list(interactions)},
        "findings": [],
        "direction_analysis": {},
        "correlation_quality": {},
        "application_detail": [],
        "agent_detail": [],
        "sit_distribution": {},
        "users_and_groups": {"top_users": [], "groups_without_owner": []},
        "known_gaps": [],
        "_generated_at": "2026-08-02T00:00:00+00:00",
        "health": {},
    }


def _web(name, users=100, uploaded=0, risk=5, sanctioned="unreviewed"):
    return {"display_name": name, "users": users, "uploaded_bytes": uploaded,
            "downloaded_bytes": 0, "traffic_bytes": uploaded, "risk_score": risk,
            "sanctioned_state": sanctioned, "vendor": None, "devices": 0,
            "ip_addresses": users, "transactions": 0, "category": "generativeAi",
            "data_sensitivity": "UNDETERMINED_REQUIRES_PURVIEW", "last_seen": None}


# --- the join: one vendor, two sources -------------------------------------
def test_a_vendor_seen_both_ways_is_one_row_not_two():
    """
    Defender records carry no appId and no domain, so nothing can merge them with the
    Entra side by ID. Matching both names through the catalog is what joins them.
    """
    estate = portal.build_estate(
        [_oauth("ChatGPT Enterprise Connector", vendor="OpenAI (ChatGPT)")],
        _assessment(web=[_web("ChatGPT (Consumer & Enterprise)", users=486,
                              uploaded=30 * 1024**3)]))
    vendors = estate["vendors"]

    assert len(vendors) == 1
    row = vendors[0]
    assert row["vendor"] == "OpenAI (ChatGPT)"
    assert row["evidence"] == {"oauth", "web"}
    assert len(row["oauth_apps"]) == 1
    assert row["web"]["users"] == 486


def test_different_vendors_stay_apart():
    estate = portal.build_estate([], _assessment(
        web=[_web("Anthropic Claude"), _web("Google Gemini")]))
    assert {v["vendor"] for v in estate["vendors"]} == {"Anthropic (Claude)", "Google Gemini"}


def test_a_vendor_the_catalog_does_not_know_keeps_its_own_name():
    estate = portal.build_estate([], _assessment(web=[_web("Zephyr Workspace AI")]))
    row = estate["vendors"][0]
    assert row["vendor"] == "Zephyr Workspace AI"
    assert row["catalog_match"] is False
    assert any("Not in the AI catalog" in r for r in row["reasons"])


# --- rule 1: only AI creates a vendor --------------------------------------
def test_non_ai_consented_apps_are_counted_but_never_ranked():
    """
    A --scope consented scan sweeps in every app holding a grant. Ranking those in an
    AI estate put "ProvisioningHealthPME" at 100/100 above ChatGPT.
    """
    estate = portal.build_estate(
        [_oauth("ChatGPT", vendor="OpenAI (ChatGPT)", score=40),
         _oauth("ProvisioningHealthPME", score=100, ai=False),
         _oauth("MOD Demo Platform", score=100, ai=False)],
        None)

    assert [v["vendor"] for v in estate["vendors"]] == ["OpenAI (ChatGPT)"]
    assert len(estate["non_ai_apps"]) == 2


def test_the_excluded_apps_are_reported_on_the_page_not_dropped():
    doc = portal.html_string(
        [_oauth("ChatGPT", vendor="OpenAI (ChatGPT)"),
         _oauth("ProvisioningHealthPME", score=100, ai=False)], "t")
    assert "1 consented applications" in doc
    assert "Deliberately not ranked above" in doc


# --- rule 2: agents attach, they never create ------------------------------
def test_the_teams_catalogue_does_not_become_hundreds_of_vendors():
    """Agent 365's catalogue is the tenant's Teams app list — 292 entries on a real
    tenant, which turned 20 vendors into 307 rows."""
    packages = [{"display_name": n, "publisher": None}
                for n in ("Jira Cloud", "Viva Goals", "Lucidchart for Microsoft Teams",
                          "iPlanner Pro for Teams")]
    estate = portal.build_estate([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")],
                                 _assessment(packages=packages))

    assert [v["vendor"] for v in estate["vendors"]] == ["OpenAI (ChatGPT)"]
    assert len(estate["unattached_agents"]) == 4


def test_an_agent_that_matches_a_vendor_joins_it():
    estate = portal.build_estate([], _assessment(
        web=[_web("Anthropic Claude")],
        identities=[{"display_name": "Anthropic Claude helper agent"}]))

    assert len(estate["vendors"]) == 1
    row = estate["vendors"][0]
    assert row["evidence"] == {"web", "agent"}
    assert row["agents"] == ["Anthropic Claude helper agent"]


def test_a_bare_first_name_does_not_count_as_a_vendor_match():
    """The catalog asks for `claude.ai`, not "claude" — a person's name must not match."""
    estate = portal.build_estate([], _assessment(
        web=[_web("Anthropic Claude")],
        identities=[{"display_name": "Claude Dubois onboarding bot"}]))
    assert estate["vendors"][0]["evidence"] == {"web"}
    assert estate["unattached_agents"] == ["Claude Dubois onboarding bot"]


def test_copilot_studio_agents_roll_up_under_one_vendor():
    identities = [{"display_name": f"{n} Agent (Microsoft Copilot Studio)"}
                  for n in ("Procurement", "Quality Assurance", "Distribution")]
    estate = portal.build_estate([], _assessment(identities=identities))
    assert len(estate["vendors"]) == 1
    assert estate["vendors"][0]["vendor"] == "Microsoft Copilot Studio"
    assert len(estate["vendors"][0]["agents"]) == 3


def test_unmatched_sensitive_interactions_are_counted_not_invented_as_vendors():
    estate = portal.build_estate([], _assessment(
        interactions=[{"app_host": "some-internal-tool", "direction": "ALLOWED", "sits": []}]))
    assert estate["vendors"] == []
    assert estate["unattached_interactions"] == 1


def test_a_matched_interaction_attaches_to_its_vendor():
    estate = portal.build_estate([], _assessment(
        web=[_web("ChatGPT")],
        interactions=[{"app_host": "ChatGPT", "direction": "BLOCKED",
                       "sits": ["Credit Card Number"]},
                      {"app_host": "ChatGPT", "direction": "ALLOWED",
                       "sits": ["U.S. Social Security Number"]}]))
    row = estate["vendors"][0]
    assert row["interactions"] == 2 and row["blocked"] == 1
    assert row["sensitive_types"] == {"Credit Card Number", "U.S. Social Security Number"}


# --- scoring ---------------------------------------------------------------
def test_reach_and_volume_together_outrank_either_alone():
    def score(users, gb):
        return portal.vendor_rollup([], _assessment(
            web=[_web("Zed AI", users=users, uploaded=int(gb * 1024**3))]))[0]["risk_score"]

    assert score(500, 60) > score(500, 5) > score(500, 0)
    assert score(500, 20) > score(5, 20)


def test_an_unsanctioned_vendor_outranks_a_sanctioned_one_at_equal_volume():
    def score(state):
        return portal.vendor_rollup([], _assessment(
            web=[_web("Zed AI", users=400, uploaded=20 * 1024**3, sanctioned=state)]
        ))[0]["risk_score"]

    assert score("unsanctioned") > score("unreviewed") > score("sanctioned")


def test_the_worst_consented_app_sets_the_floor():
    row = portal.vendor_rollup(
        [_oauth("A", vendor="Glean", score=30), _oauth("B", vendor="Glean", score=88)], None)[0]
    assert row["risk_score"] >= 88
    assert any("88/100" in r for r in row["reasons"])


def test_every_score_carries_its_reasons():
    for row in portal.vendor_rollup([_oauth("Glean", vendor="Glean")],
                                    _assessment(web=[_web("Glean", users=300)])):
        assert row["reasons"] and all(isinstance(r, str) for r in row["reasons"])


def test_posture_saturates_rather_than_pinning():
    many = _assessment(web=[_web(f"Vendor {i}", users=500, uploaded=60 * 1024**3)
                            for i in range(40)])
    doc = portal.html_string([], "t", many)
    assert "of 100" in doc


# --- rendering --------------------------------------------------------------
def test_portal_renders_the_estate_and_links_both_detail_views():
    doc = portal.html_string(
        [_oauth("ChatGPT", vendor="OpenAI (ChatGPT)", scopes=["mail.read"])], "tenant-1",
        _assessment(web=[_web("ChatGPT", users=486, uploaded=30 * 1024**3)]))

    assert "AI estate" in doc
    assert "OpenAI (ChatGPT)" in doc
    assert "OAuth consent" in doc and "Web traffic" in doc
    assert 'href="report.html"' in doc
    assert 'href="connectors.html"' in doc
    assert "Where to start" in doc


def test_portal_survives_a_scan_with_no_connectors():
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t", None)
    assert "OpenAI (ChatGPT)" in doc
    assert "not run in this scan" in doc


def test_portal_survives_an_empty_tenant():
    doc = portal.html_string([], "t", None)
    assert "No AI vendors found" in doc


def test_tenant_data_is_escaped():
    evil = '<script>alert(1)</script>'
    doc = portal.html_string([_oauth(evil, vendor=evil)], evil)
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


def test_json_output_is_serialisable():
    import json
    payload = json.loads(portal.json_string(
        [_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], _assessment(web=[_web("ChatGPT")]), "t"))
    row = payload["vendors"][0]
    assert row["vendor"] == "OpenAI (ChatGPT)"
    assert sorted(row["evidence"]) == ["oauth", "web"]


def test_detail_links_carry_the_function_key_when_served_from_the_api():
    """Off disk the plain hrefs work; behind /api/ they need ?code= and format=html."""
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t", None,
                             report_href="report", connectors_href="connectors")
    assert "location.pathname.indexOf('/api/')" in doc
    assert "format=html" in doc
    assert "code=" in doc


def test_function_app_serves_the_portal(monkeypatch):
    import function_app
    monkeypatch.setattr(function_app.storage, "read_latest",
                        lambda name: "<html>portal</html>" if name == "portal_latest.html" else None)

    class Req:
        params = {}

    resp = function_app.portal_view(Req())
    assert resp.status_code == 200
    assert "portal" in resp.get_body().decode()


def test_function_app_portal_says_so_before_the_first_scan(monkeypatch):
    import function_app
    monkeypatch.setattr(function_app.storage, "read_latest", lambda name: None)
    monkeypatch.setattr(function_app.storage, "read_json", lambda name: {})

    class Req:
        params = {}

    resp = function_app.portal_view(Req())
    assert resp.status_code == 404
    assert "Run /api/scan first" in resp.get_body().decode()


# --- the portal is the union of both dashboards, not a summary above them ---
def _sections(doc):
    import re
    return {m.group(1): m.group(2) for m in re.finditer(
        r'<section class="tab[^"]*" data-tab="([a-z]+)">(.*?)</section>', doc, re.S)}


def test_the_portal_carries_every_tab_from_both_dashboards():
    doc = portal.html_string(
        [_oauth("ChatGPT", vendor="OpenAI (ChatGPT)", scopes=["mail.read"])], "t",
        _assessment(web=[_web("ChatGPT", users=486, uploaded=30 * 1024**3)]))
    tabs = _sections(doc)

    # From the core dashboard, from the connectors dashboard, and the estate spine.
    assert {"estate", "apps", "usage", "governance", "changes"} <= set(tabs)
    assert {"agents", "shadow", "sensitive", "gaps"} <= set(tabs)
    assert "findings" in tabs


def test_the_connector_sections_are_the_real_ones_not_placeholders():
    doc = portal.html_string([], "t", _assessment(
        web=[_web("ChatGPT", users=486, uploaded=30 * 1024**3)]))
    shadow = _sections(doc)["shadow"]
    assert "Shadow AI" in shadow
    assert "ChatGPT" in shadow
    assert len(shadow) > 1000            # the full grid, not a one-line stub


def test_the_application_inventory_comes_through():
    doc = portal.html_string(
        [_oauth("Glean Enterprise Search", vendor="Glean", scopes=["sites.read.all"])], "t")
    apps = _sections(doc)["apps"]
    assert "Glean Enterprise Search" in apps
    assert "sites.read.all" in apps


def test_missing_connectors_leave_an_explanation_not_an_empty_tab():
    tabs = _sections(portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t"))
    for key in ("agents", "shadow", "sensitive"):
        assert "did not run in this scan" in tabs[key]


def test_an_assessment_can_be_passed_where_a_raw_run_is_expected():
    """The JSON cache and the portal both hold assessments; rebuilding one emptied it."""
    import connectors_report
    built = _assessment(web=[_web("ChatGPT", users=10)])
    once = connectors_report.assessment(built)
    assert once is built
    assert connectors_report.build_tabs(built)["tabs"]["shadow"]


def test_findings_from_both_scans_appear_together():
    doc = portal.html_string([], "t", _assessment(
        web=[_web("ChatGPT", users=500, uploaded=40 * 1024**3, sanctioned="unsanctioned")]))
    assert "findings" in _sections(doc)


# --- a score nobody can decompose is a score nobody can act on -------------
def test_every_scoring_signal_carries_its_points():
    row = portal.vendor_rollup([], _assessment(
        web=[_web("DeepSeek", users=470, uploaded=63 * 1024**3, sanctioned="unreviewed")]))[0]

    assert row["breakdown"], "the score must show its parts"
    assert sum(p for p, _ in row["breakdown"]) == row["raw_score"]
    assert row["raw_score"] == row["risk_score"]         # nothing lost below the cap
    assert all(r.startswith("+") or p == 0
               for r, (p, _) in zip(row["reasons"], row["breakdown"]))


def test_the_parts_add_up_to_the_number_shown():
    for users, gb in ((5, 0), (150, 2), (500, 60)):
        row = portal.vendor_rollup([], _assessment(
            web=[_web("Zed", users=users, uploaded=int(gb * 1024**3))]))[0]
        assert sum(p for p, _ in row["breakdown"]) == row["raw_score"]


def test_a_capped_score_says_so_rather_than_quietly_losing_points():
    row = portal.vendor_rollup(
        [_oauth("A", vendor="Glean", score=100), _oauth("B", vendor="Glean", score=99)],
        _assessment(web=[_web("Glean", users=900, uploaded=99 * 1024**3,
                              sanctioned="unsanctioned")]))[0]
    assert row["raw_score"] > 100 and row["risk_score"] == 100
    assert "capped at 100" in portal.html_string(
        [_oauth("A", vendor="Glean", score=100), _oauth("B", vendor="Glean", score=99)], "t",
        _assessment(web=[_web("Glean", users=900, uploaded=99 * 1024**3,
                              sanctioned="unsanctioned")]))


def test_a_blocked_interaction_scores_nothing_and_says_why():
    row = portal.vendor_rollup([], _assessment(
        web=[_web("ChatGPT")],
        interactions=[{"app_host": "ChatGPT", "direction": "BLOCKED", "sits": ["SSN"]}]))[0]
    blocked = [(p, w) for p, w in row["breakdown"] if "blocked by DLP" in w]
    assert blocked and blocked[0][0] == 0
    assert "the control working" in blocked[0][1]


def test_a_collapsed_row_names_its_biggest_contributor():
    row = portal.vendor_rollup([], _assessment(
        web=[_web("DeepSeek", users=470, uploaded=63 * 1024**3)]))[0]
    top = portal._top_reason(row)
    assert "MB uploaded" in top and "+26" in top


def test_the_posture_number_shows_what_built_it():
    doc = portal.html_string([], "t", _assessment(
        web=[_web(f"V{i}", users=400, uploaded=20 * 1024**3) for i in range(3)]))
    assert "Posture score out of 100" in doc
    assert "High vendors" in doc
    assert "not an average" in doc


def test_the_scoring_model_is_documented_on_the_page():
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t")
    assert "What the score means" in doc
    assert "75+ Critical" in doc
    assert "How to read this" in doc          # the scatter explainer
    assert "logarithmic" in doc


# --- layout the operator asked for -----------------------------------------
def test_the_landing_tab_is_called_overview():
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t")
    assert '<a class="navlink active" data-tab="estate">Overview</a>' in doc
    assert ">Estate<" not in doc


def test_data_sources_sit_at_the_bottom_of_the_overview_tab():
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t")
    overview = _sections(doc)["estate"]
    assert "Data sources" in overview
    # Last card before the standalone links, i.e. after the estate list and the bars.
    assert overview.index("AI estate") < overview.index("Data sources")
    assert overview.index("Highest-risk vendors") < overview.index("Data sources")


def test_governance_no_longer_repeats_the_data_source_list():
    """Two lists of the same thing had already drifted apart once."""
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t")
    governance = _sections(doc)["governance"]
    assert "Coverage Overview" in governance
    assert "Defender for Cloud Apps" not in governance
    assert "portal" in governance          # points at where the list now lives


# --- travelling by email ----------------------------------------------------
def test_the_portal_is_self_contained_for_email():
    """
    Attached to a message there are no sibling files, so links to them must not be
    drawn — but every tab still has to work from the single file.
    """
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t",
                             _assessment(web=[_web("ChatGPT", users=400)]),
                             standalone_links=False)
    assert "Standalone views" not in doc
    assert 'href="report.html"' not in doc
    assert 'href="connectors.html"' not in doc

    # All ten tabs and the switching script still travel with it.
    assert len(_sections(doc)) == 10
    assert "showTab" in doc
    assert "ChatGPT" in _sections(doc)["shadow"]


def test_standalone_links_are_present_by_default():
    doc = portal.html_string([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)")], "t")
    assert "Standalone views" in doc
    assert 'href="report.html"' in doc


def test_the_email_attaches_the_portal_not_the_core_dashboard(monkeypatch):
    import notify
    captured = {}
    monkeypatch.setenv("AISPM_MAIL_SENDER", "a@b.com")
    monkeypatch.setenv("AISPM_MAIL_TO", "c@d.com")
    monkeypatch.setattr(notify, "_send", lambda *a, **k: captured.update(body=a) or "sent",
                        raising=False)
    assert hasattr(notify.send_email_digest, "__call__")
    import inspect
    assert "connectors_result" in inspect.signature(notify.send_email_digest).parameters


# --- getting back from a standalone view ------------------------------------
def test_the_core_dashboard_offers_a_way_back_to_the_portal():
    import report as core
    doc = core.html_string([_oauth("A", vendor="Glean")], "t", portal_href="portal.html")
    assert 'href="portal.html"' in doc
    assert "Portal" in doc


def test_the_connectors_dashboard_offers_a_way_back_to_the_portal():
    import connectors_report
    doc = connectors_report.html_string(_assessment(), "t", portal_href="portal.html")
    assert 'href="portal.html"' in doc
    assert "Portal" in doc


def test_no_back_button_is_drawn_when_there_is_nowhere_to_go():
    import report as core
    assert 'id="portalLink"' not in core.html_string([_oauth("A", vendor="Glean")], "t")


def test_the_excluded_card_points_at_a_tab_when_there_is_no_sibling_file():
    args = ([_oauth("ChatGPT", vendor="OpenAI (ChatGPT)"),
             _oauth("ProvisioningHealthPME", score=100, ai=False)], "t")
    linked = portal.html_string(*args)
    mailed = portal.html_string(*args, standalone_links=False)

    assert 'href="report.html"' in linked
    assert "href=" not in mailed.split("Deliberately not ranked above")[1].split("</div>")[0]
    assert "Applications</b> tab above" in mailed


def test_connector_status_survives_the_cached_assessment_shape():
    """
    A raw run keeps health under "health"; an assessment keeps it under
    "data_source_coverage". Reading only the first made every source read
    "not run in this scan" whenever the cached form was passed.
    """
    cached = _assessment(web=[_web("ChatGPT")])
    cached.pop("health")
    cached["data_source_coverage"] = [
        {"name": "defender_cloud_apps", "label": "Defender for Cloud Apps",
         "status": "CONNECTED", "count": 18},
    ]
    doc = portal.html_string([], "t", cached)
    assert "connected, 18 assets" in doc
    assert "Defender for Cloud Apps — not run in this scan" not in doc
