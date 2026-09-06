"""The consolidated detail page: two dashboards, one page, nothing said twice."""
import detail_report


def _app(**kw):
    base = {"app_id": "app-1", "sp_id": "sp-1", "display_name": "SomeAI", "vendor": "SomeAI",
            "publisher": "Some Corp", "verified_publisher": True, "third_party": True,
            "first_party_microsoft": False, "scopes": ["files.read.all"],
            "delegated_permissions": [], "application_permissions": [],
            "has_app_only_access": False, "consent_type": "AllPrincipals",
            "user_count": 40, "risk_score": 55, "risk_level": "High",
            "reasons": ["broad read"], "remediation": ["narrow it"],
            "asset_type": "application",
            "ownership": {"application_owners": [], "service_principal_owners": []},
            "business_context": {}, "lifecycle": {"status": "Discovered"},
            "classification": {"category": "Third-Party Shadow AI", "confidence": 70},
            "technical_inventory": {"credential_count": 0}, "usage": None}
    base.update(kw)
    return base


def test_every_tab_has_a_body():
    """A nav button that opens an empty section is worse than no nav button."""
    built = detail_report.build([_app()], "t")
    for key, label, _group in detail_report._TABS:
        assert built["tabs"].get(key), "%s (%s) rendered empty" % (key, label)


def test_the_page_carries_all_nine_tabs_and_the_way_back():
    doc = detail_report.html_string([_app()], "tenant-1",
                                    assessment_href="assessment.html")
    for key, _l, _g in detail_report._TABS:
        assert 'data-tab="%s"' % key in doc, key
    assert 'href="assessment.html"' in doc
    assert "<!doctype html>" in doc


def test_neither_overview_is_repeated_here():
    """
    The two dashboards each opened with their own overview. The assessment page opens
    with one now, so these do not — that duplication is the reason this page exists.
    """
    built = detail_report.build([_app()], "t")
    assert "overview" not in built["tabs"]
    assert len(built["tabs"]) == len(detail_report._TABS)


def test_findings_are_one_tab_not_two():
    built = detail_report.build([_app()], "t")
    assert "findings" in built["tabs"]
    keys = [k for k, _l, _g in detail_report._TABS]
    assert keys.count("findings") == 1


def test_coverage_says_both_what_is_owned_and_what_each_source_can_see():
    """
    The connector status table used to live at the foot of the data-sources overview.
    Dropping that overview must not drop it: a quiet section means "clean" or "blind",
    and this is the only thing that says which.
    """
    result = {"health": {"defender_cloud_apps": {"status": "CONNECTED", "count": 3}},
              "assets": [], "coverage": {}, "profiles": [], "portfolio": {},
              "counts": {"raw": 0, "merged": 0}}
    built = detail_report.build([_app()], "t", connectors_result=result)
    cov = built["tabs"]["coverage"]
    assert "What is owned and reviewed" in cov
    assert "What each source can see" in cov
    assert "Data source coverage" in cov


def test_without_connectors_the_source_tabs_explain_themselves():
    built = detail_report.build([_app()], "t", connectors_result=None)
    for key in ("agents", "shadow", "sensitive"):
        assert "No AI data sources are connected" in built["tabs"][key], key
    # and the page still renders rather than half-collapsing
    doc = detail_report.html_string([_app()], "t")
    assert 'data-tab="coverage"' in doc


def test_the_page_is_signed():
    assert "Created by Ali Koc" in detail_report.html_string([_app()], "t")


def test_the_nav_groups_are_separated_but_every_tab_is_a_peer():
    doc = detail_report.html_string([_app()], "t")
    assert doc.count('class="grp-sep"') == 2      # oauth | sources | shared
