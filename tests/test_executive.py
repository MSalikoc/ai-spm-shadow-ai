"""Executive dashboard tests."""
import executive
import report


def _app(app_id, atype="application", ms=False, owner="", purpose="", cat="Third-Party Shadow AI",
         consent="Principal", active=None, bu=""):
    return {"app_id": app_id, "display_name": app_id, "asset_type": atype,
            "first_party_microsoft": ms, "consent_type": consent,
            "ownership": {"business_owner": owner}, "risk_score": 20,
            "business_context": {"purpose": purpose, "business_unit": bu},
            "classification": {"category": cat},
            "lifecycle": {"status": "Discovered"},
            "usage": ({"active_users_30d": active} if active is not None else None)}


def test_application_and_agent_counts_separate():
    """Acceptance 1: application vs agent distinction."""
    apps = [_app("a1", "application"), _app("a2", "agent"), _app("a3", "agent")]
    m = executive.estate_metrics(apps)
    assert m["total_applications"] == 1
    assert m["total_agents"] == 2


def test_usage_surface_enterprise_web_local():
    """Acceptance 2: local and web AI are separate."""
    apps = [_app("a1", consent="AllPrincipals"), _app("a2", consent="Principal"),
            _app("a3", consent="Principal")]
    s = executive.usage_surface(apps)
    assert s["enterprise"] == 1 and s["web"] == 2 and s["local"] == 0


def test_models_and_mcp_are_connector_gated():
    """Acceptance 3: model & MCP are summarized (no connector → 0, no fabrication)."""
    m = executive.estate_metrics([_app("a1")])
    assert m["ai_models"] == 0 and m["mcp_servers"] == 0 and m["local_agents"] == 0


def test_coverage_gaps_visible():
    """Acceptance 4: coverage gaps are visible."""
    apps = [_app("a1", owner=""), _app("a2", owner="Fin Team")]
    cov = executive.coverage(apps)
    assert cov["owner_coverage"] == 50
    names = {c[0]: c[1] for c in cov["connectors"]}
    assert names["Microsoft Purview"] is False           # not connected
    assert names["Entra ID / Microsoft Graph"] is True


def test_needs_attention_generates_stories():
    """Acceptance 5: meaningful executive narratives."""
    apps = [_app("a1", "application", owner="", bu="Finance"),
            _app("a2", "agent", owner="X", purpose=""),
            _app("a3", "application", owner="X", cat="Unknown AI")]
    changes = [{"change_type": "NEW_APPLICATION", "asset_id": "a1"},
               {"change_type": "ACTIVITY_INCREASED", "asset_name": "Claude",
                "old_value": 100, "new_value": 142}]
    lines = executive.needs_attention(apps, changes, [])
    joined = " ".join(lines)
    assert "1 new AI applications discovered in Finance." in lines
    assert "Claude usage increased by 42% in the last 7 days." in joined
    assert "missing business owner information" in joined
    assert "no business purpose information" in joined
    assert "Sensitive data visibility is unavailable because the Purview connector is not connected." in lines


def test_top_changes_ordered_by_importance():
    ch = [{"importance": "Info", "change_type": "ACTIVITY_INCREASED", "asset_name": "a", "description": "d"},
          {"importance": "Critical", "change_type": "NEW_APP_ONLY_ACCESS", "asset_name": "b", "description": "d"},
          {"importance": "Medium", "change_type": "LIFECYCLE_CHANGED", "asset_name": "c", "description": "d"}]
    top = executive.top_changes(ch, 5)
    assert top[0]["importance"] == "Critical"


def test_dashboard_renders_executive_and_drilldown():
    apps = [{"display_name": "ChatGPT", "vendor": "OpenAI", "first_party_microsoft": False,
             "asset_type": "application", "third_party": True, "verified_publisher": True,
             "scopes": ["user.read"], "consent_type": "Principal", "user_count": 3, "risk_score": 20,
             "risk_level": "Low", "reasons": ["r"], "remediation": ["m"], "delegated_permissions": [],
             "application_permissions": [], "has_app_only_access": False, "usage": None,
             "ownership": {"service_principal_owners": [], "business_owner": ""}, "business_context": {},
             "lifecycle": {"status": "Discovered"}, "technical_inventory": {}, "notes": "", "history": [],
             "classification": {"category": "Third-Party Shadow AI", "ownership": "External",
                                "confidence": 90, "reasons": ["x"], "manual_override": False},
             "app_id": "a1"}]
    doc = report.html_string(apps, "t", [], [])
    assert 'data-tab="overview"' in doc                           # tab navigation
    assert "Needs Attention" in doc
    assert "Coverage Overview" in doc
    assert "MCP Servers" in doc and "AI Models" in doc            # connector-gated cards
    assert 'data-goto="apps"' in doc                              # KPI drill-down → tab
    assert 'data-tab="findings"' in doc and 'data-tab="governance"' in doc
    assert "not connected" in doc                                  # connector gap
