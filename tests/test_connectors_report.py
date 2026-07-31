"""Step 7 — connectors_report.py: 15-section assessment + standalone HTML/JSON."""
import html
import json
import os
import re

import connectors
import connectors_report
import pipeline
from connectors.base import ConnectorStatus

FXDIR = os.path.join(os.path.dirname(connectors.__file__), "fixtures")


class MegaFakeGraph:
    """Feeds all four connectors with a single fake Graph client (from fixture files)."""

    def __init__(self):
        with open(os.path.join(FXDIR, "agent365_packages.json"), encoding="utf-8") as f:
            self.pkgs = json.load(f)
        with open(os.path.join(FXDIR, "entra_agent_identities.json"), encoding="utf-8") as f:
            self.entra = json.load(f)
        with open(os.path.join(FXDIR, "defender_cloud_apps.json"), encoding="utf-8") as f:
            self.defender = json.load(f)
        with open(os.path.join(FXDIR, "purview_audit_records.json"), encoding="utf-8") as f:
            self.audit_records = json.load(f)
        self._poll_done = False

    def get_all(self, path, params=None, max_items=None):
        if path == "/copilot/admin/catalog/packages":
            return self.pkgs
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            return [r["sp"] for r in self.entra["identities"]]
        if path == "/applications/microsoft.graph.agentIdentityBlueprint":
            return self.entra["blueprints"]
        if "/uploadedStreams" in path and "aggregatedAppsDetails" not in path:
            return self.defender["streams"]
        if "aggregatedAppsDetails" in path:
            sid = path.split("/uploadedStreams/", 1)[1].split("/aggregatedAppsDetails", 1)[0]
            return self.defender["apps_by_stream"].get(sid, [])
        if path.endswith("/records"):
            return self.audit_records
        for parts in ("/owners", "/sponsors", "/appRoleAssignments",
                      "/oauth2PermissionGrants", "/memberOf"):
            if path.endswith(parts):
                oid = path.split("/")[2]
                rec = next((r for r in self.entra["identities"] if r["sp"]["id"] == oid), None)
                if rec is None:
                    return []
                key = {"/owners": "owners", "/sponsors": "sponsors",
                       "/appRoleAssignments": "appRoleAssignments",
                       "/oauth2PermissionGrants": "oauth2PermissionGrants",
                       "/memberOf": "memberOf"}[parts]
                return rec.get(key, [])
        return []

    def get(self, path, params=None):
        if path.rsplit("/", 1)[-1] in {p["id"] for p in self.pkgs}:
            pid = path.rsplit("/", 1)[-1]
            return next((p for p in self.pkgs if p["id"] == pid), {})
        if "/auditLog/queries/" in path:
            self._poll_done = True
            return {"id": "query-1", "status": "succeeded"}
        return {}

    def post(self, path, body):
        return {"id": "query-1", "status": "notStarted"}


def _enable_all(monkeypatch):
    for f in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS",
              "ENABLE_PURVIEW_AUDIT", "ENABLE_PREVIEW_CONNECTORS"):
        monkeypatch.setenv(f, "true")
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)


def test_full_pipeline_to_assessment(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    assert result is not None
    assert result["health"]["agent365"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["entra_agent_id"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["defender_cloud_apps"]["status"] == ConnectorStatus.CONNECTED
    assert result["health"]["purview_audit"]["status"] == ConnectorStatus.CONNECTED

    a = connectors_report.assessment(result)
    assert set(a) >= {
        "executive", "data_source_coverage", "sensitive_exposure", "agent_identities",
        "agent365_packages", "shadow_ai_usage", "sensitive_interactions", "findings",
        "direction_analysis", "correlation_quality", "application_detail", "agent_detail",
        "sit_distribution", "users_and_groups", "known_gaps",
    }
    assert a["executive"]["connectors_connected"] == 4
    assert len(a["agent_identities"]["identities"]) == 2
    assert len(a["agent365_packages"]["packages"]) == 2
    assert len(a["shadow_ai_usage"]["applications"]) >= 1
    # The sensitive interaction in Purview audit -> correlates with apps like ChatGPT / Finance Assistant
    assert isinstance(a["sensitive_interactions"]["sample"], list)
    assert a["known_gaps"]                                  # honest gaps are always present


def test_agent_detail_shows_blueprint_relation(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    # Since this identity is correlated with the Agent365 package via entra_app_id,
    # display_name Agent365'ten gelir ("Finance Assistant") — owner/blueprint verisi
    # it's still carried in the agent_identity sub-dict (correlation never loses data).
    fin = next(x for x in a["agent_detail"] if x["owners"])
    assert fin["owners"][0]["display_name"] == "Alice Admin"
    assert fin["blueprint"]["display_name"] == "Finance Agent Blueprint"


def test_application_detail_matches_sensitive_exposure_count(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    exposed = [p for p in a["application_detail"]
              if p["sensitive_data_summary"]["window_30d"]["sensitive"] > 0]
    assert len(exposed) == len(a["sensitive_exposure"])


def test_json_and_html_render_without_error(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    js = connectors_report.json_string(result)
    parsed = json.loads(js)
    assert "executive" in parsed

    doc = connectors_report.html_string(result, tenant_id="contoso.onmicrosoft.com")
    assert "<html>" in doc and "AI Data Sources" in doc
    assert "contoso.onmicrosoft.com" in doc
    assert "Applications with Sensitive Data Exposure" in doc
    # The Step 7 HTML also renders discovery/traffic/review sections (so it isn't
    # limited to just the 4 sections) — agent inventory, Shadow AI traffic, Purview
    # interaction log, and the "assessment results" table + a slide-over detail panel
    # that opens on click (Microsoft Zero Trust Assessment pattern: Risk/Status badges,
    # facts, Result, What was checked, Remediation action).
    assert "Finance Assistant" in doc                    # Agent 365 package table
    assert "Orphan Agent Identity" in doc                # Entra Agent Identity table
    assert "ChatGPT" in doc                              # Shadow AI traffic table
    assert 'class="zt-row"' in doc                       # clickable assessment rows
    assert 'id="zt-panel"' in doc and "What was checked" in doc and "Remediation action" in doc
    assert "data-detail=" in doc                         # each row's detail data is embedded
    assert "alice@contoso.com" in doc                    # agent detail owner (in the JSON) is visible
    # Multi-page structure (Overview + Agents + Shadow AI + Sensitive Data + Findings + Gaps)
    for tab in ("overview", "agents", "shadow", "sensitive", "findings", "gaps"):
        assert f'data-tab="{tab}"' in doc
    assert 'class="tab active" data-tab="overview"' in doc   # only Overview is active initially
    # Flow (Sankey-style) diagrams on Overview
    assert 'class="flow"' in doc
    # Top 5 highest-risk items
    assert "Top 5 Highest-Risk Items" in doc
    # The Shadow AI tab should show the same columns as Defender for Cloud Apps' own
    # "Discovered apps" grid (Risk Score/Tag/Traffic/Upload/Transactions/Users/IP Addresses/
    # Devices/Last Seen) — a real traffic table, not plain facts.
    for col in ("Risk Score", "Tag", "Traffic", "Upload", "Transactions",
               "Users", "IP Addresses", "Devices", "Last Seen"):
        assert f"<th>{col}</th>" in doc


def test_shadow_traffic_table_shows_mdca_style_columns(monkeypatch):
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    items = connectors_report._shadow_items(a["shadow_ai_usage"]["applications"])
    chatgpt = next(i for i in items if i["name"] == "ChatGPT")
    # Aggregate: stream-fw-1 (users40/devices35/ips12/up2M) + stream-proxy-2 (users25/devices20/
    # ips8/up1M) -> conservative max for users/devices/ips, additive for upload/transactions.
    t = chatgpt["traffic"]
    assert t["users"] == 40 and t["devices"] == 35 and t["ip_addresses"] == 12
    assert t["uploaded_bytes"] == 3_000_000

    table = connectors_report._shadow_traffic_section("shadow", "t", "s", items, "empty")
    # Visible cells (NOT the data-detail JSON) should have human-readable byte format and counts.
    visible = re.sub(r"data-detail='.*?' onclick", "", table, flags=re.S)
    chatgpt_row = re.search(r'<tr class="zt-row"[^>]*data-name="chatgpt"[^>]*>.*?</tr>', visible, re.S)
    assert chatgpt_row, "ChatGPT row not found"
    row = chatgpt_row.group(0)
    assert "2.9 MB" in row          # upload bytes in human-readable format (3,000,000 B, base 1024)
    assert ">40<" in row            # users
    assert ">35<" in row            # devices
    assert ">12<" in row            # ip addresses
    assert 'style="--pc:' in row    # risk score bar / sanction pill color


def test_fmt_bytes():
    assert connectors_report._fmt_bytes(0) == "0 B"
    assert connectors_report._fmt_bytes(500) == "500 B"
    assert connectors_report._fmt_bytes(3_000_000) == "2.9 MB"
    assert connectors_report._fmt_bytes(1_500_000_000) == "1.4 GB"


def test_item_scores_are_transparent_0_to_100_with_reasons(monkeypatch):
    """'It says 45, based on what?' — every item's reasons list must carry the score rationale."""
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    doc = connectors_report.html_string(result)

    for m in re.finditer(r"data-detail='(.*?)' onclick", doc):
        d = json.loads(html.unescape(m.group(1)))
        assert 0 <= d["score"] <= 100
        assert isinstance(d["reasons"], list) and len(d["reasons"]) >= 1
        assert d["risk_label"] == connectors_report._RISK_LABEL[connectors_report._risk_tier(d["score"])]
        # each reason is either in "+N — reason" format (positive contribution) or a plain 0-point explanation
        for r in d["reasons"]:
            assert isinstance(r, str) and r


def test_shadow_item_exposes_user_device_ip_counts(monkeypatch):
    """User/device/IP COUNTS (like Defender for Cloud Apps) must show in facts (not individual identity)."""
    _enable_all(monkeypatch)
    result = pipeline.run_connectors(MegaFakeGraph())
    a = connectors_report.assessment(result)
    items = connectors_report._shadow_items(a["shadow_ai_usage"]["applications"])
    assert items
    chatgpt = next(i for i in items if i["name"] == "ChatGPT")
    fact_labels = {f[0] for f in chatgpt["facts"]}
    assert {"Users (30d)", "Devices (30d)", "IP Addresses (30d)"} <= fact_labels
    assert "individual user/device/IP identity" in chatgpt["what_checked"]


def test_risk_tier_derives_from_score():
    assert connectors_report._risk_tier(85) == "high"
    assert connectors_report._risk_tier(50) == "medium"
    assert connectors_report._risk_tier(20) == "low"
    assert connectors_report._risk_tier(5) == "info"


def test_html_tables_render_even_with_only_partial_data(monkeypatch):
    """The page shouldn't crash when some connectors are empty (e.g. entra_agent_id) — it should print an honest 'none' message."""
    monkeypatch.setenv("ENABLE_AGENT365", "true")
    for f in ("ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"):
        monkeypatch.delenv(f, raising=False)
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)

    class _FG:
        def get_all(self, path, params=None, max_items=None):
            if path == "/copilot/admin/catalog/packages":
                return [{"id": "p1", "displayName": "Solo Agent", "applicationId": "APP-1"}]
            return []

        def get(self, path, params=None):
            return {}

    result = pipeline.run_connectors(_FG())
    doc = connectors_report.html_string(result)
    assert "Solo Agent" in doc
    assert "No Entra Agent Identity discovered" in doc
    assert "No Shadow AI application discovered" in doc


def test_coverage_section_reports_not_configured_when_all_off():
    result = {"assets": [], "coverage": {}, "health": {}, "counts": {"raw": 0, "merged": 0}}
    a = connectors_report.assessment(result)
    statuses = {r["status"] for r in a["data_source_coverage"]}
    assert statuses == {ConnectorStatus.NOT_CONFIGURED}
    assert a["sensitive_exposure"] == []
    assert a["executive"]["connectors_connected"] == 0
