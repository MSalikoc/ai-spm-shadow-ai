"""
Executive layer — produces the AI estate summary, executive narratives, and coverage.

HONESTY NOTE: Application & (name-signaled) agent data comes for real from Entra/Graph.
Local AI agent (device), MCP server, AI model, and Purview visibility each require a
separate CONNECTOR; until connected their counts are 0 and Coverage shows this openly
(NO fabricated inventory).
"""
from datetime import datetime, timezone

# Data source / connector status. Unconnected ones produce a coverage gap.
# Sources that exist as real connectors, keyed by the name registry.run() reports them
# under. Their status comes from the run — never asserted.
_LIVE_CONNECTORS = [
    ("agent365", "Microsoft Agent 365", "Registered Copilot/agent packages"),
    ("entra_agent_id", "Microsoft Entra Agent ID", "Agent identities, owners, permissions"),
    ("defender_cloud_apps", "Defender for Cloud Apps", "Shadow AI web usage & traffic"),
    ("purview_audit", "Microsoft Purview Audit", "Sensitive AI interactions"),
]

# Sources that are on the roadmap but have no collector yet. Kept visible so the
# dashboard states the limits of its own coverage, but labelled distinctly: "not
# connected" wrongly implies an operator could go and connect it.
_PLANNED_CONNECTORS = [
    ("Defender for Endpoint / Intune", "Local AI agent & device discovery"),
    ("Azure AI Foundry", "AI model inventory"),
    ("MCP server inventory", "MCP server discovery"),
]

# Retained for callers that predate connector_status(); the live view is preferred.
CONNECTORS = [
    ("Entra ID / Microsoft Graph", True, "AI application & OAuth consent discovery"),
    *[(label, False, purpose) for label, purpose in _PLANNED_CONNECTORS],
]

_STATUS_LABEL = {
    "CONNECTED": ("connected", True),
    "PARTIALLY_CONNECTED": ("partially connected", True),
    "NO_DATA": ("connected, no data in this period", True),
    "TIMEOUT": ("still running when the scan stopped waiting", False),
    "PERMISSION_MISSING": ("permission missing", False),
    "LICENSE_MISSING": ("not licensed in this tenant", False),
    "API_UNAVAILABLE": ("not available in this tenant", False),
    "NOT_CONFIGURED": ("not enabled", False),
    "ERROR": ("error", False),
}


def connector_status(health=None):
    """
    The real state of every data source: (label, ok, detail).

    `health` is the dict pipeline.run_connectors() returns under "health". Without it
    the live connectors report "not run in this scan" rather than a fabricated
    "not connected" — the previous hardcoded list said Purview and Defender were
    disconnected even while those connectors were running and returning data, and it
    listed Defender for *Endpoint*, which has no collector, in place of Defender for
    Cloud Apps, which does.
    """
    rows = [("Entra ID / Microsoft Graph", True, "AI application & OAuth consent discovery")]
    for key, label, purpose in _LIVE_CONNECTORS:
        entry = (health or {}).get(key)
        if not entry:
            rows.append((label, False, f"{purpose} — not run in this scan"))
            continue
        text, ok = _STATUS_LABEL.get(entry.get("status"), (entry.get("status", "unknown"), False))
        count = entry.get("count")
        detail = f"{purpose} — {text}"
        if ok and count:
            detail += f", {count} assets"
        rows.append((label, ok, detail))
    for label, purpose in _PLANNED_CONNECTORS:
        rows.append((label, None, f"{purpose} — no collector yet"))
    return rows

_IMP_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _pct(part, whole):
    return round(100 * part / whole) if whole else 0


def _has_owner(a):
    return bool((a.get("ownership") or {}).get("business_owner"))


def _agents(apps):
    return [a for a in apps if a.get("asset_type") == "agent"]


def _applications(apps):
    return [a for a in apps if a.get("asset_type") != "agent"]


def _unapproved(apps):
    return [a for a in apps if (a.get("classification") or {}).get("category")
            not in ("Approved Enterprise AI", "Microsoft First-Party AI")]


def estate_metrics(apps, changes=None, findings=None):
    changes = changes or []
    findings = findings or []
    non_ms = [a for a in apps if not a.get("first_party_microsoft")]
    agents = _agents(apps)
    active_users = sum((a.get("usage") or {}).get("active_users_30d", 0) for a in apps)
    open_f = sum(1 for f in findings
                 if f.get("status") in ("Open", "Assigned", "In Progress", "Pending Review", "Reopened"))
    now = datetime.now(timezone.utc)
    overdue_f = 0
    for f in findings:
        d = f.get("due_date")
        if d and f.get("status") not in ("Resolved", "Accepted", "False Positive"):
            try:
                dt = datetime.fromisoformat(str(d).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < now:
                    overdue_f += 1
            except (ValueError, AttributeError):
                pass
    # Assessment coverage: share that are owned + classified + reviewed (not Discovered)
    governed = sum(1 for a in non_ms if _has_owner(a)
                   and (a.get("classification") or {}).get("category") not in ("Unknown AI", None)
                   and (a.get("lifecycle") or {}).get("status") not in ("Discovered", None))
    return {
        "total_applications": len(_applications(apps)),
        "total_agents": len(agents),
        "active_users": active_users,
        "unapproved": len(_unapproved(apps)),
        "local_agents": 0,          # requires a connector (endpoint)
        "mcp_servers": 0,           # requires a connector
        "ai_models": 0,             # requires a connector (Foundry)
        "new_this_week": sum(1 for e in changes if e.get("change_type") == "NEW_APPLICATION"),
        "unknown_assets": sum(1 for a in apps
                              if (a.get("classification") or {}).get("category") == "Unknown AI"),
        "apps_without_owner": sum(1 for a in non_ms if not _has_owner(a)),
        "agents_without_purpose": sum(1 for a in agents
                                      if not (a.get("business_context") or {}).get("purpose")),
        "open_findings": open_f,
        "overdue_findings": overdue_f,
        "assessment_coverage": _pct(governed, len(non_ms)),
    }


def usage_surface(apps):
    """Enterprise (admin-sanctioned) / Web (user-consent) / Local (connector) breakdown."""
    enterprise = sum(1 for a in apps if a.get("consent_type") == "AllPrincipals")
    web = sum(1 for a in apps if a.get("consent_type") == "Principal")
    return {"enterprise": enterprise, "web": web, "local": 0}


def coverage(apps, health=None):
    non_ms = [a for a in apps if not a.get("first_party_microsoft")]
    agents = _agents(apps)
    return {
        "owner_coverage": _pct(sum(1 for a in non_ms if _has_owner(a)), len(non_ms)),
        "purpose_coverage": _pct(sum(1 for a in agents
                                     if (a.get("business_context") or {}).get("purpose")), len(agents)),
        "connectors": connector_status(health),
    }


def top_changes(changes, n=5):
    return sorted(changes or [], key=lambda e: _IMP_ORDER.get(e.get("importance"), 5))[:n]


def needs_attention(apps, changes=None, findings=None, health=None):
    """Rule-based executive narratives — from real data only (no fabrication)."""
    changes = changes or []
    findings = findings or []
    lines = []
    m = estate_metrics(apps, changes, findings)

    # New applications by business unit
    id_map = {a.get("app_id"): a for a in apps}
    new_by_bu = {}
    for e in changes:
        if e.get("change_type") == "NEW_APPLICATION":
            a = id_map.get(e.get("asset_id")) or {}
            bu = (a.get("business_context") or {}).get("business_unit") or "Unassigned"
            new_by_bu[bu] = new_by_bu.get(bu, 0) + 1
    for bu, n in sorted(new_by_bu.items(), key=lambda kv: -kv[1]):
        if bu != "Unassigned":
            lines.append(f"{n} new AI applications discovered in {bu}.")

    # Activity increases (drift)
    acts = [e for e in changes if e.get("change_type") == "ACTIVITY_INCREASED"]
    for e in sorted(acts, key=lambda x: (x.get("new_value") or 0) - (x.get("old_value") or 0),
                    reverse=True)[:2]:
        pct = round(((e.get("new_value") or 0) - (e.get("old_value") or 0))
                    / max(e.get("old_value") or 1, 1) * 100)
        lines.append(f"{e.get('asset_name')} usage increased by {pct}% in the last 7 days.")

    if m["apps_without_owner"]:
        lines.append(f"{m['apps_without_owner']} AI applications are missing business owner information.")
    if m["agents_without_purpose"]:
        lines.append(f"{m['agents_without_purpose']} agents have no business purpose information.")
    if m["unknown_assets"]:
        lines.append(f"{m['unknown_assets']} AI applications are awaiting classification (Unknown).")
    if m["overdue_findings"]:
        lines.append(f"{m['overdue_findings']} findings are overdue — SLA breach.")

    # Connector gaps (honest coverage narratives). Driven by the real run when one is
    # available, so a source that IS connected no longer gets reported as a gap.
    for name, connected, purpose in connector_status(health):
        if connected:
            continue
        if "Purview" in name:
            lines.append("Sensitive data visibility is unavailable because the Purview connector is not connected.")
        elif "Endpoint" in name:
            lines.append("Local AI agent visibility is unavailable because the Endpoint connector is not connected.")
        elif "Foundry" in name:
            lines.append("AI model inventory is not visible because Azure AI Foundry is not connected.")
        elif "MCP" in name:
            lines.append("MCP server visibility is unavailable because the MCP connector is not connected.")
        elif "Agent 365" in name:
            lines.append("Registered Copilot agents are not visible because Agent 365 is not connected.")
        elif "Agent ID" in name:
            lines.append("Agent identities and their owners are not visible because Entra Agent ID is not connected.")
        elif "Cloud Apps" in name:
            lines.append("Shadow AI web usage is not visible because Defender for Cloud Apps is not connected.")
    return lines
