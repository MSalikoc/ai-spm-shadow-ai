"""
Preflight — probe what this identity can actually read, before running a scan.

The failure mode this exists to kill: a scan finishes, a dashboard renders, a section
is empty, and there is no way to tell whether the tenant genuinely has nothing there or
the identity was simply not allowed to look. Each probe is the cheapest possible call
against a real endpoint, and the result says which of the two it was and what to grant.

Nothing here writes, and every probe is capped at one item.
"""
from graph_client import GraphError

OK = "OK"
DENIED = "PERMISSION_MISSING"
UNAVAILABLE = "NOT_AVAILABLE"
FAILED = "ERROR"

_STATUS_NOTE = {
    OK: "readable",
    DENIED: "the identity lacks this permission",
    UNAVAILABLE: "not provisioned or licensed in this tenant",
    FAILED: "the call failed",
}

# (key, label, path, permission, beta, what it powers, whether a scan is useless without it)
PROBES = [
    ("service_principals", "Enterprise applications", "/servicePrincipals",
     "Application.Read.All or Directory.Read.All", False,
     "AI application discovery — the core scan", True),
    ("oauth_grants", "Delegated OAuth consents", "/oauth2PermissionGrants",
     "Directory.Read.All", False,
     "which permissions users consented to, and the risk score", True),
    ("signin_logs", "Sign-in logs", "/auditLogs/signIns",
     "AuditLog.Read.All + Entra ID P1", False,
     "real usage: active users, unused apps, activity trend", False),
    ("directory_roles", "Directory roles", "/directoryRoles",
     "Directory.Read.All", False, "privileged-role context on owners", False),
    ("agent365", "Agent 365 catalog", "/copilot/admin/catalog/packages",
     "CopilotPackages.Read.All + Microsoft 365 Copilot", False,
     "registered Copilot agent packages", False),
    ("entra_agent_id", "Entra Agent ID", "/servicePrincipals/microsoft.graph.agentIdentity",
     "Application.Read.All + Directory.Read.All", False,
     "agent identities: owners, sponsors, permissions", False),
    ("defender_cloud_apps", "Defender for Cloud Apps",
     "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams",
     "CloudApp-Discovery.Read.All + Defender for Cloud Apps", True,
     "Shadow AI web usage: traffic, users, devices", False),
    ("purview_audit", "Purview Audit", "/security/auditLog/queries",
     "AuditLogsQuery.Read.All + Purview Audit turned on", False,
     "sensitive AI interactions, blocked vs allowed", False),
]


def _probe(graph, path, beta):
    try:
        graph.get_all(path, {"$top": "1"}, max_items=1, beta=beta)
        return OK, ""
    except GraphError as e:
        if e.is_permission:
            return DENIED, e.body
        if e.is_missing:
            return UNAVAILABLE, e.body
        return FAILED, e.body
    except Exception as e:                      # a fake client, or something unforeseen
        text = str(e)
        low = text.lower()
        if "403" in low or "401" in low or "forbidden" in low:
            return DENIED, text[:300]
        if "404" in low or "400" in low or "not found" in low:
            return UNAVAILABLE, text[:300]
        return FAILED, text[:300]


def run(graph) -> list[dict]:
    """Runs every probe and returns one result row each, in PROBES order."""
    rows = []
    for key, label, path, permission, beta, powers, required in PROBES:
        status, detail = _probe(graph, path, beta)
        rows.append({"key": key, "label": label, "path": path, "permission": permission,
                     "powers": powers, "required": required,
                     "status": status, "detail": detail,
                     "note": _STATUS_NOTE[status]})
    return rows


def blocking(rows) -> list[dict]:
    """Probes that a useful scan genuinely cannot proceed without."""
    return [r for r in rows if r["required"] and r["status"] != OK]


def connector_flags(rows) -> dict[str, bool]:
    """
    Which connectors this identity can actually feed — used to switch them on
    automatically instead of asking the operator to guess at env vars.
    """
    by_key = {r["key"]: r["status"] == OK for r in rows}
    return {
        "ENABLE_AGENT365": by_key.get("agent365", False),
        "ENABLE_ENTRA_AGENT_ID": by_key.get("entra_agent_id", False),
        "ENABLE_DEFENDER_CLOUD_APPS": by_key.get("defender_cloud_apps", False),
        "ENABLE_PREVIEW_CONNECTORS": by_key.get("defender_cloud_apps", False),
        "ENABLE_PURVIEW_AUDIT": by_key.get("purview_audit", False),
    }


_ICON = {OK: "  OK  ", DENIED: "DENIED", UNAVAILABLE: " N/A  ", FAILED: " FAIL "}


def format_text(rows) -> str:
    """A readable preflight report for the terminal."""
    width = max(len(r["label"]) for r in rows) if rows else 20
    lines = ["", "Preflight — what this identity can read", "=" * 58]
    for r in rows:
        flag = "required" if r["required"] else "optional"
        lines.append(f"  [{_ICON[r['status']]}] {r['label']:<{width}}  {flag}")
        if r["status"] != OK:
            lines.append(f"           {r['note']} — grant: {r['permission']}")
            lines.append(f"           powers: {r['powers']}")
    missing = blocking(rows)
    lines.append("=" * 58)
    if missing:
        lines.append("Cannot run a useful scan yet. Missing: "
                     + ", ".join(r["label"] for r in missing))
    else:
        degraded = [r for r in rows if r["status"] != OK]
        if degraded:
            lines.append(f"Ready to scan. {len(degraded)} optional source(s) unavailable — "
                         "those sections will say so rather than appear empty.")
        else:
            lines.append("Ready to scan. Every source is readable.")
    lines.append("")
    return "\n".join(lines)
