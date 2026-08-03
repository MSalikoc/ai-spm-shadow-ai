"""
Preflight — probe what this identity can actually read, before running a scan.

The failure mode this exists to kill: a scan finishes, a dashboard renders, a section
is empty, and there is no way to tell whether the tenant genuinely has nothing there or
the identity was simply not allowed to look. Each probe is the cheapest possible call
against a real endpoint, and the result says which of the two it was and what to grant.

Nothing here writes, and every probe is capped at one item.
"""
import os

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

# (key, label, path, permission, beta, what it powers, required, graph scopes that satisfy it)
#
# `scopes` is the machine-readable form of `permission`: any ONE of them is enough. It
# exists so a denial can be explained against the scopes the token actually carries,
# rather than leaving the operator to guess whether it is a permission or a licence.
PROBES = [
    ("service_principals", "Enterprise applications", "/servicePrincipals",
     "Application.Read.All or Directory.Read.All", False,
     "AI application discovery — the core scan", True,
     ["Application.Read.All", "Directory.Read.All"]),
    ("oauth_grants", "Delegated OAuth consents", "/oauth2PermissionGrants",
     "Directory.Read.All", False,
     "which permissions users consented to, and the risk score", True,
     ["Directory.Read.All"]),
    ("signin_logs", "Sign-in logs", "/auditLogs/signIns",
     "AuditLog.Read.All + Entra ID P1", False,
     "real usage: active users, unused apps, activity trend", False,
     ["AuditLog.Read.All"]),
    ("directory_roles", "Directory roles", "/directoryRoles",
     "Directory.Read.All", False, "privileged-role context on owners", False,
     ["Directory.Read.All"]),
    ("agent365", "Agent 365 catalog", "/copilot/admin/catalog/packages",
     "CopilotPackages.Read.All + Microsoft 365 Copilot", False,
     "registered Copilot agent packages", False,
     ["CopilotPackages.Read.All"]),
    ("entra_agent_id", "Entra Agent ID", "/servicePrincipals/microsoft.graph.agentIdentity",
     "Application.Read.All + Directory.Read.All", False,
     "agent identities: owners, sponsors, permissions", False,
     ["Application.Read.All", "Directory.Read.All"]),
    ("defender_cloud_apps", "Defender for Cloud Apps",
     "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams",
     "CloudApp-Discovery.Read.All + Defender for Cloud Apps", True,
     "Shadow AI web usage: traffic, users, devices", False,
     ["CloudApp-Discovery.Read.All"]),
    ("purview_audit", "Purview Audit", "/security/auditLog/queries",
     "AuditLogsQuery.Read.All + Purview Audit turned on", False,
     "sensitive AI interactions, blocked vs allowed", False,
     ["AuditLogsQuery.Read.All"]),
]


def _probe(graph, path, beta):
    try:
        graph.get_all(path, {"$top": "1"}, max_items=1, beta=beta)
        return OK, ""
    except GraphError as e:
        # Some collections reject a page size outright — /directoryRoles answers 400
        # "This resource does not support custom page sizes". Without this retry the
        # probe reported a perfectly readable source as absent from the tenant.
        if e.status == 400 and "page size" in (e.body or "").lower():
            try:
                graph.get_all(path, None, max_items=1, beta=beta)
                return OK, ""
            except GraphError as retry:
                e = retry
            except Exception:
                return FAILED, "retry without a page size also failed"
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


NOT_IN_TOKEN = ("the sign-in does not carry this scope at all — the client application "
                "is not authorized for it, so no directory role will change this")


def run(graph, held_scopes: set[str] | None = None, token_kind: str = "unknown") -> list[dict]:
    """
    Runs every probe and returns one result row each, in PROBES order.

    Pass `held_scopes` (from `auth.token_scopes`) to sharpen a denial. A 403 has two
    very different causes and the remedy differs completely: the scope is missing from
    the token because the client application was never authorized for it — common with
    an `az login` sign-in, and unfixable by granting the *user* another directory role —
    or the scope is present and the tenant refused anyway.
    """
    held = {s.lower() for s in (held_scopes or set())}
    rows = []
    for key, label, path, permission, beta, powers, required, scopes in PROBES:
        status, detail = _probe(graph, path, beta)
        satisfied = any(s.lower() in held for s in scopes) if held else None
        note = _STATUS_NOTE[status]
        if status == DENIED and satisfied is False:
            note = NOT_IN_TOKEN
        rows.append({"key": key, "label": label, "path": path, "permission": permission,
                     "powers": powers, "required": required, "scopes": scopes,
                     "status": status, "detail": detail, "note": note,
                     "scope_in_token": satisfied, "token_kind": token_kind})
    return rows


def missing_scopes(rows) -> list[str]:
    """Graph scopes that would unlock a currently-denied source, deduplicated."""
    out = []
    for r in rows:
        if r["status"] == DENIED and r.get("scope_in_token") is False:
            for s in r["scopes"]:
                if s not in out:
                    out.append(s)
    return out


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


def _remedy_text() -> str:
    """
    The fix, written for the shell the reader is actually in.

    Printing `./scripts/create_app_registration.sh` to someone on Windows is advice they
    cannot follow; the PowerShell twin and the `$env:` form are what work there.
    """
    windows = os.name == "nt"
    script = (r".\scripts\create_app_registration.ps1" if windows
              else "./scripts/create_app_registration.sh")
    rerun = ("$env:AISPM_TENANT_ID / AISPM_CLIENT_ID / AISPM_CLIENT_SECRET, then:\n"
             "         python aispm.py doctor --auth app" if windows
             else "the values it prints, then:\n"
                  "         python3 aispm.py doctor --auth app")
    deploy = ("./scripts/postdeploy.sh <RESOURCE_GROUP> <FUNCTION_APP>"
              + ("   (run this one in Cloud Shell Bash)" if windows else ""))
    return f"""
Why these are denied
--------------------
An `az login` sign-in is a DELEGATED token: it can only carry Graph scopes the Azure
CLI application itself is authorized for. The CLI is authorized for directory reads,
which is why Entra discovery works — but not for the specialised connector scopes
below. Being a Global Administrator does not change this; the limit is on the client
application, not on you.

Two ways to get them, both using APPLICATION permissions instead. Both need a role that
can GRANT application permissions — Privileged Role Administrator, Cloud Application
Administrator or Global Administrator. Global Reader is read-only and cannot do either;
if that is you, an admin runs step 1 once and hands you the three values.



  1. An app registration you own (stays local, no Azure resources):
         {script}
     then set {rerun}

  2. Deploy, and let the Function's Managed Identity hold them:
         {deploy}

Either way the scopes to grant are:
"""


def format_text(rows) -> str:
    """A readable preflight report for the terminal."""
    width = max(len(r["label"]) for r in rows) if rows else 20
    kind = rows[0].get("token_kind", "unknown") if rows else "unknown"
    header = {"delegated": "Preflight — what this sign-in can read (delegated token)",
              "application": "Preflight — what this app identity can read (application token)"
              }.get(kind, "Preflight — what this identity can read")

    lines = ["", header, "=" * 58]
    for r in rows:
        flag = "required" if r["required"] else "optional"
        lines.append(f"  [{_ICON[r['status']]}] {r['label']:<{width}}  {flag}")
        if r["status"] != OK:
            lines.append(f"           {r['note']}")
            lines.append(f"           needs: {r['permission']}")
            lines.append(f"           powers: {r['powers']}")
    lines.append("=" * 58)

    absent = missing_scopes(rows)
    if absent and kind == "delegated":
        lines.append(_remedy_text().rstrip())
        lines.extend(f"     {s}" for s in absent)
        lines.append("")

    missing = blocking(rows)
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
