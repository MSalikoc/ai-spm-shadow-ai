"""
Collects and normalizes Shadow AI signals from Graph.

Main idea:
  1) Pull every servicePrincipal in the tenant.
  2) Filter out the ones that are Microsoft/first-party (keep third-party).
  3) Flag the ones that look like AI vendors.
  4) Match each SP's granted delegated OAuth consents (scopes).
  5) Add application (app-only) permissions and real sign-in activity.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from config import AI_VENDORS, GENERIC_AI_HINTS, MICROSOFT_OWNER_TENANTS

_MAX_WORKERS = 10  # used in enrichment loops that make a separate Graph call per app


def _text_blob(sp: dict) -> str:
    parts = [sp.get("displayName", ""), sp.get("publisherName", ""),
             sp.get("homepage", "") or "", (sp.get("verifiedPublisher") or {}).get("displayName", "")]
    return " ".join(p.lower() for p in parts if p)


def _match_vendor(sp: dict):
    """Returns (vendor_name, confidence, signal); (None, None, None) if no match.
    Signal: 'app_id' (strongest) > 'pattern' / 'domain' > 'generic'."""
    blob = _text_blob(sp)
    app_id = sp.get("appId", "")
    homepage = (sp.get("homepage") or "").lower()
    for v in AI_VENDORS:
        if app_id and app_id in v.get("app_ids", []):
            return v["name"], "high", "app_id"
    for v in AI_VENDORS:
        if any(pat in blob for pat in v.get("patterns", [])):
            return v["name"], "high", "pattern"
        if any(dom in homepage or dom in blob for dom in v.get("domains", [])):
            return v["name"], "high", "domain"
    if any(hint in blob for hint in GENERIC_AI_HINTS):
        return "Unknown AI (generic match)", "low", "generic"
    return None, None, None


_AGENT_HINTS = ("agent", "copilot", " bot", "bot ", "studio", "botframework", "assistant")


def _asset_type(sp: dict) -> str:
    """application vs agent (via name/publisher signals — not exact, for admin triage)."""
    blob = _text_blob(sp)
    return "agent" if any(h in blob for h in _AGENT_HINTS) else "application"


def _is_third_party(sp: dict, home_tenant: str) -> bool:
    owner = sp.get("appOwnerOrganizationId")
    if owner is None:
        return False  # owner unknown — usually first-party/managed
    if owner in MICROSOFT_OWNER_TENANTS:
        return False
    if owner == home_tenant:
        return False  # built in our own tenant (internal app)
    return True


def collect_service_principals(graph, home_tenant: str) -> list[dict]:
    select = ("id,appId,displayName,appOwnerOrganizationId,publisherName,"
              "verifiedPublisher,servicePrincipalType,homepage,tags,accountEnabled")
    sps = graph.get_all("/servicePrincipals", {"$select": select, "$top": "999"})
    out = []
    for sp in sps:
        vendor, confidence, signal = _match_vendor(sp)
        if not vendor:
            continue
        owner = sp.get("appOwnerOrganizationId")
        out.append({
            "sp_id": sp["id"],
            "app_id": sp.get("appId"),
            "display_name": sp.get("displayName"),
            "publisher": sp.get("publisherName") or "—",
            "verified_publisher": bool(sp.get("verifiedPublisher")),
            "owner_tenant": owner,
            "third_party": _is_third_party(sp, home_tenant),
            "first_party_microsoft": owner in MICROSOFT_OWNER_TENANTS,
            "vendor": vendor,
            "confidence": confidence,
            "match_signal": signal,          # app_id / pattern / domain / generic
            "asset_type": _asset_type(sp),   # application / agent
            "scopes": [],                    # delegated scope names (scoring backward-compat)
            "consent_type": None,            # AllPrincipals (admin) / Principal (user)
            "user_count": 0,
            "delegated_permissions": [],     # [{resource, permission, consent_type}]
            "application_permissions": [],   # [{resource, permission, permission_id}]
            "has_app_only_access": False,    # can it access without a user (app-only)
        })
    return out


ZERO_GUID = "00000000-0000-0000-0000-000000000000"


class _ResourceResolver:
    """Caches resourceId → {name, roles:{roleId:permName}} resolution."""
    def __init__(self, graph):
        self._graph = graph
        self._cache: dict[str, dict] = {}

    def resolve(self, resource_id: str, fallback_name: str = "") -> dict:
        if resource_id not in self._cache:
            obj = self._graph.get(f"/servicePrincipals/{resource_id}",
                                   {"$select": "displayName,appRoles"}) or {}
            roles = {r.get("id"): (r.get("value") or r.get("displayName"))
                     for r in obj.get("appRoles", []) if r.get("id")}
            self._cache[resource_id] = {
                "name": obj.get("displayName") or fallback_name or "Unknown API",
                "roles": roles,
            }
        elif fallback_name and self._cache[resource_id]["name"] == "Unknown API":
            self._cache[resource_id]["name"] = fallback_name
        return self._cache[resource_id]


def enrich_with_oauth_grants(graph, discovered: list[dict]) -> None:
    """
    Adds delegated (on-behalf-of-user) consent scopes.
    Preserved: `scopes` (scoring), `consent_type`, `user_count`.
    Added: `delegated_permissions` = [{resource, permission, consent_type}].
    """
    grants = graph.get_all("/oauth2PermissionGrants", {"$top": "999"})
    by_client: dict[str, list[dict]] = {}
    for g in grants:
        by_client.setdefault(g.get("clientId"), []).append(g)
    resolver = _ResourceResolver(graph)

    for app in discovered:
        scopes: set[str] = set()
        consent_types: set[str] = set()
        users: set[str] = set()
        delegated: list[dict] = []
        for g in by_client.get(app["sp_id"], []):
            ct = g.get("consentType")
            res = resolver.resolve(g.get("resourceId", ""), "")
            for s in (g.get("scope") or "").split():
                s = s.strip()
                if not s:
                    continue
                scopes.add(s.lower())
                delegated.append({"resource": res["name"], "permission": s,
                                  "consent_type": ct})
            if ct:
                consent_types.add(ct)
            if g.get("principalId"):
                users.add(g["principalId"])
        app["scopes"] = sorted(scopes)
        app["consent_type"] = "AllPrincipals" if "AllPrincipals" in consent_types \
            else ("Principal" if consent_types else None)
        app["user_count"] = len(users)
        app["delegated_permissions"] = delegated


def enrich_with_app_role_assignments(graph, discovered: list[dict]) -> None:
    """
    Adds application (app-only) permissions:
      GET /servicePrincipals/{id}/appRoleAssignments
    The appRoleId GUID is resolved to a readable name from the target resource SP's
    appRoles; if it can't be resolved the GUID is kept (stored as permission_id).
    Custom enterprise APIs outside Microsoft Graph are also supported (resolved from
    the resource SP).
    """
    resolver = _ResourceResolver(graph)

    def _enrich(app):
        try:
            assigns = graph.get_all(
                f"/servicePrincipals/{app['sp_id']}/appRoleAssignments", {"$top": "999"})
        except Exception:
            assigns = []
        perms: list[dict] = []
        for a in assigns:
            role_id = a.get("appRoleId")
            if not role_id or role_id == ZERO_GUID:
                continue  # no role (assignment only) → not an application permission
            res = resolver.resolve(a.get("resourceId", ""), a.get("resourceDisplayName", ""))
            perms.append({
                "resource": res["name"],
                "permission": res["roles"].get(role_id, role_id),  # GUID if unresolved
                "permission_id": role_id,
            })
        app["application_permissions"] = perms
        app["has_app_only_access"] = bool(perms)

    # A separate appRoleAssignments call per app — doing this sequentially creates
    # serious delay on large tenants (dozens of apps) (see the same fix in
    # connectors/agent365.py). GraphClient is thread-safe; run in parallel.
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        list(ex.map(_enrich, discovered))


# --- Real usage / sign-in activity -----------------------------------
def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _app_usage(graph, app, now, iso90):
    """Produces usage metrics from sign-in logs for one app."""
    app_id = app.get("app_id")
    if not app_id:
        return None
    date_flt = f"createdDateTime ge {iso90}"
    try:
        user_si = graph.get_all("/auditLogs/signIns",
                                {"$filter": f"appId eq '{app_id}' and {date_flt}",
                                 "$top": "999"}, max_items=5000)
    except Exception:
        user_si = []
    try:
        sp_si = graph.get_all(
            "/auditLogs/signIns",
            {"$filter": f"appId eq '{app_id}' and signInEventTypes/any(t:t eq 'servicePrincipal') and {date_flt}",
             "$top": "999"}, max_items=5000)
    except Exception:
        sp_si = []

    w7, w30, w90 = now - timedelta(days=7), now - timedelta(days=30), now - timedelta(days=90)
    prev7_lo, prev7_hi = now - timedelta(days=14), now - timedelta(days=7)
    u7, u30, u90, uprev7 = set(), set(), set(), set()
    users_all, ips, countries = set(), set(), set()
    ok30 = fail30 = 0
    last_deleg = None
    daily = {}  # day-index(0..29) → set(user)

    for s in user_si:
        dt = _parse_dt(s.get("createdDateTime"))
        if not dt:
            continue
        uid = s.get("userId") or s.get("userPrincipalName") or ""
        last_deleg = dt if last_deleg is None or dt > last_deleg else last_deleg
        if uid:
            users_all.add(uid)
            if dt >= w7:
                u7.add(uid)
            if dt >= w30:
                u30.add(uid)
            if dt >= w90:
                u90.add(uid)
            if prev7_lo <= dt < prev7_hi:
                uprev7.add(uid)
            didx = (now.date() - dt.date()).days
            if 0 <= didx < 30:
                daily.setdefault(29 - didx, set()).add(uid)
        if s.get("ipAddress"):
            ips.add(s["ipAddress"])
        country = (s.get("location") or {}).get("countryOrRegion")
        if country:
            countries.add(country)
        if dt >= w30:
            if (s.get("status") or {}).get("errorCode", 0) == 0:
                ok30 += 1
            else:
                fail30 += 1

    last_sp = None
    for s in sp_si:
        dt = _parse_dt(s.get("createdDateTime"))
        if dt and (last_sp is None or dt > last_sp):
            last_sp = dt

    last_used = max([d for d in (last_deleg, last_sp) if d], default=None)
    daily_active = [len(daily.get(i, set())) for i in range(30)]

    return {
        "available": True,
        "consent_user_count": app.get("user_count", 0),
        "active_users_7d": len(u7),
        "active_users_30d": len(u30),
        "active_users_90d": len(u90),
        "last_delegated_signin": last_deleg.isoformat() if last_deleg else None,
        "last_service_principal_signin": last_sp.isoformat() if last_sp else None,
        "successful_signins_30d": ok30,
        "failed_signins_30d": fail30,
        "unique_user_count": len(users_all),
        "unique_ip_count": len(ips),
        "country_count": len(countries),
        "last_used_date": last_used.isoformat() if last_used else None,
        "never_used": last_used is None,
        "inactive_30d": last_used is None or last_used < w30,
        "inactive_90d": last_used is None or last_used < w90,
        "growth_7d": len(u7) - len(uprev7),
        "daily_active_30d": daily_active,
    }


def enrich_with_ownership(graph, discovered) -> None:
    """
    Adds technical owner + inventory fields:
      - service_principal_owners: /servicePrincipals/{id}/owners
      - technical_inventory: enabled, publisher, homepage, tags, description,
        credential count, and nearest credential expiry.
    Left empty if no owner is found (no automatic person is FABRICATED — criterion 2).
    Application owner (the local application object) doesn't exist for most third-party
    multi-tenant apps; so application_owners stays empty.
    """
    def _enrich(app):
        obj = graph.get(
            f"/servicePrincipals/{app['sp_id']}",
            {"$select": "accountEnabled,publisherName,homepage,tags,notes,description,"
                        "servicePrincipalType,keyCredentials,passwordCredentials"}) or {}
        creds = (obj.get("keyCredentials") or []) + (obj.get("passwordCredentials") or [])
        expiries = sorted(c["endDateTime"] for c in creds if c.get("endDateTime"))
        try:
            owners = graph.get_all(f"/servicePrincipals/{app['sp_id']}/owners",
                                   {"$select": "id,displayName,userPrincipalName"})
        except Exception:
            owners = []
        sp_owners = [{"id": o.get("id"),
                      "name": o.get("displayName") or o.get("userPrincipalName") or o.get("id")}
                     for o in owners]

        app["ownership"] = {"application_owners": [], "service_principal_owners": sp_owners}
        app["technical_inventory"] = {
            "enabled": obj.get("accountEnabled"),
            "publisher": obj.get("publisherName") or app.get("publisher"),
            "homepage": obj.get("homepage"),
            "tags": obj.get("tags") or [],
            "description": obj.get("description") or obj.get("notes") or "",
            "sp_type": obj.get("servicePrincipalType"),
            "credential_count": len(creds),
            "credential_next_expiry": expiries[0] if expiries else None,
        }

    # 2 sequential calls per app (object + owners) — same reasoning as
    # enrich_with_app_role_assignments. Run in parallel.
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        list(ex.map(_enrich, discovered))


def enrich_with_signin_activity(graph, discovered, now=None):
    """
    Adds real usage metrics from sign-in logs (requires Entra ID P1).
    Criterion 10: if activity fails (no P1 / 403), every app's usage becomes None and
    the assessment continues uninterrupted.
    """
    now = now or datetime.now(timezone.utc)
    iso90 = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:  # probe accessibility first
        graph.get_all("/auditLogs/signIns", {"$top": "1"}, max_items=1)
    except Exception:
        for app in discovered:
            app["usage"] = None
        return
    def _enrich(app):
        try:
            app["usage"] = _app_usage(graph, app, now, iso90)
        except Exception:
            app["usage"] = None

    # 2 sign-in log queries per app (delegated + service principal) — these are
    # filtered analytical queries against /auditLogs/signIns, one at a time the
    # slowest enrichment step. Same reasoning as enrich_with_app_role_assignments.
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        list(ex.map(_enrich, discovered))
