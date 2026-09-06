"""
Collects and normalizes Shadow AI signals from Graph.

Main idea:
  1) Pull every servicePrincipal in the tenant.
  2) Select which ones to assess — see `scan_scope()`.
  3) Flag the ones that look like AI vendors.
  4) Match each SP's granted delegated OAuth consents (scopes).
  5) Add application (app-only) permissions and real sign-in activity.

Scan scope (`AISPM_SCAN_SCOPE`) decides step 2. The default, `ai`, only keeps apps that
match the AI catalog — precise, but blind to any AI vendor the catalog has not heard of.
`consented` also keeps every app holding a real OAuth grant, which is the honest view of
the tenant's consent surface; `all` keeps every third-party app. See `scan_scope`.
"""
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from config import AI_VENDORS, GENERIC_AI_HINTS, MICROSOFT_OWNER_TENANTS

_MAX_WORKERS = 10  # used in enrichment loops that make a separate Graph call per app

MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"

SCAN_SCOPES = ("ai", "consented", "all")


def scan_scope() -> str:
    """
    Which service principals get assessed.

      ai        — only apps matching the AI catalog (default; precise, narrowest)
      consented — the above plus every app that actually holds a delegated OAuth grant
                  or an app-only role. This is the full consent surface: an AI tool the
                  catalog has never heard of still shows up, tagged `ai_match=False`.
      all       — every third-party app, consented or not.

    Read at call time (not import time) so it can be changed without a redeploy.
    """
    scope = (os.environ.get("AISPM_SCAN_SCOPE") or "ai").strip().lower()
    return scope if scope in SCAN_SCOPES else "ai"


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


def match_vendor_name(*texts):
    """
    Maps free text to a catalog vendor, or None.

    The unified portal needs one name for what the two sides call differently: Entra
    reports the service principal's display name, Defender reports its own app name
    ("ChatGPT (Consumer & Enterprise)"), and neither carries an ID the other shares.
    Running both through the same catalog is what lets a vendor be counted once.
    """
    blob = " ".join(t.lower() for t in texts if t)
    if not blob:
        return None
    for v in AI_VENDORS:
        if any(pat in blob for pat in v.get("patterns", [])):
            return v["name"]
        if any(dom in blob for dom in v.get("domains", [])):
            return v["name"]
    return None


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


def _consented_sp_ids(graph, sps) -> tuple[set[str], dict[str, list]]:
    """
    Include grants to every API, not only Microsoft Graph. A failed scope lookup must
    stop discovery rather than turn missing inventory into apparent removals.
    """
    ids: set[str] = set()
    for g in graph.get_all("/oauth2PermissionGrants", {"$top": "999"}):
        if g.get("clientId"):
            ids.add(g["clientId"])
    candidates = [{"sp_id": sp["id"]} for sp in sps
                  if sp.get("appOwnerOrganizationId") not in MICROSOFT_OWNER_TENANTS]
    assignments = _batched_collection(
        graph, candidates, lambda app: f"/servicePrincipals/{app['sp_id']}/appRoleAssignments?$top=100")
    ids.update(sp_id for sp_id, roles in assignments.items()
               if any(role.get("appRoleId") and role["appRoleId"] != ZERO_GUID for role in roles))
    return ids, assignments


def collect_service_principals(graph, home_tenant: str) -> list[dict]:
    select = ("id,appId,displayName,appOwnerOrganizationId,publisherName,"
              "verifiedPublisher,servicePrincipalType,homepage,tags,accountEnabled")
    sps = graph.get_all("/servicePrincipals", {"$select": select, "$top": "100"})

    scope = scan_scope()
    consented, assignments = _consented_sp_ids(graph, sps) if scope == "consented" else (set(), {})

    out = []
    for sp in sps:
        vendor, confidence, signal = _match_vendor(sp)
        owner = sp.get("appOwnerOrganizationId")
        third_party = _is_third_party(sp, home_tenant)
        first_party_ms = owner in MICROSOFT_OWNER_TENANTS

        if vendor:
            keep = True
        elif scope == "consented":
            keep = sp["id"] in consented and not first_party_ms
        elif scope == "all":
            keep = third_party
        else:
            keep = False
        if not keep:
            continue

        out.append({
            "sp_id": sp["id"],
            "app_id": sp.get("appId"),
            "display_name": sp.get("displayName"),
            "publisher": sp.get("publisherName") or "—",
            "verified_publisher": bool((sp.get("verifiedPublisher") or {}).get("verifiedPublisherId")),
            "owner_tenant": owner,
            "third_party": third_party,
            "first_party_microsoft": first_party_ms,
            # Apps kept by scope rather than by a catalog hit are labelled honestly —
            # they are part of the consent surface, not a claimed AI detection.
            "vendor": vendor or "Not an AI catalog match",
            "confidence": confidence or "none",
            "match_signal": signal or "scope",  # app_id / pattern / domain / generic / scope
            "ai_match": bool(vendor),
            "asset_type": _asset_type(sp),   # application / agent
            "scopes": [],                    # delegated scope names (scoring backward-compat)
            "consent_type": None,            # AllPrincipals (admin) / Principal (user)
            "user_count": 0,
            "delegated_permissions": [],     # [{resource, permission, consent_type}]
            "application_permissions": [],   # [{resource, permission, permission_id}]
            "has_app_only_access": False,    # can it access without a user (app-only)
        })
        if sp["id"] in assignments:
            out[-1]["_app_role_assignments"] = assignments[sp["id"]]
    logging.info("discovery: %s of %s service principals kept (scope=%s, ai_match=%s)",
                 len(out), len(sps), scope, sum(1 for a in out if a["ai_match"]))
    return out


class _ResourceResolver:
    """
    Caches resourceId → {name, roles:{roleId:permName}} resolution.

    Shared across the enrichment thread pools, so the cache is lock-guarded: without it
    two threads resolving the same API race and issue duplicate Graph calls.
    """
    def __init__(self, graph):
        self._graph = graph
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def resolve(self, resource_id: str, fallback_name: str = "") -> dict:
        with self._lock:
            hit = self._cache.get(resource_id)
        if hit is None:
            getter = getattr(self._graph, "get_checked", None) or self._graph.get
            obj = getter(f"/servicePrincipals/{resource_id}",
                         {"$select": "displayName,appRoles"}) or {}
            roles = {r.get("id"): (r.get("value") or r.get("displayName"))
                     for r in obj.get("appRoles", []) if r.get("id")}
            hit = {"name": obj.get("displayName") or fallback_name or "Unknown API",
                   "roles": roles}
            with self._lock:
                hit = self._cache.setdefault(resource_id, hit)
        if fallback_name and hit["name"] == "Unknown API":
            hit["name"] = fallback_name
        return hit


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

    One assignment call per app, sent through $batch — 20 apps per round-trip instead
    of one, which is what keeps a several-hundred-app tenant inside the scan budget.
    """
    resolver = _ResourceResolver(graph)
    assignments = {app["sp_id"]: app.pop("_app_role_assignments") for app in discovered
                   if "_app_role_assignments" in app}
    assignments.update(_batched_collection(
        graph, [app for app in discovered if app["sp_id"] not in assignments],
        lambda app: f"/servicePrincipals/{app['sp_id']}/appRoleAssignments?$top=100"))

    for app in discovered:
        perms: list[dict] = []
        for a in assignments.get(app["sp_id"], []):
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


def _batched_collection(graph, discovered, url_for) -> dict[str, list]:
    """
    Runs one collection GET per app through Graph's $batch, keyed by sp_id.
    Falls back to sequential calls against clients that predate `batch_collection`
    (the test fakes, mainly), so callers never need to care which they were given.
    """
    spec = [{"id": app["sp_id"], "url": url_for(app)} for app in discovered]
    if hasattr(graph, "batch_collection"):
        return graph.batch_collection(spec)

    out: dict[str, list] = {}

    def _one(item):
        from urllib.parse import parse_qsl
        path, _, query = item["url"].partition("?")
        out[item["id"]] = graph.get_all(path, dict(parse_qsl(query))) or []

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        list(ex.map(_one, spec))
    return out


# --- Real usage / sign-in activity -----------------------------------
def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def activity_days() -> int:
    """Graph sign-in retention is at most 30 days for standard P1/P2 access."""
    try:
        return max(7, min(int(os.environ.get("AISPM_ACTIVITY_DAYS", "30")), 30))
    except ValueError:
        return 30


def usage_complete(app, days=0):
    usage = app.get("usage") or {}
    return bool(usage.get("available") and usage.get("window_days", 30) >= days)


def core_health(apps):
    incomplete = sum(bool(a.get("collection_errors")) or not usage_complete(a) for a in apps)
    return {"status": "PARTIALLY_CONNECTED" if incomplete else "CONNECTED",
            "count": len(apps), "incomplete_records": incomplete,
            "detail": f"{incomplete} records with incomplete ownership, inventory or activity evidence"}


_APPID_CHUNK = 15          # appId filters per sign-in query (Graph filter length limit)
_SIGNIN_CAP = 50000        # hard ceiling on sign-in rows pulled per pass


def _signin_filter(app_ids, iso_from, sp_events=False) -> str:
    clause = " or ".join(f"appId eq '{a}'" for a in app_ids)
    flt = f"({clause}) and createdDateTime ge {iso_from}"
    if sp_events:
        flt += " and signInEventTypes/any(t:t eq 'servicePrincipal')"
    else:
        flt += " and signInEventTypes/any(t:t eq 'interactiveUser' or t eq 'nonInteractiveUser')"
    return flt


def _pull_signins(graph, app_ids, iso_from, sp_events=False) -> tuple[list[dict], list[str]]:
    """
    Pulls sign-in records for many apps at once.

    The previous implementation ran two filtered queries *per app*; on a tenant with a
    few hundred apps that was hundreds of the slowest call in the whole scan, and it is
    the reason large tenants timed out. Chunking the appId filter cuts it to a couple of
    queries per 15 apps, and the rows are grouped by appId in memory afterwards.

    Both passes use beta to explicitly include non-interactive user and service-principal
    events. The v1.0 default user list alone is not complete usage evidence.
    """
    rows: list[dict] = []
    errors = []
    for i in range(0, len(app_ids), _APPID_CHUNK):
        chunk = app_ids[i:i + _APPID_CHUNK]
        remaining = _SIGNIN_CAP - len(rows)
        if remaining <= 0:
            logging.warning("sign-in pull hit the %s row cap; metrics are partial", _SIGNIN_CAP)
            errors.append("Sign-in row cap reached")
            break
        try:
            rows.extend(graph.get_all(
                "/auditLogs/signIns",
                {"$filter": _signin_filter(chunk, iso_from, sp_events), "$top": "999"},
                max_items=remaining, beta=True))
            if len(rows) >= _SIGNIN_CAP:
                errors.append("Sign-in row cap reached; full coverage cannot be established")
        except Exception as e:
            # One concise line for the whole pass rather than a traceback per chunk:
            # a tenant without P1 would otherwise print twenty stack traces.
            errors.append(str(e)[:200])
    if errors:
        logging.warning("sign-in pull (%s pass) incomplete: %s",
                        "service principal" if sp_events else "user", "; ".join(errors))
    return rows, errors


def _group_by_app(rows: list[dict]) -> dict[str, list[dict]]:
    by_app: dict[str, list[dict]] = {}
    for r in rows:
        aid = r.get("appId")
        if aid:
            by_app.setdefault(aid, []).append(r)
    return by_app


def _usage_from_rows(app, user_si, sp_si, now, *, window_days=30, errors=None):
    """Builds one app's usage metrics from its already-fetched sign-in rows."""
    w7, w30 = now - timedelta(days=7), now - timedelta(days=30)
    prev7_lo, prev7_hi = now - timedelta(days=14), now - timedelta(days=7)
    u7, u30, uprev7 = set(), set(), set()
    users_all, ips, countries = set(), set(), set()
    ok30 = fail30 = 0
    last_deleg = None
    daily = {}  # day-index(0..29) → set(user)
    window_start = now - timedelta(days=window_days)

    for s in user_si:
        dt = _parse_dt(s.get("createdDateTime"))
        if not dt or dt.tzinfo is None or not window_start <= dt <= now:
            continue
        successful = (s.get("status") or {}).get("errorCode") == 0
        if dt >= w30:
            if successful:
                ok30 += 1
            else:
                fail30 += 1
        if not successful:
            continue
        uid = s.get("userId") or s.get("userPrincipalName") or ""
        last_deleg = dt if last_deleg is None or dt > last_deleg else last_deleg
        if uid:
            users_all.add(uid)
            if dt >= w7:
                u7.add(uid)
            if dt >= w30:
                u30.add(uid)
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

    last_sp = None
    for s in sp_si:
        dt = _parse_dt(s.get("createdDateTime"))
        if (dt and dt.tzinfo is not None and window_start <= dt <= now
                and (s.get("status") or {}).get("errorCode") == 0
                and (last_sp is None or dt > last_sp)):
            last_sp = dt

    last_used = max([d for d in (last_deleg, last_sp) if d], default=None)
    daily_active = [len(daily.get(i, set())) for i in range(30)]

    return {
        "available": not errors,
        "collection_status": "partial" if errors else "complete",
        "collection_errors": errors or [],
        "window_days": window_days,
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "retention_note": "Graph retained window only; absence is not lifetime non-use.",
        "consent_user_count": app.get("user_count", 0),
        "active_users_7d": len(u7),
        "active_users_30d": len(u30) if window_days >= 30 and not errors else None,
        "active_users_90d": None,
        "last_delegated_signin": last_deleg.isoformat() if last_deleg else None,
        "last_service_principal_signin": last_sp.isoformat() if last_sp else None,
        "successful_signins_30d": ok30,
        "failed_signins_30d": fail30,
        "unique_user_count": len(users_all),
        "unique_ip_count": len(ips),
        "country_count": len(countries),
        "last_used_date": last_used.isoformat() if last_used else None,
        "never_used": False if last_used else None,
        "no_signins_observed": last_used is None if not errors else None,
        "inactive_30d": (last_used is None or last_used < w30)
                       if not errors and window_days >= 30 else None,
        "inactive_90d": None,
        "growth_7d": len(u7) - len(uprev7) if window_days >= 14 and not errors else None,
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
    try:
        owners_by_sp = _batched_collection(
            graph, discovered,
            lambda app: (f"/servicePrincipals/{app['sp_id']}/owners"
                         "?$select=id,displayName,userPrincipalName&$top=100"))
    except Exception as exc:
        logging.warning("Owner collection unavailable: %s", exc)
        owners_by_sp = {}
        for app in discovered:
            app.setdefault("collection_errors", {})["owners"] = str(exc)[:200]

    def _enrich(app):
        getter = getattr(graph, "get_checked", None) or graph.get
        try:
            obj = getter(
            f"/servicePrincipals/{app['sp_id']}",
            {"$select": "accountEnabled,publisherName,homepage,tags,notes,description,"
                        "servicePrincipalType,keyCredentials,passwordCredentials"}) or {}
            if "keyCredentials" not in obj or "passwordCredentials" not in obj:
                raise ValueError("Credential metadata absent from selected service principal")
        except Exception as exc:
            logging.warning("Inventory metadata unavailable for %s: %s", app["sp_id"], exc)
            app.setdefault("collection_errors", {})["inventory"] = str(exc)[:200]
            obj = {}
        creds = (obj.get("keyCredentials") or []) + (obj.get("passwordCredentials") or [])
        expiries = sorted(c["endDateTime"] for c in creds if c.get("endDateTime"))
        sp_owners = [{"id": o.get("id"),
                      "name": o.get("displayName") or o.get("userPrincipalName") or o.get("id")}
                     for o in owners_by_sp.get(app["sp_id"], [])]

        app["ownership"] = {"application_owners": [], "service_principal_owners": sp_owners}
        app["technical_inventory"] = {
            "enabled": obj.get("accountEnabled"),
            "publisher": obj.get("publisherName") or app.get("publisher"),
            "homepage": obj.get("homepage"),
            "tags": obj.get("tags") or [],
            "description": obj.get("description") or obj.get("notes") or "",
            "sp_type": obj.get("servicePrincipalType"),
            "credential_count": len(creds) if obj else None,
            "credential_next_expiry": expiries[0] if expiries else None,
        }

    # Owners came from $batch above; the SP object itself still needs a per-app GET
    # (it selects credential fields $batch cannot expand). Run those in parallel.
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        list(ex.map(_enrich, discovered))


def enrich_with_signin_activity(graph, discovered, now=None):
    """
    Adds real usage metrics from sign-in logs (requires Entra ID P1).
    Criterion 10: if activity fails (no P1 / 403), every app's usage becomes None and
    the assessment continues uninterrupted.
    """
    now = now or datetime.now(timezone.utc)
    iso_from = (now - timedelta(days=activity_days())).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:  # probe accessibility first
        graph.get_all("/auditLogs/signIns", {"$top": "1"}, max_items=1)
    except Exception:
        logging.exception("Sign-in accessibility probe failed")
        for app in discovered:
            app["usage"] = None
        return

    app_ids = [a["app_id"] for a in discovered if a.get("app_id")]
    user_rows, user_errors = _pull_signins(graph, app_ids, iso_from)
    sp_rows, sp_errors = _pull_signins(graph, app_ids, iso_from, sp_events=True)
    user_by_app, sp_by_app = _group_by_app(user_rows), _group_by_app(sp_rows)

    for app in discovered:
        aid = app.get("app_id")
        if not aid:
            app["usage"] = None
            continue
        try:
            app["usage"] = _usage_from_rows(app, user_by_app.get(aid, []),
                                            sp_by_app.get(aid, []), now,
                                            window_days=activity_days(),
                                            errors=user_errors + sp_errors)
        except Exception:
            logging.exception("usage computation failed for %s", aid)
            app["usage"] = None


def tenant_profile(graph) -> dict:
    """
    Descriptive facts about the tenant being scanned, for the report header.

    Read-only and best-effort: a tenant that will not answer /organization still gets a
    scan, it just gets fewer facts. Nothing here is inferred — a field absent from the
    response is absent from the report.
    """
    try:
        orgs = graph.get_all("/organization", {"$select": "id,displayName,verifiedDomains,"
                                                          "createdDateTime,countryLetterCode,"
                                                          "tenantType"})
    except Exception:
        logging.info("tenant profile unavailable (needs Organization.Read.All or "
                     "Directory.Read.All)")
        return {}
    if not orgs:
        return {}
    org = orgs[0]
    domains = org.get("verifiedDomains") or []
    default = next((d.get("name") for d in domains if d.get("isDefault")), None)
    return {
        "display_name": org.get("displayName"),
        "primary_domain": default or (domains[0].get("name") if domains else None),
        "domain_count": len(domains),
        "created": org.get("createdDateTime"),
        "country": org.get("countryLetterCode"),
        "tenant_type": org.get("tenantType"),
    }
