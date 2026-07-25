"""
Graph'tan Shadow AI sinyallerini toplar ve normalize eder.

Ana fikir:
  1) Tenant'taki tüm servicePrincipal'ları çek.
  2) Microsoft/first-party olmayanları (3. parti) ayıkla.
  3) Bunlardan AI vendor'a benzeyenleri işaretle.
  4) Her SP için verilmiş delegated OAuth consent'lerini (scope'lar) eşle.
"""
from config import AI_VENDORS, GENERIC_AI_HINTS, MICROSOFT_OWNER_TENANTS


def _text_blob(sp: dict) -> str:
    parts = [sp.get("displayName", ""), sp.get("publisherName", ""),
             sp.get("homepage", "") or "", (sp.get("verifiedPublisher") or {}).get("displayName", "")]
    return " ".join(p.lower() for p in parts if p)


def _match_vendor(sp: dict):
    """(vendor_adı, güven) döner; eşleşme yoksa (None, 0)."""
    blob = _text_blob(sp)
    app_id = sp.get("appId", "")
    for v in AI_VENDORS:
        if app_id and app_id in v["appIds"]:
            return v["name"], "high"
        if any(pat in blob for pat in v["patterns"]):
            return v["name"], "high"
    if any(hint in blob for hint in GENERIC_AI_HINTS):
        return "Bilinmeyen AI (jenerik eşleşme)", "low"
    return None, None


def _is_third_party(sp: dict, home_tenant: str) -> bool:
    owner = sp.get("appOwnerOrganizationId")
    if owner is None:
        return False  # sahibi belirsiz — genelde first-party/managed
    if owner in MICROSOFT_OWNER_TENANTS:
        return False
    if owner == home_tenant:
        return False  # kendi tenant'ımızda üretilmiş (iç uygulama)
    return True


def collect_service_principals(graph, home_tenant: str) -> list[dict]:
    select = ("id,appId,displayName,appOwnerOrganizationId,publisherName,"
              "verifiedPublisher,servicePrincipalType,homepage,tags,accountEnabled")
    sps = graph.get_all("/servicePrincipals", {"$select": select, "$top": "999"})
    out = []
    for sp in sps:
        vendor, confidence = _match_vendor(sp)
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
            "scopes": [],                    # delegated scope adları (skorlama geriye-uyum)
            "consent_type": None,            # AllPrincipals (admin) / Principal (kullanıcı)
            "user_count": 0,
            "delegated_permissions": [],     # [{resource, permission, consent_type}]
            "application_permissions": [],   # [{resource, permission, permission_id}]
            "has_app_only_access": False,    # kullanıcısız (app-only) erişebiliyor mu
        })
    return out


ZERO_GUID = "00000000-0000-0000-0000-000000000000"


class _ResourceResolver:
    """resourceId → {name, roles:{roleId:permName}} çözümlemesini önbellekler."""
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
                "name": obj.get("displayName") or fallback_name or "Bilinmeyen API",
                "roles": roles,
            }
        elif fallback_name and self._cache[resource_id]["name"] == "Bilinmeyen API":
            self._cache[resource_id]["name"] = fallback_name
        return self._cache[resource_id]


def enrich_with_oauth_grants(graph, discovered: list[dict]) -> None:
    """
    Delegated (kullanıcı adına) consent scope'larını ekler.
    Korunur: `scopes` (skorlama), `consent_type`, `user_count`.
    Eklenir: `delegated_permissions` = [{resource, permission, consent_type}].
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
    Application (app-only) permission'ları ekler:
      GET /servicePrincipals/{id}/appRoleAssignments
    appRoleId GUID'i, hedef resource SP'nin appRoles'undan okunabilir ada çevrilir;
    çözümlenemezse GUID kaybedilmez (permission_id olarak saklanır). Microsoft Graph
    dışındaki custom enterprise API'ler de desteklenir (resource SP'den çözümlenir).
    """
    resolver = _ResourceResolver(graph)
    for app in discovered:
        try:
            assigns = graph.get_all(
                f"/servicePrincipals/{app['sp_id']}/appRoleAssignments", {"$top": "999"})
        except Exception:
            assigns = []
        perms: list[dict] = []
        for a in assigns:
            role_id = a.get("appRoleId")
            if not role_id or role_id == ZERO_GUID:
                continue  # rol yok (yalnızca atama) → application permission değil
            res = resolver.resolve(a.get("resourceId", ""), a.get("resourceDisplayName", ""))
            perms.append({
                "resource": res["name"],
                "permission": res["roles"].get(role_id, role_id),  # çözülemezse GUID
                "permission_id": role_id,
            })
        app["application_permissions"] = perms
        app["has_app_only_access"] = bool(perms)
