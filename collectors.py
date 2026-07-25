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
            "scopes": [],           # sonra doldurulur
            "consent_type": None,   # AllPrincipals (admin) / Principal (kullanıcı)
            "user_count": 0,
        })
    return out


def enrich_with_oauth_grants(graph, discovered: list[dict]) -> None:
    """Her keşfedilen SP'ye verilmiş delegated consent scope'larını ekler."""
    grants = graph.get_all("/oauth2PermissionGrants", {"$top": "999"})
    by_client: dict[str, list[dict]] = {}
    for g in grants:
        by_client.setdefault(g.get("clientId"), []).append(g)

    for app in discovered:
        scopes: set[str] = set()
        consent_types: set[str] = set()
        users: set[str] = set()
        for g in by_client.get(app["sp_id"], []):
            for s in (g.get("scope") or "").split():
                scopes.add(s.strip().lower())
            ct = g.get("consentType")
            if ct:
                consent_types.add(ct)
            if g.get("principalId"):
                users.add(g["principalId"])
        app["scopes"] = sorted(scopes)
        # AllPrincipals varsa admin onayı (tüm org) → en yüksek blast radius
        app["consent_type"] = "AllPrincipals" if "AllPrincipals" in consent_types \
            else ("Principal" if consent_types else None)
        app["user_count"] = len(users)
