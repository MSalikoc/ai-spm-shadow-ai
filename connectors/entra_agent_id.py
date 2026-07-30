"""
Microsoft Entra Agent ID collector — agent identity / blueprint / owner / sponsor /
permission envanteri (Adım 3).

Endpoint : GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity          (identity listesi)
           GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint       (blueprint listesi)
           GET /servicePrincipals/{id}/microsoft.graph.agentIdentity/owners     (sahipler)
           GET /servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors   (sponsorlar)
           GET /servicePrincipals/{id}/appRoleAssignments                       (app-only izin)
           GET /servicePrincipals/{id}/oauth2PermissionGrants                   (delege izin)
           GET /servicePrincipals/{id}/memberOf                                 (grup üyeliği)
Permission: Application.Read.All + Directory.Read.All (owner/sponsor/grant için).
Lisans/erişim yoksa: PERMISSION_MISSING / API_UNAVAILABLE / LICENSE_MISSING.

Her agent identity birleşik AGENT_IDENTITY asset'ine, her blueprint AGENT_BLUEPRINT
asset'ine normalize edilir. entra_app_id → Agent365 package'ıyla; agent_blueprint_id →
blueprint'iyle korele olur. Alt-kaynak (owner/sponsor/perm) hataları tek başına tüm
toplamayı düşürmez → connector PARTIALLY_CONNECTED olur.
"""
import os
from concurrent.futures import ThreadPoolExecutor

from .base import (ApiUnavailable, BaseCollector, ConnectorStatus, EntityType,
                   LicenseMissing, PermissionMissing, Source)
from .model import make_asset, raw_reference


class EntraAgentIdCollector(BaseCollector):
    name = "entra_agent_id"
    source = Source.ENTRA_AGENT_ID

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_ENTRA_AGENT_ID", "").lower() == "true"

    # --- toplama ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("Graph istemcisi yok")
        try:
            identities = self._graph.get_all(
                "/servicePrincipals/microsoft.graph.agentIdentity", {"$top": "999"})
        except RuntimeError as e:
            raise self._classify(e)

        # Blueprint listesi ayrı bir izin/önizleme kapısı olabilir → düşerse identity'ler yine gelir.
        try:
            blueprints = self._graph.get_all(
                "/applications/microsoft.graph.agentIdentityBlueprint", {"$top": "999"})
        except RuntimeError as e:
            blueprints = []
            self._status = ConnectorStatus.PARTIALLY_CONNECTED
            self._error = self._error or f"blueprints: {str(e)[:160]}"

        def _fetch_identity(sp):
            oid = sp.get("id")
            base = f"/servicePrincipals/{oid}/microsoft.graph.agentIdentity"
            return {
                "_kind": "identity",
                "sp": sp,
                "owners": self._sub(f"{base}/owners"),
                "sponsors": self._sub(f"{base}/sponsors"),
                "app_roles": self._sub(f"/servicePrincipals/{oid}/appRoleAssignments"),
                "oauth_grants": self._sub(f"/servicePrincipals/{oid}/oauth2PermissionGrants"),
                "groups": self._sub(f"/servicePrincipals/{oid}/memberOf"),
            }

        # Her identity için 5 ayrı alt-kaynak çağrısı — büyük tenant'larda sıralı yapıldığında
        # aynı gecikme riski (bkz. connectors/agent365.py, collectors.py'deki eş düzeltmeler).
        with ThreadPoolExecutor(max_workers=10) as ex:
            out = list(ex.map(_fetch_identity, identities))
        out.extend({"_kind": "blueprint", "app": app} for app in blueprints)
        return out

    def _sub(self, path):
        """Alt-kaynak GET — tekil hata tüm collect'i düşürmez, connector'ı PARTIAL yapar."""
        if self._graph is None:
            return []
        try:
            return self._graph.get_all(path, {"$top": "999"}) or []
        except RuntimeError as e:
            self._status = ConnectorStatus.PARTIALLY_CONNECTED
            self._error = self._error or str(e)[:160]
            return []

    @staticmethod
    def _classify(err):
        s = str(err).lower()
        if "403" in s or "forbidden" in s or "authorization" in s:
            return PermissionMissing(str(err)[:200])
        if "license" in s or "quota" in s or "subscription" in s:
            return LicenseMissing(str(err)[:200])
        if "404" in s or "not found" in s or "notfound" in s or "400" in s:
            return ApiUnavailable(str(err)[:200])
        return err   # generic → safe_run ERROR yapar

    # --- normalize ---
    def normalize(self, raw_records: list) -> list:
        out = []
        for r in raw_records:
            if r.get("_kind") == "blueprint":
                out.append(self._normalize_blueprint(r.get("app") or {}))
            else:
                out.append(self._normalize_identity(r))
        return out

    def _normalize_identity(self, r: dict) -> dict:
        sp = r.get("sp") or {}
        oid = sp.get("id")
        app_id = sp.get("appId")
        # Blueprint bağı henüz kesin şema değil → birkaç olası anahtarı dene, kaybetme.
        ai = sp.get("agentIdentity") or {}
        blueprint_id = (sp.get("blueprintId") or sp.get("agentIdentityBlueprintId")
                        or ai.get("blueprintId") or ai.get("agentIdentityBlueprintId"))

        owners = [self._principal(o) for o in (r.get("owners") or [])]
        sponsors = [self._principal(o) for o in (r.get("sponsors") or [])]
        app_perms = [self._app_role(a) for a in (r.get("app_roles") or [])]
        delegated = [self._oauth(g) for g in (r.get("oauth_grants") or [])]
        groups = [self._group(g) for g in (r.get("groups") or [])]

        asset = make_asset(
            EntityType.AGENT_IDENTITY,
            sp.get("displayName") or sp.get("appDisplayName"),
            self.source,
            external_ids={
                "entra_app_id": app_id,
                "agent_identity_id": oid,      # object id — korelasyonun güçlü anahtarı
                "entra_object_id": oid,
                "agent_blueprint_id": blueprint_id,
            },
            first_seen=sp.get("createdDateTime"),
            last_seen=sp.get("createdDateTime"),
        )
        asset["agent_identity"] = {
            "object_id": oid,
            "app_id": app_id,
            "blueprint_id": blueprint_id,
            "account_enabled": sp.get("accountEnabled"),
            "created_date": sp.get("createdDateTime"),
            "sign_in_audience": sp.get("signInAudience"),
            "service_principal_type": sp.get("servicePrincipalType"),
            "app_owner_org_id": sp.get("appOwnerOrganizationId"),
            "owners": owners,
            "sponsors": sponsors,
            "application_permissions": app_perms,     # app-only (appRoleAssignments)
            "delegated_permissions": delegated,       # delege (oauth2PermissionGrants)
            "group_memberships": groups,
            "raw_reference": raw_reference(self.source, object_id=oid),
        }
        return asset

    def _normalize_blueprint(self, app: dict) -> dict:
        bid = app.get("id")
        asset = make_asset(
            EntityType.AGENT_BLUEPRINT,
            app.get("displayName"),
            self.source,
            external_ids={
                "agent_blueprint_id": bid,
                "entra_app_id": app.get("appId"),
            },
            first_seen=app.get("createdDateTime"),
            last_seen=app.get("createdDateTime"),
        )
        asset["agent_blueprint"] = {
            "blueprint_id": bid,
            "app_id": app.get("appId"),
            "publisher_domain": app.get("publisherDomain"),
            "created_date": app.get("createdDateTime"),
            "sign_in_audience": app.get("signInAudience"),
            "required_resource_access": app.get("requiredResourceAccess") or [],
            "raw_reference": raw_reference(self.source, blueprint_id=bid),
        }
        return asset

    @staticmethod
    def _principal(o: dict) -> dict:
        return {
            "id": o.get("id"),
            "display_name": o.get("displayName"),
            "upn": o.get("userPrincipalName") or o.get("mail"),
            "type": (o.get("@odata.type") or "").rsplit(".", 1)[-1] or None,
        }

    @staticmethod
    def _app_role(a: dict) -> dict:
        return {
            "app_role_id": a.get("appRoleId"),
            "resource_id": a.get("resourceId"),
            "resource_display_name": a.get("resourceDisplayName"),
            "principal_id": a.get("principalId"),
            "created": a.get("createdDateTime"),
        }

    @staticmethod
    def _oauth(g: dict) -> dict:
        return {
            "resource_id": g.get("resourceId"),
            "consent_type": g.get("consentType"),
            "principal_id": g.get("principalId"),
            "scopes": [s for s in (g.get("scope") or "").split(" ") if s],
        }

    @staticmethod
    def _group(gr: dict) -> dict:
        return {
            "id": gr.get("id"),
            "display_name": gr.get("displayName"),
            "type": (gr.get("@odata.type") or "").rsplit(".", 1)[-1] or None,
        }

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}


def metrics(assets, now=None):
    """Entra Agent ID dashboard metrikleri (bu connector'ın normalize asset listesinden)."""
    ids = [x for x in assets if x.get("agent_identity")]
    bps = [x for x in assets if x.get("agent_blueprint")]

    def g(x):
        return x["agent_identity"]

    return {
        "total_identities": len(ids),
        "enabled": sum(1 for x in ids if g(x).get("account_enabled")),
        "disabled": sum(1 for x in ids if g(x).get("account_enabled") is False),
        "without_owner": sum(1 for x in ids if not g(x).get("owners")),
        "without_sponsor": sum(1 for x in ids if not g(x).get("sponsors")),
        "without_blueprint": sum(1 for x in ids if not g(x).get("blueprint_id")),
        "with_app_only_permissions": sum(1 for x in ids if g(x).get("application_permissions")),
        "with_delegated_permissions": sum(1 for x in ids if g(x).get("delegated_permissions")),
        # Agent365 package'ına bağlanacak güçlü anahtarı (appId) olmayan identity'ler:
        "uncorrelated": sum(1 for x in ids if not x["external_ids"].get("entra_app_id")),
        "total_blueprints": len(bps),
    }
