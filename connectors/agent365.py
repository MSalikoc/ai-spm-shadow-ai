"""
Microsoft Agent 365 collector — agent registry & package envanteri (Adım 2).

Endpoint : GET /v1.0/copilot/admin/catalog/packages           (liste)
           GET /v1.0/copilot/admin/catalog/packages/{id}       (detay)
Permission: CopilotPackages.Read.All
Lisans/erişim yoksa: LICENSE_MISSING / API_UNAVAILABLE / PERMISSION_MISSING.

Package'ı birleşik AI_AGENT asset'ine normalize eder; entra appId varsa korelasyona
hazırdır. elementDetails parse edilir; parse edilemeyen tanımlar raw_reference ile saklanır.
"""
import os
from datetime import datetime, timedelta, timezone

from .base import (ApiUnavailable, BaseCollector, EntityType, LicenseMissing,
                   PermissionMissing, Source)
from .model import make_asset, raw_reference


class Agent365Collector(BaseCollector):
    name = "agent365"
    source = Source.AGENT_365

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_AGENT365", "").lower() == "true"

    # --- toplama ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("Graph istemcisi yok")
        try:
            packages = self._graph.get_all("/copilot/admin/catalog/packages", {"$top": "999"})
        except RuntimeError as e:
            raise self._classify(e)
        out = []
        for p in packages:
            pid = p.get("id")
            detail = self._graph.get(f"/copilot/admin/catalog/packages/{pid}") if pid else {}
            out.append({**p, **(detail or {})})
        return out

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
        for p in raw_records:
            pid = p.get("id")
            app_id = p.get("applicationId") or p.get("appId")
            manifest = p.get("manifest") or {}
            publisher = p.get("publisher") or p.get("publisherName") or ""
            elements = self._parse_elements(p.get("elementDetails") or p.get("elements") or [], pid)
            agent = make_asset(
                EntityType.AI_AGENT,
                p.get("displayName") or p.get("name"),
                self.source,
                external_ids={
                    "agent365_package_id": pid,
                    "agent365_asset_id": p.get("assetId") or p.get("asset_id"),
                    "entra_app_id": app_id,
                    "manifest_id": p.get("manifestId") or manifest.get("id"),
                },
                last_seen=p.get("lastModifiedDateTime"),
            )
            agent["publisher"] = publisher            # korelasyon (pub+domain) için
            agent["agent365"] = {
                "package_id": pid,
                "package_type": p.get("packageType") or p.get("type"),
                "publisher": publisher,
                "build_type": self._build_type(publisher, elements),
                "platform": p.get("platform"),
                "supported_hosts": p.get("supportedHosts") or [],
                "element_types": p.get("elementTypes") or [e["element_type"] for e in elements if e.get("element_type")],
                "version": p.get("version"),
                "manifest_version": p.get("manifestVersion"),
                "blocked": bool(p.get("blocked") or p.get("isBlocked")),
                "available_to": p.get("availableToScope") or p.get("availableTo"),
                "deployed_to": p.get("deployedToScope") or p.get("deployedTo"),
                "last_modified": p.get("lastModifiedDateTime"),
                "categories": p.get("categories") or [],
                "short_description": p.get("shortDescription"),
                "long_description": p.get("longDescription"),
                "sensitivity": p.get("sensitivityLabel") or p.get("sensitivity"),
                "allowed_users_groups": p.get("allowedMembers") or p.get("allowedUsersAndGroups") or [],
                "elements": elements,
            }
            out.append(agent)
        return out

    @staticmethod
    def _build_type(publisher, elements):
        if publisher and "microsoft" in publisher.lower():
            return "microsoft"
        if any(e.get("custom_engine_agent_id") for e in elements):
            return "custom"
        return "partner" if publisher else "custom"

    def _parse_elements(self, elems, pid):
        out = []
        for e in elems:
            typ = e.get("elementType") or e.get("type")
            d = e.get("definition") or e.get("elementDefinition") or {}
            out.append({
                "element_type": typ,
                "declarative_agent_id": d.get("declarativeAgentId") or (d.get("id") if typ == "declarativeAgent" else None),
                "custom_engine_agent_id": d.get("customEngineAgentId"),
                "bot_id": d.get("botId") or (d.get("bot") or {}).get("id"),
                "supported_scopes": d.get("scopes") or d.get("supportedScopes"),
                "file_support": d.get("fileSupport") if d.get("fileSupport") is not None else d.get("supportsFiles"),
                "host": d.get("host") or d.get("hostType"),
                # parse edilemeyen tanımı kaybetme:
                "raw_reference": raw_reference(self.source, package_id=pid, element_type=typ),
                "raw_definition": d or None,
            })
        return out

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}


def _within_30d(iso, now):
    if not iso:
        return False
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= now - timedelta(days=30)


def metrics(assets, now=None):
    """Agent 365 dashboard metrikleri (normalize edilmiş asset listesinden)."""
    now = now or datetime.now(timezone.utc)
    a = [x for x in assets if x.get("agent365")]

    def g(x):
        return x["agent365"]

    def scope_all(v):
        return str(v or "").strip().lower() in ("everyone", "all", "alltenant", "organization")

    return {
        "total_registered": len(a),
        "microsoft_built": sum(1 for x in a if g(x).get("build_type") == "microsoft"),
        "partner_built": sum(1 for x in a if g(x).get("build_type") == "partner"),
        "custom": sum(1 for x in a if g(x).get("build_type") == "custom"),
        "blocked": sum(1 for x in a if g(x).get("blocked")),
        "available_to_everyone": sum(1 for x in a if scope_all(g(x).get("available_to"))),
        "deployed_to_everyone": sum(1 for x in a if scope_all(g(x).get("deployed_to"))),
        "modified_last_30d": sum(1 for x in a if _within_30d(g(x).get("last_modified"), now)),
        "without_correlated_identity": sum(
            1 for x in a if not x["external_ids"].get("agent_identity_id")
            and not x["external_ids"].get("entra_app_id")),
    }
