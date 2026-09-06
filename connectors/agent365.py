"""
Microsoft Agent 365 collector — agent registry & package inventory (Step 2).

Endpoints: GET /v1.0/copilot/admin/catalog/packages           (list)
           GET /v1.0/copilot/admin/catalog/packages/{id}       (detail)
Permission: CopilotPackages.Read.All
No license/access: LICENSE_MISSING / API_UNAVAILABLE / PERMISSION_MISSING.

Normalizes a package into a merged AI_AGENT asset; ready for correlation if an entra
appId is present. elementDetails is parsed; definitions that can't be parsed are kept
via raw_reference.
"""
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from .base import (ApiUnavailable, BaseCollector, ConnectorStatus, EntityType, Source,
                   classify_graph_error)
from .model import make_asset, raw_reference


class Agent365Collector(BaseCollector):
    name = "agent365"
    source = Source.AGENT_365
    required_read_roles = ("CopilotPackages.Read.All",)

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_AGENT365", "").lower() == "true"

    # --- collection ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("No Graph client")
        try:
            packages = self._graph.get_all("/copilot/admin/catalog/packages")
        except RuntimeError as e:
            raise self._classify(e)

        def _fetch(p):
            pid = p.get("id")
            try:
                if not pid:
                    raise ApiUnavailable("Package has no id")
                get = getattr(self._graph, "get_checked", None) or self._graph.get
                detail = get(f"/copilot/admin/catalog/packages/{pid}")
                if not detail:
                    raise ApiUnavailable("Package detail was empty")
                return {**p, **detail, "_detail_status": "COLLECTED"}
            except (RuntimeError, ApiUnavailable) as e:
                return {**p, "_detail_status": "UNAVAILABLE", "_detail_error": str(e)[:160]}

        # A separate detail GET is needed per package — done sequentially, on large
        # tenants (100+ packages) hundreds of sequential Graph calls can exceed the
        # Consumption plan's ~10min functionTimeout and silently kill the scan (before
        # even an except can run) — observed on a real tenant. GraphClient.get() is
        # thread-safe (no shared mutable state) — run in parallel.
        with ThreadPoolExecutor(max_workers=10) as ex:
            records = list(ex.map(_fetch, packages))
        failures = [p for p in records if p["_detail_status"] != "COLLECTED"]
        if failures:
            self._status = ConnectorStatus.PARTIALLY_CONNECTED
            self._error = f"{len(failures)} package detail requests failed; list metadata retained."
        return records

    @staticmethod
    def _classify(err):
        return classify_graph_error(err)

    # --- normalize ---
    def normalize(self, raw_records: list) -> list:
        out = []
        for p in raw_records:
            is_agent = self._is_agent(p)
            if is_agent is False:
                continue
            pid = p.get("id")
            app_id = p.get("applicationId") or p.get("appId")
            manifest = p.get("manifest") or {}
            publisher = p.get("publisher") or p.get("publisherName") or ""
            elements = self._parse_elements(p.get("elementDetails") or p.get("elements") or [], pid)
            agent = make_asset(
                EntityType.AI_AGENT if is_agent else EntityType.AGENT_PACKAGE,
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
            agent["publisher"] = publisher            # for correlation (pub+domain)
            agent["agent365"] = {
                "package_id": pid,
                "package_type": p.get("packageType") or p.get("type"),
                "publisher": publisher,
                "build_type": self._build_type(publisher, elements, p.get("type") or p.get("packageType")),
                "is_agent": is_agent,
                "detail_status": p.get("_detail_status", "COLLECTED"),
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
    def _build_type(publisher, elements, package_type=None):
        if str(publisher or "").strip().lower() in ("microsoft", "microsoft corporation"):
            return "microsoft"
        typ = str(package_type or "").lower()
        if typ in ("custom", "internal"):
            return "custom"
        if typ in ("external", "partner"):
            return "partner"
        if any(e.get("custom_engine_agent_id") for e in elements):
            return "custom"
        return "partner" if publisher else "custom"

    @staticmethod
    def _is_agent(p):
        types = list(p.get("elementTypes") or [])
        types.extend(e.get("elementType") or e.get("type") or ""
                     for e in (p.get("elementDetails") or p.get("elements") or [])
                     if isinstance(e, dict))
        types.append(p.get("packageType") or "")
        if "agent" in str(p.get("type") or "").lower():
            types.append(p["type"])
        normalized = {str(t).lower().replace(" ", "") for t in types if t}
        hosts = {str(h).lower() for h in (p.get("supportedHosts") or [])}
        if any("agent" in t or t in ("bot", "bots") for t in normalized) or "copilot" in hosts:
            return True
        if normalized and normalized <= {"officeaddin", "officeaddins", "tab", "tabs",
                                         "teamsapp", "messagingextension"}:
            return False
        return None

    def _parse_elements(self, elems, pid):
        out = []
        for e in elems:
            if not isinstance(e, dict):
                continue
            typ = e.get("elementType") or e.get("type")
            for element in e.get("elements") or [e]:
                if not isinstance(element, dict):
                    continue
                raw = element.get("definition") or element.get("elementDefinition") or {}
                d = raw
                if isinstance(d, str):
                    try:
                        d = json.loads(d)
                    except (ValueError, TypeError):
                        d = {}
                if not isinstance(d, dict):
                    d = {}
                normalized_type = str(typ or "").lower()
                out.append({
                    "element_type": typ,
                    "id": element.get("id"),
                    "declarative_agent_id": d.get("declarativeAgentId") or
                        ((d.get("id") or element.get("id")) if normalized_type == "declarativeagent" else None),
                    "custom_engine_agent_id": d.get("customEngineAgentId") or
                        ((d.get("id") or element.get("id")) if normalized_type == "customengineagent" else None),
                    "bot_id": d.get("botId") or (d.get("bot") or {}).get("id"),
                    "supported_scopes": d.get("scopes") or d.get("supportedScopes"),
                    "file_support": d.get("fileSupport") if d.get("fileSupport") is not None else d.get("supportsFiles"),
                    "host": d.get("host") or d.get("hostType"),
                    "raw_reference": raw_reference(self.source, package_id=pid, element_type=typ),
                    "raw_definition": raw or None,
                    "definition_status": "PARSED" if d else "UNAVAILABLE",
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
    """Agent 365 dashboard metrics (from the normalized asset list)."""
    now = now or datetime.now(timezone.utc)
    a = [x for x in assets if x.get("agent365") and x["agent365"].get("is_agent", True)]

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
