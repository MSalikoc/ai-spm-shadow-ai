"""
Microsoft Defender for Cloud Apps collector — web-based Shadow AI usage (Step 4).

Endpoints: GET /beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams          (stream list)
           GET .../uploadedStreams/{id}/aggregatedAppsDetails(period=duration'P30D')    (discovered apps)
Permission: CloudApp-Discovery.Read.All
PREVIEW (beta) API — ENABLE_DEFENDER_CLOUD_APPS=true + ENABLE_PREVIEW_CONNECTORS=true.

Filters web apps discovered via MDCA log analysis down to the AI ones (MDCA category +
the out-of-code `catalogs/ai_applications.json`). Each AI app → a merged
**AI_APPLICATION** asset (users/devices/IP/traffic summary); each (stream, app)
observation → a **USAGE_OBSERVATION** record.

IMPORTANT: Upload volume ALONE is NOT "sensitive data sharing" — here it's only flagged
as usage/observation; real sensitivity is determined once correlated with Purview
(Step 5) (`data_sensitivity = UNDETERMINED_REQUIRES_PURVIEW`).
"""
import json
import logging
import os

from .base import (ApiUnavailable, BaseCollector, ConnectorStatus, EntityType,
                   LicenseMissing, PermissionMissing, Source)
from .model import NOT_EXPOSED_BY_API, field, make_asset, raw_reference

GRAPH_BETA = "https://graph.microsoft.com/beta"
_STREAMS = f"{GRAPH_BETA}/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"
_DEFAULT_CATALOG = os.path.join(os.path.dirname(__file__), "catalogs", "ai_applications.json")


class DefenderCloudAppsCollector(BaseCollector):
    name = "defender_cloud_apps"
    source = Source.DEFENDER_CLOUD_APPS

    def __init__(self, graph=None, period="P30D", catalog_path=None):
        super().__init__()
        self._graph = graph
        self._period = period
        self._catalog_path = catalog_path or os.environ.get(
            "AI_APPLICATIONS_CATALOG_PATH", _DEFAULT_CATALOG)
        self._catalog = None

    def is_configured(self) -> bool:
        return (os.environ.get("ENABLE_DEFENDER_CLOUD_APPS", "").lower() == "true"
                and os.environ.get("ENABLE_PREVIEW_CONNECTORS", "").lower() == "true")

    # --- catalog (out-of-code AI app list) ---
    def _load_catalog(self) -> dict:
        if self._catalog is not None:
            return self._catalog
        try:
            with open(self._catalog_path, encoding="utf-8") as f:
                cat = json.load(f)
        except (OSError, ValueError):
            cat = {}
        self._catalog = {
            "categories": {c.strip().lower() for c in cat.get("ai_categories", [])},
            "names": {a.get("name", "").strip().lower()
                      for a in cat.get("applications", []) if a.get("name")},
            "domains": {d.strip().lower() for a in cat.get("applications", [])
                        for d in (a.get("domains") or [])},
        }
        return self._catalog

    def _is_ai(self, category, name, domain) -> bool:
        cat = self._load_catalog()
        if (category or "").strip().lower() in cat["categories"] and cat["categories"]:
            return True
        if (name or "").strip().lower() in cat["names"]:
            return True
        d = (domain or "").strip().lower().lstrip("*.").lstrip(".")
        if d:
            for known in cat["domains"]:
                if d == known or d.endswith("." + known) or known.endswith("." + d):
                    return True
        return False

    # --- collection ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("No Graph client")
        try:
            streams = self._graph.get_all(_STREAMS, {"$top": "999"})
        except RuntimeError as e:
            raise self._classify(e)

        out = []
        for s in streams:
            sid = s.get("id")
            sname = s.get("displayName") or s.get("name")
            if not sid:
                continue
            url = f"{_STREAMS}/{sid}/aggregatedAppsDetails(period=duration'{self._period}')"
            try:
                apps = self._graph.get_all(url)
            except RuntimeError as e:
                # If one stream fails, let the others continue → connector PARTIAL.
                self._status = ConnectorStatus.PARTIALLY_CONNECTED
                self._error = self._error or str(e)[:160]
                continue
            for app in apps or []:
                out.append({"stream_id": sid, "stream_name": sname, "app": app})
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
        return err

    # --- normalize ---
    def normalize(self, raw_records: list) -> list:
        # TEMPORARY DIAGNOSTIC (enabled via AISPM_DEBUG_MDCA_RAW=true): to confirm the
        # real field names for traffic/upload bytes in the Graph beta schema — this
        # block will be removed once the bug is found and fixed.
        if raw_records and os.environ.get("AISPM_DEBUG_MDCA_RAW", "").lower() == "true":
            logging.info("AISPM_DEBUG_MDCA_RAW first record: %s",
                        json.dumps(raw_records[0].get("app"), default=str)[:2000])
        apps = {}          # app_key → aggregate
        observations = []
        for r in raw_records:
            app = r.get("app") or {}
            name = app.get("displayName") or app.get("name") or app.get("appName")
            domain = self._domain(app)
            category = app.get("category") or app.get("categoryName")
            if not self._is_ai(category, name, domain):
                continue

            mdca_id = app.get("id") or app.get("appId")
            key = f"mdca:{mdca_id}" if mdca_id else f"nd:{(name or '').lower()}|{domain}"
            m = self._metrics_of(app)

            agg = apps.get(key)
            if agg is None:
                agg = apps[key] = {
                    "mdca_id": mdca_id, "name": name, "domain": domain,
                    "category": category, "vendor": app.get("publisher") or app.get("vendor"),
                    "risk_score": m["risk_score"], "sanctioned_state": self._sanction(app),
                    "users": 0, "devices": 0, "ips": 0, "transactions": 0,
                    "uploaded_bytes": 0, "downloaded_bytes": 0, "streams": set(),
                    "first_seen": m["first_seen"], "last_seen": m["last_seen"],
                }
            # users/IPs/devices can't be deduped across different streams → conservative
            # max; traffic/transactions are additive → sum. (see known correlation gaps)
            agg["users"] = max(agg["users"], m["users"])
            agg["devices"] = max(agg["devices"], m["devices"])
            agg["ips"] = max(agg["ips"], m["ips"])
            agg["transactions"] += m["transactions"]
            agg["uploaded_bytes"] += m["uploaded_bytes"]
            agg["downloaded_bytes"] += m["downloaded_bytes"]
            agg["streams"].add(r.get("stream_id"))
            if m["risk_score"] is not None:
                agg["risk_score"] = m["risk_score"]
            agg["first_seen"] = _min_iso(agg["first_seen"], m["first_seen"])
            agg["last_seen"] = _max_iso(agg["last_seen"], m["last_seen"])

            observations.append(self._observation(r, name, domain, mdca_id, m))

        return [self._app_asset(a) for a in apps.values()] + observations

    def _app_asset(self, a: dict) -> dict:
        asset = make_asset(
            EntityType.AI_APPLICATION,
            a["name"],
            self.source,
            external_ids={"mdca_app_id": a["mdca_id"]},
            first_seen=a["first_seen"],
            last_seen=a["last_seen"],
        )
        asset["domain"] = a["domain"]                 # for correlation (pub+domain)
        asset["publisher"] = a.get("vendor") or ""
        asset["mdca"] = {
            "mdca_app_id": a["mdca_id"],
            "category": a["category"],
            "vendor": a.get("vendor"),
            "risk_score": a["risk_score"],
            "sanctioned_state": a["sanctioned_state"],
            "users": a["users"],
            "devices": a["devices"],
            "ip_addresses": a["ips"],
            "transactions": a["transactions"],
            "uploaded_bytes": a["uploaded_bytes"],
            "downloaded_bytes": a["downloaded_bytes"],
            "stream_count": len(a["streams"]),
            "period": self._period,
            # Volume alone is NOT sensitivity — will be correlated with Purview (Step 5/6):
            "data_sensitivity": "UNDETERMINED_REQUIRES_PURVIEW",
            "sensitive_data_types": field(NOT_EXPOSED_BY_API),
            "raw_reference": raw_reference(self.source, mdca_app_id=a["mdca_id"], name=a["name"]),
        }
        return asset

    def _observation(self, r, name, domain, mdca_id, m) -> dict:
        # USAGE_OBSERVATION: don't put mdca_app_id in external_ids (avoid ID collision
        # with the app asset); it links to the app via the `mdca_app_id` field. A
        # name-hash id → unique, doesn't merge.
        obs = make_asset(
            EntityType.USAGE_OBSERVATION,
            f"{name} @ {r.get('stream_name') or r.get('stream_id')}",
            self.source,
            first_seen=m["first_seen"],
            last_seen=m["last_seen"],
        )
        obs["usage_observation"] = {
            "mdca_app_id": mdca_id,
            "app_name": name,
            "domain": domain,
            "stream_id": r.get("stream_id"),
            "stream_name": r.get("stream_name"),
            "users": m["users"],
            "devices": m["devices"],
            "ip_addresses": m["ips"],
            "transactions": m["transactions"],
            "uploaded_bytes": m["uploaded_bytes"],
            "downloaded_bytes": m["downloaded_bytes"],
            "period": self._period,
            # access/upload observation ≠ sensitive sharing (Step 6 will apply the direction split):
            "direction": "UPLOADED" if m["uploaded_bytes"] else "OBSERVED",
            "data_sensitivity": "UNDETERMINED_REQUIRES_PURVIEW",
            "raw_reference": raw_reference(self.source, stream_id=r.get("stream_id"), name=name),
        }
        return obs

    # --- defensive field parsing (PREVIEW schema is not fixed) ---
    @staticmethod
    def _domain(app):
        d = (app.get("domain") or app.get("url") or app.get("appUrl")
             or app.get("primaryDomain"))
        if not d and isinstance(app.get("domains"), list) and app["domains"]:
            d = app["domains"][0]
        return d

    @staticmethod
    def _sanction(app):
        for k in ("sanctionedState", "sanctionState", "tags", "tag"):
            v = app.get(k)
            if isinstance(v, str) and v:
                return v.lower()
            if isinstance(v, list):
                for t in v:
                    if isinstance(t, str) and t.lower() in ("sanctioned", "unsanctioned", "monitored"):
                        return t.lower()
        return "unreviewed"

    @staticmethod
    def _metrics_of(app):
        def num(*keys):
            for k in keys:
                v = app.get(k)
                if isinstance(v, (int, float)):
                    return int(v)
            return 0
        rs = None
        for k in ("riskScore", "score", "risk"):
            v = app.get(k)
            if isinstance(v, (int, float)):
                rs = int(v)
                break
        return {
            "users": num("userCount", "usersCount", "distinctUsers", "distinctUsersCount"),
            "devices": num("deviceCount", "devicesCount", "distinctDevices"),
            "ips": num("ipAddressCount", "ipCount", "distinctIpAddresses"),
            "transactions": num("transactionCount", "transactionsCount", "requestCount"),
            "uploaded_bytes": num("uploadedBytes", "uploadedVolume", "dataUploaded", "bytesUploaded"),
            "downloaded_bytes": num("downloadedBytes", "downloadedVolume", "dataDownloaded", "bytesDownloaded"),
            "risk_score": rs,
            "first_seen": app.get("firstSeenDateTime") or app.get("firstSeen"),
            "last_seen": app.get("lastSeenDateTime") or app.get("lastSeen"),
        }

    def get_coverage(self) -> dict:
        return {"status": self._status, "period": self._period, "applications": self._count}


def _min_iso(a, b):
    vals = [x for x in (a, b) if x]
    return min(vals) if vals else None


def _max_iso(a, b):
    vals = [x for x in (a, b) if x]
    return max(vals) if vals else None


def metrics(assets):
    """Defender/Shadow-AI dashboard metrics (from this connector's normalized asset list)."""
    apps = [x for x in assets if x.get("mdca")]
    obs = [x for x in assets if x.get("usage_observation")]

    def g(x):
        return x["mdca"]

    return {
        "total_ai_apps": len(apps),
        "sanctioned": sum(1 for x in apps if g(x).get("sanctioned_state") == "sanctioned"),
        "unsanctioned": sum(1 for x in apps if g(x).get("sanctioned_state") == "unsanctioned"),
        "unreviewed": sum(1 for x in apps if g(x).get("sanctioned_state") in (None, "unreviewed", "monitored")),
        "total_users_observed": sum(g(x).get("users", 0) for x in apps),   # NO cross-app dedupe
        "total_uploaded_bytes": sum(g(x).get("uploaded_bytes", 0) for x in apps),
        "high_risk_apps": sum(1 for x in apps if isinstance(g(x).get("risk_score"), int)
                              and g(x)["risk_score"] <= 3),                # MDCA: lower score = higher risk
        "usage_observations": len(obs),
        # MDCA apps don't carry an appId → weak cross-source correlation (name-only doesn't merge):
        "uncorrelated": sum(1 for x in apps if not x["external_ids"].get("entra_app_id")),
    }
