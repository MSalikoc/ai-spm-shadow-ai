"""
Microsoft Purview Audit collector — the primary source of sensitive AI interactions (Step 5).

Flow    : POST /v1.0/security/auditLog/queries  (create query)
          GET  .../auditLog/queries/{id}         (poll → 'succeeded')
          GET  .../auditLog/queries/{id}/records (records)
Operations: CopilotInteraction, ConnectedAIAppInteraction, AIAppInteraction
Permission: AuditLogsQuery.Read.All

Each record → a merged **SENSITIVE_INTERACTION** entity: user, app, SIT (sensitive info
type), sensitivity label, referenced resources, DLP policy/rule/action, direction.
Fields not in the API are honestly marked with `field(NOT_EXPOSED_BY_API)`.

PRIVACY: Raw prompt/response content is NEVER stored unless STORE_RAW_AI_CONTENT=true.
Portal scraping / undocumented endpoints are NOT used.
"""
import os
import time
from datetime import datetime, timedelta, timezone

from .base import (ApiUnavailable, BaseCollector, EntityType, LicenseMissing,
                   PermissionMissing, Source)
from .model import NOT_EXPOSED_BY_API, field, make_asset, raw_reference

DEFAULT_OPERATIONS = ["CopilotInteraction", "ConnectedAIAppInteraction", "AIAppInteraction"]
_QUERIES = "/security/auditLog/queries"


class PurviewAuditCollector(BaseCollector):
    name = "purview_audit"
    source = Source.PURVIEW_AUDIT

    def __init__(self, graph=None, days=30, operations=None,
                 poll_max=30, poll_interval=2.0, sleep=time.sleep):
        super().__init__()
        self._graph = graph
        self._days = int(os.environ.get("PURVIEW_AUDIT_DAYS", days))
        self._operations = operations or DEFAULT_OPERATIONS
        self._poll_max = poll_max
        self._poll_interval = poll_interval
        self._sleep = sleep
        self._store_raw = os.environ.get("STORE_RAW_AI_CONTENT", "").lower() == "true"

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_PURVIEW_AUDIT", "").lower() == "true"

    # --- collection (create → poll → records) ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("No Graph client")
        end = datetime.now(timezone.utc)
        start = since or (end - timedelta(days=self._days))
        body = {
            "@odata.type": "#microsoft.graph.security.auditLogQuery",
            "displayName": "aispm-ai-interactions",
            "filterStartDateTime": _iso(start),
            "filterEndDateTime": _iso(end),
            "operationFilters": self._operations,
        }
        try:
            created = self._graph.post(_QUERIES, body)
        except RuntimeError as e:
            raise self._classify(e)
        qid = created.get("id")
        if not qid:
            raise ApiUnavailable("audit query did not return an id")

        status = (created.get("status") or "").lower()
        attempts = 0
        while status not in ("succeeded", "failed", "cancelled") and attempts < self._poll_max:
            self._sleep(self._poll_interval)
            attempts += 1
            q = self._graph.get(f"{_QUERIES}/{qid}") or {}
            status = (q.get("status") or "").lower()
        if status in ("failed", "cancelled"):
            raise ApiUnavailable(f"audit query {status}")
        if status != "succeeded":
            raise ApiUnavailable("audit query timed out (poll_max)")

        try:
            return self._graph.get_all(f"{_QUERIES}/{qid}/records", {"$top": "999"})
        except RuntimeError as e:
            raise self._classify(e)

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
        out = []
        for i, rec in enumerate(raw_records):
            out.append(self._normalize_one(rec, i))
        return out

    def _normalize_one(self, rec: dict, idx: int) -> dict:
        ad = rec.get("auditData") or rec.get("AuditData") or {}
        ced = ad.get("CopilotEventData") or ad.get("copilotEventData") or {}
        op = rec.get("operation") or ad.get("Operation")
        upn = rec.get("userPrincipalName") or ad.get("UserId") or ad.get("UserKey")
        user_id = rec.get("userId") or ad.get("UserId")
        ts = (rec.get("createdDateTime") or ad.get("CreationTime")
              or ad.get("CreationDateTime"))
        rec_id = (rec.get("id") or ad.get("Id") or ad.get("RecordId")
                  or f"synth:{upn or 'x'}|{ts or 'x'}|{op or 'x'}|{idx}")

        app_host = ced.get("AppHost") or ad.get("AppHost") or ad.get("Application") or ad.get("AppName")
        app_id = ad.get("ApplicationId") or ad.get("AppId") or ced.get("AppId")

        policies, action, dlp_sits = _dlp(ad)
        sits = _sits(ad) + dlp_sits
        resources = _resources(ad, ced)
        label_id = (ced.get("SensitivityLabelId") or ad.get("SensitivityLabelId")
                    or ad.get("LabelId"))
        direction = _direction(op, action, resources, sits)

        asset = make_asset(
            EntityType.SENSITIVE_INTERACTION,
            f"{op or 'AIInteraction'} — {upn or 'unknown'}",
            self.source,
            external_ids={"purview_record_id": rec_id},   # unique id; NOT a merge token
            first_seen=ts,
            last_seen=ts,
        )
        asset["interaction"] = {
            "interaction_id": rec_id,
            "operation": op,
            "user": upn,
            "user_id": user_id,
            "timestamp": ts,
            "app_host": app_host,
            "app_id": app_id,                 # join field (NOT an external_id → doesn't merge)
            "workload": ad.get("Workload"),
            "sensitivity_label_id": label_id,
            # the audit record usually doesn't give the label name → mark it honestly:
            "sensitivity_label_name": field(NOT_EXPOSED_BY_API),
            "sensitive_info_types": sits,
            "referenced_resources": resources,
            "dlp_policies": policies,
            "dlp_action": action,
            "direction": direction,
            "raw_content_stored": self._store_raw,
            "raw_reference": raw_reference(self.source, record_id=rec_id, operation=op),
        }
        if self._store_raw:  # only if explicitly allowed
            asset["interaction"]["raw_content"] = {
                "prompt": ad.get("Prompt") or ced.get("Prompt"),
                "response": ad.get("Response") or ced.get("Response"),
            }
        return asset

    def get_coverage(self) -> dict:
        return {"status": self._status, "period_days": self._days,
                "sensitive_interactions": self._count}


# --- helpers (defensive parsing; tries schema variants) ---
def _iso(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dlp(ad):
    """Extracts DLP policy/rule/action + SITs. action: Block > Audit/Allow."""
    policies, sits, action = [], [], None
    for pol in (ad.get("PolicyDetails") or ad.get("policyDetails") or []):
        pname = pol.get("PolicyName") or pol.get("policyName")
        for rule in (pol.get("Rules") or pol.get("rules") or []):
            acts = rule.get("Actions") or rule.get("actions") or []
            acts = acts if isinstance(acts, list) else [acts]
            policies.append({
                "policy": pname,
                "rule": rule.get("RuleName") or rule.get("ruleName"),
                "actions": acts,
            })
            for a in acts:
                if isinstance(a, str) and "block" in a.lower():
                    action = "Block"
            cm = rule.get("ConditionsMatched") or rule.get("conditionsMatched") or {}
            for si in (cm.get("SensitiveInformation") or []):
                n = si.get("SensitiveInformationTypeName") or si.get("Name")
                if n:
                    sits.append({"name": n, "count": si.get("Count"), "source": "dlp"})
    if action is None and policies:
        action = "Audit"
    return policies, action, sits


def _sits(ad):
    """Non-DLP SIT data (if present)."""
    out = []
    for si in (ad.get("SensitiveInfoTypeData") or ad.get("sensitiveInfoTypeData") or []):
        n = si.get("SensitiveInformationTypeName") or si.get("Name") or si.get("name")
        if n:
            out.append({"name": n, "count": si.get("Count"), "source": "audit"})
    return out


def _resources(ad, ced):
    out = []
    ctx = (ced.get("Contexts") or ad.get("Contexts")
           or ad.get("AccessedResources") or ced.get("AccessedResources") or [])
    for c in ctx:
        if not isinstance(c, dict):
            continue
        out.append({
            "id": c.get("Id") or c.get("id"),
            "type": c.get("Type") or c.get("type"),
            "name": c.get("Name") or c.get("name"),
        })
    return out


def _direction(op, action, resources, sits):
    """Rough direction inference — the precise direction taxonomy is finalized in Step 6."""
    if action and "block" in str(action).lower():
        return "BLOCKED"
    if action:                       # DLP matched but wasn't blocked
        return "ALLOWED"
    if resources:                    # grounding by accessing a corporate resource
        return "ACCESSED"
    if op and "AIApp" in str(op):    # data sent to an external AI app
        return "SHARED"
    return "UNKNOWN_DIRECTION"


def metrics(assets):
    """Purview Audit dashboard metrics (from the SENSITIVE_INTERACTION list)."""
    # note: DSPM import also produces SENSITIVE_INTERACTION; only the audit source is counted here.
    ix = [x for x in assets if x.get("interaction")
          and Source.PURVIEW_AUDIT in x.get("sources", [])]

    def g(x):
        return x["interaction"]

    def has_sensitive(x):
        return bool(g(x).get("sensitive_info_types")) or bool(g(x).get("sensitivity_label_id"))

    return {
        "total_interactions": len(ix),
        "with_sensitive_data": sum(1 for x in ix if has_sensitive(x)),
        "blocked": sum(1 for x in ix if g(x).get("direction") == "BLOCKED"),
        "allowed_with_sensitive": sum(1 for x in ix if g(x).get("direction") == "ALLOWED"),
        "accessed_org_data": sum(1 for x in ix if g(x).get("direction") == "ACCESSED"),
        "with_label": sum(1 for x in ix if g(x).get("sensitivity_label_id")),
        "distinct_users": len({g(x).get("user") for x in ix if g(x).get("user")}),
        "distinct_apps": len({g(x).get("app_host") for x in ix if g(x).get("app_host")}),
        "copilot_interactions": sum(1 for x in ix if g(x).get("operation") == "CopilotInteraction"),
        "connected_ai_app": sum(1 for x in ix if g(x).get("operation") == "ConnectedAIAppInteraction"),
    }
