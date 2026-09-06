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
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from .base import (ApiUnavailable, BaseCollector, ConnectorStatus, EntityType, QueryStillRunning, Source,
                   classify_graph_error)
from .model import NOT_EXPOSED_BY_API, field, make_asset, raw_reference

DEFAULT_OPERATIONS = ["CopilotInteraction", "ConnectedAIAppInteraction", "AIAppInteraction"]
_QUERIES = "/security/auditLog/queries"


class PurviewAuditCollector(BaseCollector):
    name = "purview_audit"
    source = Source.PURVIEW_AUDIT
    required_read_roles = ("AuditLogsQuery.Read.All",)

    def __init__(self, graph=None, days=30, operations=None,
                 poll_max=None, poll_interval=5.0, sleep=time.sleep,
                 tenant_id=None, checkpoint_store=None):
        super().__init__()
        self._graph = graph
        self._config_error = None
        try:
            self._days = int(os.environ.get("PURVIEW_AUDIT_DAYS", days))
        except (ValueError, TypeError):
            self._days = 0
        self._operations = operations or DEFAULT_OPERATIONS
        # A Purview audit search is asynchronous and routinely takes minutes. The old
        # budget was 30 polls at 2s — 60 seconds — so on a real tenant the query was
        # still running when we gave up, and the dashboard reported the source as
        # unavailable. Budget in seconds, overridable, and long enough to actually wait.
        self._poll_interval = poll_interval
        if poll_max is None:
            try:
                budget = float(os.environ.get("PURVIEW_POLL_SECONDS", 300))
            except ValueError:
                budget = 300.0
            poll_max = max(1, int(budget / max(poll_interval, 0.1)))
        self._poll_max = poll_max
        self._sleep = sleep
        self._store_raw = os.environ.get("STORE_RAW_AI_CONTENT", "").lower() == "true"
        try:
            self._tenant_id = str(UUID(str(tenant_id))) if tenant_id else None
        except (ValueError, TypeError):
            self._tenant_id = None
            self._config_error = "Invalid verified tenant ID; checkpoint isolation cannot be established"
        self._checkpoint_store = checkpoint_store
        self._checkpoint_status = "READY" if self._tenant_id else "DISABLED_NO_VERIFIED_TENANT"
        self._query_id = None
        self._query_window = None

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_PURVIEW_AUDIT", "").lower() == "true"

    # --- collection (create → poll → records) ---
    def collect(self, since=None) -> list:
        if self._graph is None:
            raise ApiUnavailable("No Graph client")
        if self._config_error:
            raise ApiUnavailable(self._config_error)
        if not 1 <= self._days <= 180:
            raise ApiUnavailable("PURVIEW_AUDIT_DAYS must be between 1 and 180")
        end = datetime.now(timezone.utc)
        start = since or (end - timedelta(days=self._days))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if start >= end or end - start > timedelta(days=180):
            raise ApiUnavailable("Audit query window must be positive and at most 180 days")
        body = {
            "@odata.type": "#microsoft.graph.security.auditLogQuery",
            "displayName": "aispm-ai-interactions",
            "filterStartDateTime": _iso(start),
            "filterEndDateTime": _iso(end),
            "operationFilters": self._operations,
        }
        checkpoint, version = self._read_checkpoint()
        if (checkpoint and checkpoint.get("status") == "pending"
                and checkpoint.get("operations") == self._operations
                and checkpoint.get("days") == self._days
                and checkpoint.get("requested_since") == (_iso(since) if since else None)):
            created = {"id": checkpoint["query_id"], "status": "running"}
            body["filterStartDateTime"] = checkpoint["start"]
            body["filterEndDateTime"] = checkpoint["end"]
            self._checkpoint_status = "RESUMED"
        else:
            try:
                created = self._graph.post(_QUERIES, body)
            except RuntimeError as e:
                raise self._classify(e)
            if created.get("id") and self._tenant_id:
                checkpoint = {
                    "schema_version": 1, "tenant_id": self._tenant_id,
                    "query_id": created["id"], "status": "pending",
                    "start": body["filterStartDateTime"], "end": body["filterEndDateTime"],
                    "operations": self._operations, "days": self._days,
                    "requested_since": _iso(since) if since else None,
                }
                version = self._write_checkpoint(checkpoint, version)
                self._checkpoint_status = "SAVED"
        qid = created.get("id")
        if not qid:
            raise ApiUnavailable("audit query did not return an id")
        self._query_id = qid
        self._query_window = {"start": body["filterStartDateTime"], "end": body["filterEndDateTime"]}

        status = (created.get("status") or "").lower()
        attempts = 0
        while status not in ("succeeded", "failed", "cancelled") and attempts < self._poll_max:
            self._sleep(self._poll_interval)
            attempts += 1
            try:
                get = getattr(self._graph, "get_checked", None) or self._graph.get
                q = get(f"{_QUERIES}/{qid}") or {}
            except RuntimeError as e:
                if getattr(e, "status", None) == 404 and checkpoint and self._tenant_id:
                    self._write_checkpoint({**checkpoint, "status": "expired"}, version)
                raise self._classify(e)
            status = (q.get("status") or "").lower()
        if status in ("failed", "cancelled"):
            if checkpoint and self._tenant_id:
                self._write_checkpoint({**checkpoint, "status": status}, version)
            raise ApiUnavailable(f"audit query {status}")
        if status != "succeeded":
            raise QueryStillRunning(
                f"the Purview audit query was still running after "
                f"{int(self._poll_max * self._poll_interval)}s. Raise PURVIEW_POLL_SECONDS, "
                f"or narrow the window with PURVIEW_AUDIT_DAYS.")

        try:
            records = self._graph.get_all(f"{_QUERIES}/{qid}/records", {"$top": "999"})
        except RuntimeError as e:
            raise self._classify(e)
        if checkpoint and self._tenant_id:
            self._write_checkpoint({**checkpoint, "status": "completed"}, version)
            self._checkpoint_status = "COMPLETED"
        return records

    def _read_checkpoint(self):
        if not self._tenant_id:
            return None, None
        if self._checkpoint_store is None:
            import storage
            self._checkpoint_store = storage
        name = "purview-query-" + hashlib.sha256(self._tenant_id.encode()).hexdigest() + ".json"
        self._checkpoint_name = name
        try:
            checkpoint, version = self._checkpoint_store.read_json_versioned(name)
            if checkpoint is not None:
                if (not isinstance(checkpoint, dict) or checkpoint.get("schema_version") != 1
                        or checkpoint.get("tenant_id") != self._tenant_id):
                    raise ValueError("Checkpoint tenant or schema mismatch")
                start = datetime.fromisoformat(checkpoint["start"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(checkpoint["end"].replace("Z", "+00:00"))
                if (not checkpoint.get("query_id") or start.tzinfo is None or end.tzinfo is None
                        or not timedelta(0) < end - start <= timedelta(days=180)
                        or end > datetime.now(timezone.utc)):
                    raise ValueError("Invalid checkpoint query/window")
            return checkpoint, version
        except Exception as e:
            raise ApiUnavailable(f"Purview checkpoint unavailable: {e}") from e

    def _write_checkpoint(self, checkpoint, version):
        try:
            self._checkpoint_store.write_json_conditional(self._checkpoint_name, checkpoint, version)
            saved, next_version = self._checkpoint_store.read_json_versioned(self._checkpoint_name)
            if saved != checkpoint:
                raise ValueError("Concurrent checkpoint update")
            return next_version
        except Exception as e:
            raise ApiUnavailable(f"Purview checkpoint could not be saved: {e}") from e

    @staticmethod
    def _classify(err):
        return classify_graph_error(err)

    # --- normalize ---
    def normalize(self, raw_records: list) -> list:
        out = []
        for i, rec in enumerate(raw_records):
            try:
                out.append(self._normalize_one(rec, i))
            except (ValueError, TypeError, AttributeError) as e:
                self._status = ConnectorStatus.PARTIALLY_CONNECTED
                self._error = f"Audit record {i + 1} could not be parsed: {e}"
        if raw_records and not out:
            raise ApiUnavailable(self._error or "No valid audit records")
        return out

    def _normalize_one(self, rec: dict, idx: int) -> dict:
        ad = rec.get("auditData") or rec.get("AuditData") or {}
        if isinstance(ad, str):
            ad = json.loads(ad)
        ced = ad.get("CopilotEventData") or ad.get("copilotEventData") or {}
        op = rec.get("operation") or ad.get("Operation")
        upn = rec.get("userPrincipalName") or ad.get("UserId") or ad.get("UserKey")
        user_id = rec.get("userId") or ad.get("UserId")
        ts = (rec.get("createdDateTime") or ad.get("CreationTime")
              or ad.get("CreationDateTime"))
        rec_id = (rec.get("id") or ad.get("Id") or ad.get("RecordId")
                  or f"synth:{upn or 'x'}|{ts or 'x'}|{op or 'x'}|{idx}")

        host = ced.get("AppHost") or ad.get("AppHost")
        app_identity = ad.get("AppIdentity") or ced.get("AppIdentity")
        agent_id = ad.get("AgentId") or ced.get("AgentId")
        agent_name = ad.get("AgentName") or ced.get("AgentName")
        app_host = agent_name or ad.get("Application") or ad.get("AppName") or host
        app_id = ad.get("ApplicationId") or ad.get("AppId") or ced.get("AppId")
        if app_identity:
            identity_parts = str(app_identity).split(".", 2)
            if len(identity_parts) == 3:
                if identity_parts[1].lower() in ("entra", "studio"):
                    app_id = app_id or identity_parts[2]
                if not agent_name:
                    app_host = (identity_parts[2] if identity_parts[1].lower() not in ("entra", "studio")
                                else app_identity)

        policies, action, dlp_sits = _dlp(ad)
        sits = _sits(ad) + dlp_sits
        resources = _resources(ad, ced)
        for resource in resources:
            rp, ra, rs = _dlp({"PolicyDetails": resource.get("policy_details") or []})
            policies.extend(rp)
            sits.extend(rs)
            if ra == "Block" or not action:
                action = ra or action
        label_id = (ced.get("SensitivityLabelId") or ad.get("SensitivityLabelId")
                    or ad.get("LabelId"))
        label_ids = sorted({r["sensitivity_label_id"] for r in resources if r.get("sensitivity_label_id")}
                           | ({label_id} if label_id else set()))
        label_id = label_id or (label_ids[0] if label_ids else None)
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
            "app_identity": app_identity,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "host": host,
            "workload": ad.get("Workload"),
            "sensitivity_label_id": label_id,
            "sensitivity_label_ids": label_ids,
            # the audit record usually doesn't give the label name → mark it honestly:
            "sensitivity_label_name": field(NOT_EXPOSED_BY_API),
            "sensitive_info_types": sits,
            "referenced_resources": resources,
            "contexts": ced.get("Contexts") or ad.get("Contexts") or [],
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
                "sensitive_interactions": self._count,
                "checkpoint_status": self._checkpoint_status,
                "query_id": self._query_id, "query_window": self._query_window}


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
                elif isinstance(a, str) and a.lower() in ("allow", "allowed") and action != "Block":
                    action = "Allow"
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
    ctx = list(ced.get("AccessedResources") or []) + list(ad.get("AccessedResources") or [])
    for c in ctx:
        if not isinstance(c, dict):
            continue
        out.append({
            "id": c.get("Id") or c.get("ID") or c.get("id"),
            "type": c.get("Type") or c.get("type"),
            "name": c.get("Name") or c.get("name"),
            "sensitivity_label_id": c.get("SensitivityLabelId") or c.get("sensitivityLabelId"),
            "action": c.get("Action") or c.get("action"),
            "status": c.get("Status") or c.get("status"),
            "policy_details": c.get("PolicyDetails") or c.get("policyDetails") or [],
        })
    return out


def _direction(op, action, resources, sits):
    """Rough direction inference — the precise direction taxonomy is finalized in Step 6."""
    if action and "block" in str(action).lower():
        return "BLOCKED"
    if str(action or "").lower() in ("allow", "allowed"):
        return "ALLOWED"
    if any(str(r.get("action") or "").lower() == "read"
           and str(r.get("status") or "").lower() not in ("failed", "failure", "blocked")
           for r in resources):
        return "ACCESSED"
    if any(str(r.get("action") or "").lower() == "create"
           and str(r.get("status") or "").lower() in ("success", "succeeded")
           for r in resources):
        return "GENERATED"
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
