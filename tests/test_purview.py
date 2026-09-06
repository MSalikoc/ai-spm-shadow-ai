"""Step 5 — Purview Audit collector + DSPM import adapter tests (offline mock)."""
import csv
import json
import os

import connectors
from connectors.base import ConnectorStatus, EntityType, Source
from connectors.purview_audit import PurviewAuditCollector, metrics
from connectors.purview_dspm_import import (IMPORT_SCHEMA_VERSION,
                                            PurviewDspmImportCollector)

FXDIR = os.path.join(os.path.dirname(connectors.__file__), "fixtures")
AUDIT_FX = os.path.join(FXDIR, "purview_audit_records.json")
DSPM_FX = os.path.join(FXDIR, "dspm_export.json")
NOSLEEP = lambda *_a, **_k: None  # noqa: E731


class FakeGraph:
    """auditLog/queries: post(create) → get(poll status) → get_all(records)."""

    def __init__(self, records, statuses=None, post_fail=None, records_fail=None):
        self._records = records
        self._statuses = statuses or ["succeeded"]
        self._poll_idx = 0
        self._post_fail = post_fail
        self._records_fail = records_fail
        self.posted = None

    def post(self, path, body):
        if self._post_fail:
            raise RuntimeError(self._post_fail)
        self.posted = body
        return {"id": "query-1", "status": "notStarted"}

    def get(self, path, params=None):
        st = self._statuses[min(self._poll_idx, len(self._statuses) - 1)]
        self._poll_idx += 1
        return {"id": "query-1", "status": st}

    def get_all(self, path, params=None, max_items=None):
        if self._records_fail:
            raise RuntimeError(self._records_fail)
        return self._records


def _records():
    with open(AUDIT_FX, encoding="utf-8") as f:
        return json.load(f)


# ---------- Purview Audit ----------

def test_query_poll_records_and_normalize(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    fg = FakeGraph(_records(), statuses=["running", "succeeded"])
    c = PurviewAuditCollector(fg, sleep=NOSLEEP)
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED
    assert len(assets) == 3
    # the audit query body was POSTed with the correct operations
    assert set(fg.posted["operationFilters"]) == {
        "CopilotInteraction", "ConnectedAIAppInteraction", "AIAppInteraction"}

    r1 = next(a for a in assets if a["interaction"]["interaction_id"] == "rec-1")
    assert r1["asset_type"] == EntityType.SENSITIVE_INTERACTION
    assert r1["interaction"]["direction"] == "BLOCKED"          # DLP BlockAccess
    assert r1["interaction"]["dlp_action"] == "Block"
    assert r1["interaction"]["sensitive_info_types"][0]["name"] == "Credit Card Number"
    assert r1["interaction"]["sensitivity_label_id"] == "label-confidential"
    assert r1["interaction"]["referenced_resources"][0]["name"] == "Q3.xlsx"
    # each interaction has a unique id → external_ids.purview_record_id (NOT a merge token)
    assert r1["external_ids"]["purview_record_id"] == "rec-1"
    # a field not in the API is honestly marked
    assert r1["interaction"]["sensitivity_label_name"]["status"] == "NOT_EXPOSED_BY_API"


def test_direction_variants(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    assets = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP).safe_run()
    d = {a["interaction"]["interaction_id"]: a["interaction"]["direction"] for a in assets}
    assert d["rec-1"] == "BLOCKED"
    assert d["rec-2"] == "UNKNOWN_DIRECTION"  # audit-only is not evidence of delivery
    assert d["rec-3"] == "ACCESSED"      # accessed a resource, no DLP


def test_raw_content_not_stored_by_default(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    monkeypatch.delenv("STORE_RAW_AI_CONTENT", raising=False)
    assets = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP).safe_run()
    i = assets[0]["interaction"]
    assert i["raw_content_stored"] is False
    assert "raw_content" not in i           # content was NEVER stored


def test_raw_content_stored_when_opted_in(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    monkeypatch.setenv("STORE_RAW_AI_CONTENT", "true")
    assets = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP).safe_run()
    assert assets[0]["interaction"]["raw_content_stored"] is True
    assert "raw_content" in assets[0]["interaction"]


def test_metrics(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    assets = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP).safe_run()
    m = metrics(assets)
    assert m["total_interactions"] == 3
    assert m["with_sensitive_data"] == 2
    assert m["blocked"] == 1 and m["allowed_with_sensitive"] == 0
    assert m["accessed_org_data"] == 1
    assert m["with_label"] == 1
    assert m["distinct_users"] == 2 and m["distinct_apps"] == 2
    assert m["copilot_interactions"] == 2 and m["connected_ai_app"] == 1


def test_permission_missing_does_not_stop(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    c = PurviewAuditCollector(
        FakeGraph([], post_fail="Graph 403 Forbidden: Authorization_RequestDenied"),
        sleep=NOSLEEP)
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_a_query_still_running_is_not_reported_as_unavailable(monkeypatch):
    """
    Seen on a real tenant: the search was still running when we stopped waiting, and the
    dashboard said "not available in this tenant" — sending someone to look for a licence
    they already had. The source works; the fix is to wait longer.
    """
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    c = PurviewAuditCollector(FakeGraph(_records(), statuses=["running"]),
                              poll_max=3, sleep=NOSLEEP)
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.TIMEOUT
    assert "PURVIEW_POLL_SECONDS" in c.get_health()["error"]


def test_the_poll_budget_is_generous_by_default_and_configurable(monkeypatch):
    """60 seconds was never enough — a Purview audit search routinely takes minutes."""
    c = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP)
    assert c._poll_max * c._poll_interval >= 240

    monkeypatch.setenv("PURVIEW_POLL_SECONDS", "600")
    c2 = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP)
    assert c2._poll_max * c2._poll_interval == 600

    monkeypatch.setenv("PURVIEW_POLL_SECONDS", "not-a-number")
    assert PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP)._poll_max > 0


def test_a_failed_query_is_still_reported_as_unavailable(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    c = PurviewAuditCollector(FakeGraph(_records(), statuses=["failed"]),
                              poll_max=3, sleep=NOSLEEP)
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE


def test_not_configured_without_env():
    assert PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP).safe_run() == []


# ---------- DSPM import ----------

def test_dspm_import_json():
    c = PurviewDspmImportCollector(import_path=DSPM_FX)
    assert c.is_configured() is True
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.CONNECTED
    assert len(assets) == 2
    for a in assets:
        assert a["asset_type"] == EntityType.SENSITIVE_INTERACTION
        assert a["sources"] == [Source.PURVIEW_DSPM_EXPORT]     # a source SEPARATE from audit
    d1 = next(a for a in assets if a["interaction"]["user"] == "carol@contoso.com")
    assert d1["interaction"]["direction"] == "SHARED"
    assert {s["name"] for s in d1["interaction"]["sensitive_info_types"]} == {
        "Credit Card Number", "U.S. Social Security Number"}
    d2 = next(a for a in assets if a["interaction"]["user"] == "dave@contoso.com")
    assert d2["interaction"]["direction"] == "BLOCKED"


def test_dspm_import_csv(tmp_path):
    p = tmp_path / "dspm.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "timestamp", "user", "app", "direction", "action", "label", "sit"])
        w.writerow(["c1", "2026-07-10T00:00:00Z", "eve@contoso.com", "Gemini",
                    "Generated", "Audit", "Confidential", "Credit Card Number; IBAN"])
    assets = PurviewDspmImportCollector(import_path=str(p)).safe_run()
    assert len(assets) == 1
    i = assets[0]["interaction"]
    assert i["app_host"] == "Gemini"
    assert i["direction"] == "GENERATED"
    assert len(i["sensitive_info_types"]) == 2


def test_dspm_schema_mismatch(tmp_path):
    p = tmp_path / "future.json"
    p.write_text(json.dumps({"schema_version": "2.0", "records": [{"id": "x", "app": "ChatGPT"}]}),
                 encoding="utf-8")
    c = PurviewDspmImportCollector(import_path=str(p))
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE   # honest incompatibility


def test_dspm_missing_file():
    c = PurviewDspmImportCollector(import_path="/no/such/dspm_export.json")
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE


def test_dspm_not_configured_without_path(monkeypatch):
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)
    c = PurviewDspmImportCollector()
    assert c.is_configured() is False
    assert c.safe_run() == []


def test_dspm_schema_version_constant():
    assert IMPORT_SCHEMA_VERSION == "1.0"


def test_documented_accessed_resources_labels_policies_and_contexts_are_distinct():
    records = [{
        "id": "documented", "operation": "CopilotInteraction",
        "auditData": {"CopilotEventData": {
            "AppHost": "BizChat",
            "Contexts": [{"Id": "conversation", "Type": "TeamsChat"}],
            "AccessedResources": [
                {"Id": "file-1", "Type": "docx", "Name": "Document1.docx",
                 "Action": "Read", "SensitivityLabelId": "confidential"},
                {"Id": "file-2", "Action": "Read", "SensitivityLabelId": "restricted",
                 "Status": "failure", "PolicyDetails": [
                     {"PolicyName": "Restrict grounding", "Rules": [
                         {"RuleName": "Restricted content", "Actions": ["BlockAccess"]}]}]},
            ]}},
    }]
    interaction = PurviewAuditCollector().normalize(records)[0]["interaction"]
    assert interaction["sensitivity_label_ids"] == ["confidential", "restricted"]
    assert {r["id"] for r in interaction["referenced_resources"]} == {"file-1", "file-2"}
    assert interaction["contexts"][0]["Id"] == "conversation"
    assert interaction["dlp_action"] == "Block"
    assert interaction["direction"] == "BLOCKED"
    assert interaction["dlp_policies"][0]["policy"] == "Restrict grounding"


def test_context_and_audit_only_policy_are_not_access_or_sharing_evidence():
    c = PurviewAuditCollector()
    for operation in ("CopilotInteraction", "AIAppInteraction", "ConnectedAIAppInteraction"):
        asset = c.normalize([{
            "id": operation, "operation": operation,
            "auditData": {
                "CopilotEventData": {"Contexts": [{"Id": "context", "Type": "TeamsChat"}]},
                "PolicyDetails": [{"PolicyName": "Observe", "Rules": [
                    {"RuleName": "Audit", "Actions": ["Audit"]}]}],
            },
        }])[0]
        assert asset["interaction"]["referenced_resources"] == []
        assert asset["interaction"]["direction"] == "UNKNOWN_DIRECTION"


def test_app_identity_and_agent_attribution_are_preserved():
    c = PurviewAuditCollector()
    assets = c.normalize([
        {"id": "connected", "auditData": {
            "AppHost": "BizChat", "AppIdentity": "ConnectedAIApp.Entra.client-id",
            "AgentId": "CopilotStudio.Declarative.agent-guid", "AgentName": "Sales Agent"}},
        {"id": "web", "auditData": {"AppIdentity": "AIApp.SaaS.ChatGPT"}},
    ])
    i = assets[0]["interaction"]
    assert i["app_id"] == "client-id"
    assert i["app_host"] == "Sales Agent" and i["host"] == "BizChat"
    assert i["agent_id"] == "CopilotStudio.Declarative.agent-guid"
    assert assets[1]["interaction"]["app_host"] == "ChatGPT"


class MemoryCheckpointStore:
    def __init__(self):
        self.data = {}
        self.versions = {}

    def read_json_versioned(self, name):
        return json.loads(json.dumps(self.data.get(name))), self.versions.get(name)

    def write_json_conditional(self, name, obj, expected_version):
        if self.versions.get(name) != expected_version:
            raise RuntimeError("Version conflict")
        self.data[name] = json.loads(json.dumps(obj))
        self.versions[name] = (expected_version or 0) + 1


TENANT = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"


def test_timed_out_query_resumes_durably_in_new_collector(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    store = MemoryCheckpointStore()
    first = PurviewAuditCollector(FakeGraph([], statuses=["running"]), poll_max=1,
                                  sleep=NOSLEEP, tenant_id=TENANT, checkpoint_store=store)
    assert first.safe_run() == []
    assert first.get_health()["status"] == ConnectorStatus.TIMEOUT
    saved = next(iter(store.data.values()))
    assert saved["query_id"] == "query-1" and saved["status"] == "pending"
    assert "auditData" not in str(saved)

    class ResumeGraph(FakeGraph):
        def post(self, *args):
            raise AssertionError("Must resume saved query, not create a new one")

    second = PurviewAuditCollector(ResumeGraph(_records()), poll_max=1, sleep=NOSLEEP,
                                   tenant_id=TENANT, checkpoint_store=store)
    assert len(second.safe_run()) == 3
    assert next(iter(store.data.values()))["status"] == "completed"
    assert second.get_coverage()["query_window"]["end"] == saved["end"]


def test_checkpoint_tenant_mismatch_prevents_all_graph_calls(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    store = MemoryCheckpointStore()
    first = PurviewAuditCollector(FakeGraph([], statuses=["running"]), poll_max=1,
                                  sleep=NOSLEEP, tenant_id=TENANT, checkpoint_store=store)
    first.safe_run()
    next(iter(store.data.values()))["tenant_id"] = "wrong-tenant"
    graph = FakeGraph([])
    second = PurviewAuditCollector(graph, sleep=NOSLEEP, tenant_id=TENANT, checkpoint_store=store)
    assert second.safe_run() == []
    assert second.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE
    assert "tenant" in second.get_health()["error"]
    assert graph.posted is None


def test_checkpoint_save_failure_is_explicit(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")

    class FailingStore(MemoryCheckpointStore):
        def write_json_conditional(self, *args):
            raise RuntimeError("Storage conflict")

    c = PurviewAuditCollector(FakeGraph([]), sleep=NOSLEEP, tenant_id=TENANT,
                              checkpoint_store=FailingStore())
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE
    assert "checkpoint could not be saved" in c.get_health()["error"]


def test_different_tenant_uses_separate_checkpoint(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    store = MemoryCheckpointStore()
    for tenant in (TENANT, "bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb"):
        graph = FakeGraph([], statuses=["running"])
        collector = PurviewAuditCollector(graph, poll_max=1, sleep=NOSLEEP,
                                           tenant_id=tenant, checkpoint_store=store)
        collector.safe_run()
        assert graph.posted is not None
    assert len(store.data) == 2
    assert {c["tenant_id"] for c in store.data.values()} == {
        TENANT, "bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb"}


def test_changed_query_configuration_does_not_resume_wrong_window(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    monkeypatch.delenv("PURVIEW_AUDIT_DAYS", raising=False)
    store = MemoryCheckpointStore()
    first = PurviewAuditCollector(FakeGraph([], statuses=["running"]), poll_max=1,
                                  sleep=NOSLEEP, tenant_id=TENANT, checkpoint_store=store)
    first.safe_run()
    graph = FakeGraph(_records())
    second = PurviewAuditCollector(graph, days=7, poll_max=1, sleep=NOSLEEP,
                                   tenant_id=TENANT, checkpoint_store=store)
    assert len(second.safe_run()) == 3
    assert graph.posted is not None
    assert next(iter(store.data.values()))["days"] == 7


def test_checkpoint_without_verified_tenant_is_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    c = PurviewAuditCollector(FakeGraph(_records()), sleep=NOSLEEP)
    assert len(c.safe_run()) == 3
    assert c.get_coverage()["checkpoint_status"] == "DISABLED_NO_VERIFIED_TENANT"


def test_invalid_windows_and_tenant_do_not_query(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")
    monkeypatch.delenv("PURVIEW_AUDIT_DAYS", raising=False)
    for options in ({"days": 0}, {"days": 181}, {"tenant_id": "not-a-tenant"}):
        graph = FakeGraph([])
        c = PurviewAuditCollector(graph, sleep=NOSLEEP, **options)
        assert c.safe_run() == []
        assert c.get_health()["status"] == ConnectorStatus.API_UNAVAILABLE
        assert graph.posted is None


def test_poll_uses_checked_get_and_classifies_permission_error(monkeypatch):
    monkeypatch.setenv("ENABLE_PURVIEW_AUDIT", "true")

    class Graph(FakeGraph):
        def get_checked(self, path):
            raise RuntimeError("Graph 403 Forbidden")

    c = PurviewAuditCollector(Graph([]), sleep=NOSLEEP)
    assert c.safe_run() == []
    assert c.get_health()["status"] == ConnectorStatus.PERMISSION_MISSING


def test_dspm_native_result_envelope_requires_complete_export(tmp_path):
    path = tmp_path / "activity.json"
    path.write_text(json.dumps({
        "LastPage": False, "ResultData": json.dumps([{
            "Application": "ChatGPT", "CreationTime": "2026-09-01T00:00:00Z",
            "User": "user@example.test", "Activity": "UploadFile",
        }]),
    }), encoding="utf-8")
    c = PurviewDspmImportCollector(import_path=str(path))
    assets = c.safe_run()
    assert c.get_health()["status"] == ConnectorStatus.PARTIALLY_CONNECTED
    assert assets[0]["interaction"]["app_host"] == "ChatGPT"
    assert assets[0]["interaction"]["direction"] == "UPLOADED"


def test_dspm_unsupported_rows_are_not_counted_as_connected():
    from connectors.base import ApiUnavailable
    import pytest
    with pytest.raises(ApiUnavailable):
        PurviewDspmImportCollector().normalize([{"unrecognized heading": "value"}])
