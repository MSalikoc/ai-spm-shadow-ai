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
    assert d["rec-2"] == "ALLOWED"       # DLP Audit (not blocked)
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
    assert m["blocked"] == 1 and m["allowed_with_sensitive"] == 1
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
    assert d2["interaction"]["direction"] == "UPLOADED"


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
