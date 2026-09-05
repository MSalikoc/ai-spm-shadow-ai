import json
import multiprocessing
import os
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

import decisions
import function_app
import storage

NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def test_decision_assignment_and_history():
    store = {}
    state = decisions.set_decision(
        store, "sensitive-access",
        {"owner": "Alice", "status": "In progress", "due_date": "2026-09-12"},
        now=NOW)
    assert state["owner"] == "Alice"
    assert state["status"] == "In progress"
    assert {h["field"] for h in state["history"]} >= {"owner", "status", "due_date"}


def test_risk_acceptance_requires_owner_rationale_approver_and_future_expiry():
    base = {"owner": "CISO", "status": "Risk accepted"}
    with pytest.raises(ValueError, match="rationale"):
        decisions.set_decision({}, "governance", base, now=NOW)
    with pytest.raises(ValueError, match="future"):
        decisions.set_decision({}, "governance", {
            **base, "acceptance": {"rationale": "Temporary", "approved_by": "CISO",
                                   "expires_at": "2026-09-01"}}, now=NOW)
    state = decisions.set_decision({}, "governance", {
        **base, "acceptance": {"rationale": "Migration in progress", "approved_by": "CISO",
                               "expires_at": "2026-10-01"}}, now=NOW)
    assert state["acceptance"]["expires_at"] == "2026-10-01"


def test_deferred_and_compensating_control_have_required_evidence():
    with pytest.raises(ValueError, match="future due_date"):
        decisions.set_decision({}, "governance",
                               {"owner": "Board", "status": "Deferred", "notes": "Budget"},
                               now=NOW)
    with pytest.raises(ValueError, match="compensating_control"):
        decisions.set_decision({}, "identity-exposure",
                               {"owner": "SecOps", "status": "Compensating control"},
                               now=NOW)


def test_expired_acceptance_is_visible_as_expired_without_mutating_store():
    stored = decisions.set_decision({}, "governance", {
        "owner": "CISO", "status": "Risk accepted",
        "acceptance": {"rationale": "Short migration", "approved_by": "CISO",
                       "expires_at": "2026-09-06"}}, now=NOW)
    view = decisions.view_state("governance", stored,
                                now=datetime(2026, 9, 7, tzinfo=timezone.utc))
    assert view["acceptance_expired"] is True
    assert view["display_status"] == "Risk acceptance expired"
    assert stored["status"] == "Risk accepted"


def test_leaving_exception_status_clears_stale_exception_data():
    store = {}
    decisions.set_decision(store, "governance", {
        "owner": "CISO", "status": "Risk accepted",
        "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                       "expires_at": "2026-10-01"}}, now=NOW)
    state = decisions.set_decision(
        store, "governance", {"status": "In progress"}, now=NOW)
    assert state["acceptance"] is None


def test_corrupt_stored_date_is_surfaced_without_breaking_the_report():
    stored = decisions.default_state("governance")
    stored["due_date"] = "not-a-date"
    view = decisions.view_state("governance", stored, now=NOW)
    assert view["display_status"] == "Workflow data invalid"
    assert "ISO-8601" in view["data_error"]


def test_invalid_fields_in_object_are_surfaced_and_refused_for_update(monkeypatch):
    record = decisions.default_state("governance")
    record["status"] = "Made up"
    record["acceptance"] = "bad"
    monkeypatch.setattr(decisions.storage, "read_json_versioned",
                        lambda _name: ({"governance": record}, "v1"))
    visible = decisions.load()
    view = decisions.view_state("governance", visible["governance"], now=NOW)
    assert view["display_status"] == "Workflow data invalid"
    with pytest.raises(ValueError, match="invalid decision status"):
        decisions.update_decision("governance", {"owner": "CISO"}, now=NOW)


def test_unknown_decision_and_fields_are_rejected():
    with pytest.raises(ValueError, match="unknown"):
        decisions.set_decision({}, "other", {})
    with pytest.raises(ValueError, match="unsupported"):
        decisions.set_decision({}, "governance", {"magic": True})


class _Request:
    def __init__(self, method="GET", body=None):
        self.method = method
        self._body = body

    def get_json(self):
        if self._body is ValueError:
            raise ValueError("bad JSON")
        return self._body


def test_decisions_api_reads_defaults_and_persists_valid_update(monkeypatch):
    store = {}
    monkeypatch.setattr(function_app.decisionstate, "load", lambda: store)
    monkeypatch.setattr(
        function_app.decisionstate, "update_decision",
        lambda key, patch: decisions.set_decision(store, key, patch, now=NOW))

    response = function_app.decisions_workflow(_Request())
    assert response.status_code == 200
    assert b'"Decision required"' in response.get_body()
    assert all(record["data_error"] is None for record in
               json.loads(response.get_body())["decisions"].values())

    response = function_app.decisions_workflow(_Request("POST", {
        "decision_key": "identity-exposure", "owner": "SecOps",
        "status": "In progress", "due_date": "2027-01-01",
    }))
    assert response.status_code == 200
    assert store["identity-exposure"]["owner"] == "SecOps"
    assert b'"report_refresh"' in response.get_body()


def test_decisions_api_rejects_invalid_acceptance_without_writing(monkeypatch):
    monkeypatch.setattr(function_app.decisionstate, "load", lambda: {})
    monkeypatch.setattr(
        function_app.decisionstate, "update_decision",
        lambda key, patch: decisions.set_decision({}, key, patch, now=NOW))
    response = function_app.decisions_workflow(_Request("POST", {
        "decision_key": "governance", "owner": "CISO", "status": "Risk accepted",
    }))
    assert response.status_code == 400
    assert b"acceptance.rationale" in response.get_body()


@pytest.mark.parametrize("body", [None, [], ["not", "an", "object"], "text", 12, False])
def test_decisions_api_rejects_non_object_json(monkeypatch, body):
    monkeypatch.setattr(function_app.decisionstate, "load", lambda: {})
    response = function_app.decisions_workflow(_Request("POST", body))
    assert response.status_code == 400
    assert b"must be an object" in response.get_body()


def test_concurrent_update_reloads_and_preserves_other_decision(monkeypatch):
    first = {}
    second = {"governance": decisions.default_state("governance")}
    reads = iter([(first, "v1"), (second, "v2")])
    written = []
    monkeypatch.setattr(decisions, "_load_versioned", lambda: next(reads))

    def conditional(_name, value, version):
        if version == "v1":
            raise storage.StorageConflict("changed")
        written.append(value)

    monkeypatch.setattr(decisions.storage, "write_json_conditional", conditional)
    decisions.update_decision(
        "identity-exposure", {"owner": "SecOps", "status": "In progress"}, now=NOW)
    assert "governance" in written[0]
    assert written[0]["identity-exposure"]["owner"] == "SecOps"


def test_corrupt_store_is_visible_but_refused_for_updates(monkeypatch):
    monkeypatch.setattr(decisions.storage, "read_json_versioned",
                        lambda _name: ("not-an-object", "v1"))
    visible = decisions.load()
    assert all(v["_data_error"] for v in visible.values())
    with pytest.raises(ValueError, match="JSON object"):
        decisions.update_decision("governance", {"owner": "CISO"}, now=NOW)


def test_local_conditional_storage_detects_stale_version(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AzureWebJobsStorage", raising=False)
    monkeypatch.delenv("REPORT_STORAGE_CONNECTION", raising=False)
    storage.write_json_conditional("decisions.json", {"a": 1}, None)
    value, version = storage.read_json_versioned("decisions.json")
    assert value == {"a": 1} and version
    storage.write_json("decisions.json", {"a": 2})
    with pytest.raises(storage.StorageConflict):
        storage.write_json_conditional("decisions.json", {"a": 3}, version)


MALFORMED_FIELDS = [
    "decision_key", "status", "owner", "notes", "compensating_control", "due_date",
    "acceptance", "acceptance.rationale", "acceptance.approved_by", "acceptance.expires_at",
]


def _patch_field(record, field, value):
    if field.startswith("acceptance."):
        record["acceptance"] = {
            "rationale": "Migration", "approved_by": "CISO", "expires_at": "2026-10-01",
            field.split(".")[1]: value,
        }
    else:
        record[field] = value


@pytest.mark.parametrize("field,value", [
    (field, value)
    for field in MALFORMED_FIELDS
    for value in [[], ["bad"], {}, {"bad": "value"}, 0, 123, False]
    if not (field == "acceptance" and isinstance(value, dict))
] + [("status", None)])
def test_malformed_request_fields_return_400_without_writing(monkeypatch, field, value):
    stored = {}
    before = deepcopy(stored)
    monkeypatch.setattr(decisions, "_load_versioned", lambda: (stored, "v1"))
    write = Mock()
    monkeypatch.setattr(storage, "write_json_conditional", write)
    monkeypatch.setattr(decisions, "load", lambda: stored)
    body = {"decision_key": "governance", "owner": "CISO", "status": "In progress"}
    _patch_field(body, field, value)
    response = function_app.decisions_workflow(_Request("POST", body))
    assert response.status_code == 400, (field, value, response.get_body())
    assert json.loads(response.get_body())["error"]
    assert stored == before
    write.assert_not_called()


@pytest.mark.parametrize("field,value", [
    (field, value)
    for field in MALFORMED_FIELDS + ["updated_at", "history"]
    for value in [[], ["bad"], {}, {"bad": "value"}, 0, 123, False]
    if not ((field == "acceptance" and isinstance(value, dict))
            or (field == "history" and value == []))
] + [("status", None), ("history", None)])
def test_malformed_persisted_fields_are_data_errors_without_mutation(field, value):
    stored = decisions.default_state("governance")
    _patch_field(stored, field, value)
    before = deepcopy(stored)
    view = decisions.view_state("governance", stored, now=NOW)
    assert view["data_error"], (field, value)
    assert view["display_status"] == "Workflow data invalid"
    assert stored == before
    json.dumps(view)


@pytest.mark.parametrize("acceptance", ["text", "", 123, False, [], ["text"]])
def test_risk_acceptance_rejects_non_object_even_when_falsy(acceptance):
    with pytest.raises(ValueError, match="acceptance"):
        decisions.set_decision({}, "governance", {
            "owner": "CISO", "status": "Risk accepted", "acceptance": acceptance}, now=NOW)


@pytest.mark.parametrize("body", [
    b"{", b"\xff", b"null", b"[]", b'{"governance": null}',
    b'{"governance": {"status": []}}',
    b'{"governance": {"owner": 123}}',
])
def test_corrupt_local_store_is_not_overwritten(tmp_path, monkeypatch, body):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AzureWebJobsStorage", raising=False)
    monkeypatch.delenv("REPORT_STORAGE_CONNECTION", raising=False)
    path = tmp_path / "out" / "decisions.json"
    path.parent.mkdir()
    path.write_bytes(body)
    visible = decisions.load()
    assert any(decisions.view_state(key, record, now=NOW)["data_error"]
               for key, record in visible.items())
    with pytest.raises(ValueError):
        decisions.update_decision("governance", {"owner": "CISO"}, now=NOW)
    assert path.read_bytes() == body
    assert not list(path.parent.glob("*.tmp"))


@pytest.mark.parametrize("offset", [timedelta(), timedelta(hours=12),
                                   timedelta(days=1, microseconds=-1)])
def test_date_only_deadlines_are_valid_through_entire_utc_day(offset):
    now = NOW + offset
    deferred = decisions.set_decision({}, "governance", {
        "owner": "Board", "status": "Deferred", "notes": "Budget", "due_date": "2026-09-05",
    }, now=now)
    accepted = decisions.set_decision({}, "governance", {
        "owner": "CISO", "status": "Risk accepted",
        "acceptance": {"rationale": "Migration", "approved_by": "CISO",
                       "expires_at": "2026-09-05"},
    }, now=now)
    assert decisions.view_state("governance", deferred, now=now)["overdue"] is False
    assert decisions.view_state("governance", accepted, now=now)["acceptance_expired"] is False
    tomorrow = NOW + timedelta(days=1)
    assert decisions.view_state("governance", deferred, now=tomorrow)["overdue"] is True
    assert decisions.view_state("governance", accepted, now=tomorrow)["acceptance_expired"] is True
    with pytest.raises(ValueError, match="future due_date"):
        decisions.set_decision({}, "governance", {
            "owner": "Board", "status": "Deferred", "notes": "Budget",
            "due_date": "2026-09-05"}, now=tomorrow)


def test_date_only_deadlines_use_utc_not_the_callers_calendar_day():
    local_now = datetime(2026, 9, 6, 1, tzinfo=timezone(timedelta(hours=3)))
    state = decisions.set_decision({}, "governance", {
        "owner": "Board", "status": "Deferred", "notes": "Budget", "due_date": "2026-09-05",
    }, now=local_now)
    assert decisions.view_state("governance", state, now=local_now)["overdue"] is False


@pytest.mark.parametrize("stamp", ["2026-09-05T12:00:00Z", "2026-09-05T12:00:00",
                                   "2026-09-05T15:00:00+03:00"])
def test_timestamp_deadlines_keep_exact_instant_semantics(stamp):
    boundary = NOW + timedelta(hours=12)
    before = boundary - timedelta(microseconds=1)
    deferred = decisions.set_decision({}, "governance", {
        "owner": "Board", "status": "Deferred", "notes": "Budget", "due_date": stamp,
    }, now=before)
    accepted = decisions.set_decision({}, "governance", {
        "owner": "CISO", "status": "Risk accepted",
        "acceptance": {"rationale": "Migration", "approved_by": "CISO", "expires_at": stamp},
    }, now=before)
    for now, elapsed in [(before, False), (boundary, True),
                          (boundary + timedelta(microseconds=1), True)]:
        assert decisions.view_state("governance", deferred, now=now)["overdue"] is elapsed
        assert decisions.view_state("governance", accepted, now=now)["acceptance_expired"] is elapsed
    with pytest.raises(ValueError, match="future"):
        decisions.set_decision({}, "governance", {
            "owner": "CISO", "status": "Risk accepted", "acceptance": accepted["acceptance"],
        }, now=boundary)


def _concurrent_writer(directory, barrier, outcomes, key, version, merge):
    os.chdir(directory)
    try:
        if merge:
            load = decisions._load_versioned
            first = True

            def synchronized_load():
                nonlocal first
                result = load()
                if first:
                    first = False
                    barrier.wait(timeout=15)
                return result

            decisions._load_versioned = synchronized_load
            decisions.update_decision(
                key, {"owner": key, "status": "In progress"}, now=NOW)
        else:
            replace = storage.os.replace

            def slow_replace(source, target):
                time.sleep(0.1)  # Force simultaneous writers to overlap before replacement.
                replace(source, target)

            storage.os.replace = slow_replace
            barrier.wait(timeout=15)
            storage.write_json_conditional("decisions.json", {key: True}, version)
        outcomes.put("ok")
    except storage.StorageConflict:
        outcomes.put("conflict")
    except Exception as exc:
        outcomes.put(f"error: {exc!r}")


def _run_writers(tmp_path, version, merge):
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    outcomes = ctx.Queue()
    processes = [ctx.Process(target=_concurrent_writer, args=(
        str(tmp_path), barrier, outcomes, key, version, merge))
        for key in ("governance", "identity-exposure")]
    try:
        for process in processes:
            process.start()
        result = [outcomes.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0
        return sorted(result)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        outcomes.close()
        outcomes.join_thread()


@pytest.mark.parametrize("existing", [False, True])
def test_concurrent_local_conditional_writers_have_exactly_one_winner(
        tmp_path, monkeypatch, existing):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AzureWebJobsStorage", raising=False)
    monkeypatch.delenv("REPORT_STORAGE_CONNECTION", raising=False)
    if existing:
        storage.write_json_conditional("decisions.json", {}, None)
    _, version = storage.read_json_versioned("decisions.json")
    assert _run_writers(tmp_path, version, merge=False) == ["conflict", "ok"]
    value, _ = storage.read_json_versioned("decisions.json")
    assert len(value) == 1
    assert not list((tmp_path / "out").glob("*.tmp"))


def test_concurrent_local_updates_retry_merge_and_preserve_both_records(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AzureWebJobsStorage", raising=False)
    monkeypatch.delenv("REPORT_STORAGE_CONNECTION", raising=False)
    assert _run_writers(tmp_path, None, merge=True) == ["ok", "ok"]
    store = decisions.load()
    assert set(store) == {"governance", "identity-exposure"}
    assert all(record["owner"] == key and record["history"] for key, record in store.items())


def test_local_replace_uses_unique_files_and_cleans_up_on_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AzureWebJobsStorage", raising=False)
    monkeypatch.delenv("REPORT_STORAGE_CONNECTION", raising=False)
    storage.write_json_conditional("decisions.json", {"initial": True}, None)
    before, version = storage.read_json_versioned("decisions.json")
    replace = storage.os.replace
    paths = []

    def fail_once(source, target):
        paths.append(source)
        if len(paths) == 1:
            raise PermissionError("replacement denied")
        replace(source, target)

    monkeypatch.setattr(storage.os, "replace", fail_once)
    with pytest.raises(PermissionError, match="replacement denied"):
        storage.write_json_conditional("decisions.json", {"next": True}, version)
    assert storage.read_json_versioned("decisions.json") == (before, version)
    assert not list((tmp_path / "out").glob("*.tmp"))
    storage.write_json_conditional("decisions.json", {"next": True}, version)
    assert len(set(paths)) == 2
    assert not list((tmp_path / "out").glob("*.tmp"))


def _hold_local_lock(path, ready, release):
    with storage._local_lock(path):
        ready.set()
        release.wait(timeout=30)


def test_local_lock_timeout_is_explicit_and_process_exit_releases_lock(tmp_path):
    path = str(tmp_path / "decisions.json")
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_hold_local_lock, args=(path, ready, release))
    process.start()
    try:
        assert ready.wait(timeout=15)
        with pytest.raises(TimeoutError, match="storage lock"):
            with storage._local_lock(path, timeout=0.05):
                pytest.fail("another process holds the lock")
    finally:
        process.terminate()
        process.join(timeout=5)
    with storage._local_lock(path, timeout=1):
        pass


@pytest.fixture
def azure_blob(monkeypatch):
    from azure.storage.blob import BlobServiceClient
    monkeypatch.setenv("AzureWebJobsStorage", "mock-connection")
    blob, container, service = Mock(), Mock(), Mock()
    service.get_blob_client.return_value = blob
    service.get_container_client.return_value = container
    container.get_blob_client.return_value = blob
    monkeypatch.setattr(BlobServiceClient, "from_connection_string", lambda _conn: service)
    return blob


@pytest.mark.parametrize("existing", [False, True])
def test_azure_writes_use_create_only_or_etag_conditions(azure_blob, existing):
    from azure.core import MatchConditions
    storage.write_json_conditional("decisions.json", {}, "etag-1" if existing else None)
    kwargs = azure_blob.upload_blob.call_args.kwargs
    assert kwargs["overwrite"] is existing
    if existing:
        assert kwargs["etag"] == "etag-1"
        assert kwargs["match_condition"] == MatchConditions.IfNotModified
    else:
        assert "etag" not in kwargs


def test_azure_etag_conflict_reloads_merges_and_retries(azure_blob):
    from azure.core import MatchConditions
    from azure.core.exceptions import ResourceModifiedError
    existing = {"governance": decisions.default_state("governance")}
    downloads = []
    for store, etag in [({}, "etag-1"), (existing, "etag-2")]:
        download = Mock()
        download.readall.return_value = json.dumps(store).encode()
        download.properties.etag = etag
        downloads.append(download)
    azure_blob.download_blob.side_effect = downloads
    azure_blob.upload_blob.side_effect = [ResourceModifiedError("changed"), None]
    decisions.update_decision(
        "identity-exposure", {"owner": "SecOps", "status": "In progress"}, now=NOW)
    calls = azure_blob.upload_blob.call_args_list
    assert [call.kwargs["etag"] for call in calls] == ["etag-1", "etag-2"]
    assert all(call.kwargs["match_condition"] == MatchConditions.IfNotModified for call in calls)
    merged = json.loads(calls[-1].args[0])
    assert merged["governance"] == existing["governance"]
    assert merged["identity-exposure"]["owner"] == "SecOps"


def test_azure_create_conflict_is_retryable(azure_blob):
    from azure.core.exceptions import ResourceExistsError
    azure_blob.upload_blob.side_effect = ResourceExistsError("created concurrently")
    with pytest.raises(storage.StorageConflict):
        storage.write_json_conditional("decisions.json", {}, None)
