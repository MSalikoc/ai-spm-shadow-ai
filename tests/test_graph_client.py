"""GraphClient: retries, honest errors, and $batch."""
import pytest

import graph_client
from graph_client import GraphClient, GraphError


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.text = text if text is not None else "{}"

    def json(self):
        return self._body


class FakeSession:
    """Replays a queued list of responses and records what was asked for."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params, "json": json})
        if not self._responses:
            return FakeResponse(200, {"value": []})
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(graph_client.time, "sleep", lambda _s: None)


def _client(responses, **kw):
    session = FakeSession(responses)
    return GraphClient("tok", session=session, **kw), session


# --- errors carry a status ------------------------------------------------
def test_error_reports_status_not_just_a_string():
    client, _ = _client([FakeResponse(403, text="Insufficient privileges")])
    with pytest.raises(GraphError) as e:
        client.get_all("/servicePrincipals")
    assert e.value.status == 403
    assert e.value.is_permission and not e.value.is_missing


def test_missing_feature_is_distinguishable_from_missing_permission():
    client, _ = _client([FakeResponse(404, text="no such endpoint")])
    with pytest.raises(GraphError) as e:
        client.get_checked("/copilot/admin/catalog/packages")
    assert e.value.is_missing and not e.value.is_permission


def test_get_still_swallows_errors_for_callers_that_want_a_dict():
    client, _ = _client([FakeResponse(403, text="nope")])
    assert client.get("/servicePrincipals/x") == {}


# --- retries are bounded ---------------------------------------------------
def test_throttling_is_retried_then_succeeds():
    client, session = _client([
        FakeResponse(429, headers={"Retry-After": "1"}),
        FakeResponse(200, {"value": [{"id": "a"}]}),
    ])
    assert client.get_all("/servicePrincipals") == [{"id": "a"}]
    assert len(session.calls) == 2
    assert client.telemetry()["throttled"] == 1


def test_server_error_is_retried_rather_than_raised_immediately():
    client, session = _client([FakeResponse(503), FakeResponse(200, {"value": []})])
    assert client.get_all("/servicePrincipals") == []
    assert len(session.calls) == 2


def test_endless_throttling_gives_up_instead_of_looping_forever():
    client, session = _client([FakeResponse(429, headers={"Retry-After": "1"})] * 20,
                              max_retries=3)
    with pytest.raises(GraphError):
        client.get_all("/servicePrincipals")
    assert len(session.calls) == 3


def test_transport_failure_is_retried():
    import requests
    client, session = _client([requests.ConnectionError("reset"),
                               FakeResponse(200, {"value": [{"id": "z"}]})])
    assert client.get_all("/servicePrincipals") == [{"id": "z"}]
    assert len(session.calls) == 2


# --- paging ----------------------------------------------------------------
def test_paging_follows_next_link_and_respects_max_items():
    page1 = FakeResponse(200, {"value": [{"i": 1}, {"i": 2}],
                               "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"})
    page2 = FakeResponse(200, {"value": [{"i": 3}]})
    client, session = _client([page1, page2])
    assert client.get_all("/servicePrincipals") == [{"i": 1}, {"i": 2}, {"i": 3}]
    assert session.calls[1]["url"].endswith("/next")

    client2, _ = _client([FakeResponse(200, {"value": [{"i": 1}, {"i": 2}, {"i": 3}]})])
    assert len(client2.get_all("/servicePrincipals", max_items=2)) == 2


# --- $batch ----------------------------------------------------------------
def test_batch_collapses_many_gets_into_one_round_trip():
    replies = {"responses": [
        {"id": "sp1", "status": 200, "body": {"value": [{"appRoleId": "r1"}]}},
        {"id": "sp2", "status": 200, "body": {"value": []}},
    ]}
    client, session = _client([FakeResponse(200, replies)])
    got = client.batch_collection([
        {"id": "sp1", "url": "/servicePrincipals/sp1/appRoleAssignments"},
        {"id": "sp2", "url": "/servicePrincipals/sp2/appRoleAssignments"},
    ])
    assert got == {"sp1": [{"appRoleId": "r1"}], "sp2": []}
    assert len(session.calls) == 1
    assert session.calls[0]["url"].endswith("/$batch")


def test_batch_splits_at_the_twenty_request_graph_limit():
    def replies(ids):
        return FakeResponse(200, {"responses": [{"id": i, "status": 200, "body": {"value": []}}
                                                for i in ids]})
    spec = [{"id": f"sp{i}", "url": f"/servicePrincipals/sp{i}/owners"} for i in range(45)]
    client, session = _client([replies([f"sp{i}" for i in range(0, 20)]),
                               replies([f"sp{i}" for i in range(20, 40)]),
                               replies([f"sp{i}" for i in range(40, 45)])])
    got = client.batch_collection(spec)
    assert len(got) == 45
    assert len(session.calls) == 3
    assert len(session.calls[0]["json"]["requests"]) == 20
    assert len(session.calls[2]["json"]["requests"]) == 5


def test_batch_never_drops_an_id_when_a_chunk_fails():
    client, _ = _client([FakeResponse(500)] * 10)
    got = client.batch([{"id": "sp1", "url": "/a"}, {"id": "sp2", "url": "/b"}])
    assert set(got) == {"sp1", "sp2"}
    assert all(v["body"] == {} for v in got.values())


def test_batch_reports_per_item_failure_without_failing_the_others():
    replies = {"responses": [
        {"id": "ok", "status": 200, "body": {"value": [{"id": "x"}]}},
        {"id": "denied", "status": 403, "body": {"error": {"code": "Authorization_RequestDenied"}}},
    ]}
    client, _ = _client([FakeResponse(200, replies)])
    got = client.batch([{"id": "ok", "url": "/a"}, {"id": "denied", "url": "/b"}])
    assert got["ok"]["status"] == 200
    assert got["denied"]["status"] == 403


def test_batch_follows_a_paged_reply_so_nothing_is_truncated():
    replies = {"responses": [
        {"id": "sp1", "status": 200,
         "body": {"value": [{"i": 1}],
                  "@odata.nextLink": "https://graph.microsoft.com/v1.0/more"}},
    ]}
    client, _ = _client([FakeResponse(200, replies),
                         FakeResponse(200, {"value": [{"i": 2}]})])
    assert client.batch_collection([{"id": "sp1", "url": "/a"}]) == {"sp1": [{"i": 1}, {"i": 2}]}


# --- time budget -----------------------------------------------------------
def test_exhausted_time_budget_stops_instead_of_running_past_the_deadline(monkeypatch):
    client, session = _client([FakeResponse(200, {"value": []})], deadline=0.0)
    monkeypatch.setattr(graph_client.time, "monotonic", lambda: 100.0)
    with pytest.raises(GraphError):
        client.get_all("/servicePrincipals")
    assert session.calls == []
