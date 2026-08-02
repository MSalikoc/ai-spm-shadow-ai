"""
Microsoft Graph client: pagination, $batch, bounded retries, and honest errors.

Three things the rest of the codebase depends on:

  * `$batch` — Graph accepts 20 requests per round-trip. The scan makes several calls
    per discovered app (appRoleAssignments, owners, SP detail); batching collapses those
    into a twentieth of the HTTP round-trips, which is what keeps a large tenant inside
    the Function's execution budget.
  * bounded retries — 429 and 5xx are both retried with backoff, but a call can never
    loop forever: `max_retries` and the per-client `deadline` both cap it.
  * honest errors — `GraphError` carries the HTTP status, so a caller can tell
    "403, you lack the permission" from "404, this tenant has no such feature" from
    "empty result". Silently returning {} on every failure is what made missing
    permissions look like missing data.
"""
import json
import logging
import random
import threading
import time

import requests

GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_BASE = GRAPH_V1  # back-compat: modules that import GRAPH_BASE

_BATCH_LIMIT = 20  # Graph's hard cap on requests per $batch


class GraphError(RuntimeError):
    """A Graph call that failed. `status` is the HTTP status code (0 = transport error)."""

    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = (body or "")[:400]
        super().__init__(f"Graph {status} @ {url}: {self.body}")

    @property
    def is_permission(self) -> bool:
        return self.status in (401, 403)

    @property
    def is_missing(self) -> bool:
        return self.status in (400, 404, 501)


class GraphClient:
    """
    Thread-safe. A single instance is shared across the scan's thread pools; the only
    mutable state is the telemetry counter, which is guarded by a lock.
    """

    def __init__(self, token: str, timeout: int = 60, max_retries: int = 5,
                 deadline: float | None = None, session=None):
        self._headers = {"Authorization": f"Bearer {token}",
                         "ConsistencyLevel": "eventual"}
        self._timeout = timeout
        self._max_retries = max_retries
        self._deadline = deadline           # absolute time.monotonic() budget, or None
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self.stats = {"requests": 0, "retries": 0, "throttled": 0, "errors": 0,
                      "batched_requests": 0, "batch_calls": 0}

    # --- internals ---------------------------------------------------------
    def _count(self, key: str, n: int = 1) -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + n

    def _out_of_time(self) -> bool:
        return self._deadline is not None and time.monotonic() >= self._deadline

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        """Retry-After wins when the server sends it; otherwise exponential + jitter."""
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return min(2 ** attempt, 32) * (0.5 + random.random() / 2)

    def _request(self, method: str, url: str, *, params=None, json_body=None) -> requests.Response:
        """One HTTP call with bounded retry on 429/5xx/transport failure."""
        last: Exception | None = None
        for attempt in range(self._max_retries):
            if self._out_of_time():
                raise GraphError(0, url, "Graph time budget exhausted")
            try:
                self._count("requests")
                headers = dict(self._headers)
                if json_body is not None:
                    headers["Content-Type"] = "application/json"
                resp = self._session.request(method, url, headers=headers, params=params,
                                             json=json_body, timeout=self._timeout)
            except requests.RequestException as e:
                last = e
                self._count("retries")
                time.sleep(self._backoff(attempt, None))
                continue

            if resp.status_code == 429:
                self._count("throttled")
                self._count("retries")
                time.sleep(self._backoff(attempt, resp.headers.get("Retry-After")))
                continue
            if resp.status_code >= 500:
                self._count("retries")
                time.sleep(self._backoff(attempt, resp.headers.get("Retry-After")))
                continue
            return resp

        self._count("errors")
        raise GraphError(0, url, f"exhausted {self._max_retries} retries: {last}")

    @staticmethod
    def _abs(path: str, beta: bool = False) -> str:
        if path.startswith("http"):
            return path
        return f"{GRAPH_BETA if beta else GRAPH_V1}{path}"

    # --- public API --------------------------------------------------------
    def get_all(self, path: str, params: dict | None = None,
                max_items: int | None = None, beta: bool = False) -> list[dict]:
        """Follows @odata.nextLink until exhausted. `max_items` caps the result."""
        url = self._abs(path, beta)
        items: list[dict] = []
        first = True
        while url:
            resp = self._request("GET", url, params=params if first else None)
            first = False
            if resp.status_code >= 400:
                self._count("errors")
                raise GraphError(resp.status_code, url, resp.text)
            body = resp.json()
            items.extend(body.get("value", []))
            if max_items is not None and len(items) >= max_items:
                return items[:max_items]
            url = body.get("@odata.nextLink")
            if url and self._out_of_time():
                logging.warning("Graph paging stopped early (time budget) at %s items", len(items))
                break
        return items

    def get(self, path: str, params: dict | None = None, beta: bool = False) -> dict:
        """Single-object GET. Returns {} on error — use `get_checked` to see the error."""
        try:
            return self.get_checked(path, params, beta=beta)
        except GraphError:
            return {}

    def get_checked(self, path: str, params: dict | None = None, beta: bool = False) -> dict:
        """Single-object GET that raises `GraphError` instead of hiding the failure."""
        url = self._abs(path, beta)
        resp = self._request("GET", url, params=params)
        if resp.status_code >= 400:
            self._count("errors")
            raise GraphError(resp.status_code, url, resp.text)
        return resp.json() if resp.text else {}

    def post(self, path: str, body: dict, beta: bool = False) -> dict:
        url = self._abs(path, beta)
        resp = self._request("POST", url, json_body=body)
        if resp.status_code >= 400:
            self._count("errors")
            raise GraphError(resp.status_code, url, resp.text)
        return resp.json() if resp.text else {}

    # --- $batch ------------------------------------------------------------
    def batch(self, requests_spec: list[dict], beta: bool = False) -> dict[str, dict]:
        """
        Runs many GETs in as few round-trips as possible.

        `requests_spec` is [{"id": <your key>, "url": "/servicePrincipals/x/owners"}, ...]
        where `url` is Graph-relative. Returns {id: {"status": int, "body": dict}} — one
        entry per input, always. A per-item failure is reported in that item's status; it
        never raises and never drops an id, so callers can treat the result as a lookup.
        """
        out: dict[str, dict] = {}
        pending = [r for r in requests_spec if r.get("id") and r.get("url")]
        batch_url = f"{GRAPH_BETA if beta else GRAPH_V1}/$batch"

        for start in range(0, len(pending), _BATCH_LIMIT):
            chunk = pending[start:start + _BATCH_LIMIT]
            payload = {"requests": [{"id": str(r["id"]), "method": "GET", "url": r["url"]}
                                    for r in chunk]}
            try:
                self._count("batch_calls")
                self._count("batched_requests", len(chunk))
                resp = self._request("POST", batch_url, json_body=payload)
                if resp.status_code >= 400:
                    raise GraphError(resp.status_code, batch_url, resp.text)
                replies = resp.json().get("responses", [])
            except (GraphError, ValueError) as e:
                status = e.status if isinstance(e, GraphError) else 0
                for r in chunk:
                    out[str(r["id"])] = {"status": status, "body": {}}
                logging.warning("Graph $batch chunk failed (%s items): %s", len(chunk), e)
                continue

            got = set()
            for rep in replies:
                rid = str(rep.get("id"))
                got.add(rid)
                out[rid] = {"status": rep.get("status", 0), "body": rep.get("body") or {}}
            for r in chunk:  # Graph omitted a reply — record it rather than lose the id
                if str(r["id"]) not in got:
                    out[str(r["id"])] = {"status": 0, "body": {}}

        # A $batch reply is not paged; a collection with a nextLink needs a real follow-up.
        return out

    def batch_collection(self, requests_spec: list[dict], beta: bool = False) -> dict[str, list]:
        """
        `batch` for collection endpoints: returns {id: [items]}. When a batched reply is
        paged, the remaining pages are fetched normally so nothing is silently truncated.
        """
        raw = self.batch(requests_spec, beta=beta)
        out: dict[str, list] = {}
        for rid, rep in raw.items():
            body = rep.get("body") or {}
            items = list(body.get("value", []) or [])
            nxt = body.get("@odata.nextLink")
            if nxt:
                try:
                    items.extend(self.get_all(nxt))
                except GraphError:
                    pass
            out[rid] = items
        return out

    def telemetry(self) -> dict:
        with self._lock:
            return dict(self.stats)


def json_default(o):
    """Helper for logging raw Graph payloads without blowing up on odd types."""
    try:
        return json.dumps(o)
    except TypeError:
        return str(o)
