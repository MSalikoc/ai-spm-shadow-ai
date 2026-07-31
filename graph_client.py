"""Thin client for Microsoft Graph: pagination + simple error handling."""
import time
import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphClient:
    def __init__(self, token: str):
        self._headers = {"Authorization": f"Bearer {token}",
                         "ConsistencyLevel": "eventual"}

    def get_all(self, path: str, params: dict | None = None,
                max_items: int | None = None) -> list[dict]:
        """Collects pages by following @odata.nextLink. max_items sets an upper bound."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        items: list[dict] = []
        first = True
        while url:
            resp = requests.get(url, headers=self._headers,
                                 params=params if first else None, timeout=60)
            first = False
            if resp.status_code == 429:  # throttling
                wait = int(resp.headers.get("Retry-After", "5"))
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                raise RuntimeError(f"Graph {resp.status_code} @ {url}: {resp.text[:400]}")
            body = resp.json()
            items.extend(body.get("value", []))
            if max_items is not None and len(items) >= max_items:
                return items[:max_items]
            url = body.get("@odata.nextLink")
        return items

    def get(self, path: str, params: dict | None = None) -> dict:
        """Single-object GET (e.g. a servicePrincipal). Returns {} on error."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        for _ in range(4):
            resp = requests.get(url, headers=self._headers, params=params, timeout=60)
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("Retry-After", "5")))
                continue
            if resp.status_code >= 400:
                return {}
            return resp.json()
        return {}

    def post(self, path: str, body: dict) -> dict:
        """Single-object POST (e.g. creating an audit log query). Error → RuntimeError."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        while True:
            resp = requests.post(url, headers={**self._headers,
                                               "Content-Type": "application/json"},
                                 json=body, timeout=60)
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("Retry-After", "5")))
                continue
            if resp.status_code >= 400:
                raise RuntimeError(f"Graph {resp.status_code} @ {url}: {resp.text[:400]}")
            return resp.json() if resp.text else {}
