"""Microsoft Graph için ince istemci: sayfalama + basit hata yönetimi."""
import time
import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphClient:
    def __init__(self, token: str):
        self._headers = {"Authorization": f"Bearer {token}",
                         "ConsistencyLevel": "eventual"}

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """@odata.nextLink'i takip ederek tüm sayfaları toplar."""
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
            url = body.get("@odata.nextLink")
        return items
