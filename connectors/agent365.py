"""
Microsoft Agent 365 collector — agent registry & package envanteri (Adım 2).
Endpoint : GET /v1.0/copilot/admin/catalog/packages[/{id}]
Permission: CopilotPackages.Read.All
Lisans yoksa: LICENSE_MISSING / API_UNAVAILABLE.

Bu dosya Adım 1'de yalnızca iskelettir; toplama mantığı Adım 2'de eklenecek.
"""
import os

from .base import BaseCollector, Source


class Agent365Collector(BaseCollector):
    name = "agent365"
    source = Source.AGENT_365

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_AGENT365", "").lower() == "true"

    def collect(self, since=None) -> list:
        return []          # Adım 2

    def normalize(self, raw_records: list) -> list:
        return []          # Adım 2

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}
