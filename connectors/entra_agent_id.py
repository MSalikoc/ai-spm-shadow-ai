"""
Microsoft Entra Agent ID collector — agent identity/blueprint/owner/sponsor/permission (Adım 3).
Endpoint : /v1.0/servicePrincipals/microsoft.graph.agentIdentity,
           /v1.0/applications/microsoft.graph.agentIdentityBlueprint
Permission: Directory.Read.All / Application.Read.All (Adım 3'te doğrulanacak)

Adım 1'de iskelet.
"""
import os

from .base import BaseCollector, Source


class EntraAgentIdCollector(BaseCollector):
    name = "entra_agent_id"
    source = Source.ENTRA_AGENT_ID

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_ENTRA_AGENT_ID", "").lower() == "true"

    def collect(self, since=None) -> list:
        return []          # Adım 3

    def normalize(self, raw_records: list) -> list:
        return []          # Adım 3

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}
