"""
Microsoft Purview Audit collector — hassas AI etkileşimlerinin ana kaynağı (Adım 5).
Endpoint : POST /v1.0/security/auditLog/queries → GET .../{id} → GET .../{id}/records
Operations: CopilotInteraction, ConnectedAIAppInteraction, AIAppInteraction
Permission: AuditLogsQuery.Read.All (Adım 5'te doğrulanacak)

Portal scraping / undocumented endpoint KULLANILMAZ. Raw prompt/response içeriği
STORE_RAW_AI_CONTENT=false iken saklanmaz. Adım 1'de iskelet.
"""
import os

from .base import BaseCollector, Source


class PurviewAuditCollector(BaseCollector):
    name = "purview_audit"
    source = Source.PURVIEW_AUDIT

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return os.environ.get("ENABLE_PURVIEW_AUDIT", "").lower() == "true"

    def collect(self, since=None) -> list:
        return []          # Adım 5

    def normalize(self, raw_records: list) -> list:
        return []          # Adım 5

    def get_coverage(self) -> dict:
        return {"status": self._status, "period_days": 30, "sensitive_interactions": self._count}
