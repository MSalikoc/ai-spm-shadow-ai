"""
Microsoft Defender for Cloud Apps collector — web-tabanlı Shadow AI kullanımı (Adım 4).
Endpoint : /beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams[/{id}/aggregatedAppsDetails]
Permission: CloudApp-Discovery.Read.All
PREVIEW (beta) API — ENABLE_PREVIEW_CONNECTORS=true ile açılır.

Adım 1'de iskelet.
"""
import os

from .base import BaseCollector, Source


class DefenderCloudAppsCollector(BaseCollector):
    name = "defender_cloud_apps"
    source = Source.DEFENDER_CLOUD_APPS

    def __init__(self, graph=None):
        super().__init__()
        self._graph = graph

    def is_configured(self) -> bool:
        return (os.environ.get("ENABLE_DEFENDER_CLOUD_APPS", "").lower() == "true"
                and os.environ.get("ENABLE_PREVIEW_CONNECTORS", "").lower() == "true")

    def collect(self, since=None) -> list:
        return []          # Adım 4

    def normalize(self, raw_records: list) -> list:
        return []          # Adım 4

    def get_coverage(self) -> dict:
        return {"status": self._status, "period_days": 30, "applications": self._count}
