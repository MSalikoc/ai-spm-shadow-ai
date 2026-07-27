"""
AI-SPM birleşik connector framework'ü.

Dört Microsoft veri kaynağı (Agent 365, Entra Agent ID, Defender for Cloud Apps,
Purview) + mevcut Entra OAuth keşfi, ortak BaseCollector interface'i üzerinden aynı
normalize modele yazar; registry.run() dayanıklı çalıştırır ve correlation birleştirir.
"""
from .base import (BaseCollector, ConnectorStatus, Source, EntityType,
                   LicenseMissing, PermissionMissing, ApiUnavailable)
from . import model, correlation, registry
from .agent365 import Agent365Collector
from .entra_agent_id import EntraAgentIdCollector
from .defender_cloud_apps import DefenderCloudAppsCollector
from .purview_audit import PurviewAuditCollector
from .purview_dspm_import import PurviewDspmImportCollector

__all__ = [
    "BaseCollector", "ConnectorStatus", "Source", "EntityType",
    "LicenseMissing", "PermissionMissing", "ApiUnavailable",
    "model", "correlation", "registry", "default_collectors",
    "Agent365Collector", "EntraAgentIdCollector", "DefenderCloudAppsCollector",
    "PurviewAuditCollector", "PurviewDspmImportCollector",
]


def default_collectors(graph=None):
    """Dört Microsoft connector + DSPM import adapter'ı (hepsi env ile gate'li)."""
    return [
        Agent365Collector(graph),
        EntraAgentIdCollector(graph),
        DefenderCloudAppsCollector(graph),
        PurviewAuditCollector(graph),
        PurviewDspmImportCollector(),
    ]
