"""
AI-SPM unified connector framework.

The four Microsoft data sources (Agent 365, Entra Agent ID, Defender for Cloud Apps,
Purview) + the existing Entra OAuth discovery all write to the same normalized model
through the shared BaseCollector interface; registry.run() runs them resiliently and
correlation merges the results.
"""
from .base import (BaseCollector, ConnectorStatus, Source, EntityType,
                   LicenseMissing, PermissionMissing, ApiUnavailable)
from . import model, correlation, registry, sensitive_data
from .agent365 import Agent365Collector
from .entra_agent_id import EntraAgentIdCollector
from .defender_cloud_apps import DefenderCloudAppsCollector
from .purview_audit import PurviewAuditCollector
from .purview_dspm_import import PurviewDspmImportCollector

__all__ = [
    "BaseCollector", "ConnectorStatus", "Source", "EntityType",
    "LicenseMissing", "PermissionMissing", "ApiUnavailable",
    "model", "correlation", "registry", "sensitive_data", "default_collectors",
    "Agent365Collector", "EntraAgentIdCollector", "DefenderCloudAppsCollector",
    "PurviewAuditCollector", "PurviewDspmImportCollector",
]


def default_collectors(graph=None):
    """The four Microsoft connectors + the DSPM import adapter (all env-gated)."""
    return [
        Agent365Collector(graph),
        EntraAgentIdCollector(graph),
        DefenderCloudAppsCollector(graph),
        PurviewAuditCollector(graph),
        PurviewDspmImportCollector(),
    ]
