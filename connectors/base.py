"""
Unified connector infrastructure — shared interface, status/entity/source constants, and
resilient execution. The four Microsoft data sources (Agent 365, Entra Agent ID,
Defender for Cloud Apps, Purview) all write to the same normalized model through this
interface.

Design rule: one connector's failure does NOT stop the overall assessment (safe_run
always returns a list, status is surfaced via get_health/get_coverage).
"""
from abc import ABC, abstractmethod


class ConnectorStatus:
    CONNECTED = "CONNECTED"
    PARTIALLY_CONNECTED = "PARTIALLY_CONNECTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PERMISSION_MISSING = "PERMISSION_MISSING"
    LICENSE_MISSING = "LICENSE_MISSING"
    NO_DATA = "NO_DATA"
    API_UNAVAILABLE = "API_UNAVAILABLE"
    ERROR = "ERROR"


class Source:
    AGENT_365 = "AGENT_365"
    ENTRA_AGENT_ID = "ENTRA_AGENT_ID"
    DEFENDER_CLOUD_APPS = "DEFENDER_CLOUD_APPS"
    PURVIEW_AUDIT = "PURVIEW_AUDIT"
    PURVIEW_DSPM_EXPORT = "PURVIEW_DSPM_EXPORT"
    ENTRA_APPS = "ENTRA_APPS"          # existing OAuth/SP discovery (collectors.py)


class EntityType:
    AI_APPLICATION = "AI_APPLICATION"
    AI_AGENT = "AI_AGENT"
    AGENT_PACKAGE = "AGENT_PACKAGE"
    AGENT_IDENTITY = "AGENT_IDENTITY"
    AGENT_BLUEPRINT = "AGENT_BLUEPRINT"
    USER = "USER"
    DEVICE = "DEVICE"
    MODEL = "MODEL"
    TOOL = "TOOL"
    MCP_SERVER = "MCP_SERVER"
    DATA_RESOURCE = "DATA_RESOURCE"
    SENSITIVE_INTERACTION = "SENSITIVE_INTERACTION"
    USAGE_OBSERVATION = "USAGE_OBSERVATION"
    FINDING = "FINDING"


# Custom exceptions — connectors report specific conditions through these.
class LicenseMissing(Exception):
    pass


class PermissionMissing(Exception):
    pass


class ApiUnavailable(Exception):
    pass


def classify_graph_error(err):
    """
    Maps a failed Graph call to the connector status the dashboard should show.

    Prefers the real HTTP status off a `GraphError`; falls back to sniffing the message
    so hand-built fakes and plain RuntimeErrors still classify. Returns an exception to
    raise — a generic one is returned unchanged so `safe_run` records it as ERROR.
    """
    status = getattr(err, "status", None)
    text = str(err)
    s = text.lower()

    # A licensing failure can arrive as 402, 403, or 400 depending on the endpoint, so
    # the message is the only reliable signal — check it before the status code.
    if "license" in s or "quota" in s or "subscription" in s:
        return LicenseMissing(text[:200])
    if status in (401, 403):
        return PermissionMissing(text[:200])
    if status in (400, 404, 501):
        return ApiUnavailable(text[:200])
    if "403" in s or "401" in s or "forbidden" in s or "authorization" in s:
        return PermissionMissing(text[:200])
    if "404" in s or "not found" in s or "notfound" in s or "400" in s:
        return ApiUnavailable(text[:200])
    return err


class BaseCollector(ABC):
    """
    Shared contract for all connectors. Subclasses implement `name`, `source`, and
    is_configured/collect/normalize; get_health/get_coverage come with defaults.
    """
    name: str = "base"
    source: str = None

    def __init__(self):
        self._status = ConnectorStatus.NOT_CONFIGURED
        self._error = None
        self._count = 0
        self._raw_count = 0

    # --- implemented by subclasses ---
    @abstractmethod
    def is_configured(self) -> bool:
        """Is the required env/license/permission present?"""

    @abstractmethod
    def collect(self, since=None) -> list:
        """Pulls raw records from the source (API/import)."""

    @abstractmethod
    def normalize(self, raw_records: list) -> list:
        """Converts raw records into the unified entity model (see model.make_asset)."""

    # --- shared behavior ---
    def get_health(self) -> dict:
        return {"name": self.name, "source": self.source, "status": self._status,
                "count": self._count, "raw_count": self._raw_count, "error": self._error}

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}

    def safe_run(self, since=None) -> list:
        """
        Runs collect+normalize resiliently. NEVER raises — writes status to
        self._status and returns an entity list (which may be empty).
        """
        try:
            if not self.is_configured():
                if self._status == ConnectorStatus.NOT_CONFIGURED:
                    self._status = ConnectorStatus.NOT_CONFIGURED
                return []
            raw = self.collect(since) or []
            self._raw_count = len(raw)
            entities = self.normalize(raw) or []
            self._count = len(entities)
            if self._status not in (ConnectorStatus.PARTIALLY_CONNECTED,):
                self._status = ConnectorStatus.CONNECTED if entities else ConnectorStatus.NO_DATA
            return entities
        except LicenseMissing as e:
            self._status, self._error = ConnectorStatus.LICENSE_MISSING, str(e)
        except PermissionMissing as e:
            self._status, self._error = ConnectorStatus.PERMISSION_MISSING, str(e)
        except ApiUnavailable as e:
            self._status, self._error = ConnectorStatus.API_UNAVAILABLE, str(e)
        except Exception as e:  # no error is allowed to stop the assessment
            self._status, self._error = ConnectorStatus.ERROR, str(e)
        return []
