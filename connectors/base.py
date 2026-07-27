"""
Birleşik connector altyapısı — ortak interface, durum/entity/kaynak sabitleri ve
dayanıklı çalıştırma. Dört Microsoft veri kaynağı (Agent 365, Entra Agent ID,
Defender for Cloud Apps, Purview) bu interface üzerinden aynı normalize modele yazar.

Tasarım kuralı: bir connector'ın hatası genel assessment'ı DURDURMAZ (safe_run her
zaman liste döner, durum bilgisi get_health/get_coverage üzerinden yayılır).
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
    ENTRA_APPS = "ENTRA_APPS"          # mevcut OAuth/SP keşfi (collectors.py)


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


# Custom exception'lar — connector'lar hassas durumları bunlarla bildirebilir.
class LicenseMissing(Exception):
    pass


class PermissionMissing(Exception):
    pass


class ApiUnavailable(Exception):
    pass


class BaseCollector(ABC):
    """
    Tüm connector'ların ortak sözleşmesi. Alt sınıflar `name`, `source`'u ve
    is_configured/collect/normalize'ı uygular; get_health/get_coverage varsayılan gelir.
    """
    name: str = "base"
    source: str = None

    def __init__(self):
        self._status = ConnectorStatus.NOT_CONFIGURED
        self._error = None
        self._count = 0
        self._raw_count = 0

    # --- alt sınıfların uygulayacağı ---
    @abstractmethod
    def is_configured(self) -> bool:
        """Gerekli env/lisans/permission mevcut mu?"""

    @abstractmethod
    def collect(self, since=None) -> list:
        """Kaynaktan ham kayıtları çeker (API/import)."""

    @abstractmethod
    def normalize(self, raw_records: list) -> list:
        """Ham kayıtları birleşik entity modeline çevirir (bkz. model.make_asset)."""

    # --- ortak davranış ---
    def get_health(self) -> dict:
        return {"name": self.name, "source": self.source, "status": self._status,
                "count": self._count, "raw_count": self._raw_count, "error": self._error}

    def get_coverage(self) -> dict:
        return {"status": self._status, "assets": self._count}

    def safe_run(self, since=None) -> list:
        """
        collect+normalize'ı dayanıklı çalıştırır. ASLA exception fırlatmaz —
        durumu self._status'a yazar ve (boş olabilecek) entity listesi döner.
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
        except Exception as e:  # hiçbir hata assessment'ı durdurmaz
            self._status, self._error = ConnectorStatus.ERROR, str(e)
        return []
