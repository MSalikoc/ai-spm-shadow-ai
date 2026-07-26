"""
Ticketing adapter interface — SADECE arayüz (kriter 8).

Jira/ServiceNow entegrasyonu henüz GELİŞTİRİLMEDİ. Bu modül yalnızca ileride
bir adapter'ın uygulaması gereken sözleşmeyi tanımlar. Varsayılan NoopAdapter
hiçbir şey yapmaz; finding.ticket_reference alanı manuel doldurulur.

İleride: JiraAdapter(TicketAdapter) / ServiceNowAdapter(TicketAdapter) bu arayüzü
uygular ve get_adapter() ortam değişkenine göre onları döndürür.
"""
from abc import ABC, abstractmethod


class TicketAdapter(ABC):
    @abstractmethod
    def create_ticket(self, finding: dict) -> str | None:
        """Finding'den ticket oluşturur, ticket referansı döner (yoksa None)."""

    @abstractmethod
    def get_status(self, ticket_reference: str) -> str | None:
        """Ticket durumunu döner (yoksa None)."""


class NoopAdapter(TicketAdapter):
    """Entegrasyon yok — hiçbir şey yapmaz. ticket_reference manuel yönetilir."""
    def create_ticket(self, finding: dict) -> str | None:
        return None

    def get_status(self, ticket_reference: str) -> str | None:
        return None


def get_adapter() -> TicketAdapter:
    # Şimdilik daima Noop. İleride: os.environ['TICKETING_PROVIDER'] ile seçim.
    return NoopAdapter()
