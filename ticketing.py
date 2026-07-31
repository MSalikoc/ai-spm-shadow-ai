"""
Ticketing adapter interface — interface ONLY (criterion 8).

Jira/ServiceNow integration is NOT YET IMPLEMENTED. This module only defines the
contract a future adapter must implement. The default NoopAdapter does nothing; the
finding.ticket_reference field is filled in manually.

Future: JiraAdapter(TicketAdapter) / ServiceNowAdapter(TicketAdapter) will implement
this interface, and get_adapter() will select between them based on an env var.
"""
from abc import ABC, abstractmethod


class TicketAdapter(ABC):
    @abstractmethod
    def create_ticket(self, finding: dict) -> str | None:
        """Creates a ticket from a finding, returns the ticket reference (None if unavailable)."""

    @abstractmethod
    def get_status(self, ticket_reference: str) -> str | None:
        """Returns the ticket status (None if unavailable)."""


class NoopAdapter(TicketAdapter):
    """No integration — does nothing. ticket_reference is managed manually."""
    def create_ticket(self, finding: dict) -> str | None:
        return None

    def get_status(self, ticket_reference: str) -> str | None:
        return None


def get_adapter() -> TicketAdapter:
    # Always Noop for now. Future: select via os.environ['TICKETING_PROVIDER'].
    return NoopAdapter()
