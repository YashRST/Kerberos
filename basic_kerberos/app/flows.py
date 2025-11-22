from __future__ import annotations

from ..protocol.kdc_protocol import KdcProtocol
from ..protocol.client_protocol import ClientProtocol
from ..protocol.service_protocol import ServiceProtocol
from ..core.models import Ticket

def as_flow(kdc: KdcProtocol, client: ClientProtocol) -> None:
    as_rep = kdc.issue_tgt(client.username)
    client.process_as_reply(as_rep)

def tgs_flow(kdc: KdcProtocol, client: ClientProtocol, service_name: str) -> tuple[bytes, Ticket]:
    auth = client.create_tgs_authenticator()
    tgs_rep = kdc.issue_service_ticket(client.username, service_name, client.tgt, auth)
    return client.process_tgs_reply(tgs_rep)

def service_flow(service: ServiceProtocol, client: ClientProtocol, session_key_c_s: bytes, ticket: Ticket) -> bool:
    auth = client.create_service_authenticator(session_key_c_s)
    return service.accept(ticket, auth)
