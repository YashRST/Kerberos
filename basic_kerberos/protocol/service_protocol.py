from __future__ import annotations

import json
from cryptography.exceptions import InvalidTag

from ..core.crypto import (
    aesgcm_decrypt,
    b64_decode,
    current_millis,
    TIMESTAMP_SKEW_MS,
)
from ..core.models import ServiceRecord, Ticket, Authenticator
from ..core.errors import AuthenticationError, TicketError

class ServiceProtocol:
    """Service-side Kerberos logic."""
    def __init__(self, record: ServiceRecord) -> None:
        self.name = record.name
        self._shared_key = record.shared_key

    def accept(self, service_ticket: Ticket, authenticator: Authenticator) -> bool:
        # Decrypt ticket; if the key is wrong or ciphertext is tampered, treat as invalid ticket.
        try:
            ticket_plain = aesgcm_decrypt(self._shared_key, service_ticket.ciphertext)
        except InvalidTag:
            raise TicketError("Failed to decrypt service ticket (invalid key or tampered ticket)")

        ticket_body = json.loads(ticket_plain.decode("utf-8"))

        client_from_ticket = ticket_body["client"]
        service_name = ticket_body["service"]
        session_key_c_s = b64_decode(ticket_body["session_key_c_s"])

        if service_name != self.name:
            raise TicketError("Service ticket not meant for this service")

        # Decrypt authenticator; again map low-level crypto failure to AuthenticationError.
        try:
            auth_plain = aesgcm_decrypt(session_key_c_s, authenticator.ciphertext)
        except InvalidTag:
            raise AuthenticationError("Failed to decrypt authenticator (invalid key or tampered data)")

        auth_body = json.loads(auth_plain.decode("utf-8"))

        client_from_auth = auth_body["client"]
        ts = int(auth_body["ts"])

        if client_from_auth != client_from_ticket:
            raise AuthenticationError("Client mismatch between ticket and authenticator")

        now = current_millis()
        if abs(now - ts) > TIMESTAMP_SKEW_MS:
            raise AuthenticationError("Authenticator timestamp too old or too far in the future")

        print(f"[Service {self.name}] Accepted request from '{client_from_ticket}' at ts={ts}")
        return True
