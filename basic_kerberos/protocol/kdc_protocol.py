from __future__ import annotations

import json
from typing import Any

from ..core.crypto import (
    aesgcm_encrypt,
    aesgcm_decrypt,
    b64_encode,
    b64_decode,
    generate_aes_key,
    current_millis,
    TIMESTAMP_SKEW_MS,
)
from ..core.models import Ticket, Authenticator, UserRecord, ServiceRecord
from ..core.errors import AuthenticationError, TicketError

class KdcProtocol:
    """Implements AS and TGS logic using injected stores."""

    def __init__(self, tgs_key: bytes, user_store: Any, service_store: Any) -> None:
        self._tgs_key = tgs_key
        self._user_store = user_store
        self._service_store = service_store

    def issue_tgt(self, username: str) -> bytes:
        user: UserRecord | None = self._user_store.get(username)
        if user is None:
            raise AuthenticationError(f"Unknown user: {username}")

        k_c = user.password_key
        session_key_c_tgs = generate_aes_key()

        tgt_body = {
            "client": username,
            "session_key_c_tgs": b64_encode(session_key_c_tgs),
        }
        tgt_plain = json.dumps(tgt_body).encode("utf-8")
        tgt_cipher = aesgcm_encrypt(self._tgs_key, tgt_plain)

        body_for_client = {
            "session_key_c_tgs": b64_encode(session_key_c_tgs),
            "tgt": b64_encode(tgt_cipher),
        }
        return aesgcm_encrypt(k_c, json.dumps(body_for_client).encode("utf-8"))

    def issue_service_ticket(self, username: str, service_name: str, tgt: Ticket, authenticator: Authenticator) -> bytes:
        service: ServiceRecord | None = self._service_store.get(service_name)
        if service is None:
            raise TicketError(f"Unknown service: {service_name}")

        tgt_plain = aesgcm_decrypt(self._tgs_key, tgt.ciphertext)
        tgt_body = json.loads(tgt_plain.decode("utf-8"))

        client_from_tgt = tgt_body["client"]
        session_key_c_tgs = b64_decode(tgt_body["session_key_c_tgs"])

        if client_from_tgt != username:
            raise TicketError("Client mismatch between TGT and request")

        auth_plain = aesgcm_decrypt(session_key_c_tgs, authenticator.ciphertext)
        auth_body = json.loads(auth_plain.decode("utf-8"))

        client_from_auth = auth_body["client"]
        ts = int(auth_body["ts"])

        if client_from_auth != username:
            raise AuthenticationError("Client mismatch between authenticator and request")

        now = current_millis()
        if abs(now - ts) > TIMESTAMP_SKEW_MS:
            raise AuthenticationError("Authenticator timestamp too old or too far in the future")

        session_key_c_s = generate_aes_key()

        service_ticket_body = {
            "client": username,
            "service": service_name,
            "session_key_c_s": b64_encode(session_key_c_s),
        }
        service_ticket_plain = json.dumps(service_ticket_body).encode("utf-8")
        service_ticket_cipher = aesgcm_encrypt(service.shared_key, service_ticket_plain)

        body_for_client = {
            "session_key_c_s": b64_encode(session_key_c_s),
            "service_ticket": b64_encode(service_ticket_cipher),
        }
        return aesgcm_encrypt(session_key_c_tgs, json.dumps(body_for_client).encode("utf-8"))
