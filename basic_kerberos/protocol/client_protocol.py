from __future__ import annotations

import json
from typing import Optional, Tuple

from ..core.crypto import (
    aesgcm_encrypt,
    aesgcm_decrypt,
    b64_decode,
    derive_key_from_password,
    current_millis,
)
from ..core.models import Ticket, Authenticator, UserRecord

class ClientProtocol:
    """Client-side Kerberos logic (no networking)."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self._password = password
        self._k_c: Optional[bytes] = None
        self._session_key_c_tgs: Optional[bytes] = None
        self._tgt: Optional[Ticket] = None

    def bootstrap_from_user_record(self, user: UserRecord) -> None:
        self._k_c = derive_key_from_password(self._password, user.salt)

    def process_as_reply(self, encrypted_for_client: bytes) -> None:
        if self._k_c is None:
            raise RuntimeError("Client key not derived")

        body_bytes = aesgcm_decrypt(self._k_c, encrypted_for_client)
        body = json.loads(body_bytes.decode("utf-8"))

        self._session_key_c_tgs = b64_decode(body["session_key_c_tgs"])
        tgt_cipher = b64_decode(body["tgt"])
        self._tgt = Ticket(ciphertext=tgt_cipher)

    @property
    def tgt(self) -> Ticket:
        if self._tgt is None:
            raise RuntimeError("TGT not available; AS exchange not done")
        return self._tgt

    def create_tgs_authenticator(self) -> Authenticator:
        if self._session_key_c_tgs is None:
            raise RuntimeError("session_key_c_tgs not available")

        auth_body = {
            "client": self.username,
            "ts": current_millis(),
        }
        auth_plain = json.dumps(auth_body).encode("utf-8")
        cipher = aesgcm_encrypt(self._session_key_c_tgs, auth_plain)
        return Authenticator(ciphertext=cipher)

    def process_tgs_reply(self, encrypted_for_client: bytes) -> Tuple[bytes, Ticket]:
        if self._session_key_c_tgs is None:
            raise RuntimeError("session_key_c_tgs not available")

        body_bytes = aesgcm_decrypt(self._session_key_c_tgs, encrypted_for_client)
        body = json.loads(body_bytes.decode("utf-8"))

        session_key_c_s = b64_decode(body["session_key_c_s"])
        ticket_cipher = b64_decode(body["service_ticket"])
        ticket = Ticket(ciphertext=ticket_cipher)
        return session_key_c_s, ticket

    def create_service_authenticator(self, session_key_c_s: bytes) -> Authenticator:
        auth_body = {
            "client": self.username,
            "ts": current_millis(),
        }
        auth_plain = json.dumps(auth_body).encode("utf-8")
        cipher = aesgcm_encrypt(session_key_c_s, auth_plain)
        return Authenticator(ciphertext=cipher)
