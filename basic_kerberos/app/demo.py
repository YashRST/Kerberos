from __future__ import annotations

import os

from ..core.crypto import generate_aes_key, derive_key_from_password
from ..core.models import UserRecord, ServiceRecord
from ..infra.user_store import InMemoryUserStore
from ..infra.service_store import InMemoryServiceStore
from ..protocol.kdc_protocol import KdcProtocol
from ..protocol.client_protocol import ClientProtocol
from ..protocol.service_protocol import ServiceProtocol
from .flows import as_flow, tgs_flow, service_flow

def demo_flow() -> None:
    print("=== Initialising stores and KDC ===")
    user_store = InMemoryUserStore()
    service_store = InMemoryServiceStore()
    tgs_key = generate_aes_key()
    kdc = KdcProtocol(tgs_key=tgs_key, user_store=user_store, service_store=service_store)

    username = "alice"
    password = "password123"
    salt = os.urandom(16)
    password_key = derive_key_from_password(password, salt)
    user_record = UserRecord(username=username, salt=salt, password_key=password_key)
    user_store.add(user_record)

    service_name = "fileserver"
    service_key = generate_aes_key()
    service_record = ServiceRecord(name=service_name, shared_key=service_key)
    service_store.add(service_record)

    client = ClientProtocol(username=username, password=password)
    client.bootstrap_from_user_record(user_record)

    service = ServiceProtocol(record=service_record)

    print("\n=== AS exchange (obtain TGT) ===")
    as_flow(kdc, client)
    print("Client obtained TGT and session_key_c_tgs")

    print("\n=== TGS exchange (obtain service ticket) ===")
    session_key_c_s, ticket = tgs_flow(kdc, client, service_name)
    print("Client obtained service ticket and session_key_c_s")

    print("\n=== Service exchange (access service) ===")
    accepted = service_flow(service, client, session_key_c_s, ticket)
    print("Service accepted request:", accepted)
