import unittest
import os

from basic_kerberos.core.crypto import generate_aes_key, derive_key_from_password
from basic_kerberos.core.models import UserRecord, ServiceRecord, Ticket
from basic_kerberos.core.errors import AuthenticationError, TicketError
from basic_kerberos.infra.user_store import InMemoryUserStore
from basic_kerberos.infra.service_store import InMemoryServiceStore
from basic_kerberos.protocol.kdc_protocol import KdcProtocol
from basic_kerberos.protocol.client_protocol import ClientProtocol
from basic_kerberos.protocol.service_protocol import ServiceProtocol
from basic_kerberos.app.flows import as_flow, tgs_flow, service_flow

class TestKerberosBasicFlow(unittest.TestCase):
    def setUp(self):
        self.user_store = InMemoryUserStore()
        self.service_store = InMemoryServiceStore()
        self.tgs_key = generate_aes_key()
        self.kdc = KdcProtocol(tgs_key=self.tgs_key, user_store=self.user_store, service_store=self.service_store)

        # bootstrap one user and one service
        self.username = "alice"
        self.password = "password123"
        salt = os.urandom(16)
        password_key = derive_key_from_password(self.password, salt)
        self.user_record = UserRecord(username=self.username, salt=salt, password_key=password_key)
        self.user_store.add(self.user_record)

        self.service_name = "fileserver"
        service_key = generate_aes_key()
        self.service_record = ServiceRecord(name=self.service_name, shared_key=service_key)
        self.service_store.add(self.service_record)

    def test_full_flow_success(self):
        client = ClientProtocol(username=self.username, password=self.password)
        client.bootstrap_from_user_record(self.user_record)
        service = ServiceProtocol(record=self.service_record)

        as_flow(self.kdc, client)
        session_key_c_s, ticket = tgs_flow(self.kdc, client, self.service_name)
        accepted = service_flow(service, client, session_key_c_s, ticket)

        self.assertTrue(accepted)

    def test_unknown_user_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.kdc.issue_tgt("bob")  # not registered

    def test_unknown_service_rejected(self):
        client = ClientProtocol(username=self.username, password=self.password)
        client.bootstrap_from_user_record(self.user_record)
        as_flow(self.kdc, client)
        # use some non-existent service
        with self.assertRaises(TicketError):
            from basic_kerberos.core.models import Authenticator  # just for type hints
            auth = client.create_tgs_authenticator()
            self.kdc.issue_service_ticket(self.username, "nonexistent", client.tgt, auth)

    def test_ticket_for_wrong_service_fails(self):
        # normal bootstrap
        client = ClientProtocol(username=self.username, password=self.password)
        client.bootstrap_from_user_record(self.user_record)
        as_flow(self.kdc, client)
        session_key_c_s, ticket = tgs_flow(self.kdc, client, self.service_name)

        # create another service with different name/key
        other_service_record = ServiceRecord(name="dbserver", shared_key=generate_aes_key())
        other_service = ServiceProtocol(record=other_service_record)

        # attempting to use ticket for fileserver on dbserver should fail
        with self.assertRaises(TicketError):
            auth = client.create_service_authenticator(session_key_c_s)
            other_service.accept(ticket, auth)

if __name__ == "__main__":
    unittest.main()
