from __future__ import annotations
from dataclasses import dataclass

@dataclass
class UserRecord:
    username: str
    salt: bytes
    password_key: bytes  # derived from password

@dataclass
class ServiceRecord:
    name: str
    shared_key: bytes  # shared key between KDC and service

@dataclass
class Ticket:
    ciphertext: bytes

@dataclass
class Authenticator:
    ciphertext: bytes
