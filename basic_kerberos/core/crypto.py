from __future__ import annotations

import base64
import os
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS: int = 65_536
AES_KEY_BITS: int = 256
AES_KEY_BYTES: int = AES_KEY_BITS // 8
NONCE_LENGTH: int = 12
TIMESTAMP_SKEW_MS: int = 5 * 60 * 1000  # 5 minutes

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64_decode(encoded: str) -> bytes:
    return base64.b64decode(encoded.encode("ascii"))

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext

def aesgcm_decrypt(key: bytes, combined: bytes, aad: Optional[bytes] = None) -> bytes:
    nonce = combined[:NONCE_LENGTH]
    ciphertext = combined[NONCE_LENGTH:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

def current_millis() -> int:
    return int(time.time() * 1000)

def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=AES_KEY_BITS)
