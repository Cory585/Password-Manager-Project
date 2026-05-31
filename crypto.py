import os
from typing import cast

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ITERATIONS = 480_000
_NONCE_SIZE = 12


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from master_password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return cast(bytes, kdf.derive(master_password.encode()))


def encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM; returns a blob of nonce + ciphertext + auth tag."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = cast(bytes, aesgcm.encrypt(nonce, plaintext.encode(), None))
    return nonce + ciphertext


def decrypt(blob: bytes, key: bytes) -> str:
    """Decrypt a blob produced by encrypt; raises InvalidTag if the ciphertext has been tampered with."""
    aesgcm = AESGCM(key)
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return cast(bytes, aesgcm.decrypt(nonce, ciphertext, None)).decode()
