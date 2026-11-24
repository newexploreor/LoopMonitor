from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_text(key: bytes, plaintext: str) -> str:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    token = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + token).decode("ascii")


def decrypt_text(key: bytes, encoded: str) -> str:
    raw = base64.b64decode(encoded)
    nonce, token = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, token, None).decode("utf-8")
