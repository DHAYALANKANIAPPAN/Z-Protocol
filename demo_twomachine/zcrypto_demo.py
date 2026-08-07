# zcrypto_demo.py
# AES-256-GCM encrypt and decrypt used by the demo

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext. Returns nonce(12B) + ciphertext."""
    nonce  = os.urandom(12)
    return nonce + AESGCM(session_key).encrypt(nonce, plaintext, None)

def decrypt(session_key: bytes, blob: bytes) -> bytes:
    """Decrypt blob of nonce(12B) + ciphertext. Returns plaintext."""
    return AESGCM(session_key).decrypt(blob[:12], blob[12:], None)
