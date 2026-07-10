import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce+ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # 12 bytes nonce prepended


def decrypt(session_key: bytes, nonce_and_ct: bytes) -> bytes:
    """Decrypt AES-256-GCM. Expects nonce+ciphertext."""
    nonce      = nonce_and_ct[:12]
    ciphertext = nonce_and_ct[12:]
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


if __name__ == "__main__":
    key       = os.urandom(32)
    message   = b"Z-Protocol encrypted payload test"
    encrypted = encrypt(key, message)
    decrypted = decrypt(key, encrypted)

    print(f"[+] Original  : {message}")
    print(f"[+] Encrypted : {encrypted.hex()[:48]}...")
    print(f"[+] Decrypted : {decrypted}")
    print(f"[+] Match     : {message == decrypted}")
