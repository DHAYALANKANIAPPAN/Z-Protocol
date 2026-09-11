# zkem_demo.py
# Hybrid KEM: X25519 + ML-KEM-1024 combined via HKDF
# Both sides independently derive the same 32-byte session key.
# The session key itself is NEVER transmitted.

import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"z-protocol-demo-session-key-v1"

def generate_server_keypair():
    """
    Generate server long-term keypairs.
    Called once when server starts.
    Returns dict with both private and public keys.
    """
    kem     = oqs.KeyEncapsulation("ML-KEM-1024")
    kem_pub = kem.generate_keypair()
    kem_priv= kem.export_secret_key()

    x_priv  = X25519PrivateKey.generate()
    x_pub   = x_priv.public_key().public_bytes_raw()

    return {
        "kem_pub"  : kem_pub,
        "kem_priv" : kem_priv,
        "x_priv"   : x_priv,
        "x_pub"    : x_pub,
    }

def client_encapsulate(server_kem_pub: bytes, server_x_pub: bytes):
    """
    Client side: encapsulate using server public keys.
    Returns session_key, kem_ciphertext, client_x_pub_raw
    """
    # ML-KEM-1024 encapsulation
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        kem_ct, kem_shared = kem.encap_secret(server_kem_pub)

    # X25519 exchange
    cli_x_priv   = X25519PrivateKey.generate()
    cli_x_pub    = cli_x_priv.public_key().public_bytes_raw()
    srv_x_pub_obj= X25519PublicKey.from_public_bytes(server_x_pub)
    x_shared     = cli_x_priv.exchange(srv_x_pub_obj)

    # Combine both shared secrets via HKDF
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=HKDF_INFO
    ).derive(kem_shared + x_shared)

    return session_key, kem_ct, cli_x_pub

def server_decapsulate(keypair: dict, kem_ct: bytes, client_x_pub: bytes):
    """
    Server side: decapsulate to recover same session key.
    """
    # ML-KEM-1024 decapsulation
    with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=keypair["kem_priv"]) as kem:
        kem_shared = kem.decap_secret(kem_ct)

    # X25519 exchange
    cli_x_pub_obj = X25519PublicKey.from_public_bytes(client_x_pub)
    x_shared      = keypair["x_priv"].exchange(cli_x_pub_obj)

    # Combine both shared secrets via HKDF
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=HKDF_INFO
    ).derive(kem_shared + x_shared)

    return session_key
