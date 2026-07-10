import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_hybrid_keypair():
    """Generate both X25519 and ML-KEM-1024 keypairs."""
    # X25519
    x_private = X25519PrivateKey.generate()
    x_public  = x_private.public_key()
    x_pub_bytes = x_public.public_bytes_raw()

    # ML-KEM-1024
    kem = oqs.KeyEncapsulation("ML-KEM-1024")
    kem_pub_bytes = kem.generate_keypair()

    return {
        "x_private"    : x_private,
        "x_pub_bytes"  : x_pub_bytes,
        "kem"          : kem,
        "kem_pub_bytes": kem_pub_bytes
    }


def client_encapsulate(server_kem_pub: bytes, server_x_pub_bytes: bytes):
    """
    Client side: encapsulate secrets using server's public keys.
    Returns ciphertexts + derived session key.
    """
    # X25519 client side
    client_x_priv    = X25519PrivateKey.generate()
    client_x_pub     = client_x_priv.public_key()
    client_x_pub_raw = client_x_pub.public_bytes_raw()

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    server_x_pub = X25519PublicKey.from_public_bytes(server_x_pub_bytes)
    x_shared = client_x_priv.exchange(server_x_pub)

    # ML-KEM-1024 encapsulation
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem_client:
        kem_ciphertext, kem_shared = kem_client.encap_secret(server_kem_pub)

    # Combine both secrets via HKDF
    combined = x_shared + kem_shared
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"z-protocol-session-key-v1"
    ).derive(combined)

    return {
        "session_key"      : session_key,
        "kem_ciphertext"   : kem_ciphertext,
        "client_x_pub_raw" : client_x_pub_raw
    }


def server_decapsulate(keypair: dict, kem_ciphertext: bytes, client_x_pub_bytes: bytes):
    """
    Server side: decapsulate to recover same session key.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)
    x_shared = keypair["x_private"].exchange(client_x_pub)

    kem_shared = keypair["kem"].decap_secret(kem_ciphertext)

    combined = x_shared + kem_shared
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"z-protocol-session-key-v1"
    ).derive(combined)

    return session_key


if __name__ == "__main__":
    print("[*] Testing Hybrid KEM (X25519 + ML-KEM-1024)...")

    # Server generates keypair
    server_keys = generate_hybrid_keypair()

    # Client encapsulates
    client_result = client_encapsulate(
        server_keys["kem_pub_bytes"],
        server_keys["x_pub_bytes"]
    )

    # Server decapsulates
    server_key = server_decapsulate(
        server_keys,
        client_result["kem_ciphertext"],
        client_result["client_x_pub_raw"]
    )

    # Both keys must match
    match = client_result["session_key"] == server_key
    print(f"[+] Client session key : {client_result['session_key'].hex()[:32]}...")
    print(f"[+] Server session key : {server_key.hex()[:32]}...")
    print(f"[+] Keys match         : {match}")
    assert match, "SESSION KEY MISMATCH — something is wrong"
    print("[+] Hybrid KEM working correctly!")

    server_keys["kem"].free()
