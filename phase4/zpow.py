import hashlib
import os
import time
import struct

DIFFICULTY = 2  # number of leading zero bytes required

def compute_pow(session_id: bytes, timestamp: float, difficulty: int = DIFFICULTY) -> bytes:
    """
    Client side: brute-force a nonce so that
    SHA3-512(nonce + session_id + timestamp) starts with `difficulty` zero bytes.
    Returns the winning nonce (8 bytes).
    """
    ts_bytes = struct.pack("!d", timestamp)
    attempts = 0
    while True:
        nonce = os.urandom(8)
        digest = hashlib.sha3_512(nonce + session_id + ts_bytes).digest()
        attempts += 1
        if digest[:difficulty] == b'\x00' * difficulty:
            return nonce


def verify_pow(nonce: bytes, session_id: bytes, timestamp: float, difficulty: int = DIFFICULTY) -> bool:
    """
    Server side: verify client's PoW nonce in O(1) — one hash, no brute force.
    """
    ts_bytes = struct.pack("!d", timestamp)
    digest = hashlib.sha3_512(nonce + session_id + ts_bytes).digest()
    return digest[:difficulty] == b'\x00' * difficulty


if __name__ == "__main__":
    print(f"[*] Testing SHA3-512 PoW with difficulty={DIFFICULTY} zero bytes...")
    session_id = os.urandom(8)
    timestamp  = time.time()

    start = time.perf_counter()
    nonce = compute_pow(session_id, timestamp)
    elapsed = time.perf_counter() - start

    digest = hashlib.sha3_512(nonce + session_id + struct.pack("!d", timestamp)).digest()
    valid  = verify_pow(nonce, session_id, timestamp)

    print(f"[+] Nonce found     : {nonce.hex()}")
    print(f"[+] Hash prefix     : {digest[:4].hex()}")
    print(f"[+] Time to solve   : {elapsed*1000:.2f} ms")
    print(f"[+] Server verify   : {valid}")
    print(f"[+] SHA3-512 PoW working correctly!")
