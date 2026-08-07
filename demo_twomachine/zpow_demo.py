# zpow_demo.py
# SHA3-512 Proof-of-Work
# Client brute-forces a nonce. Server verifies in O(1) — one hash.
# Protects server from DDoS: invalid PoW = packet dropped before KEM runs.

import hashlib
import os
import struct
import time

DIFFICULTY = 2  # number of leading zero bytes required

def compute_pow(session_id: bytes, timestamp: float) -> tuple:
    """
    Client side: find nonce where SHA3-512(nonce+sid+ts)[:DIFFICULTY] == 0x00...
    Returns (nonce, attempts, elapsed_ms)
    """
    ts_bytes = struct.pack("!d", timestamp)
    attempts = 0
    t0       = time.perf_counter()
    while True:
        nonce  = os.urandom(8)
        digest = hashlib.sha3_512(nonce + session_id + ts_bytes).digest()
        attempts += 1
        if digest[:DIFFICULTY] == b'\x00' * DIFFICULTY:
            elapsed = (time.perf_counter() - t0) * 1000
            return nonce, attempts, elapsed

def verify_pow(nonce: bytes, session_id: bytes, timestamp: float) -> tuple:
    """
    Server side: verify in a single hash. Returns (valid, hash_prefix_hex)
    """
    ts_bytes = struct.pack("!d", timestamp)
    digest   = hashlib.sha3_512(nonce + session_id + ts_bytes).digest()
    valid    = digest[:DIFFICULTY] == b'\x00' * DIFFICULTY
    return valid, digest[:4].hex()
