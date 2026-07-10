import time
import os
import struct
import hashlib

TIMESTAMP_WINDOW = 30  # seconds — reject packets older than this


class ReplayFilter:
    """
    Tracks seen nonces to prevent replay attacks.
    Stores (nonce, timestamp) pairs and evicts expired ones.
    """
    def __init__(self, window: int = TIMESTAMP_WINDOW):
        self.window  = window
        self.seen    = {}  # nonce_hex -> timestamp

    def _evict_expired(self):
        """Remove nonces older than the time window."""
        now     = time.time()
        expired = [n for n, t in self.seen.items() if now - t > self.window]
        for n in expired:
            del self.seen[n]

    def is_replay(self, nonce: bytes, timestamp: float) -> bool:
        """
        Returns True if this packet is a replay and should be dropped.
        Returns False if packet is fresh and registers it.
        """
        now = time.time()

        # Check timestamp window first
        if abs(now - timestamp) > self.window:
            return True  # too old or too far in future

        nonce_hex = nonce.hex()

        # Check if nonce was seen before
        if nonce_hex in self.seen:
            return True  # replay detected

        # Register nonce
        self.seen[nonce_hex] = timestamp
        self._evict_expired()
        return False

    def stats(self):
        return f"Active nonces tracked: {len(self.seen)}"


if __name__ == "__main__":
    print("[*] Testing Replay Attack Filter...")
    rf = ReplayFilter()

    nonce     = os.urandom(8)
    timestamp = time.time()

    # First use — should pass
    result1 = rf.is_replay(nonce, timestamp)
    print(f"[+] First packet  (fresh)  : replay={result1} — expected False")

    # Replay — same nonce, same timestamp
    result2 = rf.is_replay(nonce, timestamp)
    print(f"[+] Second packet (replay) : replay={result2} — expected True")

    # New nonce — should pass
    new_nonce = os.urandom(8)
    result3   = rf.is_replay(new_nonce, timestamp)
    print(f"[+] Third packet  (fresh)  : replay={result3} — expected False")

    # Old timestamp — should be rejected
    old_ts  = time.time() - 60
    result4 = rf.is_replay(os.urandom(8), old_ts)
    print(f"[+] Fourth packet (old ts) : replay={result4} — expected True")

    print(f"\n[+] {rf.stats()}")
    print("[+] Replay filter working correctly!")
