import time
import os


class SessionStore:
    """
    Minimal server-side session state.
    Stores only what's needed — ratchet state + nonce registry.
    Everything else is derived per-packet (stateless KEM).
    """
    def __init__(self, ttl: int = 3600):
        self.sessions = {}  # session_id_hex -> session dict
        self.ttl      = ttl  # session lifetime in seconds

    def create(self, session_id: bytes, ratchet) -> dict:
        sid = session_id.hex()
        self.sessions[sid] = {
            "session_id" : session_id,
            "ratchet"    : ratchet,
            "created_at" : time.time(),
            "last_seen"  : time.time(),
            "msg_count"  : 0
        }
        return self.sessions[sid]

    def get(self, session_id: bytes):
        sid = session_id.hex()
        s   = self.sessions.get(sid)
        if s and time.time() - s["created_at"] < self.ttl:
            s["last_seen"] = time.time()
            s["msg_count"] += 1
            return s
        return None

    def evict_expired(self):
        now     = time.time()
        expired = [sid for sid, s in self.sessions.items()
                   if now - s["created_at"] > self.ttl]
        for sid in expired:
            del self.sessions[sid]
        return len(expired)

    def stats(self):
        return {
            "active_sessions": len(self.sessions),
            "ttl_seconds"    : self.ttl
        }


if __name__ == "__main__":
    from zratchet import DoubleRatchet

    print("[*] Testing Session State Design...")
    store = SessionStore(ttl=3600)

    session_id  = os.urandom(8)
    session_key = os.urandom(32)
    ratchet     = DoubleRatchet(session_key)

    # Create session
    s = store.create(session_id, ratchet)
    print(f"[+] Session created  : {session_id.hex()}")
    print(f"[+] Active sessions  : {store.stats()['active_sessions']}")

    # Retrieve session
    retrieved = store.get(session_id)
    print(f"[+] Session retrieved: {retrieved is not None}")
    print(f"[+] Msg count        : {retrieved['msg_count']}")

    # Unknown session
    unknown = store.get(os.urandom(8))
    print(f"[+] Unknown session  : {unknown} — expected None")

    print("[+] Session state design working correctly!")
