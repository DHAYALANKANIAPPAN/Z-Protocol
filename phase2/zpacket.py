import struct
import time
import os
import hashlib

# Header format:
# B  = version        (1 byte)
# B  = packet_type    (1 byte)
# 8s = session_id     (8 bytes)
# d  = timestamp      (8 bytes, double)
# 32s= pow_token      (32 bytes)
# 1568s = kem_pubkey  (1568 bytes, ML-KEM-1024)
# 32s = x25519_pubkey (32 bytes)
# I  = payload_len    (4 bytes)
# Total fixed = 1654 bytes

HEADER_FORMAT = "!BB8sd32s1568s32sI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

VERSION_1      = 0x01
TYPE_HANDSHAKE = 0x01
TYPE_DATA      = 0x02


def build_pow_token(session_id: bytes, timestamp: float) -> bytes:
    """Generate SHA3-256 proof-of-work token."""
    raw = session_id + struct.pack("!d", timestamp)
    return hashlib.sha3_256(raw).digest()  # 32 bytes


def build_packet(
    packet_type: int,
    session_id: bytes,
    kem_pubkey: bytes,
    x25519_pubkey: bytes,
    payload: bytes
) -> bytes:
    """Pack a full Z-Protocol packet."""
    timestamp  = time.time()
    pow_token  = build_pow_token(session_id, timestamp)
    payload_len = len(payload)

    header = struct.pack(
        HEADER_FORMAT,
        VERSION_1,
        packet_type,
        session_id,
        timestamp,
        pow_token,
        kem_pubkey,
        x25519_pubkey,
        payload_len
    )
    return header + payload


def parse_packet(raw: bytes) -> dict:
    """Unpack raw bytes into a Z-Protocol packet dict."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Packet too short: {len(raw)} < {HEADER_SIZE}")

    header_bytes = raw[:HEADER_SIZE]
    payload      = raw[HEADER_SIZE:]

    (
        version,
        packet_type,
        session_id,
        timestamp,
        pow_token,
        kem_pubkey,
        x25519_pubkey,
        payload_len
    ) = struct.unpack(HEADER_FORMAT, header_bytes)

    return {
        "version"      : version,
        "packet_type"  : packet_type,
        "session_id"   : session_id,
        "timestamp"    : timestamp,
        "pow_token"    : pow_token,
        "kem_pubkey"   : kem_pubkey,
        "x25519_pubkey": x25519_pubkey,
        "payload_len"  : payload_len,
        "payload"      : payload[:payload_len]
    }


def verify_pow(packet: dict) -> bool:
    """Verify the proof-of-work token."""
    expected = build_pow_token(packet["session_id"], packet["timestamp"])
    return expected == packet["pow_token"]


def verify_timestamp(packet: dict, window_seconds: int = 30) -> bool:
    """Reject packets older than window_seconds (replay defence)."""
    age = abs(time.time() - packet["timestamp"])
    return age <= window_seconds


if __name__ == "__main__":
    print(f"[+] Header size: {HEADER_SIZE} bytes")

    # Test build + parse round trip
    session_id    = os.urandom(8)
    fake_kem_pub  = os.urandom(1568)
    fake_x_pub    = os.urandom(32)
    payload       = b"Hello Z-Protocol"

    raw = build_packet(TYPE_HANDSHAKE, session_id, fake_kem_pub, fake_x_pub, payload)
    print(f"[+] Built packet: {len(raw)} bytes")

    parsed = parse_packet(raw)
    print(f"[+] Parsed version     : {parsed['version']}")
    print(f"[+] Parsed packet_type : {parsed['packet_type']}")
    print(f"[+] PoW valid          : {verify_pow(parsed)}")
    print(f"[+] Timestamp valid    : {verify_timestamp(parsed)}")
    print(f"[+] Payload recovered  : {parsed['payload']}")
