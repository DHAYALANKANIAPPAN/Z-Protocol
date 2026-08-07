# zpacket_demo.py
# Binary packet builder and parser for Z-Protocol demo
#
# Header layout (1654 bytes fixed):
# VERSION(1) | TYPE(1) | SESSION_ID(8) | TIMESTAMP(8) |
# POW_TOKEN(32) | KEM_PUBKEY(1568) | X25519_PUBKEY(32) | PAYLOAD_LEN(4)

import struct
import time

HEADER_FORMAT = "!BB8sd32s1568s32sI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # 1654 bytes

VERSION_1      = 0x01
TYPE_HANDSHAKE = 0x01
TYPE_DATA      = 0x02

def build_packet(session_id, pow_token, timestamp,
                 kem_pubkey, x25519_pubkey, payload):
    """Pack all fields into a binary Z-Protocol packet."""
    header = struct.pack(
        HEADER_FORMAT,
        VERSION_1,
        TYPE_HANDSHAKE,
        session_id,
        timestamp,
        pow_token,
        kem_pubkey,
        x25519_pubkey,
        len(payload)
    )
    return header + payload

def parse_packet(raw: bytes) -> dict:
    """Unpack raw bytes back into a Z-Protocol packet dictionary."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Packet too short: {len(raw)} < {HEADER_SIZE}")
    (
        version, ptype, session_id, timestamp,
        pow_token, kem_pubkey, x25519_pubkey, payload_len
    ) = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])

    return {
        "version"      : version,
        "type"         : ptype,
        "session_id"   : session_id,
        "timestamp"    : timestamp,
        "pow_token"    : pow_token,
        "kem_pubkey"   : kem_pubkey,
        "x25519_pubkey": x25519_pubkey,
        "payload_len"  : payload_len,
        "payload"      : raw[HEADER_SIZE : HEADER_SIZE + payload_len]
    }

def verify_timestamp(packet: dict, window: int = 30) -> bool:
    """Reject packets older than window seconds (replay defence layer 1)."""
    import time
    return abs(time.time() - packet["timestamp"]) <= window
