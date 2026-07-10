import struct
import time
import os
import hashlib

HEADER_FORMAT = "!BB8sd32s1568s32sI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

VERSION_1      = 0x01
TYPE_HANDSHAKE = 0x01
TYPE_DATA      = 0x02


def build_packet(packet_type, session_id, kem_pubkey, x25519_pubkey, payload, pow_token=None, timestamp=None):
    """Pack a full Z-Protocol packet."""
    if timestamp is None:
        timestamp = time.time()
    if pow_token is None:
        pow_token = os.urandom(32)

    header = struct.pack(
        HEADER_FORMAT,
        VERSION_1,
        packet_type,
        session_id,
        timestamp,
        pow_token,
        kem_pubkey,
        x25519_pubkey,
        len(payload)
    )
    return header + payload


def parse_packet(raw: bytes) -> dict:
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Packet too short: {len(raw)} < {HEADER_SIZE}")

    (
        version, packet_type, session_id, timestamp,
        pow_token, kem_pubkey, x25519_pubkey, payload_len
    ) = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])

    return {
        "version"      : version,
        "packet_type"  : packet_type,
        "session_id"   : session_id,
        "timestamp"    : timestamp,
        "pow_token"    : pow_token,
        "kem_pubkey"   : kem_pubkey,
        "x25519_pubkey": x25519_pubkey,
        "payload_len"  : payload_len,
        "payload"      : raw[HEADER_SIZE:HEADER_SIZE + payload_len]
    }


def verify_timestamp(packet: dict, window_seconds: int = 30) -> bool:
    age = abs(time.time() - packet["timestamp"])
    return age <= window_seconds
