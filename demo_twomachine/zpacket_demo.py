# zpacket_demo.py
# Binary packet builder and parser for Z-Protocol demo

import struct
import time

# Handshake Header (1654 bytes)
# VERSION(1) | TYPE(1) | SESSION_ID(8) | TIMESTAMP(8) | POW_TOKEN(32) | KEM_PUBKEY(1568) | X25519_PUBKEY(32) | PAYLOAD_LEN(4)
HANDSHAKE_FORMAT = "!BB8sd32s1568s32sI"
HANDSHAKE_SIZE   = struct.calcsize(HANDSHAKE_FORMAT)

# Data Header (26 bytes)
# VERSION(1) | TYPE(1) | SESSION_ID(8) | SEQUENCE_NUM(4) | FRAG_INDEX(4) | FRAG_TOTAL(4) | PAYLOAD_LEN(4)
DATA_FORMAT = "!BB8sIIII"
DATA_SIZE   = struct.calcsize(DATA_FORMAT)

VERSION_1      = 0x01
TYPE_HANDSHAKE = 0x01
TYPE_DATA      = 0x02

def build_handshake_packet(session_id, pow_token, timestamp, kem_pubkey, x25519_pubkey, payload):
    header = struct.pack(
        HANDSHAKE_FORMAT,
        VERSION_1, TYPE_HANDSHAKE, session_id, timestamp, pow_token,
        kem_pubkey, x25519_pubkey, len(payload)
    )
    return header + payload

def build_data_packet(session_id, seq_num, frag_index, frag_total, payload):
    header = struct.pack(
        DATA_FORMAT,
        VERSION_1, TYPE_DATA, session_id, seq_num, frag_index, frag_total, len(payload)
    )
    return header + payload

def parse_packet(raw: bytes) -> dict:
    if len(raw) < 2:
        raise ValueError("Packet too short to read type.")
    
    version, ptype = struct.unpack("!BB", raw[:2])
    
    if ptype == TYPE_HANDSHAKE:
        if len(raw) < HANDSHAKE_SIZE:
            raise ValueError(f"Handshake packet too short: {len(raw)} < {HANDSHAKE_SIZE}")
        
        _, _, session_id, timestamp, pow_token, kem_pubkey, x25519_pubkey, payload_len = struct.unpack(HANDSHAKE_FORMAT, raw[:HANDSHAKE_SIZE])
        
        return {
            "version"      : version,
            "type"         : ptype,
            "session_id"   : session_id,
            "timestamp"    : timestamp,
            "pow_token"    : pow_token,
            "kem_pubkey"   : kem_pubkey,
            "x25519_pubkey": x25519_pubkey,
            "payload_len"  : payload_len,
            "payload"      : raw[HANDSHAKE_SIZE : HANDSHAKE_SIZE + payload_len]
        }
    
    elif ptype == TYPE_DATA:
        if len(raw) < DATA_SIZE:
            raise ValueError(f"Data packet too short: {len(raw)} < {DATA_SIZE}")
            
        _, _, session_id, seq_num, frag_index, frag_total, payload_len = struct.unpack(DATA_FORMAT, raw[:DATA_SIZE])
        
        return {
            "version"      : version,
            "type"         : ptype,
            "session_id"   : session_id,
            "seq_num"      : seq_num,
            "frag_index"   : frag_index,
            "frag_total"   : frag_total,
            "payload_len"  : payload_len,
            "payload"      : raw[DATA_SIZE : DATA_SIZE + payload_len]
        }
    else:
        raise ValueError(f"Unknown packet type: {ptype}")

def verify_timestamp(packet: dict, window: int = 30) -> bool:
    if packet.get("type") != TYPE_HANDSHAKE:
        return True # Data packets don't have timestamp in this design
    import time
    return abs(time.time() - packet["timestamp"]) <= window
