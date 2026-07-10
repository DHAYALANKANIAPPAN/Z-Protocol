# Z-Protocol: A Post-Quantum Zero-RTT Transport Security Protocol
## Draft Specification v1.0

---

## Abstract

Z-Protocol is a UDP-based transport security protocol designed to achieve
quantum-resistant encryption with zero visible handshake latency from the
first packet. It combines ML-KEM-1024 and X25519 in a hybrid key
encapsulation mechanism (KEM), AES-256-GCM stream encryption, a
Double Ratchet forward secrecy mechanism, and a SHA3-512 proof-of-work
DDoS mitigation layer — all delivered in a single monolithic first packet.

---

## 1. Protocol Overview

### 1.1 Goals
- G1: Quantum-resistant session key establishment
- G2: Zero round-trip handshake latency (0-RTT)
- G3: Forward secrecy via per-message key rotation
- G4: DDoS resistance via stateless proof-of-work
- G5: Replay attack prevention via nonce registry

### 1.2 Non-Goals
- Congestion control (delegated to application layer)
- Reliable delivery (application responsibility)
- NAT traversal

---

## 2. Packet Structure

Every Z-Protocol packet has the following binary layout: 0                   1                   2                   3

0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|    VERSION    |  PACKET TYPE  |                               |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +

|                    SESSION ID (8 bytes)                       |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    TIMESTAMP  (8 bytes / double)              |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    POW TOKEN  (32 bytes)                      |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    ML-KEM-1024 PUBLIC KEY (1568 bytes)        |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    X25519 PUBLIC KEY (32 bytes)               |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    PAYLOAD LENGTH (4 bytes)                   |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    PAYLOAD (variable)                         |

|         [ KEM ciphertext (1568B) + encrypted data ]          |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+[200~Total fixed header size: 1654 bytes
Typical first packet size: 3294 bytes

### 2.1 Field Definitions

| Field          | Size     | Description                              |
|----------------|----------|------------------------------------------|
| VERSION        | 1 byte   | Protocol version. Current: 0x01          |
| PACKET_TYPE    | 1 byte   | 0x01=handshake, 0x02=data               |
| SESSION_ID     | 8 bytes  | Random per-connection identifier         |
| TIMESTAMP      | 8 bytes  | Unix timestamp (IEEE 754 double)         |
| POW_TOKEN      | 32 bytes | SHA3-512 proof-of-work nonce + padding   |
| KEM_PUBKEY     | 1568 bytes| ML-KEM-1024 server public key           |
| X25519_PUBKEY  | 32 bytes | X25519 server public key                 |
| PAYLOAD_LEN    | 4 bytes  | Length of payload in bytes               |
| PAYLOAD        | variable | KEM ciphertext + AES-GCM encrypted data  |

---

## 3. Cryptographic Specification

### 3.1 Hybrid Key Exchange (X-Change KEM)

Session key derivation uses a hybrid of classical and post-quantum KEMs:~x_shared    = X25519(client_priv, server_x_pub)

kem_shared  = ML-KEM-1024.Decap(server_kem_priv, kem_ciphertext)

combined    = x_shared || kem_shared

session_key = HKDF-SHA256(combined, info="z-protocol-session-key-v1", len=32)
Security property: Session key is secure if either X25519 OR ML-KEM-1024
remains unbroken. Provides classical and post-quantum security simultaneously.

### 3.2 Stream Encryption

All payload data is encrypted with AES-256-GCM:nonce      = RANDOM(12 bytes)

ciphertext = AES-256-GCM.Encrypt(session_key, nonce, plaintext)

wire_data  = nonce || ciphertext### 3.3 Double Ratchet Forward Secrecy

Per-message keys are derived by advancing a chain key:msg_key    = HKDF(chain_key, info="z-protocol-msg-key")

chain_key  = HKDF(chain_key, info="z-protocol-chain-advance")Property: Compromise of msg_key_N does not reveal msg_key_1..N-1.

### 3.4 Proof-of-Work DDoS Mitigation

Client must find nonce such that:SHA3-512(nonce || session_id || timestamp)[:2] == 0x0000Server verifies in O(1) before any KEM operation. Invalid PoW → packet dropped.

---

## 4. Server Processing State MachineIDLE

│

▼

RECEIVE PACKET

│

├─ timestamp invalid?  ──► DROP

│

├─ PoW invalid?        ──► DROP

│

├─ nonce replayed?     ──► DROP

│

▼

DECAPSULATE KEM

│

▼

DERIVE SESSION KEY

│

▼

DECRYPT PAYLOAD

│

▼

SEND ACK ──► IDLE---

## 5. Security Analysis

### 5.1 Threat Model
- Adversary with quantum computer (breaks X25519, RSA, classical DH)
- Network-level DDoS attacker
- Passive eavesdropper recording all traffic
- Replay attacker resending captured packets

### 5.2 Security Properties

| Property              | Mechanism                    | Status  |
|-----------------------|------------------------------|---------|
| Quantum resistance    | ML-KEM-1024 hybrid KEM       | Achieved|
| Forward secrecy       | Double Ratchet chain keys    | Achieved|
| DDoS resistance       | SHA3-512 PoW difficulty=2    | Achieved|
| Replay prevention     | Nonce registry + 30s window  | Achieved|
| 0-RTT latency         | Monolithic first packet      | Achieved|

---

## 6. Implementation Notes

### 6.1 MTU Fragmentation
Z-Protocol's 3294-byte first packet exceeds IPv4 MTU (1500 bytes) and will
fragment across 3 IP packets. Future work: PMTUD support and key compression.

### 6.2 Python Prototype Limitations
This implementation is a research prototype in Python. Performance numbers
reflect architectural overhead, not absolute throughput. A C implementation
using liboqs native bindings is expected to show 10-50x latency improvement.

### 6.3 Replay Window
The 30-second timestamp window represents a tradeoff between replay security
and clock skew tolerance. Production deployment should use NTP synchronization.

---

## 7. Comparison with Existing Protocols

| Feature              | TLS 1.3    | QUIC       | Z-Protocol |
|----------------------|------------|------------|------------|
| Quantum safe         | No         | No         | Yes        |
| 0-RTT first packet   | Optional   | Yes        | Yes        |
| Forward secrecy      | Yes        | Yes        | Yes        |
| DDoS PoW filter      | No         | No         | Yes        |
| Transport layer      | TCP        | UDP        | UDP        |
| Handshake RTTs       | 1          | 0-1        | 0          |

---

## 8. References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. RFC 8446 — TLS Protocol Version 1.3
3. RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
4. Marlinspike, M. — The Double Ratchet Algorithm, Signal, 2016
5. Open Quantum Safe Project — liboqs v0.10, github.com/open-quantum-safe
