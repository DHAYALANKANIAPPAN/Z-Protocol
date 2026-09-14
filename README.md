# Z-Protocol — Post-Quantum Zero-RTT Transport Security Protocol

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![liboqs](https://img.shields.io/badge/liboqs-ML--KEM--1024-green)](https://openquantumsafe.org)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203-orange)](https://csrc.nist.gov/pubs/fips/203/final)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> A custom-built network security protocol that achieves quantum-resistant encryption with **zero round-trip handshake latency** from the very first packet — built on ML-KEM-1024 + X25519 hybrid key exchange over stateless UDP.

---

## What is Z-Protocol

Z-Protocol replaces the TLS handshake with a single UDP packet containing everything needed to establish a quantum-safe encrypted session — key exchange, authentication, and encrypted data — all in one shot.

Standard HTTPS/TLS 1.3 requires at least one round trip before data can flow. Z-Protocol sends the key exchange, proof-of-work authentication token, and encrypted payload all in the very first packet. This is called **0-RTT (zero round-trip time)**.

It is also post-quantum secure — meaning it uses cryptographic algorithms that remain hard to break even with a large-scale quantum computer, unlike the classical algorithms (RSA, ECDSA) securing most of today's internet.

---

## Why Z-Protocol

TLS 1.3, which secures all HTTPS traffic today, has two structural limitations:

| Problem | Impact |
|---------|--------|
| Quantum vulnerability | X25519 and RSA are breakable by Shor's Algorithm on a quantum computer |
| Handshake latency | TLS grows from ~7ms to ~98ms as packet loss increases from 0% to 10% |

Z-Protocol solves both simultaneously: **quantum-resistant + zero handshake overhead + stateless UDP**.

---

## Benchmark Results

| Packet Loss | TLS 1.3 | Z-Protocol | Speed Advantage |
|-------------|---------|------------|-----------------|
| 0% | 7.26ms | 0.25ms | **28.5x faster** |
| 1% | 28.46ms | 0.30ms | **95.7x faster** |
| 5% | 50.91ms | 0.24ms | **210x faster** |
| 10% | ~98.4ms | ~0.26ms | **~378x faster** |

> Z-Protocol latency stays flat across all loss conditions. TLS 1.3 degrades 13x because TCP retransmits lost handshake packets. Z-Protocol on UDP simply has no handshake to lose.

---

## Architecture

```
Client                                          Server
  │                                               │
  │── Single UDP packet ─────────────────────────>│
  │   ┌─────────────────────────────────────┐     │
  │   │ VERSION (1B)                        │     │
  │   │ SESSION ID (8B)                     │     │
  │   │ TIMESTAMP (8B)                      │     │
  │   │ POW TOKEN (32B) ← SHA3-512          │     │
  │   │ ML-KEM-1024 PUBKEY (1568B)          │     │
  │   │ X25519 PUBKEY (32B)                 │     │
  │   │ KEM CIPHERTEXT (1568B)              │     │
  │   │ AES-256-GCM PAYLOAD (variable)      │     │
  │   └─────────────────────────────────────┘     │
  │                                               │
  │<── Encrypted response ────────────────────────│
  │                                               │
```

Total fixed header: **1654 bytes** | Typical first packet: **3294 bytes**

---

## Security Design

### Hybrid Key Exchange (X-Change KEM)

```
x_shared    = X25519(client_private, server_x_public)
kem_shared  = ML-KEM-1024.Decap(server_kem_private, ciphertext)
session_key = HKDF-SHA256(x_shared ∥ kem_shared, info="z-protocol-session-key-v1")
```

Both algorithms must be broken simultaneously to compromise a session.

### Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Quantum resistance | ML-KEM-1024 (NIST FIPS 203) | ✅ |
| Classical security | X25519 hybrid | ✅ |
| Forward secrecy | Double Ratchet per-message keys | ✅ |
| DDoS resistance | SHA3-512 proof-of-work | ✅ |
| Replay prevention | Nonce registry + 30s timestamp window | ✅ |
| Data integrity | AES-256-GCM authenticated encryption | ✅ |

---

## Project Structure

```
secure_protocol_project/
├── phase1/                  # Environment and baseline
│   ├── verify_kem.py        # Confirms ML-KEM-1024 works
│   ├── tls_server.py        # TLS 1.3 baseline server
│   ├── tls_client.py        # TLS 1.3 baseline client
│   ├── capture_baseline.py  # Scapy PCAP capture
│   ├── kem_benchmark.py     # X25519 vs ML-KEM-1024 speed
│   └── tls13_baseline.pcap  # Captured handshake evidence
│
├── phase2/                  # Core protocol engine
│   ├── zpacket.py           # Binary packet builder and parser
│   ├── zkem.py              # Hybrid KEM module
│   ├── zcrypto.py           # AES-256-GCM encryption
│   ├── zserver.py           # asyncio UDP server
│   └── zclient.py           # UDP client
│
├── phase3/                  # Resilience layer
│   ├── zpow.py              # SHA3-512 proof-of-work
│   ├── zratchet.py          # Double Ratchet forward secrecy
│   ├── zreplay.py           # Replay attack filter
│   ├── zsession.py          # Session state manager
│   ├── zserver_v2.py        # Hardened server
│   └── zclient_v2.py        # Hardened client
│
├── phase4/                  # Evaluation and documentation
│   ├── znetem.py            # tc-netem network stress test
│   ├── zcharts.py           # Benchmark chart generator
│   ├── zspec.md             # IETF-style protocol specification
│   ├── zlimitations.md      # Limitations and future work
│   └── charts/              # Generated PNG benchmark charts
│
└── browser/                 # Live browser demonstration
    ├── z_server_proxy.py    # Z-Protocol proxy + stats API
    ├── z_client_proxy.py    # Browser-facing TCP proxy
    └── index.html           # Live monitoring dashboard
```

---

## Installation

### 1. System dependencies

```bash
sudo apt update
sudo apt install -y build-essential cmake gcc ninja-build \
  libssl-dev python3-dev python3-pip git
```

### 2. Build liboqs from source

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
cd ../..
```

### 3. Install Python wrapper

```bash
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
pip3 install . --break-system-packages
cd ..
```

### 4. Install additional dependencies

```bash
pip3 install cryptography scapy matplotlib aiohttp --break-system-packages
```

### 5. Verify installation

```bash
python3 -c "import oqs; kem = oqs.KeyEncapsulation('ML-KEM-1024'); pk = kem.generate_keypair(); print(f'ML-KEM-1024 working — pubkey: {len(pk)} bytes')"
```

Expected: `ML-KEM-1024 working — pubkey: 1568 bytes`

---

## Quick Start

### Run Phase 2 — core protocol (two terminals)

```bash
# Terminal 1 — server
cd phase2
python3 zserver.py

# Terminal 2 — client
cd phase2
python3 zclient.py
```

### Run Phase 3 — hardened protocol (two terminals)

```bash
# Terminal 1
cd phase3
python3 zserver_v2.py

# Terminal 2
cd phase3
python3 zclient_v2.py
```

### Run live browser demonstration (three terminals)

```bash
# Terminal 1 — web server
cd browser
python3 -m http.server 8080

# Terminal 2 — Z-Protocol server
cd browser
python3 z_server_proxy.py

# Terminal 3 — browser proxy
cd browser
python3 z_client_proxy.py
```

Then in Firefox: Settings → Network Settings → Manual proxy → HTTP: `127.0.0.1` Port: `9999` → navigate to `http://127.0.0.1:8080`

---

## Running Benchmarks

```bash
cd phase4

# Network stress test (requires sudo for tc-netem)
sudo python3 znetem.py

# Generate charts
python3 zcharts.py

# View results
cat netem_results.json
```

---

## How It Works — Key Exchange

Neither side ever transmits the session key. Both sides independently derive the same key:

```
Server generates:  ML-KEM-1024 keypair + X25519 keypair (done once at startup)
Client receives:   Server's public keys (from server_kem.pub, server_x25519.pub)

Client computes:
  kem_ct, kem_shared = ML-KEM-1024.encap(server_kem_public)
  x_shared = X25519(client_private, server_x_public)
  session_key = HKDF(kem_shared + x_shared)

Server computes:
  kem_shared = ML-KEM-1024.decap(client_kem_ciphertext)
  x_shared = X25519(server_private, client_x_public)
  session_key = HKDF(kem_shared + x_shared)

Result: identical session_key on both sides — key never crossed the network
```

---

## Captured Evidence

All claims in this repository are backed by real packet captures:

- `phase1/tls13_baseline.pcap` — 30 TCP packets for one TLS 1.3 page load
- `browser/zproof_single_packet.pcap` — 2 UDP packets for one Z-Protocol request
- Plain HTTP capture shows `GET /index.html HTTP/1.1` in readable ASCII
- Z-Protocol capture shows only `ZP` magic bytes followed by pure ciphertext

---

## Limitations

| Limitation | Details |
|------------|---------|
| Python overhead | Numbers reflect architectural comparison; native C implementation would be faster in absolute terms |
| MTU fragmentation | 3294-byte first packet exceeds 1500-byte standard MTU — fragments on real networks |
| No congestion control | Raw UDP — no built-in rate limiting or retransmission |
| In-memory nonce store | Replay filter stores nonces in process memory |

---

## Future Work

- C implementation using native liboqs bindings (10–50x absolute speed improvement)
- Path MTU Discovery to avoid IP fragmentation
- QUIC-style congestion control integration
- Formal verification using ProVerif or Tamarin Prover
- Multi-device real-network testing across physical hardware

---

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (2024)
2. RFC 8446 — TLS Protocol Version 1.3
3. RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
4. Marlinspike, M. — The Double Ratchet Algorithm, Signal (2016)
5. Open Quantum Safe Project — liboqs, github.com/open-quantum-safe

---

## Environment

- **OS:** Kali Linux
- **Python:** 3.11+
- **liboqs:** 0.16.0
- **Key algorithm:** ML-KEM-1024 (NIST FIPS 203)
- **Symmetric cipher:** AES-256-GCM
- **Transport:** Raw UDP (asyncio DatagramProtocol)
