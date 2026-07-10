# Z-Protocol — Limitations and Future Work

## Current Limitations

### L1: Python Interpreter Overhead
All benchmark numbers in this study reflect Python 3.13 interpreter overhead.
CPython's GIL and dynamic dispatch add approximately 5-20x latency compared
to equivalent C implementations. Performance numbers should be read as
architectural comparisons, not absolute throughput claims.

### L2: MTU Fragmentation
Z-Protocol's 3294-byte first packet exceeds standard IPv4 MTU (1500 bytes).
This causes IP-layer fragmentation into 3 fragments, adding reassembly overhead
on the receiver side. Future work should explore key compression or PMTUD.

### L3: No Congestion Control
Z-Protocol operates over raw UDP with no congestion control mechanism.
Production deployment would require integration with a congestion control
algorithm such as CUBIC or BBR, or deployment on top of QUIC.

### L4: In-Memory Nonce Registry
The replay filter stores nonces in process memory. Under sustained high
load, memory growth could become an issue. Production systems should use
a time-bucketed bloom filter or Redis-backed nonce store.

### L5: Single-Threaded Server
The asyncio event loop is single-threaded. Multi-core servers would need
worker process pools (via multiprocessing) to fully utilize hardware.

## Future Work

### F1: C Implementation
Reimplement Z-Protocol core in C using liboqs native API.
Expected improvement: 10-50x latency reduction for KEM operations.

### F2: PMTUD Support
Implement Path MTU Discovery to avoid IP fragmentation on constrained links.

### F3: Fragmentation-Aware Packet Design
Compress ML-KEM-1024 public key using structured lattice compression
to reduce first-packet size below 1500 bytes.

### F4: Congestion Control Integration
Integrate QUIC's loss detection and congestion control algorithms
while preserving Z-Protocol's 0-RTT KEM design.

### F5: Formal Verification
Apply ProVerif or Tamarin Prover to formally verify Z-Protocol's
security properties against a symbolic adversary model.
