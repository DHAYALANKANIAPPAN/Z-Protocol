# Z-PROTOCOL: ZERO-RTT POST-QUANTUM SECURE COMMUNICATION

## TITLE PAGE
**Title:** Z-PROTOCOL: ZERO-RTT POST-QUANTUM SECURE COMMUNICATION
**Submitted by:** [Your Name / Team Names]
**Register Number:** [Your Register Numbers]
**Degree:** BACHELOR OF ENGINEERING in COMPUTER SCIENCE AND ENGINEERING
**College:** [Your College Name]
**University:** [Your University Name]
**Date:** [Month - Year]

---

## BONAFIDE CERTIFICATE
Certified that this project report "Z-PROTOCOL: ZERO-RTT POST-QUANTUM SECURE COMMUNICATION" is the bonafide work of "[Your Name]" who carried out the project work under my supervision.

**SIGNATURE**  
[Guide Name], Assistant Professor  
**SIGNATURE**  
[HOD Name], Head of the Department  

---

## ACKNOWLEDGEMENT
We express our deepest gratitude to our Principal, Head of the Department, and our Project Guide for their continuous encouragement and support throughout the course of study and the development of this project.

---

## ABSTRACT
As global network communications increasingly demand ultra-low latency, traditional security protocols such as TCP/TLS struggle to meet these requirements due to the overhead of multi-step cryptographic handshakes. Furthermore, the foundational security of these protocols relies on classical asymmetric algorithms (e.g., RSA and Elliptic Curve Cryptography), which are acutely vulnerable to the rapidly advancing threat of Cryptographically Relevant Quantum Computers (CRQCs). This project introduces Z-Protocol: a custom, zero-round-trip-time (0-RTT), quantum-resistant secure communication protocol built over UDP. 

Z-Protocol eliminates connection setup delays by encapsulating both the cryptographic key exchange and the encrypted payload within the initial transmission packet. The protocol implements a hybrid cryptographic architecture, combining ML-KEM-1024 (NIST Post-Quantum Cryptography standard) with the battle-tested X25519 elliptic curve. Additionally, Z-Protocol features a custom fragmentation engine for large payloads and a SHA3-512 Proof-of-Work (PoW) mechanism to defend against DDoS attacks.

---

## TABLE OF CONTENTS
1. Introduction
2. Literature Survey
3. System Requirements
4. Proposed Methodology
5. Implementation and Results
6. Conclusion and Future Enhancements
7. References

---

## LIST OF ABBREVIATIONS
* **0-RTT:** Zero Round-Trip Time
* **PQC:** Post-Quantum Cryptography
* **UDP:** User Datagram Protocol
* **TCP:** Transmission Control Protocol
* **TLS:** Transport Layer Security
* **MTU:** Maximum Transmission Unit
* **PoW:** Proof-of-Work
* **NIST:** National Institute of Standards and Technology
* **KEM:** Key Encapsulation Mechanism

---

## CHAPTER 1: INTRODUCTION

### 1.1 INTRODUCTION TO NETWORK SECURITY
In modern network architecture, secure communication is primarily handled by the Transport Layer Security (TLS) protocol running over the Transmission Control Protocol (TCP). While this guarantees ordered, error-checked, and encrypted delivery of data, it requires significant back-and-forth communication (handshakes) before a single byte of application data is securely transmitted. 

### 1.2 NEED FOR LOW-LATENCY AND POST-QUANTUM PROTOCOLS
In high-latency environments (such as satellite communications) or real-time systems (such as autonomous vehicles and IoT sensors), the delay introduced by traditional handshakes is unacceptable. Furthermore, the mathematical foundations of current public-key cryptography (RSA and Elliptic Curves) are theoretically broken by Shor's algorithm running on a sufficiently powerful quantum computer. Threat actors are currently engaging in "Store-Now-Decrypt-Later" (SNDL) attacks—harvesting encrypted traffic today to decrypt it tomorrow when quantum computers become available.

### 1.3 INTRODUCTION TO Z-PROTOCOL
Z-Protocol is a custom cryptographic network protocol designed to solve both the latency and quantum-threat problems. Operating over UDP, it achieves 0-RTT (Zero Round-Trip Time) communication by packing the client's public keys, the ciphertext, and a cryptographic puzzle solution into the very first packet. It utilizes a hybrid approach, securing data with both classical X25519 and post-quantum ML-KEM-1024.

### 1.4 BENEFITS OF Z-PROTOCOL
* **Speed:** Instantaneous encrypted data transmission without handshake overhead.
* **Quantum Resistance:** Immune to future quantum computer attacks via NIST-approved ML-KEM-1024.
* **DDoS Protection:** Built-in Proof-of-Work forces attackers to spend computational resources, protecting the server.

---

## CHAPTER 2: LITERATURE SURVEY

### 2.1 EVOLUTION OF SECURE COMMUNICATION
Historically, secure communication required pre-shared keys. The invention of public-key cryptography (Diffie-Hellman, RSA) allowed secure key exchange over public channels, forming the basis of SSL and TLS. TLS 1.3 introduced a 0-RTT mode, but it relies on a previously established session ticket, meaning the *very first* connection still requires a full handshake.

### 2.2 THE QUANTUM THREAT
Research indicates that CRQCs (Cryptographically Relevant Quantum Computers) will eventually break the discrete logarithm problem. In response, NIST initiated a multi-year competition to standardize Post-Quantum Cryptography (PQC). In 2024, ML-KEM (originally known as CRYSTALS-Kyber) was officially standardized as FIPS 203.

### 2.3 LIMITATIONS OF EXISTING PROTOCOLS
While protocols like WireGuard have popularized modern, UDP-based cryptography (using X25519 and ChaCha20), they are not yet quantum-resistant by default, and adapting them to encapsulate massive 1000+ byte quantum keys introduces severe fragmentation issues. Z-Protocol addresses this by custom-building a fragmentation engine tailored for massive 0-RTT PQC payloads.

---

## CHAPTER 3: SYSTEM REQUIREMENTS

### 3.1 HARDWARE REQUIREMENTS
* **Processor:** Dual-core CPU or higher (Intel/AMD)
* **RAM:** Minimum 4 GB
* **Networking:** Standard Wi-Fi or Ethernet adapter supporting UDP traffic

### 3.2 SOFTWARE REQUIREMENTS
* **Operating System:** Linux (Ubuntu, Kali Linux), macOS, or Windows
* **Programming Language:** Python 3.10+
* **Core Libraries:**
  * `liboqs-python` (Open Quantum Safe library for ML-KEM)
  * `cryptography` (For X25519, AES-256-GCM, and SHA3-512)
  * `scapy` (For packet manipulation and crafting)
  * `asyncio` (For asynchronous network streaming)

---

## CHAPTER 4: PROPOSED METHODOLOGY

### 4.1 DESIGN GOALS
The primary goal is to build a peer-to-peer chat and file-transfer application that is completely invisible to quantum decryption and requires absolutely no connection setup time (0-RTT). 

### 4.2 SYSTEM ARCHITECTURE
The system operates in a Client-Server topology during the initial connection, evolving into full bidirectional peer-to-peer communication.
1. **Server Initialization:** The server generates long-term ML-KEM-1024 and X25519 keypairs and publishes the public keys.
2. **Client 0-RTT Handshake:** The client reads the server's public keys, generates its own ephemeral keypairs, encapsulates a shared secret, and derives a master AES-256-GCM key.
3. **Proof-of-Work (PoW):** The client hashes the packet header with a random Nonce until the SHA3-512 hash begins with a specific prefix (e.g., `0x0000`).
4. **Data Fragmentation:** If the user's message is larger than the UDP MTU (approx 1400 bytes), the payload is fragmented into sequential packets.

### 4.3 PACKET STRUCTURE
The protocol relies on a strict binary structure:
* **Header (26 bytes):** Magic bytes (`0x5A`), Version, Packet Type, Session ID, Timestamp, PoW Nonce, Sequence Number, Fragment Index, Fragment Total.
* **Key Encapsulation (1600 bytes):** Appears only in Type 1 (Handshake) packets. Contains ML-KEM ciphertext and X25519 public key.
* **Payload (Variable):** AES-256-GCM encrypted ciphertext and 16-byte authentication tag.

---

## CHAPTER 5: IMPLEMENTATION AND RESULTS

### 5.1 IMPLEMENTATION DETAILS
The system was implemented in Python using the `asyncio` framework for non-blocking I/O. The `zdemo_server.py` and `zdemo_client.py` scripts act as the terminal interfaces.
* **Cryptography:** The `cryptography.hazmat` primitives were used for AES-GCM and X25519, while the `oqs` wrapper was utilized for ML-KEM-1024.
* **Network Transport:** Python's low-level `socket` library was used to transmit raw UDP datagrams.

### 5.2 EXPERIMENTAL SETUP
The protocol was tested across two distinct machines over a wireless network:
* **Machine A (Server):** Ubuntu 22.04 LTS
* **Machine B (Client):** Kali Linux VM (Bridged Adapter)
The machines communicated over a local subnet (10.72.45.X).

### 5.3 RESULTS AND PERFORMANCE
The implementation successfully demonstrated 0-RTT communication. The client was able to launch the application and immediately transmit an encrypted message within the first network transmission. 
The custom fragmentation engine successfully handled large text files, splitting them into multiple UDP packets and reassembling them on the server side in correct sequential order. 
The PoW mechanism effectively delayed the client by ~0.5 seconds, proving its viability as a rate-limiting Anti-DDoS tool.

---

## CHAPTER 6: CONCLUSION AND FUTURE ENHANCEMENTS

### 6.1 CONCLUSION
The Z-Protocol project successfully proves that combining Post-Quantum Cryptography with Zero-Round-Trip-Time UDP transmission is not only possible but highly effective. By eliminating the multi-step handshake, the protocol dramatically reduces latency. By implementing ML-KEM-1024, the transmitted data is secured against future quantum computing threats.

### 6.2 FUTURE ENHANCEMENTS
* **Forward Secrecy:** Implement a continuous key-ratchet mechanism (similar to the Signal Protocol) so that if a session key is compromised, past and future messages remain secure.
* **Congestion Control:** Implement a packet-loss recovery system (ACKs and Retransmissions) over UDP to ensure reliability on unstable networks.
* **C-Language Port:** Rewrite the core protocol engine in C/Rust for kernel-level integration and maximum performance.

---

## REFERENCES
1. National Institute of Standards and Technology (NIST). (2024). *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*.
2. Langley, A., et al. (2016). *The QUIC Transport Protocol: Design and Internet-Scale Deployment*.
3. Bernstein, D. J. (2006). *Curve25519: New Diffie-Hellman Speed Records*.
4. Dwork, C., & Naor, M. (1992). *Pricing via Processing or Combatting Junk Mail* (Proof of Work concepts).
