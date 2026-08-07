# zdemo_server.py
# Z-Protocol Demo Server
#
# Usage:
#   python3 zdemo_server.py
#
# This machine becomes the SERVER.
# It generates keypairs, saves public keys, and listens for Z-Protocol packets.
# Every cryptographic step is printed in detail so both sides are fully visible.
#
# The other machine (client) needs:
#   - srv_kem.pub     (copy with scp or USB)
#   - srv_x25519.pub  (copy with scp or USB)
# Then runs: python3 zdemo_client.py <this_machine_ip>

import asyncio
import os
import time
import struct
import hashlib

from zcolors     import log, divider, GREEN, BLUE, AMBER, RED, PURPLE, CYAN, GRAY, RESET, BOLD
from zkem_demo   import generate_server_keypair, server_decapsulate
from zcrypto_demo import encrypt, decrypt
from zpow_demo   import verify_pow, DIFFICULTY
from zpacket_demo import parse_packet, verify_timestamp, HEADER_SIZE

PORT = 9000

# ── Generate server keypairs ─────────────────────────────────────────────────
divider("Z-PROTOCOL SERVER STARTING")
print(f"{CYAN}{BOLD}  Role     : SERVER{RESET}")
print(f"{CYAN}  Port     : UDP {PORT}{RESET}")
print(f"{CYAN}  Protocol : ML-KEM-1024 + X25519 + AES-256-GCM{RESET}\n")

log("SERVER", "KEYGEN", "Generating ML-KEM-1024 keypair...", AMBER)
KEYPAIR = generate_server_keypair()
log("SERVER", "KEYGEN", f"ML-KEM-1024 public key  : {len(KEYPAIR['kem_pub'])} bytes", GREEN)
log("SERVER", "KEYGEN", f"ML-KEM-1024 pubkey hex  : {KEYPAIR['kem_pub'].hex()[:48]}...", GRAY)

log("SERVER", "KEYGEN", "Generating X25519 keypair...", AMBER)
log("SERVER", "KEYGEN", f"X25519 public key       : {KEYPAIR['x_pub'].hex()}", GREEN)

# Save public keys for client to use
with open("srv_kem.pub",    "wb") as f: f.write(KEYPAIR["kem_pub"])
with open("srv_x25519.pub", "wb") as f: f.write(KEYPAIR["x_pub"])
log("SERVER", "KEYGEN", "Public keys saved → srv_kem.pub, srv_x25519.pub", GREEN)
log("SERVER", "KEYGEN", "Copy these files to the CLIENT machine before running zdemo_client.py", PURPLE)

divider("WAITING FOR CONNECTIONS")

# Track seen nonces for replay protection
SEEN_NONCES = {}
PACKET_COUNT = 0

class ZDemoServer(asyncio.DatagramProtocol):

    def connection_made(self, transport):
        self.transport = transport
        print(f"\n{GREEN}{BOLD}[SERVER] Listening on 0.0.0.0:{PORT} — ready to receive Z-Protocol packets{RESET}\n")

    def datagram_received(self, data, addr):
        global PACKET_COUNT
        PACKET_COUNT += 1
        divider(f"PACKET #{PACKET_COUNT} FROM {addr[0]}:{addr[1]}")

        # ── Step 1: Parse header ──────────────────────────────────────────
        log("SERVER", "PARSE", f"Raw bytes received      : {len(data)} bytes", BLUE)
        log("SERVER", "PARSE", f"Fixed header size       : {HEADER_SIZE} bytes", GRAY)

        try:
            pkt = parse_packet(data)
        except ValueError as e:
            log("SERVER", "DROP", f"Packet too short — {e}", RED); return

        log("SERVER", "PARSE", f"Version                 : {pkt['version']}", GRAY)
        log("SERVER", "PARSE", f"Packet type             : {pkt['type']} (1=handshake)", GRAY)
        log("SERVER", "PARSE", f"Session ID              : {pkt['session_id'].hex()}", GRAY)
        log("SERVER", "PARSE", f"Timestamp               : {time.strftime('%H:%M:%S', time.localtime(pkt['timestamp']))}", GRAY)

        # ── Step 2: Timestamp check ───────────────────────────────────────
        age = abs(time.time() - pkt["timestamp"])
        if not verify_timestamp(pkt):
            log("SERVER", "DROP", f"Timestamp expired ({age:.1f}s old > 30s window) — DROP", RED)
            return
        log("SERVER", "TIMESTAMP", f"Valid — packet age {age:.3f}s (within 30s window)", GREEN)

        # ── Step 3: PoW verification ──────────────────────────────────────
        pow_nonce = pkt["pow_token"][:8]
        valid, hash_prefix = verify_pow(pow_nonce, pkt["session_id"], pkt["timestamp"])
        if not valid:
            log("SERVER", "DROP", f"Proof-of-Work invalid — DROP (no KEM attempted)", RED)
            return
        log("SERVER", "POW", f"Valid — SHA3-512 prefix : 0x{hash_prefix}", GREEN)
        log("SERVER", "POW", f"Nonce                   : {pow_nonce.hex()}", GRAY)
        log("SERVER", "POW", f"Server CPU cost         : 1 hash (O(1)) — DDoS protected", GRAY)

        # ── Step 4: Replay check ──────────────────────────────────────────
        nonce_hex = pow_nonce.hex()
        if nonce_hex in SEEN_NONCES:
            log("SERVER", "DROP", f"REPLAY DETECTED — nonce already seen — DROP", RED)
            return
        SEEN_NONCES[nonce_hex] = time.time()
        # evict old nonces
        now = time.time()
        expired = [n for n, t in SEEN_NONCES.items() if now - t > 30]
        for n in expired: del SEEN_NONCES[n]
        log("SERVER", "REPLAY", f"Nonce fresh — registered in replay filter", GREEN)
        log("SERVER", "REPLAY", f"Active nonces tracked   : {len(SEEN_NONCES)}", GRAY)

        # ── Step 5: KEM decapsulation ─────────────────────────────────────
        log("SERVER", "KEM", "Running ML-KEM-1024 decapsulation...", AMBER)
        kem_ct   = pkt["payload"][:1568]
        enc_data = pkt["payload"][1568:]
        log("SERVER", "KEM", f"KEM ciphertext size     : {len(kem_ct)} bytes", GRAY)

        session_key = server_decapsulate(
            KEYPAIR, kem_ct, pkt["x25519_pubkey"]
        )
        log("SERVER", "KEM", f"ML-KEM-1024 decap       : shared secret recovered", GREEN)
        log("SERVER", "KEM", f"X25519 exchange         : shared secret recovered", GREEN)
        log("SERVER", "KEM", f"HKDF combined           : session key derived", GREEN)
        log("SERVER", "KEM", f"Session key             : {session_key.hex()[:32]}...{session_key.hex()[32:]}", AMBER)
        log("SERVER", "KEM", f"Session key size        : {len(session_key)} bytes (AES-256)", GRAY)

        # ── Step 6: Decrypt ───────────────────────────────────────────────
        log("SERVER", "DECRYPT", f"Encrypted payload size  : {len(enc_data)} bytes", BLUE)
        log("SERVER", "DECRYPT", f"Nonce (first 12B)       : {enc_data[:12].hex()}", GRAY)
        log("SERVER", "DECRYPT", f"Ciphertext preview      : {enc_data[12:28].hex()}...", GRAY)

        try:
            plaintext = decrypt(session_key, enc_data)
        except Exception:
            log("SERVER", "DROP", "AES-GCM authentication FAILED — tampered packet — DROP", RED)
            return

        log("SERVER", "DECRYPT", f"AES-256-GCM auth        : PASSED", GREEN)
        log("SERVER", "DECRYPT", f"Plaintext recovered     : \"{plaintext.decode()}\"", GREEN)

        # ── Step 7: Send encrypted response ──────────────────────────────
        response = f"[SERVER ACK] Message received securely from {addr[0]} — Z-Protocol working!".encode()
        enc_resp = encrypt(session_key, response)
        self.transport.sendto(enc_resp, addr)
        log("SERVER", "SEND", f"Response encrypted      : {len(enc_resp)} bytes sent back", GREEN)
        log("SERVER", "SEND", f"Response plaintext      : \"{response.decode()}\"", GRAY)

        divider(f"PACKET #{PACKET_COUNT} COMPLETE")
        print(f"\n{GREEN}{BOLD}  ✓ Full Z-Protocol exchange successful{RESET}\n")

async def main():
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        ZDemoServer,
        local_addr=("0.0.0.0", PORT)
    )
    try:
        await asyncio.sleep(86400)
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
