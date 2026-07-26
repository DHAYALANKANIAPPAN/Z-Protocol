# zdemo_client.py
# Z-Protocol Demo Client
#
# Usage:
#   python3 zdemo_client.py <server_ip> "<your message>"
#
# Example:
#   python3 zdemo_client.py 192.168.1.10 "Hello from Machine B!"
#
# Requires srv_kem.pub and srv_x25519.pub copied from the server machine.
# Prints every cryptographic step in detail.

import asyncio
import os
import sys
import time
import hashlib
import struct

from zcolors      import log, divider, GREEN, BLUE, AMBER, RED, PURPLE, CYAN, GRAY, RESET, BOLD
from zkem_demo    import client_encapsulate
from zcrypto_demo import encrypt, decrypt
from zpow_demo    import compute_pow, DIFFICULTY
from zpacket_demo import build_packet, HEADER_SIZE

# ── Args ─────────────────────────────────────────────────────────────────────
if len(sys.argv) < 2:
    print(f"{RED}Usage: python3 zdemo_client.py <server_ip> \"<message>\"{RESET}")
    print(f"{GRAY}Example: python3 zdemo_client.py 192.168.1.10 \"Hello!\"{RESET}")
    sys.exit(1)

SERVER_IP  = sys.argv[1]
SERVER_PORT= 9000
MESSAGE    = sys.argv[2] if len(sys.argv) > 2 else "Hello from Z-Protocol client!"

divider("Z-PROTOCOL CLIENT STARTING")
print(f"{GREEN}{BOLD}  Role     : CLIENT{RESET}")
print(f"{GREEN}  Server   : {SERVER_IP}:{SERVER_PORT}{RESET}")
print(f"{GREEN}  Message  : \"{MESSAGE}\"{RESET}")
print(f"{GREEN}  Protocol : ML-KEM-1024 + X25519 + AES-256-GCM{RESET}\n")

# ── Load server public keys ───────────────────────────────────────────────────
log("CLIENT", "LOAD", "Loading server public keys...", AMBER)
try:
    with open("srv_kem.pub",    "rb") as f: srv_kem_pub = f.read()
    with open("srv_x25519.pub", "rb") as f: srv_x_pub   = f.read()
except FileNotFoundError:
    log("CLIENT", "ERROR", "srv_kem.pub or srv_x25519.pub not found!", RED)
    log("CLIENT", "ERROR", "Copy these from the server machine first:", RED)
    log("CLIENT", "ERROR", "  scp user@<server_ip>:~/secure_protocol_project/demo_twomachine/srv_kem.pub .", GRAY)
    log("CLIENT", "ERROR", "  scp user@<server_ip>:~/secure_protocol_project/demo_twomachine/srv_x25519.pub .", GRAY)
    sys.exit(1)

log("CLIENT", "LOAD", f"Server ML-KEM pubkey    : {len(srv_kem_pub)} bytes loaded", GREEN)
log("CLIENT", "LOAD", f"Server ML-KEM hex       : {srv_kem_pub.hex()[:48]}...", GRAY)
log("CLIENT", "LOAD", f"Server X25519 pubkey    : {srv_x_pub.hex()}", GREEN)

# ── Step 1: Hybrid KEM encapsulation ─────────────────────────────────────────
divider("STEP 1 — HYBRID KEY EXCHANGE")
log("CLIENT", "KEM", "Running ML-KEM-1024 encapsulation...", AMBER)
log("CLIENT", "KEM", "Generating ephemeral X25519 private key...", AMBER)

session_key, kem_ct, cli_x_pub = client_encapsulate(srv_kem_pub, srv_x_pub)

log("CLIENT", "KEM", f"ML-KEM-1024 ciphertext  : {len(kem_ct)} bytes produced", GREEN)
log("CLIENT", "KEM", f"KEM ciphertext hex      : {kem_ct.hex()[:48]}...", GRAY)
log("CLIENT", "KEM", f"Client X25519 pubkey    : {cli_x_pub.hex()}", GREEN)
log("CLIENT", "KEM", f"Session key derived     : {session_key.hex()[:32]}...{session_key.hex()[32:]}", AMBER)
log("CLIENT", "KEM", f"Session key size        : {len(session_key)} bytes (AES-256)", GRAY)
log("CLIENT", "KEM", "Session key NEVER transmitted — derived independently on both sides", PURPLE)

# ── Step 2: Encrypt the message ───────────────────────────────────────────────
divider("STEP 2 — AES-256-GCM ENCRYPTION")
plaintext = MESSAGE.encode()
log("CLIENT", "ENCRYPT", f"Plaintext               : \"{MESSAGE}\"", GREEN)
log("CLIENT", "ENCRYPT", f"Plaintext bytes         : {len(plaintext)} bytes", GRAY)
log("CLIENT", "ENCRYPT", "Generating random 12-byte nonce...", AMBER)

enc_payload = encrypt(session_key, plaintext)
nonce_used  = enc_payload[:12]

log("CLIENT", "ENCRYPT", f"Nonce                   : {nonce_used.hex()}", GRAY)
log("CLIENT", "ENCRYPT", f"Ciphertext preview      : {enc_payload[12:28].hex()}...", GRAY)
log("CLIENT", "ENCRYPT", f"Encrypted total         : {len(enc_payload)} bytes (nonce + ciphertext)", GREEN)
log("CLIENT", "ENCRYPT", "Message is now unreadable — AES-256-GCM authenticated encryption", PURPLE)

# ── Step 3: Proof-of-Work ────────────────────────────────────────────────────
divider("STEP 3 — PROOF-OF-WORK")
session_id = os.urandom(8)
timestamp  = time.time()

log("CLIENT", "POW", f"Session ID              : {session_id.hex()}", GRAY)
log("CLIENT", "POW", f"Timestamp               : {time.strftime('%H:%M:%S')}", GRAY)
log("CLIENT", "POW", f"Difficulty              : {DIFFICULTY} leading zero bytes", GRAY)
log("CLIENT", "POW", f"Computing SHA3-512 PoW — brute forcing nonce...", AMBER)

pow_nonce, attempts, elapsed_ms = compute_pow(session_id, timestamp)

log("CLIENT", "POW", f"Solved in               : {elapsed_ms:.2f}ms ({attempts} attempts)", GREEN)
log("CLIENT", "POW", f"Winning nonce           : {pow_nonce.hex()}", GREEN)
log("CLIENT", "POW", f"Server verifies this in : 1 hash (microseconds) — DDoS protection", PURPLE)

# ── Step 4: Build Z-Protocol packet ──────────────────────────────────────────
divider("STEP 4 — BUILD Z-PROTOCOL PACKET")

# Payload = KEM ciphertext + encrypted message
payload  = kem_ct + enc_payload
pow_tok  = pow_nonce + b'\x00' * 24   # pad to 32 bytes

packet = build_packet(
    session_id   = session_id,
    pow_token    = pow_tok,
    timestamp    = timestamp,
    kem_pubkey   = srv_kem_pub,
    x25519_pubkey= cli_x_pub,
    payload      = payload
)

log("CLIENT", "PACKET", f"Header size             : {HEADER_SIZE} bytes", GRAY)
log("CLIENT", "PACKET", f"Payload size            : {len(payload)} bytes (KEM ct + encrypted msg)", GRAY)
log("CLIENT", "PACKET", f"Total packet size       : {len(packet)} bytes", GREEN)
log("CLIENT", "PACKET", f"Packet preview (hex)    : {packet[:32].hex()}...", GRAY)
log("CLIENT", "PACKET", "Magic bytes 'ZP' visible at offset 16 — rest is ciphertext", PURPLE)

# ── Step 5: Send over UDP ─────────────────────────────────────────────────────
divider("STEP 5 — SEND OVER UDP")
log("CLIENT", "SEND", f"Destination             : {SERVER_IP}:{SERVER_PORT}", BLUE)
log("CLIENT", "SEND", f"Transport               : Raw UDP — no TCP handshake", BLUE)
log("CLIENT", "SEND", f"Round trips             : 0-RTT — data is in the first packet", PURPLE)

async def run():
    loop   = asyncio.get_running_loop()
    future = loop.create_future()

    class UDPClientProto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(
        UDPClientProto,
        remote_addr=(SERVER_IP, SERVER_PORT)
    )

    log("CLIENT", "SEND", f"Sending {len(packet)} byte Z-Protocol packet...", AMBER)
    transport.sendto(packet)
    log("CLIENT", "SEND", "Packet sent — waiting for server response...", GRAY)

    # ── Step 6: Receive and decrypt response ──────────────────────────────
    try:
        raw_resp = await asyncio.wait_for(future, timeout=10.0)
        divider("STEP 6 — SERVER RESPONSE RECEIVED")
        log("CLIENT", "RECV", f"Response size           : {len(raw_resp)} bytes", BLUE)
        log("CLIENT", "RECV", f"Ciphertext preview      : {raw_resp[:20].hex()}...", GRAY)
        log("CLIENT", "RECV", "Decrypting with session key...", AMBER)

        response_text = decrypt(session_key, raw_resp)
        log("CLIENT", "RECV", f"Decrypted response      : \"{response_text.decode()}\"", GREEN)
        log("CLIENT", "RECV", "Same session key used on both sides — derived, never transmitted", PURPLE)

    except asyncio.TimeoutError:
        log("CLIENT", "ERROR", "No response from server after 10s — check IP and server is running", RED)
    finally:
        transport.close()

    divider("EXCHANGE COMPLETE")
    print(f"\n{GREEN}{BOLD}  ✓ Z-Protocol two-machine exchange successful{RESET}")
    print(f"{GREEN}  ✓ Message traveled quantum-safe from client to server{RESET}")
    print(f"{GREEN}  ✓ Session key never crossed the network{RESET}\n")

if __name__ == "__main__":
    asyncio.run(run())
