# zdemo_server.py
# Z-Protocol Demo Server - Interactive Bidirectional & Fragments

import asyncio
import os
import sys
import time
import struct
import hashlib

from zcolors     import log, divider, GREEN, BLUE, AMBER, RED, PURPLE, CYAN, GRAY, RESET, BOLD
from zkem_demo   import generate_server_keypair, server_decapsulate
from zcrypto_demo import encrypt, decrypt
from zpow_demo   import verify_pow, DIFFICULTY
from zpacket_demo import parse_packet, verify_timestamp, HANDSHAKE_SIZE, TYPE_HANDSHAKE, TYPE_DATA, build_data_packet

PORT = 9000

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

with open("srv_kem.pub",    "wb") as f: f.write(KEYPAIR["kem_pub"])
with open("srv_x25519.pub", "wb") as f: f.write(KEYPAIR["x_pub"])
log("SERVER", "KEYGEN", "Public keys saved → srv_kem.pub, srv_x25519.pub", GREEN)

divider("WAITING FOR CONNECTIONS")

SEEN_NONCES = {}
PACKET_COUNT = 0

# Store active sessions and buffers
SESSIONS = {} # session_id -> (session_key, remote_addr)
FRAG_BUFFERS = {} # (session_id, seq_num) -> {frag_index: payload}

class ZDemoServer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = transport
        print(f"\n{GREEN}{BOLD}[SERVER] Listening on 0.0.0.0:{PORT} — ready to receive packets{RESET}")
        print(f"{GRAY}Type your message and press Enter to broadcast to the last active client.{RESET}")
        print(f"{GRAY}To send a file, type: /send <path_to_file>{RESET}\n")

    def datagram_received(self, data, addr):
        global PACKET_COUNT
        PACKET_COUNT += 1
        
        try:
            pkt = parse_packet(data)
        except ValueError as e:
            return

        sid = pkt['session_id']
        
        if pkt['type'] == TYPE_HANDSHAKE:
            divider(f"HANDSHAKE PACKET FROM {addr[0]}:{addr[1]}")
            if not verify_timestamp(pkt): return
            pow_nonce = pkt["pow_token"][:8]
            valid, _ = verify_pow(pow_nonce, pkt["session_id"], pkt["timestamp"])
            if not valid: return
            
            nonce_hex = pow_nonce.hex()
            if nonce_hex in SEEN_NONCES: return
            SEEN_NONCES[nonce_hex] = time.time()

            kem_ct   = pkt["payload"][:1568]
            enc_data = pkt["payload"][1568:]

            log("SERVER", "KEM", "Running ML-KEM-1024 decapsulation...", AMBER)
            session_key = server_decapsulate(KEYPAIR, kem_ct, pkt["x25519_pubkey"])
            SESSIONS[sid] = (session_key, addr)
            log("SERVER", "KEM", f"Session key derived     : {session_key.hex()[:32]}...", GREEN)
            
            log("SERVER", "DECRYPT", "Decrypting handshake payload...", AMBER)
            try:
                plaintext = decrypt(session_key, enc_data)
                log("SERVER", "DECRYPT", "AES-256-GCM auth PASSED", GREEN)
                print(f"\n{GREEN}[CLIENT {addr[0]}]: {plaintext.decode()}{RESET}")
            except Exception:
                log("SERVER", "ERROR", "Decryption failed!", RED)

        elif pkt['type'] == TYPE_DATA:
            if sid not in SESSIONS: return
            session_key, _ = SESSIONS[sid]
            seq_num = pkt["seq_num"]
            f_idx = pkt["frag_index"]
            f_tot = pkt["frag_total"]
            
            if f_tot > 1:
                log("SERVER", "RECV", f"Received Fragment [{f_idx+1}/{f_tot}] for Sequence {seq_num}", BLUE)
            
            buf_key = (sid, seq_num)
            if buf_key not in FRAG_BUFFERS:
                FRAG_BUFFERS[buf_key] = {}
            FRAG_BUFFERS[buf_key][f_idx] = pkt["payload"]
            
            if len(FRAG_BUFFERS[buf_key]) == f_tot:
                # Reassemble
                raw_payload = b""
                for i in range(f_tot):
                    raw_payload += FRAG_BUFFERS[buf_key][i]
                del FRAG_BUFFERS[buf_key]
                
                divider("INCOMING DATA RECEIVED")
                log("SERVER", "DECRYPT", f"Assembled {f_tot} fragment(s). Total ciphertext size: {len(raw_payload)} bytes", GRAY)
                log("SERVER", "DECRYPT", "Authenticating and decrypting with AES-256-GCM...", AMBER)
                
                try:
                    plaintext = decrypt(session_key, raw_payload)
                    log("SERVER", "DECRYPT", "AES-256-GCM auth PASSED!", GREEN)
                    
                    if plaintext.startswith(b"FILE:"):
                        parts = plaintext.split(b":", 2)
                        if len(parts) == 3:
                            filename = parts[1].decode()
                            filedata = parts[2]
                            with open("recv_" + filename, "wb") as f:
                                f.write(filedata)
                            print(f"\n{BLUE}{BOLD}[FILE RECV] Saved large file to: recv_{filename}{RESET}\n")
                    else:
                        print(f"\n{GREEN}{BOLD}[CLIENT {addr[0]}]: {plaintext.decode()}{RESET}\n")
                except Exception as e:
                    log("SERVER", "ERROR", "Decryption failed on reassembled fragment.", RED)

async def handle_input(transport):
    loop = asyncio.get_running_loop()
    seq_counter = 1
    while True:
        msg = await loop.run_in_executor(None, sys.stdin.readline)
        msg = msg.strip()
        if not msg: continue
        
        if not SESSIONS:
            print(f"{RED}No active clients to send to.{RESET}")
            continue
            
        sid = list(SESSIONS.keys())[-1]
        session_key, addr = SESSIONS[sid]
        
        divider("SENDING MESSAGE")
        if msg.startswith("/send "):
            path = msg[6:].strip()
            if not os.path.exists(path):
                print(f"{RED}File not found: {path}{RESET}")
                continue
            with open(path, "rb") as f:
                file_bytes = f.read()
            payload = f"FILE:{os.path.basename(path)}:".encode() + file_bytes
            log("SERVER", "ENCRYPT", f"File payload size : {len(payload)} bytes", GRAY)
        else:
            payload = msg.encode()
            log("SERVER", "ENCRYPT", f"Text payload size : {len(payload)} bytes", GRAY)
            
        log("SERVER", "ENCRYPT", "Encrypting with AES-256-GCM session key...", AMBER)
        enc_payload = encrypt(session_key, payload)
        log("SERVER", "ENCRYPT", "Encryption complete. Message is now unreadable.", GREEN)
        
        # Fragment logic (max 1000 bytes payload per UDP packet)
        CHUNK_SIZE = 1000
        fragments = [enc_payload[i:i+CHUNK_SIZE] for i in range(0, len(enc_payload), CHUNK_SIZE)]
        f_tot = len(fragments)
        
        log("SERVER", "FRAG", f"Splitting encrypted payload into {f_tot} UDP packet(s)", BLUE)
        
        for f_idx, chunk in enumerate(fragments):
            pkt = build_data_packet(sid, seq_counter, f_idx, f_tot, chunk)
            transport.sendto(pkt, addr)
        
        log("SERVER", "SEND", f"Sent securely to {addr[0]} via 0-RTT UDP stream!\n", PURPLE)
        seq_counter += 1

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        ZDemoServer,
        local_addr=("0.0.0.0", PORT)
    )
    try:
        await handle_input(transport)
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
