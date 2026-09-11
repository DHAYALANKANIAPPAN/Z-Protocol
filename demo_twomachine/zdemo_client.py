# zdemo_client.py
# Z-Protocol Demo Client - Interactive Bidirectional & Fragments

import asyncio
import os
import sys
import time

from zcolors      import log, divider, GREEN, BLUE, AMBER, RED, PURPLE, CYAN, GRAY, RESET, BOLD
from zkem_demo    import client_encapsulate
from zcrypto_demo import encrypt, decrypt
from zpow_demo    import compute_pow, DIFFICULTY
from zpacket_demo import build_handshake_packet, build_data_packet, parse_packet, TYPE_DATA

if len(sys.argv) < 2:
    print(f"{RED}Usage: python3 zdemo_client.py <server_ip> [optional_message]{RESET}")
    sys.exit(1)

SERVER_IP  = sys.argv[1]
SERVER_PORT= 9000
MESSAGE    = sys.argv[2] if len(sys.argv) > 2 else "Hello from Z-Protocol Client!"

divider("Z-PROTOCOL CLIENT STARTING")
print(f"{GREEN}{BOLD}  Role     : CLIENT{RESET}")
print(f"{GREEN}  Server   : {SERVER_IP}:{SERVER_PORT}{RESET}")

try:
    with open("srv_kem.pub",    "rb") as f: srv_kem_pub = f.read()
    with open("srv_x25519.pub", "rb") as f: srv_x_pub   = f.read()
except FileNotFoundError:
    print(f"{RED}Missing server public keys.{RESET}")
    sys.exit(1)

# Handshake
divider("STEP 1 — 0-RTT HANDSHAKE")
log("CLIENT", "KEM", "Running ML-KEM-1024 encapsulation...", AMBER)
session_key, kem_ct, cli_x_pub = client_encapsulate(srv_kem_pub, srv_x_pub)
log("CLIENT", "KEM", f"Session key derived     : {session_key.hex()[:32]}...", GREEN)

session_id = os.urandom(8)
timestamp  = time.time()
log("CLIENT", "POW", "Solving Proof-of-Work to prevent DDoS...", AMBER)
pow_nonce, _, _ = compute_pow(session_id, timestamp)
pow_tok  = pow_nonce + b'\x00' * 24
log("CLIENT", "POW", f"Solved! Nonce : {pow_nonce.hex()}", GREEN)

# Initial payload
log("CLIENT", "ENCRYPT", "Encrypting initial message with AES-256-GCM...", AMBER)
enc_payload = encrypt(session_key, MESSAGE.encode())
payload  = kem_ct + enc_payload

hs_packet = build_handshake_packet(
    session_id, pow_tok, timestamp, srv_kem_pub, cli_x_pub, payload
)
log("CLIENT", "SEND", f"Sending {len(hs_packet)} byte 0-RTT packet to {SERVER_IP}", PURPLE)

FRAG_BUFFERS = {}

class UDPClientProto(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            pkt = parse_packet(data)
        except ValueError:
            return
            
        if pkt['type'] == TYPE_DATA:
            seq_num = pkt["seq_num"]
            f_idx = pkt["frag_index"]
            f_tot = pkt["frag_total"]
            
            if f_tot > 1:
                log("CLIENT", "RECV", f"Received Fragment [{f_idx+1}/{f_tot}] for Sequence {seq_num}", BLUE)
                
            buf_key = seq_num
            if buf_key not in FRAG_BUFFERS:
                FRAG_BUFFERS[buf_key] = {}
            FRAG_BUFFERS[buf_key][f_idx] = pkt["payload"]
            
            if len(FRAG_BUFFERS[buf_key]) == f_tot:
                raw_payload = b""
                for i in range(f_tot):
                    raw_payload += FRAG_BUFFERS[buf_key][i]
                del FRAG_BUFFERS[buf_key]
                
                divider("INCOMING DATA RECEIVED")
                log("CLIENT", "DECRYPT", f"Assembled {f_tot} fragment(s). Total ciphertext size: {len(raw_payload)} bytes", GRAY)
                log("CLIENT", "DECRYPT", "Authenticating and decrypting with AES-256-GCM...", AMBER)
                
                try:
                    plaintext = decrypt(session_key, raw_payload)
                    log("CLIENT", "DECRYPT", "AES-256-GCM auth PASSED!", GREEN)
                    
                    if plaintext.startswith(b"FILE:"):
                        parts = plaintext.split(b":", 2)
                        if len(parts) == 3:
                            filename = parts[1].decode()
                            filedata = parts[2]
                            with open("recv_" + filename, "wb") as f:
                                f.write(filedata)
                            print(f"\n{BLUE}{BOLD}[FILE RECV] Saved large file from Server to: recv_{filename}{RESET}\n")
                    else:
                        print(f"\n{GREEN}{BOLD}[SERVER]: {plaintext.decode()}{RESET}\n")
                except Exception:
                    log("CLIENT", "ERROR", "Failed to decrypt incoming data.", RED)

async def handle_input(transport):
    loop = asyncio.get_running_loop()
    seq_counter = 1000 # Client starts sequences at 1000
    print(f"\n{GREEN}[0-RTT] Initial handshake sent. You are connected!{RESET}")
    print(f"{GRAY}Type your message and press Enter. To send a file, type: /send <path_to_file>{RESET}\n")
    while True:
        msg = await loop.run_in_executor(None, sys.stdin.readline)
        msg = msg.strip()
        if not msg: continue
        
        divider("SENDING MESSAGE")
        if msg.startswith("/send "):
            path = msg[6:].strip()
            if not os.path.exists(path):
                print(f"{RED}File not found: {path}{RESET}")
                continue
            with open(path, "rb") as f:
                file_bytes = f.read()
            payload = f"FILE:{os.path.basename(path)}:".encode() + file_bytes
            log("CLIENT", "ENCRYPT", f"File payload size : {len(payload)} bytes", GRAY)
        else:
            payload = msg.encode()
            log("CLIENT", "ENCRYPT", f"Text payload size : {len(payload)} bytes", GRAY)
            
        log("CLIENT", "ENCRYPT", "Encrypting with AES-256-GCM session key...", AMBER)
        enc_payload = encrypt(session_key, payload)
        log("CLIENT", "ENCRYPT", "Encryption complete. Message is now unreadable.", GREEN)
        
        CHUNK_SIZE = 1000
        fragments = [enc_payload[i:i+CHUNK_SIZE] for i in range(0, len(enc_payload), CHUNK_SIZE)]
        f_tot = len(fragments)
        
        log("CLIENT", "FRAG", f"Splitting encrypted payload into {f_tot} UDP packet(s)", BLUE)
        
        for f_idx, chunk in enumerate(fragments):
            pkt = build_data_packet(session_id, seq_counter, f_idx, f_tot, chunk)
            transport.sendto(pkt, (SERVER_IP, SERVER_PORT))
            
        log("CLIENT", "SEND", f"Sent securely to server via 0-RTT UDP stream!\n", PURPLE)
        seq_counter += 1

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        UDPClientProto,
        remote_addr=(SERVER_IP, SERVER_PORT)
    )
    
    # Send the massive 0-RTT handshake right away
    transport.sendto(hs_packet)
    
    try:
        await handle_input(transport)
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
