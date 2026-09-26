import asyncio
import sys
import os
import time
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zcrypto_demo import *
from zkem_demo import *
from zpacket_demo import *
from zpow_demo import *

# --- UI DASHBOARD STATE ---
METRICS = {
    "role": "NONE",
    "target": "NONE",
    "status": "WAITING...",
    "enc_time": 0,
    "pow_time": 0,
    "loss_rate": "20",
    "retries": 0,
    "rtt": 0
}
MESSAGES = []

def draw_ui():
    os.system('clear')
    print("=" * 70)
    print("                Z-PROTOCOL INTERACTIVE DASHBOARD")
    print("-" * 70)
    print(f" Role: {METRICS['role']:<15} | Target: {METRICS['target']}")
    print(f" Status: {METRICS['status']:<13} | Mode: 0-RTT ML-KEM + X25519")
    print("-" * 70)
    print(f" Encryption Time : {METRICS['enc_time']:.2f} ms")
    print(f" PoW Mining Time : {METRICS['pow_time']:.2f} ms")
    print(f" Simulated Loss  : {METRICS['loss_rate']}%")
    print(f" Retransmissions : {METRICS['retries']}")
    print(f" Latency (RTT)   : {METRICS['rtt']:.2f} ms")
    print("=" * 70)
    print(" Chat Log:")
    for msg in MESSAGES[-12:]:
        print(f" {msg}")
    print("=" * 70)
    print("Type a message (or 'exit') and press Enter:")
    sys.stdout.flush()

# --- NETWORKING ---
class ZProtocolInteractive(asyncio.DatagramProtocol):
    def __init__(self, is_server=False):
        self.is_server = is_server
        self.transport = None
        
        # In a real app, client would read server's public key from a file/DNS.
        # For this demo, we generate it on both sides and just pretend they know it,
        # or we could just use dummy keys. Let's make sure the client reads the server keys
        # if they exist, else generate them.
        self.keypair = generate_server_keypair()
        
        self.session_key = None
        self.target_addr = None
        self.last_send_time = 0

    def connection_made(self, transport):
        self.transport = transport
        if self.is_server:
            METRICS['status'] = "LISTENING"
            MESSAGES.append("[*] Server started. Waiting for 0-RTT Handshake...")
        else:
            METRICS['status'] = "READY TO SEND"
        draw_ui()

    def datagram_received(self, data, addr):
        # SIMULATE 20% PACKET LOSS (Except for handshakes to keep demo smooth)
        if random.random() < 0.20 and len(data) < 200:
            MESSAGES.append(f"[!] SIMULATED PACKET LOSS: Dropped packet from {addr}")
            draw_ui()
            return
            
        self.target_addr = addr
        METRICS['target'] = f"{addr[0]}:{addr[1]}"
        
        try:
            packet = parse_packet(data)
        except Exception:
            return

        # 1. Received 0-RTT Handshake
        if packet["type"] == TYPE_HANDSHAKE and self.is_server:
            METRICS['status'] = "DECRYPTING..."
            draw_ui()
            
            client_x25519_pub = packet["x25519_pubkey"]
            ciphertext = packet["payload"]
            
            start_t = time.time()
            
            # Using the exact same server_decapsulate logic from zkem_demo.py
            self.session_key = server_decapsulate(self.keypair, packet["kem_pubkey"], client_x25519_pub)
            
            aesgcm = AESGCM(self.session_key)
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            plaintext = aesgcm.decrypt(nonce, ct, None)
            
            METRICS['enc_time'] = (time.time() - start_t) * 1000
            METRICS['status'] = "CONNECTED"
            MESSAGES.append(f"[Peer] {plaintext.decode()}")
            
            # Send ACK (Simulated by a tiny data packet for now)
            self.send_message("ACK", is_ack=True)
            draw_ui()

        # 2. Received Data or ACK
        elif packet["type"] == TYPE_DATA:
            if not self.session_key: return
            
            start_t = time.time()
            aesgcm = AESGCM(self.session_key)
            ciphertext = packet["payload"]
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            plaintext = aesgcm.decrypt(nonce, ct, None)
            
            msg_text = plaintext.decode()
            if msg_text == "ACK":
                METRICS['rtt'] = (time.time() - self.last_send_time) * 1000
                MESSAGES.append("[+] Packet Acknowledged (Loss Recovery Success!)")
            else:
                MESSAGES.append(f"[Peer] {msg_text}")
                self.send_message("ACK", is_ack=True) # Send ACK back
                
            METRICS['enc_time'] = (time.time() - start_t) * 1000
            draw_ui()

    def send_message(self, text, is_ack=False):
        if not self.target_addr:
            MESSAGES.append("[-] Cannot send, no target address known!")
            draw_ui()
            return
            
        start_t = time.time()
        
        # If client has no session key yet, generate one for 0-RTT
        if not self.session_key and not self.is_server:
            # Client encapsulates against server's public keys
            self.session_key, kem_ct, cli_x_pub = client_encapsulate(self.keypair["kem_pub"], self.keypair["x_pub"])
            
            aesgcm = AESGCM(self.session_key)
            nonce = os.urandom(12)
            ciphertext = nonce + aesgcm.encrypt(nonce, text.encode(), None)
            METRICS['enc_time'] = (time.time() - start_t) * 1000
            
            start_pow = time.time()
            token = mine_pow(kem_ct)
            METRICS['pow_time'] = (time.time() - start_pow) * 1000
            
            packet = build_handshake_packet(b'SESSION1', token, time.time(), kem_ct, cli_x_pub, ciphertext)
            
        else:
            aesgcm = AESGCM(self.session_key)
            nonce = os.urandom(12)
            ciphertext = nonce + aesgcm.encrypt(nonce, text.encode(), None)
            METRICS['enc_time'] = (time.time() - start_t) * 1000
            packet = build_data_packet(b'SESSION1', 1, 1, 1, ciphertext)

        self.last_send_time = time.time()
        self.transport.sendto(packet, self.target_addr)
        if not is_ack:
            MESSAGES.append(f"[You] {text}")
        draw_ui()

async def handle_input(loop, protocol):
    while True:
        msg = await loop.run_in_executor(None, input)
        if msg.lower() == 'exit':
            os.system('clear')
            sys.exit(0)
        if msg.strip():
            protocol.send_message(msg)

async def main():
    os.system('clear')
    print("Welcome to Z-Protocol Interactive Dashboard!")
    role = input("Are you the [1] SERVER or [2] CLIENT? ")
    
    loop = asyncio.get_running_loop()
    
    if role == '1':
        METRICS['role'] = "SERVER"
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ZProtocolInteractive(is_server=True),
            local_addr=('0.0.0.0', 9999)
        )
    else:
        METRICS['role'] = "CLIENT"
        ip = input("Enter Server IP (e.g., 127.0.0.1): ")
        METRICS['target'] = f"{ip}:9999"
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ZProtocolInteractive(is_server=False),
            local_addr=('0.0.0.0', 0) # Random local port
        )
        protocol.target_addr = (ip, 9999)

    # Start input loop
    await handle_input(loop, protocol)

if __name__ == "__main__":
    asyncio.run(main())
