import asyncio
import os
from zpacket import parse_packet, verify_pow, verify_timestamp
from zkem import generate_hybrid_keypair, server_decapsulate
from zcrypto import decrypt, encrypt

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

class ZProtocolServer(asyncio.DatagramProtocol):
    def __init__(self, keypair):
        self.keypair = keypair
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        print(f"[*] Z-Protocol server listening on {SERVER_HOST}:{SERVER_PORT}")

    def datagram_received(self, data, addr):
        print(f"\n[>] Packet received from {addr} ({len(data)} bytes)")
        try:
            # Step 1: parse
            packet = parse_packet(data)

            # Step 2: verify PoW
            if not verify_pow(packet):
                print("[-] PoW invalid — dropping packet")
                return

            # Step 3: verify timestamp
            if not verify_timestamp(packet):
                print("[-] Timestamp expired — dropping packet (replay?)")
                return

            # Step 4: derive session key
            session_key = server_decapsulate(
                self.keypair,
                packet["payload"][:1568],
                packet["x25519_pubkey"]
            )

            # Step 5: decrypt actual data
            encrypted_data = packet["payload"][1568:]
            if encrypted_data:
                plaintext = decrypt(session_key, encrypted_data)
                print(f"[+] Decrypted message: {plaintext.decode()}")

            # Step 6: send encrypted response
            response = encrypt(session_key, b"Z-Protocol ACK: message received")
            self.transport.sendto(response, addr)
            print(f"[+] Response sent to {addr}")

        except Exception as e:
            print(f"[-] Processing error: {e}")


async def main():
    server_keys = generate_hybrid_keypair()
    print(f"[*] Server KEM pubkey size : {len(server_keys['kem_pub_bytes'])} bytes")
    print(f"[*] Server X25519 pubkey   : {server_keys['x_pub_bytes'].hex()[:32]}...")

    # Save pubkeys to file so client can read them
    with open("server_kem.pub", "wb") as f:
        f.write(server_keys["kem_pub_bytes"])
    with open("server_x25519.pub", "wb") as f:
        f.write(server_keys["x_pub_bytes"])
    print("[*] Public keys saved to server_kem.pub and server_x25519.pub")

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ZProtocolServer(server_keys),
        local_addr=(SERVER_HOST, SERVER_PORT)
    )
    try:
        await asyncio.sleep(3600)
    finally:
        transport.close()
        server_keys["kem"].free()

asyncio.run(main())
