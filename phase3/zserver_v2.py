import asyncio
import os
from zpacket import parse_packet, verify_timestamp
from zkem import generate_hybrid_keypair, server_decapsulate
from zcrypto import encrypt, decrypt
from zpow import verify_pow
from zreplay import ReplayFilter
from zratchet import DoubleRatchet
from zsession import SessionStore

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001

class ZProtocolServerV2(asyncio.DatagramProtocol):
    def __init__(self, keypair):
        self.keypair       = keypair
        self.transport     = None
        self.replay_filter = ReplayFilter(window=30)
        self.session_store = SessionStore(ttl=3600)

    def connection_made(self, transport):
        self.transport = transport
        print(f"[*] Z-Protocol v2 listening on {SERVER_HOST}:{SERVER_PORT}")
        print(f"[*] PoW difficulty : 2 leading zero bytes")
        print(f"[*] Replay window  : 30 seconds")

    def datagram_received(self, data, addr):
        print(f"\n[>] Packet from {addr} ({len(data)} bytes)")
        try:
            # Step 1: parse
            packet = parse_packet(data)

            # Step 2: timestamp check
            if not verify_timestamp(packet):
                print("[-] Timestamp expired — dropped")
                return
            print("[+] Timestamp valid")

            # Step 3: PoW check — extract 8 byte nonce from 32 byte field
            pow_nonce = packet["pow_token"][:8]
            if not verify_pow(pow_nonce, packet["session_id"], packet["timestamp"]):
                print("[-] PoW invalid — dropped")
                return
            print("[+] PoW verified")

            # Step 4: replay check
            if self.replay_filter.is_replay(pow_nonce, packet["timestamp"]):
                print("[-] Replay detected — dropped")
                return
            print("[+] Replay check passed")

            # Step 5: hybrid KEM decapsulate
            session_key = server_decapsulate(
                self.keypair,
                packet["payload"][:1568],
                packet["x25519_pubkey"]
            )
            print(f"[+] Session key: {session_key.hex()[:32]}...")

            # Step 6: ratchet decrypt
            ratchet   = DoubleRatchet(session_key)
            plaintext = ratchet.decrypt(packet["payload"][1568:])
            print(f"[+] Decrypted  : {plaintext.decode()}")

            # Step 7: register session
            self.session_store.create(packet["session_id"], ratchet)

            # Step 8: encrypted ACK
            ack_ratchet = DoubleRatchet(session_key)
            ack_ratchet.next_message_key()
            ack_ct, _ = ack_ratchet.encrypt(b"Z-Protocol v2 ACK - quantum safe")
            self.transport.sendto(ack_ct, addr)
            print(f"[+] ACK sent | {self.session_store.stats()}")

        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback; traceback.print_exc()


async def main():
    server_keys = generate_hybrid_keypair()
    print(f"[*] KEM pubkey: {len(server_keys['kem_pub_bytes'])} bytes")

    with open("server_kem.pub", "wb") as f:
        f.write(server_keys["kem_pub_bytes"])
    with open("server_x25519.pub", "wb") as f:
        f.write(server_keys["x_pub_bytes"])
    print("[*] Public keys saved")

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: ZProtocolServerV2(server_keys),
        local_addr=(SERVER_HOST, SERVER_PORT)
    )
    try:
        await asyncio.sleep(3600)
    finally:
        transport.close()
        server_keys["kem"].free()

asyncio.run(main())
