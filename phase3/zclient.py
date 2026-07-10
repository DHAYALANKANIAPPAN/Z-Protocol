import asyncio
import os
from zpacket import build_packet, TYPE_HANDSHAKE
from zkem import client_encapsulate
from zcrypto import encrypt, decrypt

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

async def main():
    # Load server public keys
    with open("server_kem.pub", "rb") as f:
        server_kem_pub = f.read()
    with open("server_x25519.pub", "rb") as f:
        server_x_pub = f.read()

    print(f"[*] Loaded server KEM pubkey  : {len(server_kem_pub)} bytes")
    print(f"[*] Loaded server X25519 key  : {server_x_pub.hex()[:32]}...")

    # Encapsulate hybrid KEM
    result = client_encapsulate(server_kem_pub, server_x_pub)
    session_key     = result["session_key"]
    kem_ciphertext  = result["kem_ciphertext"]
    client_x_pub    = result["client_x_pub_raw"]

    print(f"[+] Session key derived: {session_key.hex()[:32]}...")

    # Encrypt our message
    message   = b"Hello from Z-Protocol client - quantum safe!"
    encrypted = encrypt(session_key, message)

    # Build packet: payload = kem_ciphertext + encrypted_message
    session_id = os.urandom(8)
    payload    = kem_ciphertext + encrypted

    packet = build_packet(
        TYPE_HANDSHAKE,
        session_id,
        server_kem_pub,
        client_x_pub,
        payload
    )

    print(f"[+] Built Z-Protocol packet: {len(packet)} bytes")

    # Send over UDP
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(SERVER_HOST, SERVER_PORT)
    )
    transport.sendto(packet)
    print(f"[+] Packet sent to {SERVER_HOST}:{SERVER_PORT}")

    await asyncio.sleep(1)
    transport.close()

asyncio.run(main())
