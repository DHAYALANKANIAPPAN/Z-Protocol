import asyncio
import os
import time
from zpacket import build_packet, TYPE_HANDSHAKE
from zkem import client_encapsulate
from zpow import compute_pow
from zratchet import DoubleRatchet

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001

async def main():
    with open("server_kem.pub", "rb") as f:
        server_kem_pub = f.read()
    with open("server_x25519.pub", "rb") as f:
        server_x_pub = f.read()

    print("[*] Loaded server keys")

    # Hybrid KEM
    result      = client_encapsulate(server_kem_pub, server_x_pub)
    session_key = result["session_key"]
    kem_ct      = result["kem_ciphertext"]
    client_x    = result["client_x_pub_raw"]

    # Ratchet encrypt message
    ratchet = DoubleRatchet(session_key)
    message = b"Hello from Z-Protocol v2 - forward secret + replay protected!"
    ct, num = ratchet.encrypt(message)
    print(f"[+] Message encrypted with ratchet key #{num}")

    # Compute PoW — timestamp fixed at this moment
    session_id = os.urandom(8)
    timestamp  = time.time()
    print("[*] Computing SHA3-512 PoW...")
    t0        = time.perf_counter()
    pow_nonce = compute_pow(session_id, timestamp)
    pow_time  = time.perf_counter() - t0
    print(f"[+] PoW solved in {pow_time*1000:.2f} ms — nonce: {pow_nonce.hex()}")

    # Pad nonce to 32 bytes for header field
    pow_token = pow_nonce + b'\x00' * 24

    # Build packet — pass timestamp and pow_token explicitly
    payload = kem_ct + ct
    packet  = build_packet(
        TYPE_HANDSHAKE, session_id,
        server_kem_pub, client_x,
        payload,
        pow_token=pow_token,
        timestamp=timestamp
    )

    print(f"[+] Z-Protocol v2 packet: {len(packet)} bytes")

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
