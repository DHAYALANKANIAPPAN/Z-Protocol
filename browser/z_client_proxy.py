import asyncio
import os
import struct
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9999  
SERVER_UDP_HOST = "127.0.0.1"
SERVER_UDP_PORT = 9000

def client_hybrid_encap(server_kem_pub, server_x_pub):
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        kem_ciphertext, kem_shared = kem.encap_secret(server_kem_pub)
    client_x_priv = x25519.X25519PrivateKey.generate()
    client_x_pub_raw = client_x_priv.public_key().public_bytes_raw()
    srv_pub_obj = x25519.X25519PublicKey.from_public_bytes(server_x_pub)
    x25519_shared = client_x_priv.exchange(srv_pub_obj)
    combined = kem_shared + x25519_shared
    session_key = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=None, info=b"Z-Protocol Derivation").derive(combined)
    return session_key, kem_ciphertext, client_x_pub_raw

def encrypt_payload(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

def decrypt_payload(key, encrypted_blob):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(encrypted_blob[:12], encrypted_blob[12:], None)

async def handle_browser_request(reader, writer):
    raw_request = b""
    try:
        # Read incoming browser block completely
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=0.1)
            if not chunk: break
            raw_request += chunk
            if len(chunk) < 4096: break
    except asyncio.TimeoutError:
        pass
    
    if not raw_request:
        writer.close()
        return

    print(f"\n[HTTP Intercept] Caught browser request ({len(raw_request)} bytes)")

    if not (os.path.exists("server_kem.pub") and os.path.exists("server_x25519.pub")):
        print("[-] Error: Run z_server_proxy.py first to generate local public key assets.")
        writer.close()
        return

    with open("server_kem.pub", "rb") as f: server_kem_pub = f.read()
    with open("server_x25519.pub", "rb") as f: server_x_pub = f.read()

    session_key, kem_ciphertext, client_x_pub = client_hybrid_encap(server_kem_pub, server_x_pub)
    encrypted_request = encrypt_payload(session_key, raw_request)
    
    session_id = os.urandom(8)
    payload = kem_ciphertext + encrypted_request
    header = struct.pack("!2sB8s1568s32sI", b"ZP", 0x01, session_id, server_kem_pub, client_x_pub, len(payload))
    monolithic_packet = header + payload

    class UDPClientProtocol(asyncio.DatagramProtocol):
        def __init__(self, reply_future):
            self.reply_future = reply_future
        def datagram_received(self, data, addr):
            if not self.reply_future.done():
                self.reply_future.set_result(data)

    loop = asyncio.get_running_loop()
    reply_future = loop.create_future()
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPClientProtocol(reply_future),
        remote_addr=(SERVER_UDP_HOST, SERVER_UDP_PORT)
    )
    
    print(f"[Z-Tunnel] Tunneling 0-RTT Post-Quantum Packet over UDP...")
    transport.sendto(monolithic_packet)
    
    try:
        raw_udp_response = await asyncio.wait_for(reply_future, timeout=2.0)
        decrypted_response = decrypt_payload(session_key, raw_udp_response)
        print(f"[HTTP Return] Decrypted secure payload, loading assets in browser!")
        writer.write(decrypted_response)
        await writer.drain()
    except asyncio.TimeoutError:
        print("[-] Tunnel Timeout: Server did not respond.")
    finally:
        transport.close()
        writer.close()

async def main():
    server = await asyncio.start_server(handle_browser_request, PROXY_HOST, PROXY_PORT)
    print(f"🚀 Z-Protocol Client Proxy running! Point your Browser HTTP Proxy to {PROXY_HOST}:{PROXY_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
