import asyncio
import os
import struct
import time
import json
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from aiohttp import web

# ── Server keypair ────────────────────────────────────────────
with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    KEM_PUB  = kem.generate_keypair()
    KEM_PRIV = kem.export_secret_key()
X_PRIV_OBJ = x25519.X25519PrivateKey.generate()
X_PUB      = X_PRIV_OBJ.public_key().public_bytes_raw()

with open("server_kem.pub",    "wb") as f: f.write(KEM_PUB)
with open("server_x25519.pub", "wb") as f: f.write(X_PUB)

# ── Live stats store ──────────────────────────────────────────
stats = {
    "packets_received" : 0,
    "packets_decrypted": 0,
    "packets_dropped"  : 0,
    "session_keys_seen": [],
    "request_log"      : [],   # last 20 requests
    "start_time"       : time.time(),
    "bytes_tunneled"   : 0,
}

def log_request(method_path, addr, session_key_hex, size):
    entry = {
        "time"       : time.strftime("%H:%M:%S"),
        "request"    : method_path,
        "from"       : f"{addr[0]}:{addr[1]}",
        "session_key": session_key_hex[:16] + "...",
        "size"       : size,
        "status"     : "decrypted"
    }
    stats["request_log"].insert(0, entry)
    stats["request_log"] = stats["request_log"][:20]  # keep last 20

# ── Crypto ────────────────────────────────────────────────────
def server_hybrid_decap(kem_ciphertext, client_x_pub):
    with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=KEM_PRIV) as kem:
        kem_shared = kem.decap_secret(kem_ciphertext)
    cli_pub_obj   = x25519.X25519PublicKey.from_public_bytes(client_x_pub)
    x25519_shared = X_PRIV_OBJ.exchange(cli_pub_obj)
    combined      = kem_shared + x25519_shared
    return HKDF(
        algorithm=hashes.SHA3_512(), length=32,
        salt=None, info=b"Z-Protocol Derivation"
    ).derive(combined)

def decrypt_payload(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

def encrypt_payload(key, plaintext):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

# ── UDP protocol ──────────────────────────────────────────────
class ZServerUDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.process_packet(data, addr))

    async def process_packet(self, data, addr):
        stats["packets_received"] += 1
        header_size = struct.calcsize("!2sB8s1568s32sI")
        if len(data) < header_size:
            stats["packets_dropped"] += 1
            return

        magic, msg_type, session_id, _, client_x_pub, _ = struct.unpack(
            "!2sB8s1568s32sI", data[:header_size]
        )
        if magic != b"ZP":
            stats["packets_dropped"] += 1
            return

        payload        = data[header_size:]
        kem_ciphertext = payload[:1568]
        enc_request    = payload[1568:]

        print(f"\n[Z-Tunnel Ingress] Intercepted 0-RTT frame from {addr}")

        try:
            t0          = time.perf_counter()
            session_key = server_hybrid_decap(kem_ciphertext, client_x_pub)
            decap_ms    = (time.perf_counter() - t0) * 1000

            http_request = decrypt_payload(session_key, enc_request)
            stats["packets_decrypted"] += 1
            stats["bytes_tunneled"]    += len(http_request)

            key_hex = session_key.hex()
            if key_hex not in stats["session_keys_seen"]:
                stats["session_keys_seen"].append(key_hex)
            stats["session_keys_seen"] = stats["session_keys_seen"][-10:]

            lines      = http_request.decode(errors="ignore").split("\r\n")
            first_line = lines[0] if lines else "Unknown"
            print(f"  Request : {first_line}")
            print(f"  KEM decap: {decap_ms:.2f}ms | key: {key_hex[:16]}...")

            log_request(first_line, addr, key_hex, len(http_request))

            # Forward to local HTTP backend
            try:
                r, w = await asyncio.open_connection("127.0.0.1", 8080)
                w.write(http_request)
                await w.drain()
                response = b""
                while True:
                    chunk = await r.read(4096)
                    response += chunk
                    if len(chunk) < 4096: break
                w.close()
            except Exception:
                response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 20\r\n\r\nBackend offline."

            self.transport.sendto(encrypt_payload(session_key, response), addr)
            print(f"  Response encrypted and returned.")

        except Exception as e:
            stats["packets_dropped"] += 1
            print(f"[-] Pipeline error: {e}")

# ── Stats HTTP API ────────────────────────────────────────────
async def handle_stats(request):
    uptime = int(time.time() - stats["start_time"])
    payload = {
        "packets_received" : stats["packets_received"],
        "packets_decrypted": stats["packets_decrypted"],
        "packets_dropped"  : stats["packets_dropped"],
        "bytes_tunneled"   : stats["bytes_tunneled"],
        "active_sessions"  : len(stats["session_keys_seen"]),
        "uptime_seconds"   : uptime,
        "request_log"      : stats["request_log"],
        "server_kem_pub"   : KEM_PUB.hex()[:32] + "...",
        "server_x25519_pub": X_PUB.hex(),
        "protocol"         : "Z-Protocol v2 (ML-KEM-1024 + X25519 + AES-256-GCM)"
    }
    return web.Response(
        text=json.dumps(payload),
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "*"}
    )

async def handle_health(request):
    return web.Response(text="ok")

async def main():
    print("[*] Launching Z-Protocol Server + Stats API...")

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        ZServerUDPProtocol,
        local_addr=("127.0.0.1", 9000)
    )
    print("[*] UDP tunnel listening on 127.0.0.1:9000")

    app = web.Application()
    app.router.add_get("/zstats",  handle_stats)
    app.router.add_get("/zhealth", handle_health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 9001)
    await site.start()
    print("[*] Stats API running on http://127.0.0.1:9001/zstats")

    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
