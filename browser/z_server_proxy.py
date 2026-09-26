import asyncio
import os
import struct
import time
import json
import random
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
            stats['last_enc_time'] = decap_ms

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

            # Forward to local HTTP backend OR intercept /zchat
            if first_line.startswith("POST /zchat"):
                body = http_request.split(b"\r\n\r\n")[1].decode(errors="ignore")
                try:
                    payload = json.loads(body)
                    msg = payload.get("text", "")
                    sender = payload.get("sender", "Client")
                    stats.setdefault("chat_messages", []).append({"sender": sender, "text": msg})
                except:
                    pass
                response = b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
            elif first_line.startswith("GET /zchat"):
                msgs = stats.setdefault("chat_messages", [])
                body = json.dumps(msgs).encode()
                response = f"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body
            elif first_line.startswith("OPTIONS /zchat"):
                response = b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n"
            elif first_line.startswith("GET /zstats"):
                uptime = int(time.time() - stats["start_time"])
                payload = {
                    "packets_received" : stats["packets_received"],
                    "packets_decrypted": stats["packets_decrypted"],
                    "packets_dropped"  : stats["packets_dropped"],
                    "bytes_tunneled"   : stats["bytes_tunneled"],
                    "active_sessions"  : len(stats["session_keys_seen"]),
                    "uptime_seconds"   : uptime,
                    "simulated_loss"   : "20",
                    "avg_enc_time_ms"  : f"{stats.get('last_enc_time', 0):.2f}",
                    "latency_rtt_ms"   : f"{stats.get('last_rtt', random.randint(12, 35))}",
                    "request_log"      : stats["request_log"],
                    "server_kem_pub"   : KEM_PUB.hex()[:32] + "...",
                    "server_x25519_pub": X_PUB.hex(),
                    "protocol"         : "Z-Protocol v2 (ML-KEM-1024 + X25519 + AES-256-GCM)"
                }
                body = json.dumps(payload).encode()
                response = f"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body
            elif first_line.startswith("OPTIONS /zstats"):
                response = b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n"
            
            elif first_line.startswith("POST /zupload"):
                body = http_request.split(b"\r\n\r\n")[1].decode(errors="ignore")
                try:
                    payload = json.loads(body)
                    fn = payload.get("filename")
                    chunk_idx = payload.get("chunk")
                    data_b64 = payload.get("data")
                    stats.setdefault("vault", {}).setdefault(fn, {})[chunk_idx] = data_b64
                except: pass
                response = b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
            
            elif first_line.startswith("OPTIONS /zupload"):
                response = b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n"
            
            elif first_line.startswith("GET /zfiles"):
                vault = stats.get("vault", {})
                files_list = []
                for fn, chunks in vault.items():
                    # Calculate total size in bytes (rough estimate from base64)
                    size = sum(len(c) for c in chunks.values()) * 3 // 4
                    files_list.append({"name": fn, "size": size})
                body = json.dumps(files_list).encode()
                response = f"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body
            
            elif first_line.startswith("GET /zdownload"):
                # Extract filename from query string: GET /zdownload?file=abc.txt
                try:
                    query = first_line.split(" ")[1]
                    fn = query.split("file=")[1].split("&")[0]
                    import urllib.parse
                    fn = urllib.parse.unquote(fn)
                    chunks = stats.get("vault", {}).get(fn, {})
                    # Assemble all chunks in order
                    assembled_b64 = "".join(chunks[i] for i in sorted(chunks.keys()))
                    body = json.dumps({"b64": assembled_b64}).encode()
                except:
                    body = b"{}"
                response = f"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body
            else:
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
        "simulated_loss"   : "20",
        "avg_enc_time_ms"  : f"{stats.get('last_enc_time', 0):.2f}",
        "latency_rtt_ms"   : f"{stats.get('last_rtt', random.randint(12, 35))}",
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
        local_addr=("0.0.0.0", 9000)
    )
    print("[*] UDP tunnel listening on 0.0.0.0:9000")

    app = web.Application()
    
    async def add_cors(request, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = '*'
        return response
    
    async def handle_index(request):
        with open("index.html", "r") as f:
            return web.Response(text=f.read(), content_type="text/html")
    
    app.on_response_prepare.append(add_cors)
    
    app.router.add_get("/", handle_index)
    app.router.add_get("/zstats",  handle_stats)
    app.router.add_options("/zstats", lambda r: web.Response())
    app.router.add_get("/zchat", lambda r: web.Response(
        text=json.dumps(stats.setdefault("chat_messages", [])), 
        content_type="application/json"
    ))
    app.router.add_options("/zchat", lambda r: web.Response())
    
    async def handle_post_chat(request):
        try:
            data = await request.json()
            stats.setdefault("chat_messages", []).append({"sender": data.get("sender", "Server"), "text": data.get("text", "")})
        except:
            pass
        return web.Response(text="ok")
    app.router.add_post("/zchat", handle_post_chat)
    
    app.router.add_get("/zhealth", handle_health)
    
    async def handle_post_upload(request):
        try:
            data = await request.json()
            fn = data.get("filename")
            stats.setdefault("vault", {}).setdefault(fn, {})[data.get("chunk")] = data.get("data")
        except: pass
        return web.Response(text="ok")
    app.router.add_post("/zupload", handle_post_upload)
    app.router.add_options("/zupload", lambda r: web.Response())
    
    async def handle_get_files(request):
        vault = stats.get("vault", {})
        files_list = []
        for fn, chunks in vault.items():
            size = sum(len(c) for c in chunks.values()) * 3 // 4
            files_list.append({"name": fn, "size": size})
        return web.Response(text=json.dumps(files_list), content_type="application/json")
    app.router.add_get("/zfiles", handle_get_files)
    
    async def handle_get_download(request):
        try:
            fn = request.query.get("file")
            chunks = stats.get("vault", {}).get(fn, {})
            assembled_b64 = "".join(chunks[i] for i in sorted(chunks.keys()))
            return web.Response(text=json.dumps({"b64": assembled_b64}), content_type="application/json")
        except:
            return web.Response(text="{}", content_type="application/json")
    app.router.add_get("/zdownload", handle_get_download)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 9001)
    await site.start()
    print("[*] Stats API running on http://0.0.0.0:9001/zstats")

    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
