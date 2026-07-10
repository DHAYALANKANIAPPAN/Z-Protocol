import os
import oqs
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

print("=" * 50)
print("   Z-PROTOCOL — PHASE 1 RESULTS SUMMARY")
print("=" * 50)

# Check 1: liboqs
try:
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
    print(f"[+] liboqs ML-KEM-1024     : OK (pubkey={len(pk)}B, ct={len(ct)}B)")
except Exception as e:
    print(f"[-] liboqs                 : FAILED — {e}")

# Check 2: TLS cert
if os.path.exists("server.pem"):
    size = os.path.getsize("server.pem")
    print(f"[+] TLS certificate        : OK (server.pem, {size} bytes)")
else:
    print("[-] TLS certificate        : MISSING")

# Check 3: PCAP file
if os.path.exists("tls13_baseline.pcap"):
    size = os.path.getsize("tls13_baseline.pcap")
    print(f"[+] PCAP baseline          : OK (tls13_baseline.pcap, {size} bytes)")
else:
    print("[-] PCAP baseline          : MISSING — redo capture step")

# Check 4: Benchmark numbers
ITERATIONS = 1000
start = time.perf_counter()
for _ in range(ITERATIONS):
    priv = X25519PrivateKey.generate()
    peer_priv = X25519PrivateKey.generate()
    priv.exchange(peer_priv.public_key())
x25519_total = time.perf_counter() - start

start = time.perf_counter()
with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    for _ in range(ITERATIONS):
        pk = kem.generate_keypair()
        ct, se = kem.encap_secret(pk)
        kem.decap_secret(ct)
pqc_total = time.perf_counter() - start

print(f"[+] X25519 avg               : {(x25519_total/ITERATIONS)*1000:.4f} ms/op")
print(f"[+] ML-KEM-1024 avg          : {(pqc_total/ITERATIONS)*1000:.4f} ms/op")
print(f"[+] Speed ratio              : {pqc_total/x25519_total:.2f}x")
print()
print("  >> THESIS DATA POINT 1: Record the ratio above")
print("=" * 50)
